package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestFindingsOnlyModelStartsInFindingsAndBlocksExecution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enumeration.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertTarget(ctx, "example.test", "dc01"); err != nil {
		t.Fatal(err)
	}
	targetID, err := db.TargetID(ctx, "example.test", "dc01")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.NewFindingsOnly("dc01", "example.test", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	model := newFindingsOnlyModel(ctx, cfg, db, targetID, "test")
	if !model.findingsOnly() || !model.findingsView || !model.findingCategoryView || model.findings != nil {
		t.Fatalf("offline model state: mode=%v findingsView=%v manager=%v", model.mode, model.findingsView, model.findings)
	}
	normal := newModel(ctx, cfg, db, nil, nil, targetID, "test")
	defer normal.findings.Close()
	normal.handleKey(tea.KeyMsg{Type: tea.KeyCtrlF})
	if normal.findingsView != model.findingsView || normal.findingCategoryView != model.findingCategoryView || normal.findingCategory != model.findingCategory {
		t.Fatalf("offline Findings entry differs from normal Ctrl+F: offline=%+v normal=%+v", findingsEntryState(model), findingsEntryState(normal))
	}
	model.handleFindingsKey("ctrl+w")
	if !model.findingsView || model.watcher {
		t.Fatal("offline Findings view escaped to Watcher")
	}
	if command := model.execute(0); command != nil || model.batch != nil {
		t.Fatal("offline model exposed module execution")
	}
	model.openWatcher()
	if model.watcher {
		t.Fatal("offline model opened Watcher")
	}
	if view := model.View(); !containsText(view, "FINDINGS ONLY · OFFLINE") {
		t.Fatalf("offline indicator missing from view: %q", view)
	}
}

func findingsEntryState(model *model) string {
	return fmt.Sprintf("view=%v categoryView=%v category=%q detail=%v cursor=%d", model.findingsView, model.findingCategoryView, model.findingCategory, model.findingDetail, model.findingCursor)
}

func containsText(value, wanted string) bool {
	for index := 0; index+len(wanted) <= len(value); index++ {
		if value[index:index+len(wanted)] == wanted {
			return true
		}
	}
	return false
}

func TestFindingsOnlyUsesHierarchicalCategoryDrilldownAndBackNavigation(t *testing.T) {
	model := &model{
		mode:                ModeFindingsOnly,
		findingsView:        true,
		findingCategoryView: true,
		findingViewMode:     "all",
		findingAllRows: []storage.Finding{{FindingInput: storage.FindingInput{
			FindingType: "adcs_esc_1",
			Title:       "Certificate template condition",
			Severity:    "high",
		}}},
		width:  100,
		height: 30,
	}
	model.findingCategories = buildFindingCategories(model.findingAllRows)
	model.findingCursor = 0
	model.refreshFindings()
	if !model.findingCategoryView || len(model.findingCategories) == 0 {
		t.Fatal("offline model did not expose Findings categories")
	}
	model.handleFindingsKey("enter")
	if !model.findingCategoryView || !model.findingSubcategoryView {
		t.Fatal("category Enter did not open the normal subcategory view")
	}
	model.handleFindingsKey("enter")
	if model.findingCategoryView || model.findingSubcategoryView {
		t.Fatal("subcategory Enter did not open the normal record view")
	}
	model.handleFindingsKey("esc")
	if !model.findingCategoryView || !model.findingSubcategoryView {
		t.Fatal("record Esc did not return to the normal subcategory view")
	}
	model.handleFindingsKey("esc")
	if !model.findingCategoryView || model.findingSubcategoryView {
		t.Fatal("subcategory Esc did not return to the category view")
	}
	model.handleFindingsKey("esc")
	if !model.findingsView || model.watcher {
		t.Fatal("root Esc escaped the offline Findings hierarchy")
	}
	model.handleFindingsKey("ctrl+w")
	if !model.findingsView || model.watcher {
		t.Fatal("Ctrl+W escaped the offline Findings hierarchy")
	}
}
