package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/modules"
)

func TestPrompt112BOnlyFocusedPanelHasActiveArrow(t *testing.T) {
	m := &model{width: 100, height: 30, modules: []modules.Module{statusModule{id: "module", name: "Module", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP}}, selectedModules: map[string]bool{}, focus: focusModules, cursor: 0, navigationRow: 0, toolFamilies: []modules.ToolFamily{modules.ToolFamilyNetExec}}
	m.categories = []modules.Category{modules.CategoryEnumeration}
	m.protocols = []modules.Protocol{modules.ProtocolLDAP}
	m.resizeOutput()
	frame := ansi.Strip(m.View())
	if strings.Count(frame, "> [ ]") != 1 {
		t.Fatalf("modules focus should show one active arrow:\n%s", frame)
	}
	m.focus = focusNavigation
	frame = ansi.Strip(m.View())
	if strings.Contains(frame, "> [ ]") {
		t.Fatalf("navigation focus left an active module arrow:\n%s", frame)
	}
	if !strings.Contains(frame, "> TOOL FAMILY") {
		t.Fatalf("navigation focus did not show its active arrow:\n%s", frame)
	}
}

func TestPrompt112BInputRequiredMarkerStaysOnOneLine(t *testing.T) {
	m := &model{width: 44, height: 30, modules: []modules.Module{statusModule{id: "input", name: "A very long module name that must truncate", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, status: modules.StatusInputRequired}}, selectedModules: map[string]bool{}, focus: focusModules, cursor: 0}
	m.resizeOutput()
	frame := ansi.Strip(m.View())
	if strings.Contains(frame, "INPUT-\nREQ") || strings.Contains(frame, "\nREQ") {
		t.Fatalf("input marker wrapped:\n%s", frame)
	}
	if !strings.Contains(frame, "INPUT") {
		t.Fatalf("compact input marker missing:\n%s", frame)
	}
}

func TestPrompt112BFindingsCategoryUsesCombinedNavigableCount(t *testing.T) {
	m := &model{findingsView: true, findingCategoryView: true, width: 100, height: 30, findingCursor: 0, findingCategories: []findingCategory{{Name: "Active Directory", Findings: 2, Observations: 3, Highest: "high"}}}
	frame := ansi.Strip(m.View())
	if strings.Contains(frame, "OBSERVED") || strings.Contains(frame, "observations") {
		t.Fatalf("category overview still exposes a separate observations column:\n%s", frame)
	}
	if !strings.Contains(frame, "FINDINGS") || !strings.Contains(frame, " 5 ") {
		t.Fatalf("combined category count missing:\n%s", frame)
	}
}

func TestPrompt112BCtrlSIsNoOp(t *testing.T) {
	m := &model{width: 100, height: 30, focus: focusModules, cursor: 2}
	before := m.cursor
	_, cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlS})
	if cmd != nil || m.cursor != before {
		t.Fatalf("Ctrl+S changed the main view")
	}
	m.findingsView = true
	m.findingCategoryView = true
	m.findingCategories = []findingCategory{{Name: "AD CS"}}
	_, cmd = m.handleFindingsKey("ctrl+s")
	if cmd != nil || m.findingCursor != 0 {
		t.Fatalf("Ctrl+S changed Findings state")
	}
}
