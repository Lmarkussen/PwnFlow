package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/runner"
	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestFindingsViewFiltersAndDoesNotRenderEvidenceSecrets(t *testing.T) {
	model := &model{findingsView: true, width: 100, height: 24, findingRows: []storage.Finding{{FindingInput: storage.FindingInput{Title: "Potential Shadow Credentials exposure", Severity: "high", Confidence: "potential-condition", AffectedObject: "APP01$", RelatedObject: "svc-a", SourceTool: "RustHound-CE", EvidenceJSON: `{"secret":"fictional-password"}`, ArtifactPath: "restricted.json", ArtifactRef: "/data/0/Aces/0"}, FirstSeen: time.Now()}}}
	frame := ansi.Strip(model.View())
	if !strings.Contains(frame, "Potential Shadow Credentials exposure") {
		t.Fatal("finding title missing")
	}
	if strings.Contains(frame, "fictional-password") {
		t.Fatal("finding summary leaked evidence secret")
	}
	if _, command := model.handleFindingsKey("enter"); command != nil || !model.findingDetail {
		t.Fatal("detail view did not open")
	}
	if !strings.Contains(ansi.Strip(model.View()), "restricted.json") {
		t.Fatal("detail omitted artifact reference")
	}
}

func TestFindingsWarningWrappingAndWatcherNavigation(t *testing.T) {
	wrapped := ansi.Strip(wrapPaneStyle(warn, "Abort this deliberately long operator warning [y/N]", 18))
	for _, line := range strings.Split(wrapped, "\n") {
		if ansi.StringWidthWc(line) > 18 {
			t.Fatalf("warning overflowed: %q", line)
		}
	}
	m := &model{width: 80, height: 24, batch: &runner.BatchRun{}, findingsView: true}
	updated, _ := m.handleFindingsKey("ctrl+w")
	if !updated.(*model).watcher {
		t.Fatal("Ctrl+W did not return to watcher")
	}
	updated, _ = updated.(*model).handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if updated.(*model).watcher {
		t.Fatal("Esc did not leave watcher")
	}
}

func TestFindingsViewportHandlesLargeResultSets(t *testing.T) {
	rows := make([]storage.Finding, 10000)
	for index := range rows {
		rows[index] = storage.Finding{FindingInput: storage.FindingInput{
			Title: fmt.Sprintf("Synthetic condition %05d", index), Severity: "medium", AffectedObject: fmt.Sprintf("object-%05d", index),
		}}
	}
	model := &model{findingsView: true, findingViewMode: "all", width: 100, height: 24, findingRows: rows}
	frame := ansi.Strip(model.View())
	if strings.Count(frame, "Synthetic condition") > model.findingPageSize() {
		t.Fatalf("rendered more than one viewport page: %d", strings.Count(frame, "Synthetic condition"))
	}
	if _, command := model.handleFindingsKey("end"); command != nil || model.findingCursor != len(rows)-1 {
		t.Fatalf("End did not select final finding: cursor=%d", model.findingCursor)
	}
	if model.findingTop <= 0 {
		t.Fatalf("End did not move viewport: top=%d", model.findingTop)
	}
	if !strings.Contains(ansi.Strip(model.View()), "Synthetic condition 09999") {
		t.Fatal("final finding is not visible after End")
	}
	_, _ = model.handleFindingsKey("home")
	if model.findingCursor != 0 || model.findingTop != 0 {
		t.Fatalf("Home did not restore first page: cursor=%d top=%d", model.findingCursor, model.findingTop)
	}
}

func TestFindingsViewportHandlesMouseWheel(t *testing.T) {
	rows := make([]storage.Finding, 50)
	model := &model{findingsView: true, findingViewMode: "all", width: 100, height: 24, findingRows: rows}
	_, _ = model.Update(tea.MouseMsg{Button: tea.MouseButtonWheelDown})
	if model.findingCursor != 3 {
		t.Fatalf("wheel down moved cursor to %d, want 3", model.findingCursor)
	}
	_, _ = model.Update(tea.MouseMsg{Button: tea.MouseButtonWheelUp})
	if model.findingCursor != 0 {
		t.Fatalf("wheel up moved cursor to %d, want 0", model.findingCursor)
	}
}

func TestFindingCategoriesClassifyAndCountRecords(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{FindingType: "pxethief_credentials", Title: "SCCM task-sequence credentials exposed", Severity: "high", SourceTool: "PXEThief"}},
		{FindingInput: storage.FindingInput{FindingType: "kerberoastable_account", Title: "Kerberoastable account", Severity: "medium", SourceTool: "RustHound-CE"}},
		{FindingInput: storage.FindingInput{FindingType: "ad_acl_genericwrite", Title: "Direct ACL GenericWrite", Severity: "informational", SourceTool: "RustHound-CE"}},
		{FindingInput: storage.FindingInput{FindingType: "adcs_esc_esc1", Title: "Certipy reported ESC1 — WebEnrollment", Severity: "high", SourceTool: "Certipy"}},
		{FindingInput: storage.FindingInput{FindingType: "relay_exposure", Title: "Potential NTLM relay exposure", Severity: "medium", SourceTool: "RelayKing"}},
	}
	categories := buildFindingCategories(rows)
	counts := map[string]findingCategory{}
	for _, category := range categories {
		counts[category.Key] = category
	}
	if counts["credentials"].Findings != 1 || counts["kerberos"].Findings != 1 || counts["adcs"].Findings != 1 || counts["network"].Findings != 1 {
		t.Fatalf("unexpected category counts: %#v", counts)
	}
	if counts["acl"].Observations != 1 || counts["acl"].Findings != 0 {
		t.Fatalf("ACL observation was not separated: %#v", counts["acl"])
	}
	if counts["credentials"].Highest != "HIGH" || counts["acl"].Highest != "INFORMATIONAL" {
		t.Fatalf("unexpected highest severities: credentials=%s acl=%s", counts["credentials"].Highest, counts["acl"].Highest)
	}
}

func TestFindingCategoryOverviewIsBounded(t *testing.T) {
	model := &model{findingsView: true, findingCategoryView: true, findingCategories: buildFindingCategories(nil), width: 100, height: 24}
	frame := ansi.Strip(model.View())
	if !strings.Contains(frame, "Credentials & SCCM") || !strings.Contains(frame, "Network & Protocols") {
		t.Fatal("category overview omitted expected categories")
	}
	if strings.Count(frame, "Credentials & SCCM") != 1 {
		t.Fatal("category overview rendered duplicate category rows")
	}
}

func TestACLPresentationGroupsRightsWithoutChangingRecords(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{FindingType: "ad_acl_genericall", Title: "GenericAll", Severity: "medium", RelatedObjectID: "S-1-5-21-principal", RelatedObject: "LAB\\Helpdesk", AffectedObjectID: "S-1-5-21-target", AffectedObject: "LAB\\Domain Admins"}},
		{FindingInput: storage.FindingInput{FindingType: "ad_acl_writedacl", Title: "WriteDacl", Severity: "high", RelatedObjectID: "S-1-5-21-principal", RelatedObject: "LAB\\Helpdesk", AffectedObjectID: "S-1-5-21-target", AffectedObject: "LAB\\Domain Admins"}},
		{FindingInput: storage.FindingInput{FindingType: "ad_acl_genericall", Title: "GenericAll", Severity: "high", RelatedObjectID: "S-1-5-21-other", RelatedObject: "LAB\\Other", AffectedObjectID: "S-1-5-21-target", AffectedObject: "LAB\\Domain Admins"}},
	}
	grouped := groupACLFindings(rows)
	if len(grouped) != 2 {
		t.Fatalf("grouped %d relationships, want 2", len(grouped))
	}
	if !strings.Contains(grouped[0].Description, "genericall") || !strings.Contains(grouped[0].Description, "writedacl") {
		t.Fatalf("grouped rights missing: %s", grouped[0].Description)
	}
	if len(rows) != 3 || rows[0].FindingType != "ad_acl_genericall" {
		t.Fatal("grouping modified stored presentation input")
	}
}

func TestGlobalFindingSearchRendersCategories(t *testing.T) {
	model := &model{findingsView: true, findingCategoryView: true, findingSearch: "ESC1", findingViewMode: "all", width: 100, height: 24, findingRows: []storage.Finding{{FindingInput: storage.FindingInput{FindingType: "adcs_esc_esc1", Title: "Certipy reported ESC1 — WebEnrollment", Severity: "high", AffectedObject: "WebEnrollment"}}}}
	frame := ansi.Strip(model.View())
	if !strings.Contains(frame, "FINDINGS SEARCH") || !strings.Contains(frame, "adcs") || !strings.Contains(frame, "ESC1") {
		t.Fatalf("global search omitted category or result: %s", frame)
	}
	_, _ = model.handleFindingsKey("enter")
	if model.findingCategoryView || !model.findingDetail {
		t.Fatal("global search result did not open detail")
	}
}

func TestLegacyCertipyRecordIsObservationWithoutESC(t *testing.T) {
	legacy := storage.Finding{FindingInput: storage.FindingInput{SourceTool: "Certipy", FindingType: "adcs_template_vulnerability", Title: "Certipy flagged certificate template 23", Severity: "medium"}}
	if actionableFinding(legacy) {
		t.Fatal("legacy generic Certipy record remained actionable")
	}
	esc := legacy
	esc.FindingType = "adcs_esc_esc1"
	esc.Title = "Certipy reported ESC1 — WebEnrollment"
	if !actionableFinding(esc) {
		t.Fatal("explicit ESC record was downgraded to an observation")
	}
}
