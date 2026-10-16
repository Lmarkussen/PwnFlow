package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/config"
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

func TestUppercaseAIsNotFindingsAll(t *testing.T) {
	model := &model{findingsView: true, findingCategoryView: true, findingViewMode: "findings", width: 100, height: 24}
	model.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'A'}})
	if model.findingViewMode == "all" {
		t.Fatal("uppercase A was interpreted as Findings All")
	}
}

func TestFindingsHierarchyBackNavigation(t *testing.T) {
	model := &model{findingsView: true, findingCategoryView: true, findingCategories: []findingCategory{{Key: "kerberos", Name: "Kerberos"}}, findingAllRows: []storage.Finding{{FindingInput: storage.FindingInput{FindingType: "kerberoastable_account", Title: "Kerberoastable", Severity: "medium"}}}, width: 100, height: 24}
	model.handleFindingsKey("enter")
	if !model.findingSubcategoryView || model.findingCategory != "kerberos" {
		t.Fatal("category did not open subcategories")
	}
	model.handleFindingsKey("enter")
	if model.findingSubcategoryView || model.findingSubcategory != "kerberoastable" {
		t.Fatal("subcategory did not open findings")
	}
	model.handleFindingsKey("esc")
	if !model.findingSubcategoryView || model.findingCategory != "kerberos" {
		t.Fatal("Esc did not restore subcategory view")
	}
}

func TestGlobalVisibleFindingsGroupsACLRecordsOnly(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{FindingType: "ad_acl_writedacl", RelatedObjectID: "p", AffectedObjectID: "t", RelatedObject: "P", AffectedObject: "T", Severity: "high"}},
		{FindingInput: storage.FindingInput{FindingType: "ad_acl_writeowner", RelatedObjectID: "p", AffectedObjectID: "t", RelatedObject: "P", AffectedObject: "T", Severity: "high"}},
		{FindingInput: storage.FindingInput{FindingType: "kerberoastable_account", Title: "Kerberoastable", Severity: "medium"}},
	}
	grouped := groupVisibleFindings(rows)
	if len(grouped) != 2 || !strings.HasPrefix(grouped[0].FindingType, "ad_acl_group") {
		t.Fatalf("unexpected global grouping: %#v", grouped)
	}
}

func TestOriginalEvidenceViewerPreservesSyntheticSecretAndRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	artifactDir := filepath.Join(root, "results", "example.test", "artifacts")
	if err := os.MkdirAll(artifactDir, 0o700); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(artifactDir, "material.log")
	original := "$krb5tgs$fictional-ticket\nOSDJoinPassword=fictional-password\n"
	if err := os.WriteFile(artifact, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	model := &model{cfg: config.Config{Root: root, Domain: "example.test"}, findingsView: true, findingDetail: true, findingRows: []storage.Finding{{FindingInput: storage.FindingInput{ArtifactPath: "artifacts/material.log"}}}, width: 100, height: 24}
	model.handleFindingsKey("e")
	if model.evidenceError != "" || !strings.Contains(strings.Join(model.evidenceLines, "\n"), "fictional-password") {
		t.Fatalf("evidence was not shown faithfully: %q", model.evidenceError)
	}
	data, err := os.ReadFile(artifact)
	if err != nil || string(data) != original {
		t.Fatal("evidence artifact changed")
	}
	if err := os.Symlink(artifact, filepath.Join(artifactDir, "link.log")); err != nil {
		t.Fatal(err)
	}
	model.openFindingEvidence(storage.Finding{FindingInput: storage.FindingInput{ArtifactPath: "artifacts/link.log"}})
	if !strings.Contains(model.evidenceError, "symlink") {
		t.Fatalf("symlink was not rejected: %q", model.evidenceError)
	}
}

func TestFindingCategoryUsesStableDetectorIdentity(t *testing.T) {
	cases := []struct{ typ, source, want string }{
		{"ad_acl_addkeycredentiallink", "RustHound-CE", "acl"},
		{"ad_acl_genericwrite", "RustHound-CE", "acl"},
		{"kerberos_ticket_material_collected", "NetExec", "kerberos"},
		{"sccm_task_sequence_credentials_exposed", "PXEThief", "credentials"},
		{"adcs_esc_esc1", "Certipy", "adcs"},
		{"unconstrained_delegation_configured", "RustHound-CE", "delegation"},
		{"relay_exposure_observed", "RelayKing", "network"},
		{"ghostspn_orphaned_spn", "ghostSPN", "active_directory"},
		{"gpo_security_configuration_observed", "gpoParser", "active_directory"},
		{"mssql_encryption_not_enforced", "mssqlrelay", "network"},
		{"mssql_relationship_observed", "MSSqlPwner", "network"},
		{"masscan_open_port_observed", "Masscan", "network"},
	}
	for _, test := range cases {
		finding := storage.Finding{FindingInput: storage.FindingInput{FindingType: test.typ, SourceTool: test.source}}
		if got := findingCategoryKey(finding); got != test.want {
			t.Errorf("%s classified as %s, want %s", test.typ, got, test.want)
		}
	}
}

func TestInlineEvidenceLoadsPXEValuesForReferencedTaskSequence(t *testing.T) {
	root := t.TempDir()
	artifactDir := filepath.Join(root, "results", "example.test", "artifacts")
	if err := os.MkdirAll(artifactDir, 0o700); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(artifactDir, "pxethief.log")
	content := "Task sequence ONE\nOSDJoinAccount=LAB\\one\nOSDJoinPassword=p@ss\\one\nOSDLocalAdminPassword=local-one\nTask sequence TWO\nOSDJoinAccount=LAB\\two\nOSDJoinPassword=p@ss\\two\n"
	if err := os.WriteFile(artifact, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	finding := storage.Finding{FindingInput: storage.FindingInput{
		SourceTool: "PXEThief", FindingType: "sccm_task_sequence_credentials_exposed", ArtifactPath: "artifacts/pxethief.log", ArtifactRef: "line:2",
		EvidenceJSON: `{"credential_variables":["OSDJoinAccount","OSDJoinPassword","OSDLocalAdminPassword"],"task_sequence_context":"task-sequence-line:1","artifact_records":["line:2","line:3","line:4"]}`,
	}}
	loaded := loadInlineEvidence(config.Config{Root: root, Domain: "example.test"}, finding)
	if loaded.error != "" {
		t.Fatal(loaded.error)
	}
	joined := strings.Join(loaded.lines, "\n")
	for _, want := range []string{"LAB\\one", "p@ss\\one", "local-one"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("inline PXE evidence omitted %q: %q", want, joined)
		}
	}
	if strings.Contains(joined, "two") {
		t.Fatalf("inline PXE evidence mixed task sequences: %q", joined)
	}
}

func TestInlineEvidenceLoadsCompleteKerberosRecord(t *testing.T) {
	root := t.TempDir()
	artifactDir := filepath.Join(root, "results", "example.test", "artifacts")
	if err := os.MkdirAll(artifactDir, 0o700); err != nil {
		t.Fatal(err)
	}
	record := "$krb5tgs$23$*svc$EXAMPLE.TEST$MSSQL/foo*$abcdef0123456789/full-record"
	artifact := filepath.Join(artifactDir, "kerberoast.txt")
	if err := os.WriteFile(artifact, []byte(record+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	finding := storage.Finding{FindingInput: storage.FindingInput{
		SourceTool: "NetExec", FindingType: "kerberos_ticket_material_collected", ArtifactPath: "artifacts/kerberoast.txt",
		EvidenceJSON: `{"material_collected":true,"principal":"svc","record_line_numbers":[1]}`,
	}}
	loaded := loadInlineEvidence(config.Config{Root: root, Domain: "example.test"}, finding)
	if loaded.error != "" || len(loaded.lines) != 1 || loaded.lines[0] != record {
		t.Fatalf("full Kerberos record was not preserved: %#v error=%q", loaded.lines, loaded.error)
	}
}
