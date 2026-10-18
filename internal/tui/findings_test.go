package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
	"github.com/pwnflow/pwnflow/internal/config"
	findingengine "github.com/pwnflow/pwnflow/internal/findings"
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
		{FindingInput: storage.FindingInput{FindingType: "netexec_auth_success", Title: "Authentication successful — SMB", Severity: "informational", SourceTool: "NetExec (nxc)"}},
		{FindingInput: storage.FindingInput{FindingType: "netexec_privileged_access", Title: "Privileged access reported — SMB", Severity: "high", SourceTool: "NetExec (nxc)"}},
		{FindingInput: storage.FindingInput{FindingType: "smb_signing_not_required", Title: "SMB Signing Not Required", Severity: "medium", SourceTool: "NetExec (nxc)"}},
	}
	categories := buildFindingCategories(rows)
	counts := map[string]findingCategory{}
	for _, category := range categories {
		counts[category.Key] = category
	}
	if counts["credentials"].Findings != 1 || counts["kerberos"].Findings != 1 || counts["adcs"].Findings != 1 || counts["network"].Findings != 2 || counts["authentication"].Observations != 1 || counts["authentication"].Findings != 1 {
		t.Fatalf("unexpected category counts: %#v", counts)
	}
	if counts["network"].Findings != 2 || counts["network"].Observations != 0 {
		t.Fatalf("SMB signing was moved out of Network & Protocols: %#v", counts["network"])
	}
	if counts["acl"].Observations != 1 || counts["acl"].Findings != 0 {
		t.Fatalf("ACL observation was not separated: %#v", counts["acl"])
	}
	if counts["credentials"].Highest != "HIGH" || counts["acl"].Highest != "INFORMATIONAL" {
		t.Fatalf("unexpected highest severities: credentials=%s acl=%s", counts["credentials"].Highest, counts["acl"].Highest)
	}
}

func TestAuthenticationFindingsUseDedicatedSubcategories(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{FindingType: "netexec_auth_success", Title: "Authentication successful — SMB", Severity: "informational", SourceTool: "NetExec (nxc)"}},
		{FindingInput: storage.FindingInput{FindingType: "netexec_privileged_access", Title: "Privileged access reported — WinRM", Severity: "high", SourceTool: "NetExec (nxc)"}},
		{FindingInput: storage.FindingInput{FindingType: "smb_signing_not_required", Title: "SMB Signing Not Required", Severity: "medium", SourceTool: "NetExec (nxc)"}},
	}
	category := buildFindingCategories(rows)
	var authentication findingCategory
	for _, item := range category {
		if item.Key == "authentication" {
			authentication = item
		}
	}
	if authentication.Findings != 1 || authentication.Observations != 1 {
		t.Fatalf("unexpected authentication totals: %#v", authentication)
	}
	subcategories := buildFindingSubcategories("authentication", rows)
	counts := map[string]int{}
	for _, item := range subcategories {
		counts[item.Key] = item.Findings + item.Observations
	}
	if counts["successful_authentication"] != 1 || counts["privileged_access"] != 1 {
		t.Fatalf("unexpected authentication subcategories: %#v", counts)
	}
	if findingCategoryKey(rows[2]) != "network" || findingSubcategoryKey(rows[2]) != "smb" {
		t.Fatalf("SMB signing no longer routes to Network & Protocols/SMB: %q/%q", findingCategoryKey(rows[2]), findingSubcategoryKey(rows[2]))
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

func TestFindingsFooterUsesOpenBackAndQuit(t *testing.T) {
	model := &model{findingsView: true, findingCategoryView: true, width: 100, height: 24}
	frame := ansi.Strip(model.View())
	if !strings.Contains(frame, "Enter = Open Category    Esc = Close") {
		t.Fatalf("root footer missing: %s", frame)
	}
	if !strings.Contains(frame, "Q Quit") {
		t.Fatalf("root footer missing Q Quit: %s", frame)
	}
	for _, unwanted := range []string{"Search", "OBSERVED", "All"} {
		if strings.Contains(frame, unwanted) {
			t.Fatalf("findings footer still advertises %q: %s", unwanted, frame)
		}
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

func TestFindingsRootNavigationUsesAllCategories(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertTarget(ctx, "example.test", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	assessmentID, err := db.TargetID(ctx, "example.test", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.IngestFindings(ctx, []storage.FindingInput{{
		FindingKey: "root-navigation", AssessmentID: assessmentID, SourceTool: "synthetic",
		FindingType: "kerberoastable_account",
		Title:       "Synthetic Kerberos finding", Severity: "medium", Confidence: "confirmed", EvidenceJSON: "{}",
		ArtifactPath: "synthetic.log", ArtifactRef: "line 1", ObservedAt: time.Now().UTC(), Status: "open", ParserVersion: "test",
	}}); err != nil {
		t.Fatal(err)
	}
	m := &model{ctx: ctx, db: db, targetID: assessmentID, findingsView: true, findingCategoryView: true, findingViewMode: "all", width: 120, height: 40}
	m.refreshFindings()
	want := []string{"credentials", "kerberos", "active_directory", "acl", "adcs", "delegation", "authentication", "network", "other"}
	if len(m.findingCategories) != len(want) {
		t.Fatalf("category count=%d, want %d", len(m.findingCategories), len(want))
	}
	for index, key := range want {
		if m.findingCategories[index].Key != key {
			t.Fatalf("category %d=%q, want %q", index, m.findingCategories[index].Key, key)
		}
		if index > 0 {
			m.Update(tea.KeyMsg{Type: tea.KeyDown})
		}
		if m.findingCursor != index {
			t.Fatalf("after %d Down keys cursor=%d, want %d", index, m.findingCursor, index)
		}
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEnd})
	if m.findingCursor != len(want)-1 {
		t.Fatalf("End cursor=%d, want %d", m.findingCursor, len(want)-1)
	}
	for index := len(want) - 2; index >= 0; index-- {
		m.Update(tea.KeyMsg{Type: tea.KeyUp})
		if m.findingCursor != index {
			t.Fatalf("after reverse navigation cursor=%d, want %d", m.findingCursor, index)
		}
	}
}

func TestFindingsEscRemainsResponsiveWithLargeACLSet(t *testing.T) {
	rows := make([]storage.Finding, 1400)
	for index := range rows {
		rows[index] = storage.Finding{FindingInput: storage.FindingInput{
			FindingKey: fmt.Sprintf("acl-%d", index), FindingType: "ad_acl_genericwrite", Title: "Synthetic ACL",
			Severity: "informational", RelatedObjectID: fmt.Sprintf("principal-%d", index), AffectedObjectID: "target",
		}}
	}
	m := &model{findingsView: true, findingCategoryView: false, findingCategory: "acl", findingViewMode: "all", findingRows: rows, findingCursor: 700, width: 120, height: 40}
	started := time.Now()
	m.handleFindingsKey("esc")
	if elapsed := time.Since(started); elapsed >= 100*time.Millisecond {
		t.Fatalf("Esc took %s with a large ACL presentation", elapsed)
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

func TestADCSSubcategoriesReconcilePersistedObjectTypes(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{FindingType: "adcs_esc_esc7", SourceTool: "Certipy", Severity: "high", EvidenceJSON: `{"object_type":"ca","object_name":"CA"}`}},
		{FindingInput: storage.FindingInput{FindingType: "adcs_esc_esc8", SourceTool: "Certipy", Severity: "high", EvidenceJSON: `{"object_type":"ca","object_name":"CA"}`}},
		{FindingInput: storage.FindingInput{FindingType: "adcs_esc_esc1", SourceTool: "Certipy", Severity: "high", EvidenceJSON: `{"object_type":"template","object_name":"Template"}`}},
		{FindingInput: storage.FindingInput{FindingType: "adcs_esc_esc4", SourceTool: "Certipy", Severity: "high", EvidenceJSON: `{"object_type":"template","object_name":"Template"}`}},
		{FindingInput: storage.FindingInput{FindingType: "adcs_esc_esc4", SourceTool: "Certipy", Severity: "high", EvidenceJSON: `{}`}},
	}
	subcategories := buildFindingSubcategories("adcs", rows)
	counts := map[string]int{}
	for _, subcategory := range subcategories {
		counts[subcategory.Key] = subcategory.Findings + subcategory.Observations
	}
	if counts["adcs_ca"] != 2 || counts["adcs_template"] != 2 || counts["adcs_other"] != 1 {
		t.Fatalf("unexpected AD CS child counts: %#v", counts)
	}
}

func TestADCSNavigationReadsPersistedChildRecords(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertTarget(ctx, "example.test", "192.0.2.20"); err != nil {
		t.Fatal(err)
	}
	assessmentID, err := db.TargetID(ctx, "example.test", "192.0.2.20")
	if err != nil {
		t.Fatal(err)
	}
	inputs := []storage.FindingInput{
		{FindingKey: "ca-esc7", AssessmentID: assessmentID, SourceTool: "Certipy", FindingType: "adcs_esc_esc7", Title: "Certipy reported ESC7 — CA", Severity: "high", Confidence: "tool-reported-esc", EvidenceJSON: `{"object_type":"ca"}`, ArtifactPath: "certipy.json", ArtifactRef: "/ca", ParserVersion: "test", Status: "open", ObservedAt: time.Now().UTC()},
		{FindingKey: "ca-esc8", AssessmentID: assessmentID, SourceTool: "Certipy", FindingType: "adcs_esc_esc8", Title: "Certipy reported ESC8 — CA", Severity: "high", Confidence: "tool-reported-esc", EvidenceJSON: `{"object_type":"ca"}`, ArtifactPath: "certipy.json", ArtifactRef: "/ca", ParserVersion: "test", Status: "open", ObservedAt: time.Now().UTC()},
		{FindingKey: "template-esc1", AssessmentID: assessmentID, SourceTool: "Certipy", FindingType: "adcs_esc_esc1", Title: "Certipy reported ESC1 — Template", Severity: "high", Confidence: "tool-reported-esc", EvidenceJSON: `{"object_type":"template"}`, ArtifactPath: "certipy.json", ArtifactRef: "/template", ParserVersion: "test", Status: "open", ObservedAt: time.Now().UTC()},
	}
	if err := db.IngestFindings(ctx, inputs); err != nil {
		t.Fatal(err)
	}
	m := &model{ctx: ctx, db: db, targetID: assessmentID, findingsView: true, findingCategoryView: true, findingViewMode: "all", width: 120, height: 40}
	m.refreshFindings()
	for range 4 {
		m.Update(tea.KeyMsg{Type: tea.KeyDown})
	}
	if m.findingCategories[m.findingCursor].Key != "adcs" {
		t.Fatalf("root cursor selected %q instead of AD CS", m.findingCategories[m.findingCursor].Key)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	counts := map[string]int{}
	for _, subcategory := range m.findingSubcategories {
		counts[subcategory.Key] = subcategory.Findings + subcategory.Observations
	}
	if counts["adcs_ca"] != 2 || counts["adcs_template"] != 1 {
		t.Fatalf("persisted AD CS records were not reachable: %#v", counts)
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

func TestFindingsHierarchyOpensObservationOnlyGroup(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.UpsertTarget(ctx, "example.test", "198.51.100.10"); err != nil {
		t.Fatal(err)
	}
	targetID, err := db.TargetID(ctx, "example.test", "198.51.100.10")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.IngestFindings(ctx, []storage.FindingInput{{
		FindingKey: "keyword:one", AssessmentID: targetID, SourceTool: "NetExec",
		FindingType: "ad_user_description_keyword_observed", Title: "Credential keyword in info/notes",
		Severity: "informational", Confidence: "observed-sensitive-keyword", AffectedObject: "LAB\\svc-user",
		ArtifactPath: "user-info.txt", ArtifactRef: "line:4", EvidenceJSON: `{"attribute":"info/notes"}`,
		ObservedAt: time.Unix(1700000000, 0).UTC(), Status: "open", ParserVersion: "test",
	}}); err != nil {
		t.Fatal(err)
	}
	model := &model{ctx: ctx, db: db, targetID: targetID, findingsView: true, findingCategoryView: true, findingViewMode: "findings", width: 120, height: 40}
	model.refreshFindings()
	for index, category := range model.findingCategories {
		if category.Key == "active_directory" {
			model.findingCursor = index
		}
	}
	model.handleFindingsKey("enter")
	for index, subcategory := range model.findingSubcategories {
		if subcategory.Key == "user_descriptions" {
			model.findingCursor = index
		}
	}
	model.handleFindingsKey("enter")
	if model.findingViewMode != "all" || len(model.findingRows) != 1 {
		t.Fatalf("observation-only group was not opened: mode=%q rows=%d", model.findingViewMode, len(model.findingRows))
	}
	model.handleFindingsKey("enter")
	if !model.findingDetail {
		t.Fatal("finding detail did not open from populated child group")
	}
}

func TestFindingDetailUsesSecurityHierarchyWithoutRemediation(t *testing.T) {
	cases := []struct {
		name     string
		finding  storage.Finding
		want     []string
		unwanted []string
	}{
		{
			name: "privileged access",
			finding: storage.Finding{FindingInput: storage.FindingInput{
				FindingType: "netexec_privileged_access", Title: "Privileged access reported — SMB", Severity: "high", Confidence: "explicit-pwn3d-marker",
				AffectedObject: "DC", RelatedObject: "EXAMPLE\\operator", SourceTool: "NetExec (nxc)", SourceExecution: 16,
				EvidenceJSON: `{"protocol":"SMB","target":"198.51.100.40","port":"445","host":"DC","privileged":true}`, ArtifactPath: "smb-auth.txt", ArtifactRef: "line:2",
			}},
			want:     []string{"PRIVILEGED ACCESS REPORTED", "Pwn3d!", "SMB", "EXAMPLE\\operator", "SECURITY IMPACT", "LIMITATIONS"},
			unwanted: []string{"Remediation:", "Domain Administrator"},
		},
		{
			name: "certificate condition",
			finding: storage.Finding{FindingInput: storage.FindingInput{
				FindingType: "adcs_esc_esc1", Title: "Certipy reported ESC1 — Template", Severity: "high", Confidence: "tool-reported-esc",
				AffectedObject: "Template", SourceTool: "Certipy", EvidenceJSON: `{"object_type":"template","object_name":"Template"}`, ArtifactPath: "certipy.json", ArtifactRef: "/templates/0",
			}},
			want:     []string{"ESC1", "OBJECT", "Template", "EVIDENCE"},
			unwanted: []string{"Remediation:"},
		},
		{
			name: "generic condition",
			finding: storage.Finding{FindingInput: storage.FindingInput{
				FindingType: "synthetic_observation", Title: "Synthetic security observation", Severity: "informational", Confidence: "observed",
				AffectedObject: "host", Description: "A synthetic condition was observed.", SourceTool: "Synthetic", ArtifactPath: "evidence.log", ArtifactRef: "line:1",
			}},
			want:     []string{"SYNTHETIC SECURITY OBSERVATION", "A synthetic condition was observed.", "Synthetic · Execution 0"},
			unwanted: []string{"Remediation:"},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			model := &model{findingsView: true, findingDetail: true, findingRows: []storage.Finding{test.finding}, width: 120, height: 40}
			frame := ansi.Strip(model.View())
			for _, want := range test.want {
				if !strings.Contains(frame, want) {
					t.Fatalf("detail missing %q:\n%s", want, frame)
				}
			}
			for _, unwanted := range test.unwanted {
				if strings.Contains(frame, unwanted) {
					t.Fatalf("detail contains unwanted %q:\n%s", unwanted, frame)
				}
			}
		})
	}
}

func TestFindingDetailFitsResponsiveWidths(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "netexec_privileged_access", Title: "Privileged access reported — WinRM", Severity: "high", Confidence: "explicit-pwn3d-marker",
		AffectedObject: "CLIENT-WITH-A-LONG-NAME", RelatedObject: "EXAMPLE\\service-account-with-a-long-name", SourceTool: "NetExec (nxc)", SourceExecution: 3,
		EvidenceJSON: `{"protocol":"WINRM","target":"198.51.100.43","port":"5985","host":"CLIENT"}`, ArtifactPath: "a/very/long/artifact/path/that/must/remain/traceable.txt", ArtifactRef: "line:22",
	}}
	for _, width := range []int{80, 100, 120, 160} {
		model := &model{findingsView: true, findingDetail: true, findingRows: []storage.Finding{finding}, width: width, height: 45}
		for _, line := range strings.Split(ansi.Strip(model.View()), "\n") {
			if ansi.StringWidthWc(line) > width {
				t.Fatalf("width %d overflowed with %d columns: %q", width, ansi.StringWidthWc(line), line)
			}
		}
	}
}

func TestFindingDetailMarksSensitiveEvidenceWithoutDisplayingSecretValues(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })

	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType:    "kerberos_ticket_material_collected",
		Title:          "Kerberoast material collected: svc-account",
		Description:    "The original restricted artifact contains the authentication material.",
		Severity:       "medium",
		Confidence:     "observed-material",
		AffectedObject: "svc-account",
		EvidenceJSON:   `{"material_type":"kerberoast","material_collected":true,"secret":"synthetic-not-displayed"}`,
	}}
	model := &model{findingsView: true, findingDetail: true, findingRows: []storage.Finding{finding}, width: 120, height: 40}
	raw := model.View()
	plain := ansi.Strip(raw)
	if !strings.Contains(plain, "SENSITIVE EVIDENCE") {
		t.Fatalf("sensitive evidence indicator missing:\n%s", plain)
	}
	if !strings.Contains(raw, "\x1b[") {
		t.Fatal("sensitive evidence indicator is not styled")
	}
	if strings.Contains(plain, "synthetic-not-displayed") {
		t.Fatal("detail unexpectedly exposed a sensitive value")
	}
}

func TestPrivilegedACLInventoryDetailShowsRelationshipsAndLimitations(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ad_privileged_acl_evidence_inventory", Title: "AD Privileged ACL Evidence Inventory", Severity: "informational",
		SourceTool: "RustHound-CE", SourceExecution: 450, ArtifactPath: "Enumeration/ActiveDirectory/ACL/execution-450/AD_privileged_acl_inventory.json",
		EvidenceJSON: `{"source_execution_id":450,"source_artifact":"Enumeration/RustHoundCE/artifacts","human_report":"AD_PRIVILEGED_ACL_EVIDENCE.txt","high_value_targets":2,"normalized_relationships":14,"unsupported_relationships":3,"unresolved_principals":1,"omitted_relationships":2,"status":"partial","relationship_overview":[{"principal_name":"alice","principal_id":"S-1-5-21-1-1101","target_name":"Domain Admins","target_id":"S-1-5-21-1-512","target_type":"groups","permission":"WriteDacl","decision":"allow","inheritance":"explicit","artifact":"groups.json","artifact_ref":"/data/0/Aces/0"}]}`,
	}}
	condition := findingCondition(finding)
	for _, expected := range []string{"alice", "WriteDacl", "Domain Admins", "S-1-5-21-1-512", "additional in the full report"} {
		if !strings.Contains(condition, expected) {
			t.Fatalf("condition omitted %q: %s", expected, condition)
		}
	}
	if strings.Contains(findingImpact(finding), "security-relevant condition requiring operator review") {
		t.Fatal("inventory retained generic security impact wording")
	}
	limitations := findingLimitations(finding)
	for _, expected := range []string{"Unsupported ACL forms", "unresolved", "omitted", "Effective permissions"} {
		if !strings.Contains(limitations, expected) {
			t.Fatalf("limitations omitted %q: %s", expected, limitations)
		}
	}
	evidence := findingEvidenceSummary(finding)
	for _, expected := range []string{"AD_PRIVILEGED_ACL_EVIDENCE.txt", "AD_privileged_acl_inventory.json", "Enumeration/RustHoundCE/artifacts"} {
		if !strings.Contains(evidence, expected) {
			t.Fatalf("evidence summary omitted %q: %s", expected, evidence)
		}
	}
}

func TestPrivilegedACLInventoryEvidenceOpensHumanReport(t *testing.T) {
	root := t.TempDir()
	resultsRoot := filepath.Join(root, "results")
	if err := os.MkdirAll(resultsRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resultsRoot, "AD_PRIVILEGED_ACL_EVIDENCE.txt"), []byte("Target: Domain Admins\nalice -> WriteDacl\n"), 0600); err != nil {
		t.Fatal(err)
	}
	model := &model{cfg: config.Config{Root: root}, findingDetail: true}
	model.openFindingEvidence(storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ad_privileged_acl_evidence_inventory", ArtifactPath: "missing.json",
		EvidenceJSON: `{"human_report":"AD_PRIVILEGED_ACL_EVIDENCE.txt"}`,
	}})
	if model.evidenceError != "" || model.evidencePath != "AD_PRIVILEGED_ACL_EVIDENCE.txt" {
		t.Fatalf("human report was not selected: path=%s error=%s", model.evidencePath, model.evidenceError)
	}
	if !strings.Contains(strings.Join(model.evidenceLines, "\n"), "alice -> WriteDacl") {
		t.Fatal("human ACL report was not loaded")
	}
}

func TestSelectedFindingFamiliesUseEvidenceSpecificPresentation(t *testing.T) {
	tests := []struct {
		name        string
		finding     storage.Finding
		condition   string
		impact      string
		remediation string
	}{
		{
			name:      "privileged access",
			finding:   storage.Finding{FindingInput: storage.FindingInput{FindingType: "netexec_privileged_access", SourceExecution: 42, AffectedObject: "192.0.2.40", RelatedObject: "sccm.lab\\admin", EvidenceJSON: `{"protocol":"SMB","target":"192.0.2.40","port":"445","principal":"sccm.lab\\admin","outcome":"success","privileged":true}`}},
			condition: "administrative-access indicator", impact: "broader privileges", remediation: "administrative access",
		},
		{
			name:      "authentication",
			finding:   storage.Finding{FindingInput: storage.FindingInput{FindingType: "netexec_auth_success", AffectedObject: "192.0.2.43", RelatedObject: "sccm.lab\\user", EvidenceJSON: `{"protocol":"WINRM","target":"192.0.2.43","port":"5985","principal":"sccm.lab\\user","outcome":"success","privileged":false}`}},
			condition: "successful WINRM authentication", impact: "accepted the authentication", remediation: "expected to authenticate",
		},
		{
			name:      "unconstrained delegation",
			finding:   storage.Finding{FindingInput: storage.FindingInput{FindingType: "unconstrained_delegation_configured", AffectedObject: "svc-delegation", EvidenceJSON: `{"object_name":"svc-delegation","delegation_type":"unconstrained","direct_property":true}`}},
			condition: "unconstrained delegation", impact: "credential-delegation exposure", remediation: "delegation configuration",
		},
		{
			name:      "constrained delegation",
			finding:   storage.Finding{FindingInput: storage.FindingInput{FindingType: "constrained_delegation_configured", AffectedObject: "WEB01$", EvidenceJSON: `{"object_name":"WEB01$","delegation_type":"constrained","allowed_to_delegate":["MSSQLSvc/sql.example.test:1433"]}`}},
			condition: "Allowed service targets", impact: "listed service targets", remediation: "allowed service targets",
		},
		{
			name:      "relay",
			finding:   storage.Finding{FindingInput: storage.FindingInput{FindingType: "relay_exposure_observed", AffectedObject: "192.0.2.40", EvidenceJSON: `{"level":"high","impact":"signing absent","protocol":"SMB","destination":"192.0.2.40","details":"synthetic"}`}},
			condition: "relay-related path", impact: "does not prove", remediation: "signing and channel binding",
		},
		{
			name:      "SMB signing",
			finding:   storage.Finding{FindingInput: storage.FindingInput{FindingType: "smb_signing_not_required", AffectedObject: "192.0.2.40", EvidenceJSON: `{"protocol":"SMB","target":"192.0.2.40","port":"445","host":"dc.sccm.lab","signing_required":false}`}},
			condition: "signing is not required", impact: "relay exposure", remediation: "require signing",
		},
		{
			name:      "domain policy",
			finding:   storage.Finding{FindingInput: storage.FindingInput{FindingType: "ad_domain_policy_weak_minimum_password_length", AffectedObject: "sccm.lab", EvidenceJSON: `{"domain":"sccm.lab","minimum_password_length":5,"policy_scope":"domain default policy","fine_grained_policy_limitation":"not reconciled"}`}},
			condition: "minimum password length=5", impact: "domain-default policy", remediation: "fine-grained policies",
		},
		{
			name:      "Kerberos material",
			finding:   storage.Finding{FindingInput: storage.FindingInput{FindingType: "kerberos_ticket_material_collected", AffectedObject: "svc-sql@sccm.lab", EvidenceJSON: `{"material_type":"kerberoast","material_collected":true,"principal":"svc-sql@sccm.lab","record_count":1,"payload":"synthetic-secret"}`}},
			condition: "secret material is intentionally not displayed", impact: "not prove", remediation: "protected artifact",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			condition := findingCondition(test.finding)
			impact := findingImpact(test.finding)
			remediation := findingRemediation(test.finding)
			for value, expected := range map[string]string{condition: test.condition, impact: test.impact, remediation: test.remediation} {
				if !strings.Contains(strings.ToLower(value), strings.ToLower(expected)) {
					t.Fatalf("missing %q in %q", expected, value)
				}
				if strings.Contains(value, "security-relevant condition requiring operator review") || strings.Contains(value, "source tool's recommended hardening") {
					t.Fatalf("generic fallback remained: %q", value)
				}
			}
			if strings.Contains(condition+impact+remediation, "synthetic-secret") {
				t.Fatal("secret-bearing metadata leaked")
			}
		})
	}
}

func TestHistoricalACLInventoryHydratesOnlyMatchingExecution(t *testing.T) {
	root := t.TempDir()
	resultsRoot := filepath.Join(root, "results")
	report := findingengine.ACLInventoryReport{
		SchemaVersion: 1, ParserVersion: "test", Domain: "example.test", SourceExecutionID: 450,
		Status: "partial", NormalizedRelations: 1,
		HighValueTargets: []findingengine.ACLInventoryTarget{{ID: "S-1-5-21-1-512", Name: "Domain Admins", ObjectType: "groups", Class: "privileged_group"}},
		Relationships:    []findingengine.ACLInventoryRelationship{{PrincipalID: "S-1-5-21-1-1101", PrincipalName: "alice", TargetID: "S-1-5-21-1-512", TargetName: "Domain Admins", TargetType: "groups", TargetClass: "privileged_group", Permission: "WriteDacl", Decision: "allow", Inheritance: "explicit", Artifact: "groups.json", ArtifactRef: "/data/0/Aces/0"}},
	}
	artifact, err := findingengine.WriteACLInventoryArtifact(resultsRoot, report)
	if err != nil {
		t.Fatal(err)
	}
	model := &model{cfg: config.Config{Root: root}}
	finding := storage.Finding{FindingInput: storage.FindingInput{FindingType: "ad_privileged_acl_evidence_inventory", SourceExecution: 450, ArtifactPath: artifact, EvidenceJSON: `{"source_execution_id":450,"normalized_relationships":1,"status":"partial"}`}}
	hydrated := model.hydrateHistoricalACLInventory(finding)
	if !strings.Contains(findingCondition(hydrated), "alice") || !strings.Contains(findingCondition(hydrated), "WriteDacl") {
		t.Fatalf("historical ACL evidence was not hydrated: %s", findingCondition(hydrated))
	}
	mismatched := finding
	mismatched.SourceExecution = 451
	if strings.Contains(findingCondition(model.hydrateHistoricalACLInventory(mismatched)), "alice") {
		t.Fatal("ACL compatibility path crossed execution provenance")
	}
}

func TestGPOAndCredentialKeywordPresentationsAreSpecific(t *testing.T) {
	gpo := storage.Finding{FindingInput: storage.FindingInput{FindingType: "gpo_evidence_inventory", SourceExecution: 409, EvidenceJSON: `{"gpos_discovered":3,"gpo_names":["Default Domain Policy (31B2...)"],"gpos_complete":3,"gpos_partial":0,"sysvol_files":9,"configured_relationships":4,"file_failures":0,"file_limits":0,"limitations":["effective application not verified"]}`}}
	gpoCondition := findingCondition(gpo)
	for _, value := range []string{"3 GPOs", "9 SYSVOL", "Default Domain Policy", "4 configured link"} {
		if !strings.Contains(gpoCondition, value) {
			t.Fatalf("GPO condition omitted %q: %s", value, gpoCondition)
		}
	}
	if strings.Contains(findingImpact(gpo), "security-relevant condition requiring operator review") {
		t.Fatal("GPO retained generic impact wording")
	}
	keywordInput := storage.FindingInput{
		FindingType:    "ad_user_description_keyword_observed",
		AffectedObject: "snablr-lab-admin",
		EvidenceJSON:   `{"attribute":"info","keyword":"secret","line":4,"principal":"snablr-lab-admin"}`,
	}
	keyword := storage.Finding{FindingInput: keywordInput}
	condition := findingCondition(keyword)
	if !strings.Contains(condition, "snablr-lab-admin") || !strings.Contains(condition, "credential was disclosed") {
		t.Fatalf("keyword interpretation is not specific: %s", condition)
	}
	if strings.Contains(condition+findingImpact(keyword)+findingRemediation(keyword), "secret") && strings.Contains(condition+findingImpact(keyword)+findingRemediation(keyword), "fictional") {
		t.Fatal("keyword fixture leaked a secret")
	}
}

func TestKerberosMaterialRoutingAndSafeMetadata(t *testing.T) {
	materialInput := storage.FindingInput{
		FindingType:    "kerberos_ticket_material_collected",
		Severity:       "medium",
		AffectedObject: "sccm.lab\\svc-sql",
		EvidenceJSON:   `{"material_type":"kerberoast","principal":"sccm.lab\\svc-sql","material_collected":true,"record_count":3,"payload":"do-not-display"}`,
	}
	material := storage.Finding{FindingInput: materialInput}
	if findingCategoryKey(material) != "kerberos" || findingSubcategoryKey(material) != "kerberos_material" {
		t.Fatalf("Kerberos material was misrouted: category=%s subcategory=%s", findingCategoryKey(material), findingSubcategoryKey(material))
	}
	rows := buildFindingSubcategories("kerberos", []storage.Finding{material})
	for _, row := range rows {
		if row.Key == "kerberos_material" && row.Findings+row.Observations != 1 {
			t.Fatalf("Kerberos material was not visible in its subcategory: %+v", row)
		}
	}
	if strings.Contains(findingCondition(material)+findingImpact(material)+findingRemediation(material), "do-not-display") {
		t.Fatal("Kerberos material payload leaked")
	}
}

func TestCertipyESCDetailsAreEvidenceSpecificAndBounded(t *testing.T) {
	tests := []struct {
		esc, objectType, object, reason, expected string
	}{
		{"ESC1", "template", "UserAuthTemplate", "Enrollee supplies subject and template allows client authentication.", "subject"},
		{"ESC2", "template", "AnyPurposeTemplate", "Template can be used for any purpose.", "any purpose"},
		{"ESC3", "template", "EnrollmentAgent", "Template has Certificate Request Agent EKU set.", "request agent"},
		{"ESC4", "template", "ControlledTemplate", "Template is owned by user.", "control"},
		{"ESC6", "ca", "Example-CA", "EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled.", "subjectaltname"},
		{"ESC7", "ca", "Example-CA", "User has dangerous permissions.", "permissions"},
		{"ESC8", "ca", "Example-CA", "Web Enrollment is enabled over HTTP.", "web enrollment"},
		{"ESC15", "template", "SchemaTemplate", "Enrollee supplies subject and schema version is 1.", "schema version"},
		{"ESC17", "template", "ServerAuthTemplate", "Enrollee supplies subject and template allows server authentication.", "server authentication"},
		{"ESC99", "template", "FutureTemplate", "Unrecognized tool condition.", "ESC99"},
	}
	for _, test := range tests {
		t.Run(test.esc, func(t *testing.T) {
			finding := storage.Finding{FindingInput: storage.FindingInput{
				FindingType: "adcs_esc_" + strings.ToLower(test.esc), Title: "Certipy reported " + test.esc + " — " + test.object,
				Severity: "high", Confidence: "tool-reported-esc", SourceTool: "Certipy", SourceExecution: 476,
				AffectedObject: test.object, ArtifactPath: "Enumeration/Certipy/report.json", ArtifactRef: "/Certificate Templates/0/[!] Vulnerabilities",
				EvidenceJSON: fmt.Sprintf(`{"object_type":%q,"object_name":"0","esc":%q,"vulnerability":{%q:%q},"enabled":true,"manager_approval":false,"authorized_signatures":0}`, test.objectType, test.esc, test.esc, test.reason),
			}}
			condition := findingCondition(finding)
			for _, expected := range []string{test.esc, test.object, test.reason, test.expected, "execution: 476"} {
				if !strings.Contains(strings.ToLower(condition), strings.ToLower(expected)) {
					t.Fatalf("condition omitted %q: %s", expected, condition)
				}
			}
			for _, text := range []string{findingImpact(finding), findingRemediation(finding), findingLimitations(finding), findingEvidenceSummary(finding)} {
				if strings.Contains(strings.ToLower(text), "domain compromise") || strings.Contains(strings.ToLower(text), "successful certificate") || strings.Contains(strings.ToLower(text), "successful impersonation") {
					t.Fatalf("unsupported claim in %q", text)
				}
			}
			attributes := findingAttributes(finding, 120)
			if !strings.Contains(attributes, "TEMPLATE") && !strings.Contains(attributes, "CA") {
				t.Fatalf("affected AD CS identity missing: %s", attributes)
			}
		})
	}
}

func TestCertipyESCDetailsRedactSensitiveReasonText(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "adcs_esc_esc1", Title: "Certipy reported ESC1 — SensitiveTemplate", Severity: "high", SourceTool: "Certipy", SourceExecution: 477,
		AffectedObject: "SensitiveTemplate", EvidenceJSON: `{"object_type":"template","esc":"ESC1","vulnerability":{"ESC1":"password: super-secret-value"}}`,
	}}
	text := findingCondition(finding) + findingImpact(finding) + findingRemediation(finding) + findingLimitations(finding)
	if strings.Contains(text, "super-secret-value") {
		t.Fatal("AD CS presentation leaked sensitive reason text")
	}
}

func TestCertipyHistoricalRecordWithoutStructuredMetadataRemainsUseful(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "adcs_esc_esc8", Title: "Certipy reported ESC8 — Legacy CA", Severity: "high", SourceTool: "Certipy", SourceExecution: 434,
		AffectedObject: "Legacy CA", ArtifactPath: "Enumeration/Certipy/report.json", ArtifactRef: "/Certificate Authorities/Legacy CA/[!] Vulnerabilities", EvidenceJSON: `{}`,
	}}
	condition := findingCondition(finding)
	if !strings.Contains(condition, "ESC8") || !strings.Contains(condition, "Legacy CA") {
		t.Fatalf("historical AD CS record lost truthful fallback context: %s", condition)
	}
	if !strings.Contains(findingLimitations(finding), "object type is unavailable") {
		t.Fatal("historical metadata limitation was not exposed")
	}
	if !strings.Contains(findingEvidenceSummary(finding), "Execution 434") {
		t.Fatal("historical source execution was not preserved")
	}
}

func TestFindingsNavigationRestoresADCSSiblingSelection(t *testing.T) {
	rows := []storage.Finding{
		{ID: 1, FindingInput: storage.FindingInput{FindingKey: "ca", FindingType: "adcs_esc_esc7", Title: "CA finding", Severity: "high"}},
		{ID: 2, FindingInput: storage.FindingInput{FindingKey: "template", FindingType: "adcs_esc_esc1", Title: "Template finding", Severity: "high"}},
		{ID: 3, FindingInput: storage.FindingInput{FindingKey: "kerb", FindingType: "kerberoastable_account", Title: "Kerberos finding", Severity: "medium"}},
	}
	m := &model{findingsView: true, findingCategoryView: true, findingCategories: []findingCategory{
		{Key: "adcs", Name: "AD CS"}, {Key: "kerberos", Name: "Kerberos"},
	}, findingAllRows: rows, findingViewMode: "all", findingsLoaded: true, width: 120, height: 40}

	m.findingCursor = 0
	m.handleFindingsKey("enter")
	if !m.findingCategoryView || !m.findingSubcategoryView || m.findingCategory != "adcs" {
		t.Fatalf("AD CS did not open its subcategory list: category=%t subcategory=%t key=%q", m.findingCategoryView, m.findingSubcategoryView, m.findingCategory)
	}
	for index, subcategory := range m.findingSubcategories {
		if subcategory.Key == "adcs_ca" {
			m.findingCursor = index
		}
	}
	m.handleFindingsKey("enter")
	if m.findingCategoryView || m.findingSubcategoryView || m.findingSubcategory != "adcs_ca" {
		t.Fatalf("CA subcategory did not open findings: category=%t subcategory=%t key=%q", m.findingCategoryView, m.findingSubcategoryView, m.findingSubcategory)
	}
	m.findingRows = []storage.Finding{rows[0]}
	m.handleFindingsKey("enter")
	if !m.findingDetail || m.findingRows[m.findingCursor].FindingKey != "ca" {
		t.Fatalf("CA finding detail did not open: detail=%t cursor=%d", m.findingDetail, m.findingCursor)
	}
	m.handleFindingsKey("esc")
	if m.findingDetail || m.findingRows[m.findingCursor].FindingKey != "ca" {
		t.Fatalf("detail Esc did not restore CA finding: detail=%t cursor=%d", m.findingDetail, m.findingCursor)
	}
	m.handleFindingsKey("esc")
	if !m.findingCategoryView || !m.findingSubcategoryView || m.findingSubcategory != "" {
		t.Fatalf("finding-list Esc did not return to subcategories: category=%t subcategory=%t key=%q", m.findingCategoryView, m.findingSubcategoryView, m.findingSubcategory)
	}
	if m.findingSubcategories[m.findingCursor].Key != "adcs_ca" {
		t.Fatalf("finding-list Esc selected sibling subcategory %q", m.findingSubcategories[m.findingCursor].Key)
	}
	m.handleFindingsKey("esc")
	if !m.findingCategoryView || m.findingSubcategoryView || m.findingCategory != "" {
		t.Fatalf("subcategory Esc did not return to root: category=%t subcategory=%t key=%q", m.findingCategoryView, m.findingSubcategoryView, m.findingCategory)
	}
	if m.findingCategories[m.findingCursor].Key != "adcs" {
		t.Fatalf("subcategory Esc selected sibling category %q", m.findingCategories[m.findingCursor].Key)
	}

	m.findingCursor = 1
	m.handleFindingsKey("enter")
	if m.findingCategory != "kerberos" || !m.findingSubcategoryView {
		t.Fatalf("sibling category did not open: category=%q", m.findingCategory)
	}
	m.handleFindingsKey("esc")
	if m.findingCategories[m.findingCursor].Key != "kerberos" {
		t.Fatalf("root selection was not restored after sibling category: %q", m.findingCategories[m.findingCursor].Key)
	}
}

func TestFindingsNavigationRestoresScrolledRowByIdentity(t *testing.T) {
	rows := make([]storage.Finding, 0, 30)
	for index := 0; index < 30; index++ {
		rows = append(rows, storage.Finding{ID: int64(index + 1), FindingInput: storage.FindingInput{FindingKey: fmt.Sprintf("row-%d", index), FindingType: "adcs_esc_esc1", Title: fmt.Sprintf("Template %02d", index), Severity: "high"}})
	}
	m := &model{findingsView: true, findingCategoryView: true, findingCategories: []findingCategory{{Key: "adcs", Name: "AD CS"}}, findingAllRows: rows, findingViewMode: "all", findingsLoaded: true, width: 80, height: 12}
	m.handleFindingsKey("enter")
	for index, subcategory := range m.findingSubcategories {
		if subcategory.Key == "adcs_template" {
			m.findingCursor = index
		}
	}
	m.handleFindingsKey("enter")
	m.findingRows = append([]storage.Finding(nil), rows...)
	m.findingCursor = 20
	m.findingTop = 12
	selected := m.findingRows[m.findingCursor].FindingKey
	m.handleFindingsKey("esc")
	m.handleFindingsKey("enter")
	if m.findingRows[m.findingCursor].FindingKey != selected || m.findingCursor != 20 {
		t.Fatalf("row identity/scroll was not restored: key=%q cursor=%d", m.findingRows[m.findingCursor].FindingKey, m.findingCursor)
	}
	if m.findingTop != 12 {
		t.Fatalf("row viewport was not restored: top=%d", m.findingTop)
	}
}

func TestFindingsNavigationFallsBackWhenSelectionDisappears(t *testing.T) {
	rows := []storage.Finding{{ID: 1, FindingInput: storage.FindingInput{FindingKey: "one", FindingType: "adcs_esc_esc1", Title: "One", Severity: "high"}}, {ID: 2, FindingInput: storage.FindingInput{FindingKey: "two", FindingType: "adcs_esc_esc1", Title: "Two", Severity: "high"}}}
	m := &model{findingsView: true, findingCategoryView: true, findingCategories: []findingCategory{{Key: "adcs", Name: "AD CS"}}, findingAllRows: rows, findingViewMode: "all", findingsLoaded: true, width: 100, height: 20}
	m.handleFindingsKey("enter")
	for index, subcategory := range m.findingSubcategories {
		if subcategory.Key == "adcs_template" {
			m.findingCursor = index
		}
	}
	m.handleFindingsKey("enter")
	m.findingRows = append([]storage.Finding(nil), rows...)
	m.findingCursor = 1
	m.handleFindingsKey("esc")
	m.findingAllRows = m.findingAllRows[:1]
	m.findingRows = m.findingAllRows
	m.handleFindingsKey("enter")
	if len(m.findingRows) != 1 || m.findingCursor != 0 {
		t.Fatalf("disappearing selection did not fall back safely: rows=%d cursor=%d", len(m.findingRows), m.findingCursor)
	}
}
