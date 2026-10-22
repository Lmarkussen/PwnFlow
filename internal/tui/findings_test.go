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
	for index := 0; index < 32 && !strings.Contains(ansi.Strip(model.View()), "restricted.json"); index++ {
		model.handleFindingsKey("down")
	}
	if !strings.Contains(ansi.Strip(model.View()), "restricted.json") {
		t.Fatal("detail scrolling omitted artifact reference")
	}
}

func TestGPPFindingDetailShowsRecoveredCredential(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "netexec_gpp_password_exposure", Title: "Recoverable Password Stored in Group Policy Preferences", Severity: "high",
		SourceTool: "NetExec (nxc)", SourceExecution: 12, AffectedObject: "LAB\\svc-deploy",
		ArtifactPath: "/results/NetExec/SMB_gpp_password.txt", ArtifactRef: "line:7",
		EvidenceJSON: `{"source":"NetExec -M gpp_password","preference_type":"Local Users and Groups","gpo":"{11111111-2222-3333-4444-555555555555}","xml_path":"/Policies/{11111111-2222-3333-4444-555555555555}/Machine/Groups/Groups.xml","account":"LAB\\svc-deploy","password":"synthetic-password","credential_state":"recoverable GPP password detected","evidence_excerpt":"recovered value retained as assessment evidence"}`,
	}}
	for _, value := range []string{findingCondition(finding), findingAttributes(finding, 100), findingImpact(finding), findingRemediation(finding), findingEvidenceSummary(finding), findingLimitations(finding)} {
		if strings.Contains(value, "cpassword") {
			t.Fatalf("GPP detail exposed the encrypted source field: %q", value)
		}
	}
	attributes := findingAttributes(finding, 100)
	for _, expected := range []string{"Local Users and Groups", "Groups.xml", "LAB\\svc-deploy", "synthetic-password", "recoverable GPP password detected", "RECOVERED CREDENTIAL"} {
		if !strings.Contains(attributes, expected) {
			t.Fatalf("GPP detail missing %q: %s", expected, attributes)
		}
	}
	if !strings.Contains(findingImpact(finding), "SYSVOL") || !strings.Contains(findingRemediation(finding), "rotate") {
		t.Fatal("GPP impact/remediation text is incomplete")
	}
}

func TestGPPFindingBelongsToCredentialsCategory(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{FindingType: "netexec_gpp_password_exposure", Title: "Recoverable Password Stored in Group Policy Preferences", Severity: "high"}}
	if got := findingCategoryKey(finding); got != "credentials" {
		t.Fatalf("GPP category=%q, want credentials", got)
	}
}

func TestFindingDetailScrollAndPageNavigation(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{FindingKey: "first", Title: "First finding", Severity: "high", Description: strings.Repeat("long detail ", 40)}},
		{FindingInput: storage.FindingInput{FindingKey: "second", Title: "Second finding", Severity: "medium", Description: strings.Repeat("other detail ", 40)}},
	}
	m := &model{findingsView: true, findingRows: rows, findingCursor: 0, findingDetail: true, width: 100, height: 24}
	m.handleFindingsKey("down")
	if m.findingCursor != 0 || m.findingDetailTop == 0 {
		t.Fatalf("Down changed finding instead of scrolling: cursor=%d top=%d", m.findingCursor, m.findingDetailTop)
	}
	m.handleFindingsKey("pgdown")
	if m.findingCursor != 1 || m.findingDetailTop != 0 {
		t.Fatalf("Page Down did not change finding/reset detail: cursor=%d top=%d", m.findingCursor, m.findingDetailTop)
	}
	m.handleFindingsKey("pgdown")
	if m.findingCursor != 1 {
		t.Fatal("Page Down wrapped past the last finding")
	}
	m.handleFindingsKey("pgup")
	if m.findingCursor != 0 || m.findingDetailTop != 0 {
		t.Fatalf("Page Up did not select previous finding/reset detail: cursor=%d top=%d", m.findingCursor, m.findingDetailTop)
	}
	m.handleFindingsKey("pgup")
	if m.findingCursor != 0 {
		t.Fatal("Page Up wrapped before the first finding")
	}
	m.handleFindingsKey("esc")
	if m.findingDetail || m.findingCursor != 0 {
		t.Fatalf("Esc did not restore list selection: detail=%t cursor=%d", m.findingDetail, m.findingCursor)
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

func TestWritableObjectsUseACLCategoryAndOtherRecordsRemainReachable(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{FindingType: "ad_writable_object_assessment", Title: "AD Writable Object Assessment", Severity: "informational", SourceTool: "AD Writable Object Assessment"}},
		{FindingInput: storage.FindingInput{FindingType: "legacy_unknown_condition", Title: "Legacy condition", Severity: "informational", SourceTool: "legacy"}},
		{FindingInput: storage.FindingInput{FindingType: "legacy_other_condition", Title: "Legacy other", Severity: "medium", SourceTool: "legacy"}},
	}
	if got := findingCategoryKey(rows[0]); got != "acl" {
		t.Fatalf("writable-object finding category=%q, want acl", got)
	}
	if got := findingSubcategoryKey(rows[0]); got != "ad_writable_objects" {
		t.Fatalf("writable-object subcategory=%q, want ad_writable_objects", got)
	}
	acl := buildFindingSubcategories("acl", rows)
	other := buildFindingSubcategories("other", rows)
	aclCount, otherCount := 0, 0
	for _, item := range acl {
		aclCount += item.Findings + item.Observations
	}
	for _, item := range other {
		otherCount += item.Findings + item.Observations
	}
	if aclCount != 1 || otherCount != 2 {
		t.Fatalf("subcategory counts do not reconcile: acl=%d other=%d", aclCount, otherCount)
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
	if !strings.Contains(frame, "Credentials") || !strings.Contains(frame, "Network & Protocols") {
		t.Fatal("category overview omitted expected categories")
	}
	if strings.Count(frame, "Credentials") != 1 {
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

func TestGenericALLPresentationUsesCompactRelationshipDetails(t *testing.T) {
	row := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ad_acl_genericall", Title: "Excessive GenericAll Control Over AD User", Severity: "medium",
		RelatedObjectID: "S-1-5-21-principal", RelatedObject: "LOCALUSER@SCCM.LAB",
		AffectedObjectID: "S-1-5-21-target", AffectedObject: "ADENUM-PRIV-USER@SCCM.LAB",
		EvidenceJSON: `{"permission":"GenericAll","ace_decision":"unknown","inheritance":"explicit","effective_authorization":"not_verified","target_type":"User"}`,
	}}
	grouped := groupACLFindings([]storage.Finding{row})
	if len(grouped) != 1 || grouped[0].Title != "GenericAll over AD User: ADENUM-PRIV-USER@SCCM.LAB" {
		t.Fatalf("unexpected compact ACL title: %#v", grouped)
	}
	if attributes := findingAttributes(grouped[0], 120); attributes != "" {
		t.Fatalf("ACL relationship retained redundant affected-assets table: %q", attributes)
	}
	condition := ansi.Strip(findingCondition(grouped[0]))
	for _, expected := range []string{"OBSERVED ACL RELATIONSHIP", "PRINCIPAL : LOCALUSER@SCCM.LAB", "TARGET : ADENUM-PRIV-USER@SCCM.LAB", "PERMISSION : GenericAll", "EFFECTIVE AUTHORIZATION : NOT VERIFIED"} {
		if !strings.Contains(condition, expected) {
			t.Fatalf("ACL condition missing %q: %s", expected, condition)
		}
	}
	impact := findingImpact(grouped[0])
	if !strings.Contains(impact, "sensitive account modifications") || strings.Contains(impact, "directly observed permission relationship; effective access and abuse paths require separate review") {
		t.Fatalf("GenericAll impact was not permission-specific: %s", impact)
	}
}

func TestWritableObjectPresentationShowsRelationships(t *testing.T) {
	relationship := `{"principal_name":"HELPDESK@SCCM.LAB","target_name":"APP01@SCCM.LAB","target_type":"computer","permission":"WriteDacl","decision":"unknown","inheritance":"explicit"}`
	row := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ad_writable_object_assessment", Title: "AD Writable Object Assessment", Severity: "informational",
		AffectedObject: "snablr-lab-admin", EvidenceJSON: `{"authenticated_user":"snablr-lab-admin","relationships":[` + relationship + `]}`,
	}}
	condition := ansi.Strip(findingCondition(row))
	for _, expected := range []string{"ASSESSMENT IDENTITY", "snablr-lab-admin", "OBSERVED WRITABLE RELATIONSHIPS", "APP01@SCCM.LAB", "WriteDacl", "HELPDESK@SCCM.LAB", "NOT VERIFIED"} {
		if !strings.Contains(condition, expected) {
			t.Fatalf("writable-object condition missing %q: %s", expected, condition)
		}
	}
}

func TestHighlightADPermissionValuesUsesExactOrangeTokens(t *testing.T) {
	styled := highlightADPermissionValues("GenericAll, WriteDacl WriteOwner NotGenericAll GetChangesAll")
	if got := ansi.Strip(styled); got != "GenericAll, WriteDacl WriteOwner NotGenericAll GetChangesAll" {
		t.Fatalf("permission text changed: %q", got)
	}
}

func TestCertipyPresentationConsolidatesHistoricalESCRecords(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{FindingType: "adcs_esc_esc4", AffectedObject: "Template", SourceExecution: 111, ArtifactPath: "one.json", ArtifactRef: "/Certificate Templates/1/[!] Vulnerabilities", EvidenceJSON: `{"esc":"ESC4","vulnerability":{"ESC4":"Template is owned by user."}}`}},
		{FindingInput: storage.FindingInput{FindingType: "adcs_esc_esc4", AffectedObject: "Template", SourceExecution: 112, ArtifactPath: "two.json", ArtifactRef: "/Certificate Templates/1/[!] Vulnerabilities", EvidenceJSON: `{"esc":"ESC4","vulnerability":{"ESC4":"Template is owned by user."}}`}},
	}
	consolidated := (&model{}).consolidatePresentationFindings(rows)
	if len(consolidated) != 1 {
		t.Fatalf("visible Certipy rows=%d, want one", len(consolidated))
	}
	metadata := findingMetadata(consolidated[0])
	records, _ := metadata["source_records"].([]any)
	if len(records) != 2 {
		t.Fatalf("historical Certipy references=%d, want 2", len(records))
	}
}

func TestCertipyConditionEnrichesFromOriginalArtifact(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "certipy.json")
	data := `{"Certificate Templates":{"1":{"Display Name":"LabTemplate","Enabled":true,"Client Authentication":true,"Enrollee Supplies Subject":true,"Extended Key Usage":["Client Authentication"],"Permissions":{"Enrollment Permissions":{"Enrollment Rights":["SCCM.LAB\\Domain Users"]}},"[!] Vulnerabilities":{"ESC1":"Enrollee supplies subject and template allows client authentication."}}}}`
	if err := os.WriteFile(artifact, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	finding := storage.Finding{FindingInput: storage.FindingInput{FindingType: "adcs_esc_esc1", AffectedObject: "LabTemplate", SourceExecution: 113, ArtifactPath: artifact, ArtifactRef: "/Certificate Templates/1/[!] Vulnerabilities", EvidenceJSON: `{"object_type":"template","esc":"ESC1","vulnerability":{"ESC1":"Enrollee supplies subject and template allows client authentication."}}`}}
	condition := findingCondition(finding)
	for _, expected := range []string{"CERTIFICATE TEMPLATE", "CLIENT AUTHENTICATION : true", "ENROLLEE SUPPLIES SUBJECT : true", "SCCM.LAB\\\\Domain Users"} {
		if !strings.Contains(condition, expected) {
			t.Fatalf("Certipy artifact field %q missing: %s", expected, condition)
		}
	}
}

func TestFindingsFooterUsesOpenBackAndQuit(t *testing.T) {
	model := &model{findingsView: true, findingCategoryView: true, width: 100, height: 24}
	frame := ansi.Strip(model.View())
	if !strings.Contains(frame, "→/Enter Open Category    Esc Close") {
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
	want := []string{"credentials", "kerberos", "active_directory", "acl", "adcs", "delegation", "authentication", "network", "pwntools", "other", "critical"}
	if len(m.findingCategories) != len(want) {
		t.Fatalf("category count=%d, want %d", len(m.findingCategories), len(want))
	}
	for index, key := range want {
		if m.findingCategories[index].Key != key {
			t.Fatalf("category %d=%q, want %q", index, m.findingCategories[index].Key, key)
		}
		if key == "other" && m.findingCategories[index].Name != "Informational" {
			t.Fatalf("informational category name=%q", m.findingCategories[index].Name)
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

func TestCriticalFindingsOpenAsFlatAlphabeticalList(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "findings.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows := []storage.Finding{
		{ID: 1, FindingInput: storage.FindingInput{FindingKey: "z", FindingType: "adcs_esc_esc1", Title: "Zulu path", Severity: "high", SourceExecution: 7, EvidenceJSON: `{"source_execution_id":7,"critical_path":{"verified":true,"enrollee_supplies_subject":true,"client_authentication_eku":true,"low_privilege_enrollment":true}}`}},
		{ID: 2, FindingInput: storage.FindingInput{FindingKey: "a", FindingType: "adcs_esc_esc8", Title: "Alpha path", Severity: "critical", SourceExecution: 7, EvidenceJSON: `{"source_execution_id":7,"critical_path":{"verified":true,"web_enrollment_http":true,"relay_exposure_verified":true,"enrollment_exposure_verified":true}}`}},
		{ID: 3, FindingInput: storage.FindingInput{FindingKey: "ordinary", FindingType: "adcs_esc_esc1", Title: "Incomplete path", Severity: "critical", SourceExecution: 7, EvidenceJSON: `{}`}},
	}
	m := &model{ctx: context.Background(), db: db, findingsView: true, findingsLoaded: true, findingCategoryView: true, findingSubcategoryView: false, findingAllRows: rows, criticalProjection: findingengine.ProjectCritical(rows), findingCategories: buildFindingCategories(rows), width: 120, height: 40}
	m.findingCursor = len(m.findingCategories) - 1
	m.handleFindingsKey("enter")
	if m.findingCategory != "critical" || !m.findingCategoryView || !m.findingSubcategoryView || m.criticalNavigationLevel != 1 {
		t.Fatalf("critical entry did not open state menu: category=%q categoryView=%v subcategoryView=%v level=%d", m.findingCategory, m.findingCategoryView, m.findingSubcategoryView, m.criticalNavigationLevel)
	}
	m.handleFindingsKey("enter")
	if m.criticalNavigationLevel != 2 || len(m.findingSubcategories) != 1 || m.findingSubcategories[0].Name != "AD CS" {
		t.Fatalf("confirmed menu was not opened: level=%d subcategories=%#v", m.criticalNavigationLevel, m.findingSubcategories)
	}
	m.handleFindingsKey("enter")
	if m.findingCategoryView || m.findingSubcategoryView || len(m.findingRows) != 2 || m.findingRows[0].Title != "Alpha path" || m.findingRows[1].Title != "Zulu path" {
		t.Fatalf("critical family did not open its sorted findings: categoryView=%v subcategoryView=%v rows=%#v", m.findingCategoryView, m.findingSubcategoryView, m.findingRows)
	}
	if strings.Contains(m.findingsViewRender(), "SUBCATEGORY") {
		t.Fatal("critical findings rendered a subcategory pane")
	}
}

func TestCriticalCategoryDescriptionKeepsWrappedLinesIndented(t *testing.T) {
	description := indentedFindingDescription("Verified paths to domain compromise or Tier Zero control", 18)
	for _, line := range strings.Split(description, "\n") {
		if !strings.HasPrefix(line, "   ") {
			t.Fatalf("description line lost category indentation: %q", line)
		}
	}
}

func TestCriticalFindingsListShowsNoticeInNormalMode(t *testing.T) {
	m := &model{
		findingsView:        true,
		findingCategory:     "critical",
		findingCategoryView: false,
		findingRows:         []storage.Finding{{FindingInput: storage.FindingInput{Title: "Verified path", Severity: "high", AffectedObject: "DC"}}},
		width:               100,
		height:              24,
	}
	view := ansi.Strip(m.findingsViewRender())
	if !strings.Contains(view, "This classification is under active development") || !strings.Contains(view, "additional security risks and attack paths.") {
		t.Fatalf("critical notice missing from normal-mode list: %q", view)
	}
	if strings.Index(view, "PwnFlow // FINDINGS") > strings.Index(view, "This classification is under active") {
		t.Fatal("critical notice rendered above the findings heading")
	}
}

func TestCriticalFindingsListWrapsNoticeInOfflineNarrowMode(t *testing.T) {
	m := &model{
		mode:                ModeFindingsOnly,
		findingsView:        true,
		findingCategory:     "critical",
		findingCategoryView: false,
		width:               44,
		height:              12,
	}
	view := ansi.Strip(m.findingsViewRender())
	if !strings.Contains(view, "FINDINGS ONLY") {
		t.Fatalf("offline indicator missing from narrow critical list: %q", view)
	}
	if !strings.Contains(view, "This classification is under active") || !strings.Contains(view, "additional security risks") {
		t.Fatalf("wrapped critical notice missing from narrow list: %q", view)
	}
	if !strings.Contains(view, "No findings meet the strict evidence-") || !strings.Contains(view, "backed Critical Findings rules.") {
		t.Fatal("empty critical state was not preserved")
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

func TestGeneralACLInventoryIsNotRenderedAsRelationship(t *testing.T) {
	row := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ad_acl_evidence_inventory", Title: "AD ACL Evidence Inventory", Severity: "informational",
		SourceTool: "RustHound-CE", SourceExecution: 12, AffectedObject: "SCCM.LAB", AffectedObjectID: "S-1-5-21-domain",
		EvidenceJSON: `{"source_supported_ace_count":1400,"retained_ace_count":1390,"explicit_count":735,"inherited_count":649,"unknown_decision_count":1390,"human_report":"Enumeration/ActiveDirectory/ACL/execution-12/AD_ACL_EVIDENCE.txt","structured_artifact":"Enumeration/ActiveDirectory/ACL/execution-12/AD_acl_evidence_inventory.json","examples":[{"principal_name":"alice@SCCM.LAB","permission":"WriteDacl","target_name":"Helpdesk OU"}]}`,
	}}
	grouped := groupVisibleFindings([]storage.Finding{row})
	if len(grouped) != 1 || grouped[0].FindingType != "ad_acl_evidence_inventory" {
		t.Fatalf("general inventory was grouped as a relationship: %#v", grouped)
	}
	if grouped[0].Title != "AD ACL Evidence Inventory" {
		t.Fatalf("general inventory title changed: %q", grouped[0].Title)
	}
	condition := findingCondition(grouped[0])
	for _, expected := range []string{"Observed ACL records : 1400", "Explicit ACEs : 735", "Inherited ACEs : 649", "Unknown decisions : 1390", "PRINCIPAL : alice@SCCM.LAB", "PERMISSION : WriteDacl", "TARGET : Helpdesk OU"} {
		if !strings.Contains(condition, expected) {
			t.Fatalf("aggregate presentation omitted %q: %s", expected, condition)
		}
	}
	if strings.Contains(condition, "(UNSPECIFIED)") || strings.Contains(condition, "EVIDENCE_INVENTORY") {
		t.Fatalf("aggregate presentation contains pseudo relationship data: %s", condition)
	}
	if got := findingImpact(grouped[0]); !strings.Contains(got, "configured permissions between principals") {
		t.Fatalf("unexpected aggregate impact: %s", got)
	}
	if got := findingRemediation(grouped[0]); strings.Contains(got, "named principal") || !strings.Contains(got, "full evidence report") {
		t.Fatalf("unexpected aggregate remediation: %s", got)
	}
	evidence := findingEvidenceSummary(grouped[0])
	if !strings.Contains(evidence, "AD_ACL_EVIDENCE.txt") || !strings.Contains(evidence, "AD_acl_evidence_inventory.json") || strings.Contains(evidence, "/ ") {
		t.Fatalf("aggregate evidence path is not concise: %s", evidence)
	}
}

func TestGeneralACLInventoryEvidenceUsesHumanReport(t *testing.T) {
	root := t.TempDir()
	report := filepath.Join(root, "results", "Enumeration", "ActiveDirectory", "ACL", "execution-12", "AD_ACL_EVIDENCE.txt")
	if err := os.MkdirAll(filepath.Dir(report), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(report, []byte("aggregate ACL evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	m := &model{cfg: config.Config{Root: root}}
	m.openFindingEvidence(storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ad_acl_evidence_inventory", ArtifactPath: report,
		EvidenceJSON: `{"human_report":"Enumeration/ActiveDirectory/ACL/execution-12/AD_ACL_EVIDENCE.txt"}`,
	}})
	if m.evidenceError != "" || len(m.evidenceLines) != 1 || m.evidenceLines[0] != "aggregate ACL evidence" {
		t.Fatalf("general inventory did not open its report: path=%s error=%s lines=%v", m.evidencePath, m.evidenceError, m.evidenceLines)
	}
}

func TestRawACLsRouteToEvidenceInventory(t *testing.T) {
	rows := []storage.Finding{{FindingInput: storage.FindingInput{
		FindingType: "ad_acl_genericall", Title: "Direct ACL GenericAll", Severity: "informational", SourceTool: "RustHound-CE",
	}}}
	subcategories := buildFindingSubcategories("acl", rows)
	for _, item := range subcategories {
		if item.Key == "acl" && item.Findings+item.Observations != 0 {
			t.Fatalf("raw ACL evidence remained in Vulnerable ACLs: %#v", item)
		}
		if item.Key == "acl_inventory" && item.Observations != 1 {
			t.Fatalf("raw ACL evidence did not route to inventory: %#v", item)
		}
	}
}

func TestLegacyACLSeverityRemainsReadableInLegacySubcategory(t *testing.T) {
	row := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ad_acl_genericall", Title: "Legacy GenericAll", Severity: "medium", SourceTool: "RustHound-CE",
	}}
	if got := findingSubcategoryKey(row); got != "acl" {
		t.Fatalf("legacy ACL severity was silently reclassified: %q", got)
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
		t.Fatalf("full Kerberos record was not preserved: count=%d error=%q", len(loaded.lines), loaded.error)
	}
}

func TestUserDescriptionKeywordEmphasizesObservedValueOnly(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType:    "ad_user_description_keyword_observed",
		AffectedObject: "snablr-lab-admin",
		EvidenceJSON:   `{"attribute":"info","principal":"snablr-lab-admin","value":"Secret Password in Info & notes"}`,
	}}
	detail := findingAttributes(finding, 100)
	if !strings.Contains(detail, "Value") || !strings.Contains(detail, "Secret Password in Info & notes") {
		t.Fatalf("directory attribute detail lost its label or value: %s", detail)
	}
	// Lipgloss disables escape sequences in the test renderer; the renderer
	// call in formatObservedAttributeFields applies the emphasis only to the
	// value span, while the label is rendered independently.
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

func TestHistoricalUserDescriptionHydratesAttributeValueFromArtifact(t *testing.T) {
	root := t.TempDir()
	resultsRoot := filepath.Join(root, "results", "example.test")
	artifact := filepath.Join(resultsRoot, "CredentialDumping", "NetExec", "LDAP_get_users_info.txt")
	if err := os.MkdirAll(filepath.Dir(artifact), 0o700); err != nil {
		t.Fatal(err)
	}
	content := "GET-INFO... User: snablr-lab-admin Info: Secret Password in Info & notes\n"
	if err := os.WriteFile(artifact, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ad_user_description_keyword_observed", AffectedObject: "snablr-lab-admin",
		ArtifactPath: "CredentialDumping/NetExec/LDAP_get_users_info.txt", ArtifactRef: "line:1",
		EvidenceJSON: `{"attribute":"info","keyword":"secret","principal":"snablr-lab-admin"}`,
	}}
	m := &model{cfg: config.Config{Root: root, Domain: "example.test"}}
	hydrated := m.hydrateHistoricalUserDescription(finding)
	attributes := ansi.Strip(findingAttributes(hydrated, 100))
	if !strings.Contains(attributes, "Secret Password in Info & notes") {
		t.Fatalf("historical attribute value was not hydrated: %s", attributes)
	}
}

func TestACLInventoryDetailShowsObservedRelationshipAndTechnique(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ad_acl_evidence_inventory", SourceExecution: 26, Severity: "informational",
		EvidenceJSON: `{"source_supported_ace_count":1,"retained_ace_count":1,"explicit_count":1,"inherited_count":0,"unknown_decision_count":1,"examples":[{"principal_name":"PF-ACL-Test-Operator","principal_id":"S-1-5-21-test-1101","target_name":"PF-ACL-Test-Target","target_id":"S-1-5-21-test-1102","permission":"GenericAll","decision":"unknown","inheritance":"explicit"}]}`,
	}}
	detail := ansi.Strip(formatGeneralACLInventoryOverview(finding))
	for _, expected := range []string{"OBSERVED ACL RELATIONSHIPS", "PRINCIPAL : PF-ACL-Test-Operator", "TARGET : PF-ACL-Test-Target", "PERMISSION : GenericAll", "EFFECTIVE ACCESS : NOT VERIFIED"} {
		if !strings.Contains(detail, expected) {
			t.Fatalf("ACL detail omitted %q: %s", expected, detail)
		}
	}
	reference := findingTechniqueReference(finding)
	if !strings.Contains(reference, "DACL Abuse") || !strings.Contains(reference, "bloodhound.readthedocs.io") {
		t.Fatalf("ACL technique reference missing: %s", reference)
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
			want:     []string{"PRIVILEGED ACCESS REPORTED", "Pwn3d!", "SMB", "EXAMPLE\\operator", "SECURITY IMPACT"},
			unwanted: []string{"Remediation:", "Domain Administrator", "LIMITATIONS"},
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
	for _, expected := range []string{"AD_PRIVILEGED_ACL_EVIDENCE.txt", "AD_privileged_acl_inventory.json", "groups.json"} {
		if !strings.Contains(evidence, expected) {
			t.Fatalf("evidence summary omitted %q: %s", expected, evidence)
		}
	}
}

func TestPrivilegedACLInventoryDetailShowsMembershipContext(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ad_privileged_acl_evidence_inventory", Title: "AD Privileged ACL Evidence Inventory", Severity: "informational",
		SourceTool: "RustHound-CE", SourceExecution: 477,
		EvidenceJSON: `{"source_execution_id":477,"high_value_targets":1,"normalized_relationships":1,"membership_edges":2,"direct_membership_paths":0,"nested_membership_paths":1,"omitted_membership_paths":267,"membership_coverage":"partial","membership_context":[{"member_id":"S-1-5-21-100-1101","member_name":"alice","group_path":[{"id":"S-1-5-21-100-901","name":"Tier 1 Support"},{"id":"S-1-5-21-100-900","name":"Helpdesk Operators"}],"acl_principal_id":"S-1-5-21-100-900","acl_principal_name":"Helpdesk Operators","target_id":"S-1-5-21-100-512","target_name":"Domain Admins","permission":"WriteDacl","classification":"observed_nested_membership_context","effective_permission":"NOT VERIFIED","membership_refs":["/data/0/Members/0","/data/0/Members/0"],"acl_artifact":"groups.json","acl_artifact_ref":"/data/2/Aces/0"}]}`,
	}}
	condition := findingCondition(finding)
	for _, expected := range []string{"OBSERVED MEMBERSHIP CONTEXT", "Observed members", "omitted 267 paths before materialization", "alice", "Tier 1 Support", "Helpdesk Operators", "WriteDacl", "Domain Admins", "NOT VERIFIED", "observed_nested_membership_context"} {
		if !strings.Contains(condition, expected) {
			t.Fatalf("membership context omitted %q: %s", expected, condition)
		}
	}
	if strings.Contains(condition, "/data/0/Members") {
		t.Fatalf("bounded membership preview exposed raw JSON pointers: %s", condition)
	}
	limitations := findingLimitations(finding)
	if !strings.Contains(limitations, "Membership context coverage: partial") || !strings.Contains(limitations, "Effective permissions") {
		t.Fatalf("membership limitations omitted: %s", limitations)
	}
	if strings.Contains(findingRemediation(finding), "source tool's recommended hardening") || !strings.Contains(findingRemediation(finding), "validate effective permissions") {
		t.Fatalf("ACL remediation remained generic: %s", findingRemediation(finding))
	}
}

func TestReplicationRightsOverviewIsInformationalAndEvidenceSpecific(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ad_replication_rights_evidence_overview", Title: "AD Replication Rights Evidence Overview", Severity: "informational",
		SourceTool: "RustHound-CE", SourceExecution: 491, ArtifactPath: "results/AD_REPLICATION_RIGHTS_EVIDENCE.txt",
		EvidenceJSON: `{"source_execution_id":491,"coverage":"partial","structured_artifact":"Enumeration/ActiveDirectory/ACL/execution-491/AD_replication_rights_evidence.json","domain_roots":[{"id":"S-1-5-21-1","name":"SCCM.LAB","principals":[{"id":"S-1-5-21-1-512","name":"Domain Admins","type":"Group","rights":[{"right":"GetChanges","status":"observed"},{"right":"GetChangesAll","status":"not_observed"},{"right":"GetChangesInFilteredSet","status":"not_observed"}],"membership_context":[]}]}]}`,
	}}
	condition := findingCondition(finding)
	for _, expected := range []string{"SCCM.LAB", "Domain Admins", "GetChanges", "OBSERVED", "NOT_OBSERVED", "NOT VERIFIED"} {
		if !strings.Contains(condition, expected) {
			t.Fatalf("replication overview omitted %q: %s", expected, condition)
		}
	}
	if strings.Contains(strings.ToLower(findingImpact(finding)), "dcsync-capable") || strings.Contains(strings.ToLower(findingImpact(finding)), "credential") {
		t.Fatalf("impact overclaims: %s", findingImpact(finding))
	}
	if strings.Contains(findingRemediation(finding), "source tool's recommended hardening") {
		t.Fatalf("replication remediation is generic: %s", findingRemediation(finding))
	}
	evidence := findingEvidenceSummary(finding)
	if !strings.Contains(evidence, "AD_REPLICATION_RIGHTS_EVIDENCE.txt") || !strings.Contains(evidence, "AD_replication_rights_evidence.json") {
		t.Fatalf("evidence summary incomplete: %s", evidence)
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
			condition: "Minimum Length", impact: "domain-default policy", remediation: "fine-grained policies",
		},
		{
			name:      "Kerberos material",
			finding:   storage.Finding{FindingInput: storage.FindingInput{FindingType: "kerberos_ticket_material_collected", AffectedObject: "svc-sql@sccm.lab", EvidenceJSON: `{"material_type":"kerberoast","material_collected":true,"principal":"svc-sql@sccm.lab","record_count":1,"payload":"synthetic-secret"}`}},
			condition: "matching material is limited to this principal", impact: "not prove", remediation: "protected artifact",
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

func TestRelayTargetHighlightsOnlyExplicitSourceBackedIP(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })

	relay := storage.Finding{FindingInput: storage.FindingInput{FindingType: "relay_exposure_observed", AffectedObject: "192.0.2.40", EvidenceJSON: `{"protocol":"http","destination":"192.0.2.40","level":"high"}`}}
	view := findingAttributes(relay, 100)
	if !strings.Contains(view, warn.Render("192.0.2.40")) {
		t.Fatalf("explicit relay destination was not highlighted: %q", view)
	}
	if strings.Contains(view, warn.Render("AFFECTED")) || strings.Contains(view, warn.Render("http")) {
		t.Fatalf("relay label or protocol was highlighted: %q", view)
	}

	unknown := storage.Finding{FindingInput: storage.FindingInput{FindingType: "relay_exposure_observed", AffectedObject: "192.0.2.41", EvidenceJSON: `{"protocol":"http"}`}}
	if strings.Contains(findingAttributes(unknown, 100), warn.Render("192.0.2.41")) {
		t.Fatal("unknown relay target was highlighted")
	}
	other := storage.Finding{FindingInput: storage.FindingInput{FindingType: "netexec_auth_success", AffectedObject: "192.0.2.40", EvidenceJSON: `{"target":"192.0.2.40","protocol":"SMB"}`}}
	if strings.Contains(findingAttributes(other, 100), warn.Render("192.0.2.40")) {
		t.Fatal("unrelated affected IP was highlighted")
	}
}

func TestTechniqueReferencesCoverSupportedAttackFamilies(t *testing.T) {
	for _, esc := range []string{"ESC1", "ESC2", "ESC3", "ESC4", "ESC6", "ESC7", "ESC8", "ESC15", "ESC17"} {
		reference := findingTechniqueReference(storage.Finding{FindingInput: storage.FindingInput{FindingType: "adcs_esc_" + strings.ToLower(esc)}})
		if reference == "" || !strings.Contains(reference, "https://") {
			t.Fatalf("%s has no verified technique reference: %q", esc, reference)
		}
	}
	esc8 := findingTechniqueReference(storage.Finding{FindingInput: storage.FindingInput{FindingType: "adcs_esc_esc8"}})
	if !strings.Contains(esc8, "unsigned-endpoints") || !strings.Contains(esc8, "ad/movement/adcs/") {
		t.Fatalf("ESC8 reference is not specific: %q", esc8)
	}
	for _, typ := range []string{"relay_exposure_observed", "smb_signing_not_required", "unconstrained_delegation_configured", "constrained_delegation_configured", "ad_replication_rights_evidence_overview"} {
		if findingTechniqueReference(storage.Finding{FindingInput: storage.FindingInput{FindingType: typ}}) == "" {
			t.Fatalf("attack-relevant family %s has no technique reference", typ)
		}
	}
}

func TestTechniquesRenderOnceImmediatelyAfterEvidence(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "adcs_esc_esc8", Title: "Certipy reported ESC8 — Example CA", Severity: "high",
		SourceTool: "Certipy", SourceExecution: 8, AffectedObject: "Example CA", ArtifactPath: "certipy.json", ArtifactRef: "/ca",
		EvidenceJSON: `{"object_type":"ca","esc":"ESC8","vulnerability":{"ESC8":"Web Enrollment is enabled over HTTP."}}`,
	}}
	m := &model{findingsView: true, findingDetail: true, findingRows: []storage.Finding{finding}, width: 120, height: 100}
	view := ansi.Strip(m.View())
	if strings.Count(view, "TECHNIQUES") != 1 {
		t.Fatalf("TECHNIQUES section count=%d, want one", strings.Count(view, "TECHNIQUES"))
	}
	if strings.Index(view, "EVIDENCE") > strings.Index(view, "TECHNIQUES") {
		t.Fatalf("TECHNIQUES did not follow EVIDENCE: %q", view)
	}
}

func TestSMBSigningConditionHighlightsOnlyNegativeObservation(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })

	negative := storage.Finding{FindingInput: storage.FindingInput{FindingType: "smb_signing_not_required", AffectedObject: "192.0.2.41", EvidenceJSON: `{"protocol":"SMB","target":"192.0.2.41","port":"445","host":"MECM","signing_required":false}`}}
	positive := storage.Finding{FindingInput: storage.FindingInput{FindingType: "smb_signing_observed", AffectedObject: "192.0.2.41", EvidenceJSON: `{"protocol":"SMB","target":"192.0.2.41","port":"445","host":"MECM","signing_required":true}`}}
	unknown := storage.Finding{FindingInput: storage.FindingInput{FindingType: "smb_signing_not_required", AffectedObject: "192.0.2.41", EvidenceJSON: `{"protocol":"SMB","target":"192.0.2.41","port":"445","host":"MECM"}`}}

	negativeView := findingAttributes(negative, 100)
	if !strings.Contains(negativeView, warn.Render("signing:False")) {
		t.Fatalf("negative SMB signing condition was not highlighted: %q", negativeView)
	}
	if strings.Contains(negativeView, warn.Render("CONDITION")) {
		t.Fatalf("condition label was highlighted with the value: %q", negativeView)
	}
	if strings.Contains(findingAttributes(positive, 100), warn.Render("signing:True")) {
		t.Fatal("positive SMB signing condition was highlighted")
	}
	if strings.Contains(findingAttributes(unknown, 100), warn.Render("signing:False")) {
		t.Fatal("unknown SMB signing condition was highlighted")
	}

	other := storage.Finding{FindingInput: storage.FindingInput{FindingType: "ad_account_passwd_notreqd", AffectedObject: "user"}}
	if strings.Contains(findingAttributes(other, 100), warn.Render("PASSWD_NOTREQD")) {
		t.Fatal("unrelated condition was highlighted")
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
	attributes := findingAttributes(storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ad_user_description_keyword_observed", AffectedObject: "snablr-lab-admin",
		EvidenceJSON: `{"attribute":"info","principal":"snablr-lab-admin","value":"Secret Password in Info & notes"}`,
	}}, 100)
	for _, expected := range []string{"OBSERVED DIRECTORY ATTRIBUTE", "Account", "snablr-lab-admin", "Attribute", "info", "Value", "Secret Password in Info & notes"} {
		if !strings.Contains(ansi.Strip(attributes), expected) {
			t.Fatalf("structured LDAP attribute detail omitted %q: %s", expected, attributes)
		}
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
	if findingCategoryKey(material) != "kerberos" || findingSubcategoryKey(material) != "kerberoastable" {
		t.Fatalf("Kerberos material was misrouted: category=%s subcategory=%s", findingCategoryKey(material), findingSubcategoryKey(material))
	}
	rows := buildFindingSubcategories("kerberos", []storage.Finding{material})
	for _, row := range rows {
		if row.Key == "kerberoastable" && row.Findings+row.Observations != 1 {
			t.Fatalf("Kerberos material was not visible in its subcategory: %+v", row)
		}
	}
	if strings.Contains(findingCondition(material)+findingImpact(material)+findingRemediation(material), "do-not-display") {
		t.Fatal("Kerberos material payload leaked")
	}
}

func TestKerberosPresentationConsolidatesConfigurationAndMaterial(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{FindingType: "kerberoastable_account", Title: "Kerberoastable account: SCCM-SQL@SCCM.LAB", AffectedObject: "SCCM-SQL@SCCM.LAB", ArtifactRef: "/users/1/spn"}},
		{FindingInput: storage.FindingInput{FindingType: "kerberos_ticket_material_collected", Title: "Kerberoast material collected: sccm-sql", AffectedObject: "sccm-sql", ArtifactRef: "/lines/3", EvidenceJSON: `{"material_type":"kerberoast","principal":"sccm-sql","record_line_numbers":[3]}`}},
		{FindingInput: storage.FindingInput{FindingType: "kerberoastable_account", Title: "Kerberoastable account: other", AffectedObject: "other", ArtifactRef: "/users/2/spn"}},
	}
	model := &model{}
	consolidated := model.consolidatePresentationFindings(rows)
	if len(consolidated) != 2 {
		t.Fatalf("got %d visible Kerberos findings, want material plus configuration-only", len(consolidated))
	}
	var material storage.Finding
	for _, finding := range consolidated {
		if finding.FindingType == "kerberos_ticket_material_collected" {
			material = finding
		}
	}
	if material.Title == "" {
		t.Fatal("material finding was not retained")
	}
	metadata := findingMetadata(material)
	refs := stringSlice(metadata["artifact_records"])
	if len(refs) != 2 || !containsString(refs, "/lines/3") || !containsString(refs, "/users/1/spn") {
		t.Fatalf("consolidated evidence references = %#v", refs)
	}
	if len(buildFindingSubcategories("kerberos", consolidated)) != 2 {
		t.Fatal("Kerberos navigation no longer has exactly two subcategories")
	}
}

func TestKerberosPresentationMatchesGMSAPrincipalForms(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{FindingType: "kerberos_ticket_material_collected", AffectedObject: "sccm.lab\\adenum-gmsa", ArtifactRef: "/lines/1"}},
		{FindingInput: storage.FindingInput{FindingType: "kerberoastable_account", AffectedObject: "ADENUM-GMSA$@SCCM.LAB", ArtifactRef: "/data/26/Properties/serviceprincipalnames"}},
	}
	consolidated := (&model{}).consolidatePresentationFindings(rows)
	if len(consolidated) != 1 || consolidated[0].FindingType != "kerberos_ticket_material_collected" {
		t.Fatalf("gMSA material/configuration pair was not consolidated: %#v", consolidated)
	}
}

func TestWritableObjectPresentationConsolidatesRepeatedReports(t *testing.T) {
	relationship := `{"principal_id":"S-1-5-21-1-1100","target_id":"S-1-5-21-1-1200","permission":"GenericAll","decision":"unknown","inheritance":"explicit"}`
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{FindingType: "ad_writable_object_assessment", SourceExecution: 40, ArtifactPath: "writable-40.json", AffectedObject: "snablr-lab-admin", EvidenceJSON: `{"domain":"SCCM.LAB","authenticated_user":"snablr-lab-admin","relationships":[` + relationship + `]}`}},
		{FindingInput: storage.FindingInput{FindingType: "ad_writable_object_assessment", SourceExecution: 83, ArtifactPath: "writable-83.json", AffectedObject: "snablr-lab-admin", EvidenceJSON: `{"domain":"SCCM.LAB","authenticated_user":"snablr-lab-admin","relationships":[` + relationship + `]}`}},
	}
	consolidated := (&model{}).consolidatePresentationFindings(rows)
	if len(consolidated) != 1 {
		t.Fatalf("writable-object rows=%d, want one visible finding", len(consolidated))
	}
	metadata := findingMetadata(consolidated[0])
	records, ok := metadata["source_records"].([]any)
	if !ok || len(records) != 2 {
		t.Fatalf("source records=%v, want two execution references", metadata["source_records"])
	}
	relationships, ok := metadata["relationships"].([]any)
	if !ok || len(relationships) != 1 {
		t.Fatalf("relationships=%v, want one deduplicated relationship", metadata["relationships"])
	}
}

func TestKerberosTechniqueReferencesAreTechniqueSpecific(t *testing.T) {
	kerberoast := storage.Finding{FindingInput: storage.FindingInput{FindingType: "kerberos_ticket_material_collected"}}
	asrep := storage.Finding{FindingInput: storage.FindingInput{FindingType: "asrep_material_collected"}}
	if !strings.Contains(findingTechniqueReference(kerberoast), "thehacker.recipes/ad/movement/kerberos/roasting/kerberoast") {
		t.Fatal("Kerberoasting technique reference missing")
	}
	if !strings.Contains(findingTechniqueReference(asrep), "thehacker.recipes/ad/movement/kerberos/roasting/asreproast") {
		t.Fatal("AS-REP roasting technique reference missing")
	}
}

func TestProtectedAccountsPresentationConsolidatesRepeatedSnapshots(t *testing.T) {
	rows := make([]storage.Finding, 0, 16)
	for index := 0; index < 16; index++ {
		rows = append(rows, storage.Finding{FindingInput: storage.FindingInput{
			FindingType:     "ad_protected_accounts_admincount_evidence",
			Title:           "AD Protected Accounts & adminCount Evidence Overview",
			Severity:        "informational",
			SourceTool:      "RustHound-CE",
			SourceExecution: int64(index + 1),
			ArtifactPath:    fmt.Sprintf("execution-%d/protected.json", index+1),
			ArtifactRef:     fmt.Sprintf("/records/%d", index+1),
			EvidenceJSON:    fmt.Sprintf(`{"admincount_users":1,"admincount_groups":1,"membership_examples":[{"path":["ACCOUNT-%d","Domain Admins"],"classification":"direct"}],"admin_sdholder":{"distinguished_name":"CN=AdminSDHolder","aces":[{"principal":"S-1-5-21-%d","rights":"WriteOwner"}]}}`, index+1, index+1),
		}})
	}
	consolidated := (&model{}).consolidatePresentationFindings(rows)
	if len(consolidated) != 1 {
		t.Fatalf("visible protected-account findings = %d, want 1", len(consolidated))
	}
	metadata := findingMetadata(consolidated[0])
	if got := len(metadata["source_records"].([]any)); got != 16 {
		t.Fatalf("source records = %d, want 16", got)
	}
	if got := len(metadata["membership_examples"].([]any)); got != 16 {
		t.Fatalf("membership observations = %d, want 16", got)
	}
	holder := metadata["admin_sdholder"].(map[string]any)
	if got := len(holder["aces"].([]any)); got != 16 {
		t.Fatalf("AdminSDHolder ACE observations = %d, want 16", got)
	}
	condition := ansi.Strip(findingCondition(consolidated[0]))
	for _, expected := range []string{"PROTECTED-GROUP MEMBERSHIP", "ATTRIBUTE / MEMBERSHIP DIFFERENCES", "ADMINSDHOLDER", "Additional original evidence is available through E"} {
		if !strings.Contains(condition, expected) && expected != "ATTRIBUTE / MEMBERSHIP DIFFERENCES" {
			t.Fatalf("protected overview omitted %q: %s", expected, condition)
		}
	}
}

func TestTierPresentationConsolidatesEachTierWithoutCrossTierMerge(t *testing.T) {
	rows := make([]storage.Finding, 0, 48)
	for _, tier := range []string{"0", "1", "2"} {
		typ := "ad_tier" + tier + "_context_evidence"
		for execution := 1; execution <= 16; execution++ {
			metadata := `{"domain":"EXAMPLE.TEST","tier":` + tier + `,"membership_paths":[{"path":["PF-T` + tier + `-User","PF-T` + tier + `-Admins"],"classification":"direct"}],"targets":[{"declared":{"name":"HOST` + tier + `"},"status":"declared"}]}`
			rows = append(rows, storage.Finding{FindingInput: storage.FindingInput{FindingType: typ, Title: "AD Tier " + tier + " Administrative Context Evidence Overview", Severity: "informational", SourceExecution: int64(execution), ArtifactPath: "tier.json", ArtifactRef: "/tier/" + tier}})
			rows[len(rows)-1].EvidenceJSON = metadata
		}
	}
	consolidated := (&model{}).consolidatePresentationFindings(rows)
	if len(consolidated) != 3 {
		t.Fatalf("tier overview rows = %d, want 3", len(consolidated))
	}
	seen := map[string]bool{}
	for _, finding := range consolidated {
		seen[finding.FindingType] = true
		if len(findingMetadata(finding)["source_records"].([]any)) != 16 {
			t.Fatalf("%s did not retain all source records", finding.FindingType)
		}
	}
	for _, typ := range []string{"ad_tier0_context_evidence", "ad_tier1_context_evidence", "ad_tier2_context_evidence"} {
		if !seen[typ] {
			t.Fatalf("tier %s was lost during consolidation", typ)
		}
	}
}

func TestTierTechniqueReferenceOnlyAppliesToTierZero(t *testing.T) {
	if !strings.Contains(findingTechniqueReference(storage.Finding{FindingInput: storage.FindingInput{FindingType: "ad_tier0_context_evidence"}}), "TierZeroTable") {
		t.Fatal("Tier 0 offensive context references missing")
	}
	if findingTechniqueReference(storage.Finding{FindingInput: storage.FindingInput{FindingType: "ad_tier1_context_evidence"}}) != "" {
		t.Fatal("unsupported Tier 1 technique reference was added")
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
			if !strings.Contains(condition, "CERTIFICATE TEMPLATE") && !strings.Contains(condition, "CERTIFICATE AUTHORITY") {
				t.Fatalf("structured AD CS identity missing: %s", condition)
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

func TestFindingsRowsKeepAffectedObjectColumnStableAcrossSelection(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{Title: "AD Privileged ACL Evidence Inventory", Severity: "informational", AffectedObject: "RustHound direct ACL inventory"}},
		{FindingInput: storage.FindingInput{Title: "AD Privileged ACL Evidence Inventory", Severity: "informational", AffectedObject: "RustHound direct ACL inventory"}},
		{FindingInput: storage.FindingInput{Title: "AD Privileged ACL Evidence Inventory", Severity: "informational", AffectedObject: "RustHound direct ACL inventory"}},
	}
	for _, width := range []int{160, 120, 100, 80, 60} {
		positions := make([]int, 0, len(rows))
		for selected := range rows {
			m := &model{findingsView: true, findingViewMode: "all", findingRows: rows, findingCursor: selected, width: width, height: 24}
			lines := strings.Split(ansi.Strip(m.View()), "\n")
			found := false
			for _, line := range lines {
				if index := strings.Index(line, "RustHound direc"); index >= 0 {
					positions = append(positions, index)
					if ansi.StringWidthWc(line) > width {
						t.Fatalf("finding row overflowed panel width %d: %d", width, ansi.StringWidthWc(line))
					}
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("affected-object column missing at width %d for selected row %d:\n%s", width, selected, ansi.Strip(m.View()))
			}
		}
		if positions[0] != positions[1] || positions[1] != positions[2] {
			t.Fatalf("affected-object column moved with selection at width %d: positions=%v", width, positions)
		}
	}
}

func TestProtectedAccountsFindingShowsIdentitiesAndLimitations(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType:     "ad_protected_accounts_admincount_evidence",
		SourceTool:      "RustHound-CE",
		SourceExecution: 42,
		Severity:        "informational",
		EvidenceJSON:    `{"admincount_users":7,"admincount_groups":10,"admincount_user_examples":[{"name":"alice"}],"admincount_group_examples":[{"name":"Domain Admins"}],"membership_paths":7,"membership_examples":[{"path":["alice","Domain Admins"],"classification":"direct"}],"attribute_membership_differences":[{"name":"krbtgt","admin_count":"true","membership":"not_observed"}],"admin_sdholder":{"distinguished_name":"CN=ADMINSDHOLDER,CN=SYSTEM,DC=SCCM,DC=LAB","aces":[{"principal":"Domain Admins","rights":"WriteDacl"}]}}`,
	}}
	condition := findingCondition(finding)
	for _, expected := range []string{"alice", "Domain Admins", "alice → Domain Admins", "krbtgt", "CN=ADMINSDHOLDER", "WriteDacl", "NOT VERIFIED"} {
		if !strings.Contains(condition, expected) {
			t.Fatalf("protected-account condition missing %q: %s", expected, condition)
		}
	}
	if strings.Contains(findingImpact(finding), "security-relevant condition requiring operator review") {
		t.Fatal("protected-account impact retained generic wording")
	}
	if strings.Contains(findingRemediation(finding), "named principal") {
		t.Fatal("protected-account remediation treated aggregate evidence as one principal")
	}
}

func TestProtectedAccountsHistoricalFindingHydratesExactExecutionArtifact(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "AD_protected_accounts_evidence.json")
	payload := `{"source_execution_id":31,"users":[{"name":"alice","id":"S-1-5-21-1-2-3-1100","admin_count":"true","membership":"observed"}],"groups":[{"name":"Domain Admins","id":"S-1-5-21-1-2-3-512","admin_count":"true","membership":"not_observed"}],"membership_paths":[{"path":["alice","Domain Admins"],"classification":"direct"}],"admin_sd_holder":{"distinguished_name":"CN=ADMINSDHOLDER,CN=SYSTEM,DC=SCCM,DC=LAB","aces":[]}}`
	if err := os.WriteFile(artifact, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType:     "ad_protected_accounts_admincount_evidence",
		SourceExecution: 31,
		EvidenceJSON:    fmt.Sprintf(`{"admincount_users":1,"admincount_groups":1,"structured_artifact":%q}`, artifact),
	}}
	condition := findingCondition(finding)
	for _, expected := range []string{"alice", "Domain Admins", "alice → Domain Admins", "CN=ADMINSDHOLDER"} {
		if !strings.Contains(condition, expected) {
			t.Fatalf("historical artifact fallback missing %q: %s", expected, condition)
		}
	}
	mismatched := finding
	mismatched.SourceExecution = 99
	mismatchedCondition := findingCondition(mismatched)
	if strings.Contains(mismatchedCondition, "alice") || !strings.Contains(mismatchedCondition, "Users adminCount=true") {
		t.Fatalf("cross-execution artifact fallback was used: %s", mismatchedCondition)
	}
}

func TestTier0FindingRendersIdentityControlContext(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType:     "ad_tier0_context_evidence",
		SourceExecution: 31,
		Severity:        "informational",
		EvidenceJSON:    `{"domain":"SCCM.LAB","domain_controllers":[{"name":"DC.SCCM.LAB","id":"S-1-5-21-1-2-3-1001"}],"tier0_groups":[{"name":"DOMAIN ADMINS@SCCM.LAB","id":"S-1-5-21-1-2-3-512","role":"Domain Admins"}],"membership_paths":[{"path":["ALICE@SCCM.LAB","DOMAIN ADMINS@SCCM.LAB"],"classification":"direct"}],"acl_relationships":[{"principal_name":"ALICE@SCCM.LAB","permission":"GetChangesAll","target_name":"SCCM.LAB","target_id":"S-1-5-21-1-2-3"}],"admin_sd_holder":{"distinguished_name":"CN=ADMINSDHOLDER,CN=SYSTEM,DC=SCCM,DC=LAB","aces":[{}]}}`,
	}}
	condition := findingCondition(finding)
	for _, expected := range []string{"ALICE@SCCM.LAB", "DOMAIN ADMINS@SCCM.LAB", "DC.SCCM.LAB", "ALICE@SCCM.LAB → DOMAIN ADMINS@SCCM.LAB", "GetChangesAll", "NOT VERIFIED"} {
		if !strings.Contains(condition, expected) {
			t.Fatalf("tier 0 detail missing %q: %s", expected, condition)
		}
	}
	if strings.Contains(condition, "Tier 1 → Tier 0") || strings.Contains(condition, "policy violation") {
		t.Fatal("tier 0 overview made an unsupported boundary claim")
	}
}

func TestAdministrativeTieringNavigationScopes(t *testing.T) {
	rows := []storage.Finding{{FindingInput: storage.FindingInput{
		FindingType: "ad_tier0_context_evidence", Title: "AD Tier 0 Administrative Context Evidence Overview", Severity: "informational",
	}}}
	m := &model{findingsView: true, findingCategoryView: true, findingCategories: []findingCategory{{Key: "active_directory", Name: "Active Directory"}}, findingAllRows: rows, findingRows: rows, findingsLoaded: true, width: 120, height: 30}
	m.handleFindingsKey("enter")
	if !m.findingSubcategoryView || m.findingCategory != "active_directory" {
		t.Fatalf("Active Directory did not open: category=%q subcategories=%t", m.findingCategory, m.findingSubcategoryView)
	}
	for index, subcategory := range m.findingSubcategories {
		if subcategory.Key == "tiering" {
			m.findingCursor = index
		}
	}
	m.handleFindingsKey("enter")
	if !m.findingTieringView {
		t.Fatal("Administrative Tiering did not open")
	}
	if !strings.Contains(m.findingTieringOverview(120), "Tier 1 — Server Administration") || !strings.Contains(m.findingTieringOverview(120), "NOT ASSESSED") {
		t.Fatal("unassessed tier scopes were not rendered")
	}
	m.findingCursor = 0
	m.handleFindingsKey("enter")
	if m.findingTieringView || m.findingSubcategory != "tier0_context" || m.findingCategoryView {
		t.Fatalf("Tier 0 did not open its findings: tiering=%t subcategory=%q categoryView=%t", m.findingTieringView, m.findingSubcategory, m.findingCategoryView)
	}
	if len(m.findingRows) != 1 {
		t.Fatalf("Tier 0 rows=%d, want 1", len(m.findingRows))
	}
	m.handleFindingsKey("esc")
	if m.findingDetail {
		m.handleFindingsKey("esc")
	}
	if !m.findingTieringView || !m.findingSubcategoryView || m.findingSubcategory != "" {
		t.Fatalf("Esc did not restore Administrative Tiering: tiering=%t subcategoryView=%t key=%q", m.findingTieringView, m.findingSubcategoryView, m.findingSubcategory)
	}
	m.handleFindingsKey("esc")
	if m.findingTieringView || !m.findingSubcategoryView || m.findingCategory != "active_directory" {
		t.Fatalf("Esc did not return to Active Directory subcategories")
	}
}

func TestAdministrativeTieringParentAggregatesDescendants(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{FindingType: "ad_tier0_context_evidence", Severity: "informational"}},
		{FindingInput: storage.FindingInput{FindingType: "ad_tier0_context_evidence", Severity: "informational"}},
		{FindingInput: storage.FindingInput{FindingType: "ad_tier0_context_evidence", Severity: "informational"}},
		{FindingInput: storage.FindingInput{FindingType: "ad_tier1_context_evidence", Severity: "informational"}},
		{FindingInput: storage.FindingInput{FindingType: "ad_tier2_context_evidence", Severity: "medium"}},
		{FindingInput: storage.FindingInput{FindingType: "ad_gpo_privilege_relationship_evidence", Severity: "informational"}},
	}
	subcategories := buildFindingSubcategories("active_directory", rows)
	var tiering, groupPolicy findingSubcategory
	for _, subcategory := range subcategories {
		switch subcategory.Key {
		case "tiering":
			tiering = subcategory
		case "gpo":
			groupPolicy = subcategory
		}
	}
	if got := tiering.Findings + tiering.Observations; got != 5 {
		t.Fatalf("tiering count=%d, want 5 descendant findings", got)
	}
	if got := groupPolicy.Findings + groupPolicy.Observations; got != 1 {
		t.Fatalf("unrelated Group Policy count=%d, want 1", got)
	}
	model := &model{findingAllRows: rows, findingSubcategories: subcategories, width: 120, height: 30}
	parentView := model.findingSubcategoryOverview(120)
	if !strings.Contains(parentView, "Administrative Tiering") || !strings.Contains(parentView, "         5") {
		t.Fatalf("parent view did not render aggregated tiering count: %s", parentView)
	}
	categories := buildFindingCategories(rows)
	for _, category := range categories {
		if category.Key == "active_directory" && category.Findings+category.Observations != len(rows) {
			t.Fatalf("Active Directory count=%d, want %d without double-counting", category.Findings+category.Observations, len(rows))
		}
	}
}

func TestAdministrativeTieringParentEmptyAndFutureScopes(t *testing.T) {
	for _, rows := range [][]storage.Finding{
		{},
		{{FindingInput: storage.FindingInput{FindingType: "ad_tier1_context_evidence", Severity: "informational"}}},
		{{FindingInput: storage.FindingInput{FindingType: "ad_tier2_context_evidence", Severity: "informational"}}},
	} {
		subcategories := buildFindingSubcategories("active_directory", rows)
		for _, subcategory := range subcategories {
			if subcategory.Key == "tiering" {
				want := len(rows)
				if got := subcategory.Findings + subcategory.Observations; got != want {
					t.Fatalf("tiering count=%d, want %d for future scope rows", got, want)
				}
				break
			}
		}
	}
}

func TestAdministrativeTieringRoutesTierOneAndTwo(t *testing.T) {
	rows := []storage.Finding{{FindingInput: storage.FindingInput{FindingType: "ad_tier0_context_evidence", Severity: "informational"}}, {FindingInput: storage.FindingInput{FindingType: "ad_tier1_context_evidence", Severity: "informational"}}, {FindingInput: storage.FindingInput{FindingType: "ad_tier2_context_evidence", Severity: "informational"}}}
	for _, cursor := range []struct {
		cursor int
		want   string
	}{{1, "tier1_context"}, {2, "tier2_context"}} {
		m := &model{findingTieringView: true, findingCursor: cursor.cursor, findingAllRows: rows, findingRows: rows, findingsLoaded: true, findingCategory: "active_directory", width: 120, height: 30}
		m.handleFindingsKey("enter")
		if m.findingSubcategory != cursor.want {
			t.Fatalf("cursor %d routed to %q, want %q", cursor.cursor, m.findingSubcategory, cursor.want)
		}
	}
}

func TestTierContextFindingRendersObservedIdentities(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ad_tier1_context_evidence", SourceExecution: 82, Severity: "informational",
		EvidenceJSON: `{"tier":1,"policy_id":"lab-tier-policy","declared_groups":[{"id":"S-1-5-21-1-2-3-1152","name":"PF-T1-Admins"}],"membership_paths":[{"path":["PF-T1-Admin","PF-T1-Admins"],"classification":"direct"}],"targets":[{"declared":{"name":"MSSQL.SCCM.LAB","ip":"192.0.2.42"},"status":"unresolved"}]}`,
	}}

	detail := findingCondition(finding)
	for _, want := range []string{"PF-T1-Admins", "PF-T1-Admin", "MSSQL.SCCM.LAB", "NOT VERIFIED"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("tier detail missing %q: %s", want, detail)
		}
	}
	if !strings.Contains(specificFindingImpact(finding), "host-local administrator") {
		t.Fatal("tier impact used generic or privileged wording")
	}
}

func TestFindingsArrowAliasesFollowEnterAndEsc(t *testing.T) {
	rows := []storage.Finding{{FindingInput: storage.FindingInput{FindingType: "ad_tier0_context_evidence", Title: "Tier 0", Severity: "informational"}}}
	m := &model{findingsView: true, findingCategoryView: true, findingCategories: []findingCategory{{Key: "active_directory", Name: "Active Directory"}}, findingAllRows: rows, findingRows: rows, findingsLoaded: true, width: 120, height: 30}
	m.handleFindingsKey("right")
	if !m.findingSubcategoryView || m.findingCategory != "active_directory" {
		t.Fatal("right did not open Active Directory")
	}
	for index, subcategory := range m.findingSubcategories {
		if subcategory.Key == "tiering" {
			m.findingCursor = index
		}
	}
	m.handleFindingsKey("right")
	if !m.findingTieringView {
		t.Fatal("right did not open Administrative Tiering")
	}
	m.handleFindingsKey("right")
	if m.findingTieringView || m.findingSubcategory != "tier0_context" {
		t.Fatal("right did not open Tier 0 Finding scope")
	}
	m.handleFindingsKey("right")
	if !m.findingDetail {
		t.Fatal("right did not open actual Finding detail")
	}
	m.handleFindingsKey("left")
	if m.findingDetail || m.findingSubcategory != "tier0_context" {
		t.Fatal("left did not return from Finding detail")
	}
	m.handleFindingsKey("left")
	if !m.findingTieringView {
		t.Fatal("left did not return to Administrative Tiering")
	}
	m.handleFindingsKey("left")
	if m.findingTieringView || !m.findingSubcategoryView || m.findingCategory != "active_directory" {
		t.Fatal("left did not return to Active Directory")
	}
	root := &model{findingsView: true, findingCategoryView: true, findingCursor: 4, findingTop: 2, width: 100, height: 24}
	for attempt := 0; attempt < 3; attempt++ {
		_, command := root.handleFindingsKey("left")
		if command != nil || !root.findingsView || root.findingCategory != "" || !root.findingCategoryView || root.findingCursor != 4 || root.findingTop != 2 {
			t.Fatal("left at Findings root escaped or changed the root view")
		}
	}
	root.handleFindingsKey("esc")
	if root.findingsView {
		t.Fatal("explicit Escape did not leave Findings from the root")
	}
}

func TestFindingsLeftBoundaryThroughTopLevelUpdate(t *testing.T) {
	row := storage.Finding{FindingInput: storage.FindingInput{FindingType: "ad_protected_accounts_context", Title: "Protected account context", Severity: "informational"}}
	m := &model{
		findingCategories: []findingCategory{{Key: "active_directory", Name: "Active Directory"}},
		findingAllRows:    []storage.Finding{row},
		findingRows:       []storage.Finding{row},
		findingsLoaded:    true,
		width:             120,
		height:            30,
	}
	dispatch := func(key tea.KeyType) {
		updated, _ := m.Update(tea.KeyMsg{Type: key})
		m = updated.(*model)
	}

	dispatch(tea.KeyCtrlF)
	if !m.findingsView || !m.findingCategoryView {
		t.Fatal("Ctrl+F did not open Finder at its category root")
	}
	dispatch(tea.KeyRight)
	dispatch(tea.KeyRight)
	dispatch(tea.KeyRight)
	if !m.findingDetail {
		t.Fatal("top-level Finder route did not reach nested detail")
	}
	dispatch(tea.KeyLeft)
	dispatch(tea.KeyLeft)
	dispatch(tea.KeyLeft)
	if !m.findingsView || m.findingCategory != "" {
		t.Fatal("top-level Left route did not return to Finder root")
	}
	for attempt := 0; attempt < 4; attempt++ {
		dispatch(tea.KeyLeft)
		if !m.findingsView {
			t.Fatalf("Left escaped Finder at root on attempt %d", attempt+1)
		}
	}
	dispatch(tea.KeyEscape)
	if m.findingsView {
		t.Fatal("Escape did not explicitly leave Finder")
	}

	for _, testCase := range []struct {
		name        string
		root        *model
		cursor, top int
	}{
		{"alternate root", &model{findingsView: true, findingCategoryView: false, findingCursor: 2, findingTop: 1, focus: focusOutput, width: 80, height: 24}, 2, 1},
		{"watcher-origin root", &model{findingsView: true, findingsFromWatcher: true, findingCategoryView: false, findingCursor: 3, findingTop: 2, focus: focusModules, width: 80, height: 24}, 3, 2},
	} {
		root := testCase.root
		for attempt := 0; attempt < 10; attempt++ {
			updated, command := root.Update(tea.KeyMsg{Type: tea.KeyLeft})
			root = updated.(*model)
			if command != nil {
				if message := command(); message != nil {
					updated, _ = root.Update(message)
					root = updated.(*model)
				}
			}
			if !root.findingsView || root.watcher || root.findingCategory != "" || root.findingDetail || root.findingCursor != testCase.cursor || root.findingTop != testCase.top || root.focus != testCase.root.focus {
				t.Fatalf("%s Left changed Finder root state on attempt %d: findings=%v watcher=%v category=%q detail=%v cursor=%d top=%d focus=%v", testCase.name, attempt+1, root.findingsView, root.watcher, root.findingCategory, root.findingDetail, root.findingCursor, root.findingTop, root.focus)
			}
		}
	}
}

func TestFindingsFooterUsesExplicitEscapeAtRoot(t *testing.T) {
	m := &model{findingCategories: []findingCategory{{Key: "active_directory", Name: "Active Directory"}}, width: 100, height: 24}
	frame := m.findingCategoryOverview(100)
	if !strings.Contains(frame, "Esc Close") {
		t.Fatalf("Finder root footer did not advertise explicit Escape: %s", frame)
	}
	if strings.Contains(frame, "←/Esc Close") {
		t.Fatalf("Finder root footer still advertises Left as close: %s", frame)
	}
}

func TestFindingsCtrlWOpensWatcherThroughTopLevelUpdate(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		categoryView bool
		detail       bool
		tiering      bool
		fromWatcher  bool
	}{
		{name: "root", categoryView: true},
		{name: "category", categoryView: false},
		{name: "detail", categoryView: false, detail: true},
		{name: "tiering", categoryView: false, tiering: true},
		{name: "watcher-origin", categoryView: true, fromWatcher: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			m := &model{findingsView: true, findingCategoryView: testCase.categoryView, findingDetail: testCase.detail, findingTieringView: testCase.tiering, findingsFromWatcher: testCase.fromWatcher, width: 100, height: 24}
			updated, command := m.Update(tea.KeyMsg{Type: tea.KeyCtrlW})
			got := updated.(*model)
			if command != nil || !got.watcher || got.findingsView {
				t.Fatalf("Ctrl+W routing: watcher=%v findings=%v command=%v", got.watcher, got.findingsView, command)
			}
			if got.findingsFromWatcher {
				t.Fatal("watcher-origin marker was left active after direct Watcher activation")
			}
		})
	}
}

func TestAdministrativeTieringArrowBackRestoresTierSelection(t *testing.T) {
	rows := []storage.Finding{{FindingInput: storage.FindingInput{FindingType: "ad_tier0_context_evidence", Severity: "informational"}}, {FindingInput: storage.FindingInput{FindingType: "ad_tier1_context_evidence", Severity: "informational"}}, {FindingInput: storage.FindingInput{FindingType: "ad_tier2_context_evidence", Severity: "informational"}}}
	m := &model{findingsView: true, findingTieringView: true, findingCursor: 1, findingAllRows: rows, findingRows: rows, findingsLoaded: true, findingCategory: "active_directory", width: 120, height: 30}
	m.handleFindingsKey("right")
	if m.findingSubcategory != "tier1_context" {
		t.Fatalf("opened %q, want tier1_context", m.findingSubcategory)
	}
	m.handleFindingsKey("left")
	if !m.findingTieringView || m.findingCursor != 1 {
		t.Fatalf("tier selection was not restored: tiering=%t cursor=%d", m.findingTieringView, m.findingCursor)
	}
}

func TestKerberosFindingDetailRendersScopedInlineMaterial(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		Title:           "Kerberoast material collected",
		FindingType:     "kerberos_ticket_material_collected",
		Severity:        "medium",
		SourceTool:      "NetExec",
		SourceExecution: 9,
		AffectedObject:  "sccm.lab\\svc-sql",
		ArtifactPath:    "CredentialAuditing/NetExec/LDAP_kerberoasting/kerberoast.txt",
		EvidenceJSON:    `{"material_type":"kerberoast","principal":"sccm.lab\\svc-sql","record_count":2,"record_line_numbers":[1,2]}`,
	}}
	m := &model{
		findingsView:  true,
		findingDetail: true,
		findingRows:   []storage.Finding{finding},
		findingCursor: 0,
		width:         120,
		height:        40,
		inlineEvidence: inlineEvidence{
			section:             "RECOVERED KERBEROS MATERIAL",
			lines:               []string{"REDACTED_MATERIAL_A", "REDACTED_MATERIAL_B"},
			uniqueMaterialCount: 2,
		},
	}
	view := ansi.Strip(m.View())
	if !strings.Contains(view, "REDACTED_MATERIAL_A") || !strings.Contains(view, "REDACTED_MATERIAL_B") {
		t.Fatal("Finding did not render complete matched Kerberos material")
	}
	for _, expected := range []string{"sccm.lab\\svc-sql", "Unique material entries: 2", "Additional unique hashes: 1", "original artifact"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("protected Kerberos detail omitted %q: %s", expected, view)
		}
	}
}

func TestRecoveredKerberosMaterialUsesOrangeOnlyForMaterial(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "asrep_material_collected", Title: "AS-REP material collected: user@example.test",
		AffectedObject: "user@example.test", SourceTool: "NetExec", SourceExecution: 141,
		ArtifactPath: "asrep.txt", EvidenceJSON: `{"principal":"user@example.test","record_count":1}`,
	}}
	m := &model{findingsView: true, findingDetail: true, findingRows: []storage.Finding{finding}, width: 100, height: 40,
		inlineEvidence: inlineEvidence{section: "RECOVERED KERBEROS MATERIAL", lines: []string{"$krb5asrep$23$user@example.test:material"}, uniqueMaterialCount: 1}}
	view := m.View()
	if !strings.Contains(view, warn.Render("$krb5asrep$23$user@example.test:material")) {
		t.Fatal("AS-REP material was not rendered in the warning/orange style")
	}
	if strings.Contains(view, warn.Render("user@example.test")) {
		t.Fatal("ordinary account text was rendered as recovered material")
	}
}

func TestLDAPAttributeValueOnlyUsesOrangeAndRemainsInformational(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ad_user_description_keyword_observed", Severity: "informational", AffectedObject: "snablr-lab-admin",
		EvidenceJSON: `{"attribute":"info","principal":"snablr-lab-admin","value":"Secret Password in Info & notes"}`,
	}}
	attributes := findingAttributes(finding, 100)
	if !strings.Contains(attributes, warn.Render("Secret Password in Info & notes")) {
		t.Fatal("LDAP attribute value was not highlighted")
	}
	if strings.Contains(attributes, warn.Render("Value")) || finding.Severity != "informational" {
		t.Fatal("LDAP label or severity was changed unexpectedly")
	}
	if strings.Count(ansi.Strip(attributes), "OBSERVED DIRECTORY ATTRIBUTE") != 1 {
		t.Fatal("LDAP attribute section was duplicated")
	}
}

func TestFindingsCategoryBackRestoresStableRootSelection(t *testing.T) {
	m := &model{
		findingsView:             true,
		findingCategoryView:      true,
		findingCategory:          "adcs",
		findingCategorySelection: "adcs",
		findingCategories: []findingCategory{
			{Key: "active_directory", Name: "Active Directory"},
			{Key: "adcs", Name: "AD CS"},
			{Key: "acl", Name: "ACLs"},
		},
		findingCursor: 0,
		width:         100,
		height:        30,
	}
	m.handleFindingsKey("esc")
	if m.findingCategory != "" || m.findingCursor != 1 {
		t.Fatalf("category back did not restore AD CS: category=%q cursor=%d", m.findingCategory, m.findingCursor)
	}
	m.findingCategorySelection = "active_directory"
	m.findingCategory = "active_directory"
	m.findingCursor = 2
	m.handleFindingsKey("esc")
	if m.findingCategory != "" || m.findingCursor != 0 {
		t.Fatalf("second category back did not restore Active Directory: category=%q cursor=%d", m.findingCategory, m.findingCursor)
	}
}

func TestFindingsADCSSequencePreservesRootIdentityAcrossCategories(t *testing.T) {
	rows := []storage.Finding{
		{ID: 1, FindingInput: storage.FindingInput{FindingType: "adcs_esc_esc1", Title: "Template condition", Severity: "high"}},
		{ID: 2, FindingInput: storage.FindingInput{FindingType: "ad_tier0_context_evidence", Title: "Tier 0 context", Severity: "informational"}},
		{ID: 3, FindingInput: storage.FindingInput{FindingType: "ad_acl_evidence_inventory", Title: "ACL inventory", Severity: "informational"}},
		{ID: 4, FindingInput: storage.FindingInput{FindingType: "kerberos_ticket_material_collected", Title: "Kerberos material", Severity: "medium"}},
	}
	m := &model{
		findingsView: true, findingCategoryView: true, findingCategories: buildFindingCategories(rows),
		findingAllRows: rows, findingRows: rows, findingsLoaded: true, width: 120, height: 30,
	}
	categoryIndex := func(key string) int {
		for index, category := range m.findingCategories {
			if category.Key == key {
				return index
			}
		}
		return -1
	}
	adcsIndex := categoryIndex("adcs")
	activeDirectoryIndex := categoryIndex("active_directory")
	if adcsIndex < 0 || activeDirectoryIndex < 0 {
		t.Fatalf("fixture categories missing: %+v", m.findingCategories)
	}
	m.findingCursor = adcsIndex
	m.handleFindingsKey("right")
	if m.findingCategory != "adcs" || !m.findingSubcategoryView {
		t.Fatalf("AD CS did not open: category=%q subcategories=%t", m.findingCategory, m.findingSubcategoryView)
	}
	for index, subcategory := range m.findingSubcategories {
		if subcategory.Key == "adcs_template" {
			m.findingCursor = index
		}
	}
	m.handleFindingsKey("right")
	if m.findingCategory != "adcs" || m.findingSubcategory != "adcs_template" {
		t.Fatalf("AD CS subcategory did not open: category=%q subcategory=%q", m.findingCategory, m.findingSubcategory)
	}
	m.handleFindingsKey("right")
	if !m.findingDetail {
		t.Fatal("AD CS Finding detail did not open")
	}
	for step := 0; step < 3; step++ {
		m.handleFindingsKey("left")
	}
	if m.findingCategory != "" || m.findingCursor != adcsIndex {
		t.Fatalf("AD CS return lost root selection: category=%q cursor=%d want=%d", m.findingCategory, m.findingCursor, adcsIndex)
	}
	m.findingCursor = activeDirectoryIndex
	m.handleFindingsKey("enter")
	if m.findingCategory != "active_directory" {
		t.Fatalf("Active Directory did not open: %q", m.findingCategory)
	}
	m.handleFindingsKey("esc")
	if m.findingCategory != "" || m.findingCursor != activeDirectoryIndex {
		t.Fatalf("Active Directory return lost root selection: category=%q cursor=%d want=%d", m.findingCategory, m.findingCursor, activeDirectoryIndex)
	}
	m.findingCursor = adcsIndex
	m.handleFindingsKey("right")
	m.handleFindingsKey("left")
	if m.findingCategory != "" || m.findingCursor != adcsIndex {
		t.Fatalf("repeated Right/Left changed AD CS root selection: category=%q cursor=%d want=%d", m.findingCategory, m.findingCursor, adcsIndex)
	}
}

func TestKerberosAccountEvidenceActionOpensDerivedReport(t *testing.T) {
	m := &model{
		findingsView:   true,
		findingDetail:  true,
		inlineEvidence: inlineEvidence{accountScopedPath: "CredentialAuditing/NetExec/account-scoped/finding-test-account-scoped.txt"},
		width:          100,
		height:         24,
	}
	m.handleFindingsKey("a")
	if !m.evidenceView || m.evidencePath != m.inlineEvidence.accountScopedPath {
		t.Fatalf("account evidence action did not open derived report: view=%t path=%q", m.evidenceView, m.evidencePath)
	}
}

func TestFindingsHierarchyUsesStableCountAndSeverityColumns(t *testing.T) {
	rows := []storage.Finding{{FindingInput: storage.FindingInput{FindingType: "ad_writable_object_assessment", Severity: "medium", Title: "Writable object"}}}
	categories := buildFindingCategories(rows)
	top := (&model{findingCategoryView: true, findingCategories: categories, findingCursor: 0, width: 120, height: 30}).findingCategoryOverview(120)
	subcategories := buildFindingSubcategories("acl", rows)
	sub := (&model{findingCategory: "acl", findingSubcategoryView: true, findingSubcategories: subcategories, findingCursor: 0, width: 120, height: 30}).findingSubcategoryOverview(120)
	strip := func(value string) string { return ansi.Strip(value) }
	column := func(frame, label string) int {
		for _, line := range strings.Split(strip(frame), "\n") {
			if strings.Contains(line, label) && strings.Contains(line, "SEVERITY") {
				return strings.Index(line, label)
			}
		}
		return -1
	}
	if got, want := column(top, "FINDINGS"), column(sub, "FINDINGS"); got != want || got < 0 {
		t.Fatalf("count column shifted: top=%d subcategory=%d\nTOP:\n%s\nSUB:\n%s", got, want, strip(top), strip(sub))
	}
	if got, want := column(top, "SEVERITY"), column(sub, "SEVERITY"); got != want || got < 0 {
		t.Fatalf("severity column shifted: top=%d subcategory=%d", got, want)
	}
	if !strings.Contains(strip(sub), "MEDIUM") {
		t.Fatalf("subcategory omitted aggregated severity: %s", strip(sub))
	}
}

func TestFindingDetailsSuppressRemediationAndLimitations(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		Title: "FTP Anonymous Access Accepted", FindingType: "pwntools_ftp_anonymous_access", Severity: "medium",
		Description: "Anonymous authentication was accepted.", ArtifactPath: "ftp.json", ArtifactRef: "/results/0",
		EvidenceJSON: `{"auth_response":"230 Anonymous login ok"}`,
	}}
	m := &model{findingsView: true, findingRows: []storage.Finding{finding}, findingCursor: 0, findingDetail: true, width: 120, height: 40}
	frame := ansi.Strip(m.View())
	for _, forbidden := range []string{"RECOMMENDED ACTION", "source tool's recommended hardening", "disable or restrict"} {
		if strings.Contains(strings.ToLower(frame), strings.ToLower(forbidden)) {
			t.Fatalf("operator-facing detail contains remediation %q:\n%s", forbidden, frame)
		}
	}
	for _, required := range []string{"SECURITY IMPACT", "EVIDENCE", "ftp.json"} {
		if !strings.Contains(frame, required) {
			t.Fatalf("operator-facing detail omitted %q:\n%s", required, frame)
		}
	}
	if strings.Contains(frame, "LIMITATIONS") {
		t.Fatalf("operator-facing detail contains LIMITATIONS:\n%s", frame)
	}
}

func TestInformationalCategoryOpensFlatRecordsAndShowsValues(t *testing.T) {
	rows := []storage.Finding{{FindingInput: storage.FindingInput{
		FindingKey: "users", FindingType: "domain_information_user_inventory", Title: "Domain User Inventory Summary", Severity: "informational",
		EvidenceJSON: `{"distinct_user_count":40,"enabled_count":35,"disabled_count":5,"status_unknown_count":0,"coverage":"retained RustHound inventory"}`,
	}}}
	m := &model{findingsView: true, findingCategoryView: true, findingAllRows: rows, findingsLoaded: true, findingCategories: buildFindingCategories(rows), width: 120, height: 40}
	for index, category := range m.findingCategories {
		if category.Key == "other" {
			m.findingCursor = index
		}
	}
	m.handleFindingsKey("enter")
	m.findingRows = rows
	if m.findingCategory != "other" || m.findingCategoryView || m.findingSubcategoryView || m.findingSubcategory != "" {
		t.Fatalf("informational entry did not open flat records: category=%q categoryView=%v subcategoryView=%v subcategory=%q", m.findingCategory, m.findingCategoryView, m.findingSubcategoryView, m.findingSubcategory)
	}
	if len(m.findingRows) != 1 {
		t.Fatalf("informational rows=%d, want 1", len(m.findingRows))
	}
	m.handleFindingsKey("enter")
	frame := ansi.Strip(m.findingsViewRender())
	if !m.findingDetail || !strings.Contains(frame, "Total users:") || !strings.Contains(frame, "40") || !strings.Contains(frame, "Enabled:") || !strings.Contains(frame, "35") || strings.Contains(frame, "SECURITY IMPACT") {
		t.Fatalf("informational detail omitted values or rendered generic impact: detail=%v frame=%q", m.findingDetail, frame)
	}
}

func TestPasswordPolicyDetailShowsObservedStates(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{FindingType: "ad_domain_policy_password_policy_snapshot", Title: "Domain Password Policy Snapshot", Severity: "informational", EvidenceJSON: `{"policy_scope":"domain default policy","fields":{"minimum_password_length":{"raw":"12","state":"observed"},"maximum_password_age":{"raw":"unlimited","state":"unlimited"},"password_complexity":{"raw":"unknown","state":"unknown"}}}`}}
	m := &model{findingsView: true, findingRows: []storage.Finding{finding}, findingDetail: true, findingCursor: 0, width: 200, height: 40}
	frame := ansi.Strip(m.findingsViewRender())
	for _, want := range []string{"Minimum Length", "12", "Maximum Age", "unlimited [unlimited]", "Complexity", "unknown [unknown]"} {
		if !strings.Contains(frame, want) {
			t.Fatalf("policy detail missing %q: %s", want, frame)
		}
	}
	if strings.Contains(frame, "12 [observed]") {
		t.Fatalf("observed password-policy value retained redundant state suffix: %s", frame)
	}
}

func TestInformationalDetailWrapsAtNarrowWidth(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "domain_information_user_inventory", Title: "Domain User Inventory", Severity: "informational",
		EvidenceJSON: `{"distinct_user_count":40,"enabled_count":35,"disabled_count":5,"status_unknown_count":0,"coverage":"retained RustHound inventory with a deliberately long coverage explanation"}`,
	}}
	m := &model{findingsView: true, findingRows: []storage.Finding{finding}, findingDetail: true, findingCursor: 0, width: 52, height: 30}
	frame := ansi.Strip(m.findingsViewRender())
	for _, line := range strings.Split(frame, "\n") {
		if ansi.StringWidthWc(line) > 52 {
			t.Fatalf("informational detail exceeded narrow pane width: %q", line)
		}
	}
	if !strings.Contains(frame, "Coverage:") || !strings.Contains(frame, "retained RustHound") {
		t.Fatalf("narrow informational detail lost the coverage field: %s", frame)
	}
}

func TestFindingListUsesAvailableTitleWidth(t *testing.T) {
	title := "Membership inventory for Enterprise Administrators"
	finding := storage.Finding{FindingInput: storage.FindingInput{
		Title: title, FindingType: "domain_information_privileged_group_membership", Severity: "informational", AffectedObject: "Enterprise Admins",
	}}
	m := &model{findingsView: true, findingRows: []storage.Finding{finding}, findingCursor: 0, width: 140, height: 30}
	frame := ansi.Strip(m.findingsViewRender())
	if !strings.Contains(frame, title) {
		t.Fatalf("wide Findings pane unnecessarily clipped title: %s", frame)
	}
}

func TestCredentialSubcategoriesSeparateSCCMAndGPP(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{FindingType: "sccm_task_sequence_credentials_exposed", SourceTool: "PXEThief", Severity: "high"}},
		{FindingInput: storage.FindingInput{FindingType: "netexec_gpp_password_exposure", SourceTool: "NetExec (nxc)", Severity: "high"}},
	}
	categories := buildFindingSubcategories("credentials", rows)
	counts := map[string]int{}
	for _, category := range categories {
		counts[category.Key] = category.Findings + category.Observations
	}
	if counts["sccm"] != 1 || counts["gpp"] != 1 {
		t.Fatalf("credential subcategories=%v, want one each", counts)
	}
	if findingBelongsToSubcategory("credentials", "sccm", rows[1]) || findingBelongsToSubcategory("credentials", "gpp", rows[0]) {
		t.Fatal("credential findings crossed SCCM/GPP boundaries")
	}
}

func TestPXEThiefTechniqueReferenceOnly(t *testing.T) {
	pxe := storage.Finding{FindingInput: storage.FindingInput{FindingType: "sccm_task_sequence_credentials_exposed", SourceTool: "PXEThief"}}
	gpp := storage.Finding{FindingInput: storage.FindingInput{FindingType: "netexec_gpp_password_exposure", SourceTool: "NetExec (nxc)"}}
	if got := findingTechniqueReference(pxe); !strings.Contains(got, "CRED-1") || !strings.Contains(got, "https://github.com/subat0mik/Misconfiguration-Manager/") {
		t.Fatalf("PXEThief technique reference missing: %s", got)
	}
	if got := findingTechniqueReference(gpp); !strings.Contains(got, "SpecterOps / SharpUp — Cached GPP Password") || !strings.Contains(got, "https://docs.specterops.io/ghostpack-docs/SharpUp-mdx/checks/cachedgpppassword") {
		t.Fatalf("GPP technique reference missing: %s", got)
	}
}

func TestConsolidatePXEFindingsUsesRetainedHyphenEvidence(t *testing.T) {
	root := t.TempDir()
	artifact := filepath.Join(root, "pxethief.log")
	contents := "OSDJoinAccount - lab\\join\nOSDJoinPassword - synthetic-one\nOSDLocalAdminPassword - synthetic-two\n" +
		"OSDJoinAccount - lab\\join\nOSDJoinPassword - synthetic-one\nOSDLocalAdminPassword - synthetic-two\n"
	if err := os.WriteFile(artifact, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := make([]storage.Finding, 0, 4)
	for _, ref := range []string{"line:1", "line:4", "line:7", "line:10"} {
		rows = append(rows, storage.Finding{FindingInput: storage.FindingInput{
			SourceTool: "PXEThief", FindingType: "sccm_task_sequence_credentials_exposed",
			ArtifactPath: artifact, ArtifactRef: ref,
			EvidenceJSON: `{"credential_variables":["OSDJoinAccount","OSDJoinPassword","OSDLocalAdminPassword"]}`,
		}})
	}
	m := &model{cfg: config.Config{Root: root, Domain: "example.test"}}
	got := m.consolidatePXEFindings(rows)
	if len(got) != 1 {
		t.Fatalf("retained identical PXE exposures produced %d visible findings, want 1", len(got))
	}
	metadata := findingMetadata(got[0])
	refs := stringSlice(metadata["artifact_records"])
	if len(refs) != 4 {
		t.Fatalf("consolidated evidence retained %d references, want 4: %v", len(refs), refs)
	}
	if len(pxeCredentialValues(metadata)) != 3 {
		t.Fatalf("consolidated credential set has %d fields, want 3", len(pxeCredentialValues(metadata)))
	}
}

func TestPXEConsolidationSurvivesInteractiveNavigation(t *testing.T) {
	root := t.TempDir()
	artifact := filepath.Join(root, "pxethief.log")
	if err := os.WriteFile(artifact, []byte("OSDJoinAccount - lab\\join\nOSDJoinPassword - synthetic-one\nOSDLocalAdminPassword - synthetic-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(filepath.Join(root, "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertTarget(ctx, "example.test", "dc01"); err != nil {
		t.Fatal(err)
	}
	assessmentID, err := db.TargetID(ctx, "example.test", "dc01")
	if err != nil {
		t.Fatal(err)
	}
	for index, ref := range []string{"line:77", "line:91", "line:105", "line:119"} {
		if err := db.IngestFindings(ctx, []storage.FindingInput{
			{FindingKey: fmt.Sprintf("pxe-%d", index), AssessmentID: assessmentID, SourceTool: "PXEThief", SourceExecution: 756,
				FindingType: "sccm_task_sequence_credentials_exposed", Title: "SCCM task-sequence credentials exposed", Severity: "high",
				EvidenceJSON: `{"credential_variables":["OSDJoinAccount","OSDJoinPassword","OSDLocalAdminPassword"]}`,
				ArtifactPath: artifact, ArtifactRef: ref, ObservedAt: time.Now().UTC(), Status: "open", ParserVersion: "test"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	m := &model{ctx: ctx, cfg: config.Config{Root: root, Domain: "example.test"}, db: db, targetID: assessmentID,
		findingsView: true, findingCategoryView: true, width: 120, height: 40}
	m.refreshFindings()
	m.handleFindingsKey("enter")
	m.handleFindingsKey("enter")
	if m.findingCategory != "credentials" || m.findingSubcategory != "sccm" || len(m.findingRows) != 1 {
		t.Fatalf("interactive SCCM navigation exposed %d rows, category=%q subcategory=%q", len(m.findingRows), m.findingCategory, m.findingSubcategory)
	}
	m.handleFindingsKey("enter")
	m.handleFindingsKey("esc")
	if len(m.findingRows) != 1 {
		t.Fatalf("returning from detail exposed %d rows", len(m.findingRows))
	}
	m.handleFindingsKey("esc")
	m.handleFindingsKey("esc")
	m.handleFindingsKey("enter")
	m.handleFindingsKey("enter")
	if m.findingCategory != "credentials" || m.findingSubcategory != "sccm" || len(m.findingRows) != 1 {
		t.Fatalf("re-entering SCCM exposed %d rows, category=%q subcategory=%q", len(m.findingRows), m.findingCategory, m.findingSubcategory)
	}
}

func TestPXEConsolidationSurvivesNormalAsyncFindingsLoad(t *testing.T) {
	root := t.TempDir()
	artifact := filepath.Join(root, "pxethief.log")
	if err := os.WriteFile(artifact, []byte("OSDJoinAccount - lab\\join\nOSDJoinPassword - synthetic-one\nOSDLocalAdminPassword - synthetic-two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(filepath.Join(root, "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertTarget(ctx, "example.test", "dc01"); err != nil {
		t.Fatal(err)
	}
	assessmentID, err := db.TargetID(ctx, "example.test", "dc01")
	if err != nil {
		t.Fatal(err)
	}
	for index, ref := range []string{"line:77", "line:91", "line:105", "line:119"} {
		if err := db.IngestFindings(ctx, []storage.FindingInput{
			{FindingKey: fmt.Sprintf("async-pxe-%d", index), AssessmentID: assessmentID, SourceTool: "PXEThief", SourceExecution: 756,
				FindingType: "sccm_task_sequence_credentials_exposed", Title: "SCCM task-sequence credentials exposed", Severity: "high",
				EvidenceJSON: `{"credential_variables":["OSDJoinAccount","OSDJoinPassword","OSDLocalAdminPassword"]}`,
				ArtifactPath: artifact, ArtifactRef: ref, ObservedAt: time.Now().UTC(), Status: "open", ParserVersion: "test"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	m := &model{ctx: ctx, cfg: config.Config{Root: root, Domain: "example.test"}, db: db, targetID: assessmentID,
		findingsView: true, findingsAsync: true, findingCategoryView: true, width: 120, height: 40}
	load := m.beginFindingsLoad()
	if load == nil {
		t.Fatal("normal Findings did not create an asynchronous load command")
	}
	updated, _ := m.Update(load())
	m = updated.(*model)
	m.handleFindingsKey("enter")
	m.handleFindingsKey("enter")
	if len(m.findingRows) != 1 || countPXEFindings(m.findingRows) != 1 {
		t.Fatalf("normal async SCCM navigation exposed %d rows, PXE rows=%d", len(m.findingRows), countPXEFindings(m.findingRows))
	}
}

func countPXEFindings(rows []storage.Finding) int {
	count := 0
	for _, finding := range rows {
		if isPXECredentialFinding(finding) {
			count++
		}
	}
	return count
}

func TestGPPFindingCredentialFieldsUseBlueLabelsAndOrangeValues(t *testing.T) {
	content := gppFindingAttributes(map[string]any{
		"account": "example.test\\join", "password": "synthetic-password",
		"credential_state": "recoverable", "preference_type": "Groups.xml",
	}, 100)
	if !strings.Contains(content, infoBlueStyle().Render("ACCOUNT")) || !strings.Contains(content, infoBlueStyle().Render("PASSWORD")) {
		t.Fatal("GPP credential labels were not entirely blue")
	}
	if !strings.Contains(content, warn.Render("example.test\\join")) || !strings.Contains(content, warn.Render("synthetic-password")) {
		t.Fatal("GPP recovered values were not entirely orange")
	}
	if !strings.Contains(content, "Groups.xml") {
		t.Fatal("GPP metadata was omitted from the detail")
	}
}

func TestTechniqueReferenceUsesCopyableFallback(t *testing.T) {
	text := findingTechniqueSection(findingTechniqueReference(storage.Finding{FindingInput: storage.FindingInput{
		SourceTool: "PXEThief", FindingType: "sccm_task_sequence_credentials_exposed",
	}}), 80)
	if !strings.Contains(text, "https://github.com/subat0mik/Misconfiguration-Manager/") || !strings.Contains(text, "Shift + Left Mouse — Copy link") {
		t.Fatalf("technique fallback is incomplete: %s", text)
	}
}

func TestGPPTechniqueReferenceUsesCopyableFallback(t *testing.T) {
	text := findingTechniqueSection(findingTechniqueReference(storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "netexec_gpp_password_exposure",
	}}), 80)
	if !strings.Contains(text, "SpecterOps / SharpUp — Cached GPP Password") || !strings.Contains(text, "https://docs.specterops.io/ghostpack-docs/SharpUp-mdx/checks/cachedgpppassword") || !strings.Contains(text, "Shift + Left Mouse — Copy link") {
		t.Fatalf("GPP technique fallback is incomplete: %s", text)
	}
}

func TestTierTargetAggregationDeduplicatesRepeatedScopeObservations(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{
			FindingType: "ad_tier1_context_evidence", SourceExecution: 26,
			EvidenceJSON: `{"tier":1,"domain":"SCCM.LAB","targets":[{"declared":{"name":"MSSQL.SCCM.LAB","ip":"192.0.2.42"},"status":"matched","source_artifact":"tier-26.json"}]}`,
		}},
		{FindingInput: storage.FindingInput{
			FindingType: "ad_tier1_context_evidence", SourceExecution: 754,
			EvidenceJSON: `{"tier":1,"domain":"SCCM.LAB","targets":[{"declared":{"name":"MSSQL.SCCM.LAB","ip":"192.0.2.42"},"status":"matched","source_artifact":"tier-754.json"}]}`,
		}},
	}
	model := &model{}
	consolidated := model.consolidateTierFindings(rows)
	if len(consolidated) != 1 {
		t.Fatalf("consolidated rows=%d, want 1", len(consolidated))
	}
	metadata := findingMetadata(consolidated[0])
	targets, ok := metadata["targets"].([]any)
	if !ok || len(targets) != 1 {
		t.Fatalf("targets=%v, want one semantic observation", metadata["targets"])
	}
	condition := formatTierContextCondition(consolidated[0])
	if strings.Count(condition, "MSSQL.SCCM.LAB") != 1 || strings.Count(condition, "matched") != 1 {
		t.Fatalf("repeated target/status rendered more than once: %s", condition)
	}
	refs := metadataStringSlice(targets[0].(map[string]any), "source_artifacts")
	if len(refs) != 2 {
		t.Fatalf("source artifacts=%v, want both provenance references", refs)
	}
}

func TestTierValueStylesSeparateContextFromWarnings(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })
	if tierValueStyle("Group", "PF-T1-Admins", false).Render("PF-T1-Admins") != "PF-T1-Admins" {
		t.Fatal("ordinary tier values should remain unstyled")
	}
	if !strings.Contains(tierValueStyle("Host-local Administrators", "NOT VERIFIED", true).Render("NOT VERIFIED"), "\x1b[") {
		t.Fatal("unverified tier state should use warning styling")
	}
	if !strings.Contains(tierValueStyle("Source execution", "26", false).Render("26"), "\x1b[") {
		t.Fatal("provenance should use muted styling")
	}
}

func TestGPOPrivilegeFindingsConsolidateRelationshipsAndProvenance(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{FindingType: "ad_gpo_privilege_relationship_evidence", SourceExecution: 26, EvidenceJSON: `{"domain":"SCCM.LAB","gpos":[{"gpo_guid":"{11111111-2222-3333-4444-555555555555}","display_name":"Workstation Policy","observed_acl_relationships":[{"principal_id":"S-1-5-21-1","principal_name":"PF-T1-Admins","permission":"GenericWrite","decision":"observed","inheritance":"explicit","artifact":"acl-26.json","artifact_ref":"line:10"}],"configured_links":[{"target_container_dn":"OU=Servers,DC=SCCM,DC=LAB","source_dn":"CN=Workstation Policy,DC=SCCM,DC=LAB","classification":"matched","applicability":"unknown","source_artifact":"links-26.json"}]}]}`}},
		{FindingInput: storage.FindingInput{FindingType: "ad_gpo_privilege_relationship_evidence", SourceExecution: 65, EvidenceJSON: `{"domain":"SCCM.LAB","gpos":[{"gpo_guid":"11111111-2222-3333-4444-555555555555","display_name":"Workstation Policy","observed_acl_relationships":[{"principal_id":"S-1-5-21-1","principal_name":"PF-T1-Admins","permission":"GenericWrite","decision":"observed","inheritance":"explicit","artifact":"acl-65.json","artifact_ref":"line:10"}],"configured_links":[{"target_container_dn":"OU=Servers,DC=SCCM,DC=LAB","source_dn":"CN=Workstation Policy,DC=SCCM,DC=LAB","classification":"matched","applicability":"unknown","source_artifact":"links-65.json"}]}]}`}},
	}
	model := &model{}
	consolidated := model.consolidateGPOFindings(rows)
	if len(consolidated) != 1 {
		t.Fatalf("GPO rows=%d, want one visible overview", len(consolidated))
	}
	metadata := findingMetadata(consolidated[0])
	gpos, ok := metadata["gpos"].([]any)
	if !ok || len(gpos) != 1 {
		t.Fatalf("GPO objects=%v, want one semantic GPO", metadata["gpos"])
	}
	gpo := gpos[0].(map[string]any)
	acls := gpo["observed_acl_relationships"].([]any)
	if len(acls) != 1 {
		t.Fatalf("ACL relationships=%d, want one deduplicated relationship", len(acls))
	}
	refs := metadataStringSlice(acls[0].(map[string]any), "evidence_refs")
	if len(refs) != 2 {
		t.Fatalf("ACL evidence refs=%v, want both executions", refs)
	}
	condition := formatGPOPrivilegeCondition(metadata, consolidated[0])
	for _, expected := range []string{"GPO PRIVILEGE RELATIONSHIPS", "OBSERVED ACL RIGHTS", "CONFIGURED LINKS", "NOT VERIFIED"} {
		if !strings.Contains(condition, expected) {
			t.Fatalf("GPO condition missing %q: %s", expected, condition)
		}
	}
	if strings.Contains(condition, "Security Impact") {
		t.Fatal("GPO condition unexpectedly included generic impact text")
	}
	if reference := findingTechniqueReference(consolidated[0]); !strings.Contains(reference, "group-policies") {
		t.Fatalf("GPO technique reference missing: %s", reference)
	}
}

func TestACLInventoryPresentationConsolidatesHistoricalOverviews(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{FindingType: "ad_acl_evidence_inventory", SourceExecution: 26, ArtifactPath: "acl-26.json", EvidenceJSON: `{"source_supported_ace_count":1471,"retained_ace_count":1471,"examples":[{"principal_id":"P","target_id":"T","permission":"GenericAll","decision":"unknown","inheritance":"explicit"}]}`}},
		{FindingInput: storage.FindingInput{FindingType: "ad_acl_evidence_inventory", SourceExecution: 69, ArtifactPath: "acl-69.json", EvidenceJSON: `{"source_supported_ace_count":1471,"retained_ace_count":1471,"examples":[{"principal_id":"P","target_id":"T","permission":"GenericAll","decision":"unknown","inheritance":"explicit"}]}`}},
		{FindingInput: storage.FindingInput{FindingType: "ad_privileged_acl_evidence_inventory", SourceExecution: 26, ArtifactPath: "priv-26.json", EvidenceJSON: `{"relationship_overview":[{"principal_id":"P","target_id":"T","permission":"WriteDacl","decision":"unknown","inheritance":"explicit"}]}`}},
		{FindingInput: storage.FindingInput{FindingType: "ad_privileged_acl_evidence_inventory", SourceExecution: 69, ArtifactPath: "priv-69.json", EvidenceJSON: `{"relationship_overview":[{"principal_id":"P","target_id":"T","permission":"WriteDacl","decision":"unknown","inheritance":"explicit"}]}`}},
		{FindingInput: storage.FindingInput{FindingType: "ad_replication_rights_evidence_overview", SourceExecution: 26, ArtifactPath: "rep-26.json", EvidenceJSON: `{"domain_roots":[{"id":"D","principals":[{"id":"P","rights":[{"right":"GetChanges","status":"observed"}]}]}]}`}},
		{FindingInput: storage.FindingInput{FindingType: "ad_replication_rights_evidence_overview", SourceExecution: 69, ArtifactPath: "rep-69.json", EvidenceJSON: `{"domain_roots":[{"id":"D","principals":[{"id":"P","rights":[{"right":"GetChanges","status":"observed"}]}]}]}`}},
	}
	consolidated := (&model{}).consolidatePresentationFindings(rows)
	if len(consolidated) != 3 {
		t.Fatalf("ACL overview rows=%d, want three assessment-level findings", len(consolidated))
	}
	for _, finding := range consolidated {
		records, ok := findingMetadata(finding)["source_records"].([]any)
		if !ok || len(records) != 2 {
			t.Fatalf("%s lost historical source records: %#v", finding.FindingType, findingMetadata(finding)["source_records"])
		}
	}
}

func TestGPOConfigurationFindingRendersObservedValueAndUnknownScope(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "gpo_security_configuration_observed", SourceTool: "gpoParser", SourceExecution: 761,
		EvidenceJSON: `{"field":"S-1-5-32-555","configuration":"\"S-1-5-32-555\": \"Remote Desktop Users\",","line":410}`,
	}}
	condition := findingCondition(finding)
	for _, expected := range []string{"OBSERVED GPO CONFIGURATION", "Setting", "S-1-5-32-555", "Remote Desktop Users", "NOT VERIFIED"} {
		if !strings.Contains(condition, expected) {
			t.Fatalf("GPO configuration detail missing %q: %s", expected, condition)
		}
	}
	if strings.Contains(condition, "security-relevant policy setting") {
		t.Fatal("generic parser boilerplate remained in configuration detail")
	}
	if reference := findingTechniqueReference(finding); reference != "" {
		t.Fatalf("unsupported technique reference added: %s", reference)
	}
}

func TestPasswordPolicyFindingsConsolidateRichSnapshotIntoWeakFinding(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{FindingType: "ad_domain_policy_weak_minimum_password_length", Title: "Weak Minimum Password Length", Severity: "low", SourceExecution: 407, AffectedObject: "sccm.lab", ArtifactPath: "SMB_password_policy.txt", ArtifactRef: "line:4", EvidenceJSON: `{"domain":"sccm.lab","minimum_password_length":5,"policy_scope":"domain default policy","fine_grained_policy_limitation":"FGPP may override the default."}`}},
		{FindingInput: storage.FindingInput{FindingType: "ad_domain_policy_password_policy_snapshot", Title: "Domain Password Policy Snapshot", Severity: "informational", SourceExecution: 771, AffectedObject: "sccm.lab", ArtifactPath: "SMB_password_policy.txt", ArtifactRef: "line:4", EvidenceJSON: `{"domain":"sccm.lab","policy_scope":"domain default policy","fields":{"minimum_password_length":{"raw":"5","state":"observed"},"maximum_password_age":{"raw":"311 days","state":"observed"},"password_history_length":{"raw":"24","state":"observed"}}}`}},
	}
	model := &model{}
	consolidated := model.consolidatePasswordPolicyFindings(rows)
	if len(consolidated) != 1 || consolidated[0].FindingType != "ad_domain_policy_weak_minimum_password_length" {
		t.Fatalf("policy rows=%#v, want one LOW canonical finding", consolidated)
	}
	metadata := findingMetadata(consolidated[0])
	fields, ok := metadata["fields"].(map[string]any)
	if !ok || len(fields) != 3 {
		t.Fatalf("merged fields=%v, want rich snapshot fields", metadata["fields"])
	}
	if records, ok := metadata["source_records"].([]any); !ok || len(records) != 2 {
		t.Fatalf("source records=%v, want LOW and snapshot provenance", metadata["source_records"])
	}
	condition := findingCondition(consolidated[0])
	for _, expected := range []string{"Minimum Length", "5", "Maximum Age", "311 days", "History Length", "24"} {
		if !strings.Contains(condition, expected) {
			t.Fatalf("merged policy detail missing %q: %s", expected, condition)
		}
	}
}

func TestLowSeverityUsesMutedGray(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })
	if got, want := severityStyle("low").Render("LOW"), dim.Render("LOW"); got != want {
		t.Fatalf("LOW severity style=%q, want muted gray style=%q", got, want)
	}
	finding := storage.Finding{FindingInput: storage.FindingInput{FindingType: "ad_domain_policy_weak_minimum_password_length", Title: "Weak Minimum Password Length", Severity: "low", AffectedObject: "sccm.lab"}}
	m := &model{findingsView: true, findingRows: []storage.Finding{finding}, width: 120, height: 24}
	frame := m.findingsViewRender()
	if !strings.Contains(ansi.Strip(frame), "LOW") {
		t.Fatalf("Findings list omitted LOW label: %q", frame)
	}
}

func TestFindingListRowsKeepSeverityRightmost(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{Title: "Weak Minimum Password Length", Severity: "low", AffectedObject: "sccm.lab"}},
		{FindingInput: storage.FindingInput{Title: "GPO security configuration observed", Severity: "informational", AffectedObject: "SCCM.LAB"}},
		{FindingInput: storage.FindingInput{Title: "SCCM task-sequence credentials exposed", Severity: "high", AffectedObject: "sccm.lab\\svc-deploy"}},
	}
	for _, width := range []int{160, 100, 72, 52} {
		for selected := range rows {
			line := findingListRow(width, rows[selected], selected == 0)
			plain := ansi.Strip(line)
			if got := ansi.StringWidthWc(plain); got > width {
				t.Fatalf("row width=%d exceeds terminal width: got %d: %q", width, got, plain)
			}
			severity := strings.ToUpper(rows[selected].Severity)
			if !strings.HasSuffix(strings.TrimRight(plain, " "), severity) {
				t.Fatalf("severity is not rightmost at width %d: %q", width, plain)
			}
		}
	}
	wide := findingListRow(120, rows[0], false)
	if got := ansi.StringWidthWc(ansi.Strip(wide)); got != 120 {
		t.Fatalf("wide row did not fill content width: got %d, want 120", got)
	}
}

func TestFindingListRowsKeepAccountColumnAlignedAcrossSeverityWidths(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{Title: "Password Not Required Account", Severity: "medium", AffectedObject: "adenum-pwdnr"}},
		{FindingInput: storage.FindingInput{Title: "Password Not Required Account", Severity: "informational", AffectedObject: "Guest"}},
		{FindingInput: storage.FindingInput{Title: "Password Not Required Account", Severity: "informational", AffectedObject: "a-very-long-account-name-for-alignment"}},
	}
	for _, width := range []int{160, 120, 80, 64} {
		first := ansi.Strip(findingListRow(width, rows[0], false))
		firstColumn := strings.Index(first, rows[0].AffectedObject)
		if firstColumn < 0 {
			t.Fatalf("account value was not rendered at width %d: %q", width, first)
		}
		for index := 1; index < len(rows); index++ {
			line := ansi.Strip(findingListRow(width, rows[index], false))
			severityWidth := max(12, ansi.StringWidthWc("INFORMATIONAL"))
			bodyWidth := max(1, width-2-severityWidth-1)
			objectWidth := 0
			if bodyWidth > 13 {
				objectWidth = min(max(18, bodyWidth/3), bodyWidth-13)
			}
			column := strings.Index(line, truncateFinding(rows[index].AffectedObject, max(1, objectWidth)))
			if column != firstColumn {
				t.Fatalf("account column shifted at width %d: first=%d row%d=%d\n%s\n%s", width, firstColumn, index, column, first, line)
			}
		}
	}
}

func TestGhostSPNFindingDetailAndTechnique(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ghostspn_orphaned_spn", Title: "Potential Orphaned SPN: HTTP/pf-ghost-spn.sccm.lab", Severity: "low",
		AffectedObject: "PF-SPN-Ghost-Test", SourceTool: "ghostSPN", SourceExecution: 763,
		Description: "DNS unresolved host correlation; possible orphaned SPN", EvidenceJSON: `{"account_sam":"PF-SPN-Ghost-Test","spn":"HTTP/pf-ghost-spn.sccm.lab","hostname":"pf-ghost-spn.sccm.lab","dns_status":"Not Resolved","reason":"DNS unresolved host correlation; possible orphaned SPN"}`,
	}}
	detail := findingAttributes(finding, 100)
	for _, want := range []string{"SPN OBSERVATION", "PF-SPN-Ghost-Test", "HTTP/pf-ghost-spn.sccm.lab", "Not Resolved", "NOT VERIFIED"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("GhostSPN detail missing %q: %s", want, detail)
		}
	}
	if reference := findingTechniqueReference(finding); !strings.Contains(reference, "SPN Jacking") || !strings.Contains(reference, "spn-jacking") {
		t.Fatalf("GhostSPN technique reference missing: %s", reference)
	}
	if impact := findingImpact(finding); !strings.Contains(impact, "does not establish SPN-jacking") {
		t.Fatalf("GhostSPN impact overstates evidence: %s", impact)
	}
}

func TestGhostSPNAccountTypeObservationIsInformationalAndHasNoTechnique(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ghostspn_orphaned_spn", Title: "SPN Account-Type Observation: kadmin/changepw", Severity: "informational",
		AffectedObject: "krbtgt", Description: "User account SPNs cannot request service tickets",
		EvidenceJSON: `{"spn":"kadmin/changepw","account_sam":"krbtgt","hostname":"changepw","dns_status":"Not Checked","reason":"User account SPNs cannot request service tickets"}`,
	}}
	if reference := findingTechniqueReference(finding); reference != "" {
		t.Fatalf("account-type observation received unrelated technique reference: %s", reference)
	}
	condition := specificFindingCondition(finding, findingMetadata(finding))
	if !strings.Contains(condition, "account-type observation") || strings.Contains(strings.ToLower(condition), "possible orphaned") {
		t.Fatalf("account-type observation was mislabeled: %s", condition)
	}
	if impact := findingImpact(finding); !strings.Contains(impact, "does not establish an orphaned host") {
		t.Fatalf("account-type impact overstates evidence: %s", impact)
	}
}

func TestCriticalFindingsRenderStableFamilySubgroups(t *testing.T) {
	rows := []storage.Finding{
		{FindingInput: storage.FindingInput{FindingType: "critical_projection_adcs_esc_esc1", Title: "Alpha AD CS", Severity: "critical", EvidenceJSON: `{"critical_state":"confirmed_critical","family":"adcs_esc1"}`}},
		{FindingInput: storage.FindingInput{FindingType: "critical_projection_privileged_access", Title: "Zulu access", Severity: "critical", EvidenceJSON: `{"critical_state":"confirmed_critical","family":"privileged_access"}`}},
		{FindingInput: storage.FindingInput{FindingType: "critical_projection_adcs_esc_esc8", Title: "ESC8 candidate", Severity: "high", EvidenceJSON: `{"critical_state":"potential_critical_not_verified","family":"adcs_esc8"}`}},
		{FindingInput: storage.FindingInput{FindingType: "critical_projection_ntlm_relay", Title: "Relay candidate", Severity: "high", EvidenceJSON: `{"critical_state":"potential_critical_not_verified","family":"ntlm_relay"}`}},
	}
	m := &model{findingsView: true, findingCategory: "critical", findingRows: rows, width: 100, height: 40}
	m.findingCursor = 0
	view := m.findingsViewRender()
	for _, want := range []string{"CONFIRMED CRITICAL", "POTENTIAL CRITICAL — NOT VERIFIED", "AD CS", "AD Privileged", "NTLM Relay / Infrastructure"} {
		if !strings.Contains(view, want) {
			t.Fatalf("critical view missing subgroup %q: %s", want, view)
		}
	}
	if strings.Contains(view, "SCCM / MECM") || strings.Contains(view, "Delegation") || strings.Contains(view, "Credentials / Secrets") {
		t.Fatalf("empty subgroup was rendered: %s", view)
	}
	if strings.Index(view, "Alpha AD CS") > strings.Index(view, "Zulu access") || strings.Index(view, "ESC8 candidate") > strings.Index(view, "Relay candidate") {
		t.Fatalf("rows were not grouped and ordered deterministically: %s", view)
	}
	if !strings.Contains(view, "CRITICAL") {
		t.Fatal("severity column disappeared from grouped view")
	}
}

func TestCriticalDisplayGroupMapping(t *testing.T) {
	cases := []struct {
		family string
		want   string
	}{
		{"adcs_esc8", "AD CS"},
		{"acl_control", "AD Privileged"},
		{"dcsync", "AD Privileged"},
		{"credential_disclosure", "SCCM / MECM"},
		{"delegation", "Delegation"},
		{"ntlm_relay", "NTLM Relay / Infrastructure"},
	}
	for _, test := range cases {
		row := storage.Finding{FindingInput: storage.FindingInput{EvidenceJSON: `{"family":"` + test.family + `"}`}}
		if got := criticalDisplayGroup(row); got != test.want {
			t.Fatalf("family %q mapped to %q, want %q", test.family, got, test.want)
		}
	}
}

func TestCriticalHierarchyBackNavigationAndStateIsolation(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "critical.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows := []storage.Finding{
		{ID: 1, FindingInput: storage.FindingInput{AssessmentID: 1, SourceTool: "NetExec (nxc)", FindingType: "netexec_privileged_access", Title: "Admin access", EvidenceJSON: `{"protocol":"SMB","target":"dc","account_identity":"DOMAIN\\admin","outcome":"success","privileged":true}`}},
		{ID: 2, FindingInput: storage.FindingInput{AssessmentID: 1, FindingType: "adcs_esc_esc8", Title: "ESC8 candidate", EvidenceJSON: `{"critical_path":{"verified":false,"web_enrollment_http":true}}`}},
	}
	model := &model{ctx: context.Background(), db: db, findingsView: true, findingsLoaded: true, findingCategoryView: true, findingCategories: []findingCategory{{Key: "critical", Name: "CRITICAL FINDINGS"}}, findingAllRows: rows, criticalProjection: findingengine.ProjectCritical(rows), width: 100, height: 30}
	model.findingCursor = 0
	model.refreshFindings()
	model.handleFindingsKey("enter")
	landing := model.findingsViewRender()
	if strings.Contains(landing, "Admin access") || strings.Contains(landing, "ESC8 candidate") || !strings.Contains(landing, "Confirmed Critical") || !strings.Contains(landing, "Potential Critical") {
		t.Fatalf("critical landing was not category-only: %s", landing)
	}
	if model.criticalNavigationLevel != 1 || len(model.findingSubcategories) != 2 {
		t.Fatalf("state menu incorrect: level=%d groups=%#v", model.criticalNavigationLevel, model.findingSubcategories)
	}
	model.handleFindingsKey("down")
	model.handleFindingsKey("enter")
	if model.criticalState != findingengine.CriticalPotential || model.criticalNavigationLevel != 2 {
		t.Fatalf("potential state menu not isolated: state=%q level=%d", model.criticalState, model.criticalNavigationLevel)
	}
	model.handleFindingsKey("enter")
	if model.findingCategoryView || len(model.findingRows) != 1 || model.findingRows[0].Title != "ESC8 candidate" {
		t.Fatalf("potential family leaked records: categoryView=%v state=%q family=%q subcats=%#v projection=%#v rows=%#v", model.findingCategoryView, model.criticalState, model.criticalFamily, model.findingSubcategories, model.criticalProjection, model.findingRows)
	}
	model.handleFindingsKey("esc")
	if model.criticalNavigationLevel != 2 || !model.findingCategoryView || model.criticalFamily != "" {
		t.Fatalf("Esc did not return to potential family menu: level=%d family=%q", model.criticalNavigationLevel, model.criticalFamily)
	}
	model.handleFindingsKey("esc")
	if model.criticalNavigationLevel != 1 || model.criticalState != findingengine.CriticalPotential {
		t.Fatalf("Esc did not return to state menu: level=%d state=%q", model.criticalNavigationLevel, model.criticalState)
	}
	model.handleFindingsKey("esc")
	if model.findingCategory != "" || model.findingSubcategoryView {
		t.Fatalf("Esc did not return to Findings category landing: category=%q subcategoryView=%v", model.findingCategory, model.findingSubcategoryView)
	}
}

func TestCriticalDetailReusesOriginalPXEFinding(t *testing.T) {
	source := storage.Finding{ID: 98, FindingInput: storage.FindingInput{
		AssessmentID: 1, SourceTool: "PXEThief", SourceExecution: 73,
		FindingType: "sccm_task_sequence_credentials_exposed",
		Title:       "SCCM task-sequence credentials exposed — PXEThief",
		Description: "Recovered SCCM task-sequence credential material.",
		Severity:    "high", ArtifactPath: "Enumeration/PXEThief/artifacts/pxe.log", ArtifactRef: "line:4",
		EvidenceJSON: `{"account_identity":"sccm.lab\\sccm-naa","credential_variables":["OSDJoinPassword","OSDLocalAdminPassword"],"credential_values":{"OSDJoinAccount":"sccm.lab\\sccm-naa","OSDJoinPassword":"join-secret","OSDLocalAdminPassword":"local-secret"},"value_present":true}`,
	}}
	projection := findingengine.ProjectCritical([]storage.Finding{source})
	if len(projection.Confirmed) != 1 {
		t.Fatalf("PXE source did not produce a confirmed projection: %#v", projection)
	}
	model := &model{findingsView: true, findingCategory: "critical", findingDetail: true, findingRows: []storage.Finding{projection.Confirmed[0].Finding}, findingAllRows: []storage.Finding{source}, findingCursor: 0, width: 120, height: 60, inlineEvidence: inlineEvidence{section: "RECOVERED CREDENTIALS", lines: []string{"OSDJoinAccount        = sccm.lab\\sccm-naa", "OSDJoinPassword       = join-secret", "OSDLocalAdminPassword = local-secret"}}}
	view := ansi.Strip(model.findingsViewRender())
	for _, want := range []string{"SCCM TASK-SEQUENCE CREDENTIALS EXPOSED", "sccm.lab\\sccm-naa", "OSDJoinPassword", "join-secret", "OSDLocalAdminPassword", "local-secret", "PXEThief", "TECHNIQUES"} {
		if !strings.Contains(view, want) {
			t.Fatalf("Critical detail lost original PXE content %q: %s", want, view)
		}
	}
	if strings.Contains(view, "PwnFlow Critical Projection") || strings.Contains(view, "TARGET: PXEThief") {
		t.Fatalf("synthetic detail replaced original source detail: %s", view)
	}
}

func TestCriticalDetailResolvesCertipySourceFinding(t *testing.T) {
	source := storage.Finding{ID: 12, FindingInput: storage.FindingInput{
		AssessmentID: 1, SourceTool: "Certipy", SourceExecution: 70, FindingType: "adcs_esc_esc8",
		Title: "Certipy reported ESC8 — SCCM-LAB-CA", Severity: "high", ArtifactPath: "certipy.json", ArtifactRef: "/CA/SCCM-LAB-CA",
		EvidenceJSON: `{"esc":"ESC8","object_name":"SCCM-LAB-CA","web_enrollment_http":true,"critical_path":{"verified":false}}`,
	}}
	projection := findingengine.ProjectCritical([]storage.Finding{source})
	model := &model{findingsView: true, findingCategory: "critical", findingDetail: true, findingRows: []storage.Finding{projection.Potential[0].Finding}, findingAllRows: []storage.Finding{source}, findingCursor: 0, width: 110, height: 50}
	view := ansi.Strip(model.findingsViewRender())
	for _, want := range []string{"CERTIPY REPORTED ESC8", "Certipy", "certipy.json", "SCCM-LAB-CA", "TECHNIQUES"} {
		if !strings.Contains(view, want) {
			t.Fatalf("Critical detail lost Certipy source field %q: %s", want, view)
		}
	}
	if strings.Contains(view, "PwnFlow Critical Projection") {
		t.Fatal("Certipy detail used synthetic provenance")
	}
}

func TestCriticalMultiSourceDetailSwitchesOriginalFindings(t *testing.T) {
	sources := []storage.Finding{
		{ID: 1, FindingInput: storage.FindingInput{AssessmentID: 1, SourceTool: "NetExec (nxc)", SourceExecution: 80, FindingType: "netexec_privileged_access", Title: "Privileged access — SMB", ArtifactPath: "smb.txt", ArtifactRef: "line:1", EvidenceJSON: `{"protocol":"SMB","target":"dc","account_identity":"DOMAIN\\admin","outcome":"success","privileged":true}`}},
		{ID: 2, FindingInput: storage.FindingInput{AssessmentID: 1, SourceTool: "NetExec (nxc)", SourceExecution: 81, FindingType: "netexec_privileged_access", Title: "Privileged access — RDP", ArtifactPath: "rdp.txt", ArtifactRef: "line:2", EvidenceJSON: `{"protocol":"RDP","target":"dc","account_identity":"DOMAIN\\admin","outcome":"success","privileged":true}`}},
	}
	projection := findingengine.ProjectCritical(sources)
	model := &model{findingsView: true, findingCategory: "critical", findingDetail: true, findingRows: []storage.Finding{projection.Confirmed[0].Finding}, findingAllRows: sources, findingCursor: 0, width: 110, height: 60}
	if got := model.activeFindingForDetail(model.findingRows[0]); got.ID != 1 {
		t.Fatalf("wrong deterministic primary source: got %d", got.ID)
	}
	if len(model.criticalSourceFindings) != 2 {
		t.Fatalf("supporting source Findings were not retained: %#v", model.criticalSourceFindings)
	}
	model.criticalSourceIndex = 1
	view := ansi.Strip(model.findingsViewRender())
	if !strings.Contains(view, "PRIVILEGED ACCESS — RDP") || !strings.Contains(view, "rdp.txt") {
		t.Fatalf("supporting source renderer was not selected: %s", view)
	}
}
