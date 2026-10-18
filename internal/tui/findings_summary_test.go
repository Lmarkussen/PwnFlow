package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestFindingsSummaryFormatsCurrentFindingsWithoutSecrets(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, assessment, execution := summaryFixtureDB(t, root, "example.test", "completed")
	defer db.Close()
	if _, err := db.QueueAnalysis(ctx, "summary-job", assessment, execution, "synthetic", "Enumeration/synthetic.txt"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetAnalysisStatus(ctx, "summary-job", storage.AnalysisComplete, "test", ""); err != nil {
		t.Fatal(err)
	}
	inputs := []storage.FindingInput{
		{FindingKey: "critical", AssessmentID: assessment, SourceTool: "NetExec", SourceExecution: execution, FindingType: "netexec_privileged_access", Title: "Pwn3d! privileged access", Description: "password: DoNotExport", Severity: "critical", Confidence: "test", AffectedObject: "EXAMPLE\\svc-admin", EvidenceJSON: `{"password":"DoNotExport"}`, ArtifactPath: filepath.Join(root, "results", "example.test", "Enumeration", "auth.txt"), ArtifactRef: "line:1", ObservedAt: time.Now(), Status: "open", ParserVersion: "test"},
		{FindingKey: "esc1", AssessmentID: assessment, SourceTool: "Certipy", SourceExecution: execution, FindingType: "adcs_esc_esc1", Title: "Certipy reported ESC1 — ExampleTemplate", Description: "synthetic", Severity: "high", Confidence: "test", AffectedObject: "ExampleTemplate", EvidenceJSON: `{}`, ArtifactPath: filepath.Join(root, "results", "example.test", "Enumeration", "Certipy", "report.json"), ArtifactRef: "/Certificate Templates/ExampleTemplate", ObservedAt: time.Now(), Status: "open", ParserVersion: "test"},
		{FindingKey: "esc8", AssessmentID: assessment, SourceTool: "Certipy", SourceExecution: execution, FindingType: "adcs_esc_esc8", Title: "Certipy reported ESC8 — ExampleCA", Description: "synthetic", Severity: "high", Confidence: "test", AffectedObject: "ExampleCA", EvidenceJSON: `{}`, ArtifactPath: filepath.Join(root, "results", "example.test", "Enumeration", "Certipy", "report.json"), ArtifactRef: "/Certificate Authorities/ExampleCA", ObservedAt: time.Now(), Status: "open", ParserVersion: "test"},
		{FindingKey: "smb", AssessmentID: assessment, SourceTool: "NetExec", SourceExecution: execution, FindingType: "smb_signing_not_required", Title: "SMB Signing Not Required", Description: "synthetic", Severity: "medium", Confidence: "test", AffectedObject: "host.example.test", EvidenceJSON: `{}`, ArtifactPath: "Enumeration/NetExec/smb.txt", ArtifactRef: "line:2", ObservedAt: time.Now(), Status: "open", ParserVersion: "test"},
		{FindingKey: "policy", AssessmentID: assessment, SourceTool: "NetExec", SourceExecution: execution, FindingType: "ad_domain_policy_machine_account_creation_quota", Title: "Machine Account Creation Quota", Description: "synthetic", Severity: "informational", Confidence: "test", AffectedObject: "example.test", EvidenceJSON: `{}`, ArtifactPath: "Enumeration/NetExec/LDAP_machine_account_quota.txt", ArtifactRef: "line:1", ObservedAt: time.Now(), Status: "open", ParserVersion: "test"},
	}
	if err := db.IngestFindings(ctx, inputs); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(root, "results", "example.test", "findings_summary.txt")
	if err := writeFindingsSummary(ctx, db, filepath.Dir(reportPath), "example.test", assessment, []int64{execution}, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	report := string(data)
	for _, want := range []string{"PWNFLOW SECURITY SUMMARY", "IMPORTANT FINDINGS", "FINDINGS BY CATEGORY", "Pwn3d! privileged access", "ESC1", "ESC8", "Machine Account Creation Quota", "Active Directory", "AD CS", "Network & Protocols"} {
		if !strings.Contains(report, want) {
			t.Fatalf("summary missing %q:\n%s", want, report)
		}
	}
	for _, want := range []string{"EXECUTIONS:", "COUNT SCOPE:   stored findings linked to these execution IDs"} {
		if !strings.Contains(report, want) {
			t.Fatalf("summary missing explicit count scope %q:\n%s", want, report)
		}
	}
	for _, secret := range []string{"DoNotExport", "password\":", "Enumeration/NetExec/smb.txt"} {
		if secret == "Enumeration/NetExec/smb.txt" {
			continue
		}
		if strings.Contains(report, secret) {
			t.Fatalf("summary leaked %q:\n%s", secret, report)
		}
	}
}

func TestFindingsSummaryUsesOnlySelectedRunAndDeduplicatesEvidence(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, assessment, oldExecution := summaryFixtureDB(t, root, "example.test", "completed")
	defer db.Close()
	moduleID := int64(1)
	newExecution, err := db.RecordExecutionID(ctx, assessment, moduleID, time.Now(), time.Now(), "completed", 0, "new.log", "")
	if err != nil {
		t.Fatal(err)
	}
	input := storage.FindingInput{FindingKey: "stable", AssessmentID: assessment, SourceTool: "Certipy", SourceExecution: oldExecution, FindingType: "adcs_esc_esc1", Title: "Old Template", Description: "synthetic", Severity: "high", Confidence: "test", AffectedObject: "OldTemplate", EvidenceJSON: `{}`, ArtifactPath: "Enumeration/old.json", ArtifactRef: "old", ObservedAt: time.Now(), Status: "open", ParserVersion: "test"}
	if err := db.IngestFindings(ctx, []storage.FindingInput{input}); err != nil {
		t.Fatal(err)
	}
	input.SourceExecution = newExecution
	input.AffectedObject = "NewTemplate"
	input.Title = "New Template"
	input.ArtifactPath = "Enumeration/new.json"
	if err := db.IngestFindings(ctx, []storage.FindingInput{input, input}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "results", "example.test", "findings_summary.txt")
	if err := writeFindingsSummary(ctx, db, filepath.Dir(path), "example.test", assessment, []int64{newExecution}, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	report, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(report), "Old Template") || strings.Count(string(report), "New Template") != 2 {
		t.Fatalf("run isolation or expected important/category occurrence failed:\n%s", report)
	}
}

func TestFindingsSummaryWaitsForAnalysisAndPreservesPreviousReport(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, assessment, execution := summaryFixtureDB(t, root, "example.test", "completed")
	defer db.Close()
	jobKey := "pending-summary-job"
	if _, err := db.QueueAnalysis(ctx, jobKey, assessment, execution, "synthetic", "artifact.txt"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "results", "example.test", "findings_summary.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("previous report\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeFindingsSummary(ctx, db, filepath.Dir(path), "example.test", assessment, []int64{execution}, time.Now()); err == nil {
		t.Fatal("pending analysis allowed a report write")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "previous report\n" {
		t.Fatalf("previous report was not preserved: %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("summary permissions=%o, want 600", info.Mode().Perm())
	}
}

func TestFindingsSummaryReportsPartialExecutionHealth(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, assessment, failedExecution := summaryFixtureDB(t, root, "example.test", "failed")
	defer db.Close()
	unsupportedExecution, err := db.RecordExecutionID(ctx, assessment, 1, time.Now(), time.Now(), "unsupported", 0, "unsupported.log", "not available")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "results", "example.test", "findings_summary.txt")
	if err := writeFindingsSummary(ctx, db, filepath.Dir(path), "example.test", assessment, []int64{failedExecution, unsupportedExecution}, time.Now()); err != nil {
		t.Fatal(err)
	}
	report, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"STATUS:        PARTIAL", "Failed:        1", "Unsupported:   1", "Synthetic Module"} {
		if !strings.Contains(string(report), want) {
			t.Fatalf("partial report missing %q:\n%s", want, report)
		}
	}
}

func TestDefaultEnumerationSummaryHookWritesAutomatically(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, assessment, execution := summaryFixtureDB(t, root, "example.test", "completed")
	defer db.Close()
	m := &model{ctx: ctx, cfg: config.Config{Root: root, Domain: "example.test"}, db: db, targetID: assessment, batchName: "Default Enumeration", batchExecutionIDs: []int64{execution}}
	m.exportDefaultEnumerationSummary()
	path := filepath.Join(root, "results", "example.test", "findings_summary.txt")
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if !m.batchSummaryExported || !strings.Contains(m.status, "findings summary written") {
		t.Fatalf("summary hook status=%q exported=%v", m.status, m.batchSummaryExported)
	}
}

func summaryFixtureDB(t *testing.T, root, domain, status string) (*storage.DB, int64, int64) {
	t.Helper()
	db, err := storage.Open(filepath.Join(root, "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := db.UpsertTarget(ctx, domain, "198.51.100.10"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	assessment, err := db.TargetID(ctx, domain, "198.51.100.10")
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO modules(id,name,tool,protocol,description,output_filename) VALUES(1,'Synthetic Module','Synthetic','N/A','test','synthetic.log')`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	execution, err := db.RecordExecutionID(ctx, assessment, 1, time.Now(), time.Now(), status, 0, "synthetic.log", "")
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	return db, assessment, execution
}
