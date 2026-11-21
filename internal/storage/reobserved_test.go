package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestListFindingsMarksFindingsNotReobserved(t *testing.T) {
	ctx := context.Background()
	db, err := Open(filepath.Join(t.TempDir(), "enumeration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.UpsertTarget(ctx, "corp.example", "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	target, _ := db.TargetID(ctx, "corp.example", "192.0.2.10")
	spooler, _ := db.RegisterModule(ctx, "Check Print Spooler", "NetExec (nxc)", "SMB", "", "SMB_spooler.txt")
	quota, _ := db.RegisterModule(ctx, "Check Machine Account Quota", "NetExec (nxc)", "LDAP", "", "LDAP_machine_account_quota.txt")
	run1 := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	run2 := run1.Add(time.Hour)
	execute := func(module int64, started time.Time, status, jobStatus string) int64 {
		id, err := db.RecordExecutionID(ctx, target, module, started, started.Add(time.Minute), status, 0, "artifact.txt", "")
		if err != nil {
			t.Fatal(err)
		}
		key := fmt.Sprintf("job-%d", id)
		if _, err := db.QueueAnalysis(ctx, key, target, id, "NetExec (nxc)", "artifact.txt"); err != nil {
			t.Fatal(err)
		}
		if err := db.SetAnalysisStatus(ctx, key, jobStatus, "v1", ""); err != nil {
			t.Fatal(err)
		}
		return id
	}
	finding := func(key string, execution int64, observed time.Time) FindingInput {
		return FindingInput{FindingKey: key, AssessmentID: target, SourceTool: "NetExec (nxc)", SourceExecution: execution, FindingType: key, Title: key,
			Severity: "medium", Confidence: "fixture", EvidenceJSON: "{}", ArtifactPath: "artifact.txt", ArtifactRef: "line:1", ObservedAt: observed, Status: "open", ParserVersion: "v1"}
	}
	spooler1 := execute(spooler, run1, "completed", AnalysisComplete)
	quota1 := execute(quota, run1, "completed", AnalysisComplete)
	if err := db.IngestFindings(ctx, []FindingInput{
		finding("gone", spooler1, run1.Add(time.Minute)),
		finding("still-present", spooler1, run1.Add(time.Minute)),
		finding("module-not-rerun", quota1, run1.Add(time.Minute)),
	}); err != nil {
		t.Fatal(err)
	}
	// The second run repeats only the spooler module and re-observes one Finding.
	spooler2 := execute(spooler, run2, "completed", AnalysisComplete)
	if err := db.IngestFindings(ctx, []FindingInput{finding("still-present", spooler2, run2.Add(time.Minute))}); err != nil {
		t.Fatal(err)
	}
	// A later run whose analysis did not complete proves nothing.
	execute(quota, run2.Add(time.Hour), "completed", AnalysisFailed)

	rows, err := db.ListFindings(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, row := range rows {
		got[row.FindingKey] = row.NotReobserved
	}
	want := map[string]bool{"gone": true, "still-present": false, "module-not-rerun": false}
	for key, value := range want {
		if got[key] != value {
			t.Fatalf("%s NotReobserved=%v, want %v (all %v)", key, got[key], value, got)
		}
	}
}
