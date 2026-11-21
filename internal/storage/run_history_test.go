package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func historyFixture(t *testing.T) (*DB, string, int64) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "results", "corp.example", "enumeration.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := db.UpsertTarget(ctx, "corp.example", "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	target, _ := db.TargetID(ctx, "corp.example", "192.0.2.10")
	return db, path, target
}

func TestRunsAndSeverityHistory(t *testing.T) {
	ctx := context.Background()
	db, _, target := historyFixture(t)
	defer db.Close()
	first := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	second := first.Add(24 * time.Hour)
	if _, err := db.RecordRun(ctx, target, first, first.Add(time.Minute), "completed"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RecordRun(ctx, target, second, second.Add(time.Minute), "aborted"); err != nil {
		t.Fatal(err)
	}
	runs, err := db.Runs(ctx, target)
	if err != nil || len(runs) != 2 || !runs[0].Started.Equal(second) || runs[0].Status != "aborted" {
		t.Fatalf("runs %+v %v", runs, err)
	}
	input := FindingInput{FindingKey: "k", AssessmentID: target, SourceTool: "t", FindingType: "smb_v1_enabled", Title: "SMBv1", Severity: "low",
		Confidence: "c", EvidenceJSON: "{}", ArtifactPath: "a", ArtifactRef: "r", ObservedAt: first, Status: "open", ParserVersion: "v"}
	if err := db.IngestFindings(ctx, []FindingInput{input}); err != nil {
		t.Fatal(err)
	}
	input.ObservedAt = second
	if err := db.IngestFindings(ctx, []FindingInput{input}); err != nil { // same severity: no history
		t.Fatal(err)
	}
	input.Severity, input.ObservedAt = "medium", second.Add(time.Hour)
	if err := db.IngestFindings(ctx, []FindingInput{input}); err != nil {
		t.Fatal(err)
	}
	changes, err := db.SeverityChanges(ctx, target, second)
	if err != nil || len(changes) != 1 || changes[0].Old != "low" || changes[0].New != "medium" {
		t.Fatalf("changes %+v %v", changes, err)
	}
	if later, _ := db.SeverityChanges(ctx, target, second.Add(2*time.Hour)); len(later) != 0 {
		t.Fatalf("since filter ignored: %+v", later)
	}
	if _, err := db.ResetDerivedState(ctx, target); err != nil {
		t.Fatal(err)
	}
	var remaining int
	db.QueryRow(`SELECT COUNT(*) FROM finding_history`).Scan(&remaining)
	if remaining != 0 {
		t.Fatalf("reset left %d history rows", remaining)
	}
}

func TestFlushHandlesHistoryAndOlderDatabases(t *testing.T) {
	ctx := context.Background()
	for _, dropHistory := range []bool{false, true} {
		db, path, target := historyFixture(t)
		input := FindingInput{FindingKey: "k", AssessmentID: target, SourceTool: "t", FindingType: "x", Title: "x", Severity: "low",
			Confidence: "c", EvidenceJSON: "{}", ArtifactPath: "a", ArtifactRef: "r", ObservedAt: time.Now(), Status: "open", ParserVersion: "v"}
		db.IngestFindings(ctx, []FindingInput{input})
		input.Severity = "high"
		db.IngestFindings(ctx, []FindingInput{input})
		if dropHistory {
			if _, err := db.ExecContext(ctx, `DROP TABLE finding_history`); err != nil {
				t.Fatal(err)
			}
		}
		db.Close()
		if _, err := FlushAssessment(ctx, path, "corp.example", "192.0.2.10", filepath.Join(filepath.Dir(path), "backup")); err != nil {
			t.Fatalf("flush (history dropped=%v): %v", dropHistory, err)
		}
	}
}
