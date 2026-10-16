package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFlushAssessmentBacksUpAndClearsSelectedState(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	databasePath := filepath.Join(root, "results", "sccm.lab", "enumeration.db")
	artifact := filepath.Join(root, "results", "sccm.lab", "Enumeration", "raw.log")
	if err := os.MkdirAll(filepath.Dir(artifact), 0750); err != nil {
		t.Fatal(err)
	}
	original := []byte("original evidence\n")
	if err := os.WriteFile(artifact, original, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertTarget(ctx, "sccm.lab", "198.51.100.40"); err != nil {
		t.Fatal(err)
	}
	assessmentID, err := db.TargetID(ctx, "sccm.lab", "198.51.100.40")
	if err != nil {
		t.Fatal(err)
	}
	moduleID, err := db.RegisterModule(ctx, "Synthetic", "NetExec", "SMB", "test", "raw.log")
	if err != nil {
		t.Fatal(err)
	}
	executionID, err := db.RecordExecutionID(ctx, assessmentID, moduleID, time.Now(), time.Now(), "completed", 0, artifact, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO runs(target_id,started_at,finished_at,status) VALUES(?,?,?,?)`, assessmentID, time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano), "completed"); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordEndpoints(ctx, []EndpointRecord{{Domain: "sccm.lab", Address: "198.51.100.41", Hostname: "client", Role: "server", Source: "fixture", DiscoveredAt: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	input := FindingInput{FindingKey: "flush-test", AssessmentID: assessmentID, SourceTool: "NetExec", SourceExecution: executionID, FindingType: "synthetic", Title: "Synthetic", Description: "Synthetic", Severity: "medium", Confidence: "test", EvidenceJSON: `{}`, ArtifactPath: artifact, ArtifactRef: "line:1", ObservedAt: time.Now(), Status: "open", ParserVersion: "test"}
	if err := db.IngestFindings(ctx, []FindingInput{input}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.QueueAnalysis(ctx, "flush-job", assessmentID, executionID, "NetExec", artifact); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	backupDir := filepath.Join(root, "backups")
	report, err := FlushAssessment(ctx, databasePath, "sccm.lab", "198.51.100.40", backupDir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Findings != 1 || report.Evidence != 1 || report.AnalysisJobs != 1 || report.Executions != 1 || report.Runs != 1 || report.Endpoints != 1 {
		t.Fatalf("unexpected flush report: %#v", report)
	}
	if _, err := os.Stat(report.BackupPath); err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if backup, err := Open(report.BackupPath); err != nil {
		t.Fatalf("backup could not be opened: %v", err)
	} else {
		backup.Close()
	}
	if got, err := os.ReadFile(artifact); err != nil || string(got) != string(original) {
		t.Fatalf("raw artifact changed: %v", err)
	}

	clean, err := Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer clean.Close()
	for table, want := range map[string]int{"findings": 0, "finding_evidence": 0, "analysis_jobs": 0, "executions": 0, "runs": 0, "endpoints": 0, "targets": 1, "modules": 1} {
		var got int
		if err := clean.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s=%d, want %d", table, got, want)
		}
	}
	if err := clean.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(new(string)); err != nil {
		t.Fatal(err)
	}
	if _, err := FlushAssessment(ctx, databasePath, "sccm.lab", "198.51.100.40", backupDir); err != nil {
		t.Fatalf("second flush was not idempotent: %v", err)
	}
}
