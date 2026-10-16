package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestResetDerivedStatePreservesSchemaAndArtifacts(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "assessment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertTarget(ctx, "example.test", "198.51.100.10"); err != nil {
		t.Fatal(err)
	}
	assessmentID, err := db.TargetID(ctx, "example.test", "198.51.100.10")
	if err != nil {
		t.Fatal(err)
	}
	moduleID, err := db.RegisterModule(ctx, "Synthetic", "NetExec", "LDAP", "test", "synthetic.txt")
	if err != nil {
		t.Fatal(err)
	}
	executionID, err := db.RecordExecutionID(ctx, assessmentID, moduleID, time.Now(), time.Now(), "completed", 0, "synthetic.txt", "")
	if err != nil {
		t.Fatal(err)
	}
	input := FindingInput{FindingKey: "synthetic-key", AssessmentID: assessmentID, SourceTool: "NetExec", SourceExecution: executionID, FindingType: "synthetic", Title: "Synthetic", Description: "Synthetic", Severity: "medium", Confidence: "test", EvidenceJSON: `{}`, ArtifactPath: "synthetic.txt", ArtifactRef: "line:1", ObservedAt: time.Now(), Status: "open", ParserVersion: "test"}
	if err := db.IngestFindings(ctx, []FindingInput{input}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.QueueAnalysis(ctx, "synthetic-job", assessmentID, executionID, "NetExec", "synthetic.txt"); err != nil {
		t.Fatal(err)
	}
	removed, err := db.ResetDerivedState(ctx, assessmentID)
	if err != nil || removed != 1 {
		t.Fatalf("reset removed=%d err=%v", removed, err)
	}
	var findings, evidence, jobs, executions int
	for table, target := range map[string]*int{"findings": &findings, "finding_evidence": &evidence, "analysis_jobs": &jobs, "executions": &executions} {
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(target); err != nil {
			t.Fatal(err)
		}
	}
	if findings != 0 || evidence != 0 || jobs != 0 || executions != 1 {
		t.Fatalf("unexpected reset counts findings=%d evidence=%d jobs=%d executions=%d", findings, evidence, jobs, executions)
	}
	var schemaCount int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&schemaCount); err != nil || schemaCount == 0 {
		t.Fatalf("schema was not preserved: count=%d err=%v", schemaCount, err)
	}
}
