package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestFindingsMigrationAndIdempotentEvidence(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "enumeration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertTarget(ctx, "example.test", "198.51.100.10"); err != nil {
		t.Fatal(err)
	}
	assessment, err := db.TargetID(ctx, "example.test", "198.51.100.10")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.IngestFindings(ctx, []FindingInput{{FindingKey: "acl:one", AssessmentID: assessment, SourceTool: "RustHound-CE", FindingType: "ad_acl_genericall", Title: "Direct ACL GenericAll", Description: "observed", Severity: "high", Confidence: "observed-direct-ace", AffectedObjectID: "S-1", RelatedObjectID: "S-2", EvidenceJSON: `{"right_name":"GenericAll"}`, ArtifactPath: "artifact.json", ArtifactRef: "/data/0/Aces/0", ObservedAt: time.Unix(1, 0), Status: "open", ParserVersion: "test"}}); err != nil {
		t.Fatal(err)
	}
	if err := db.IngestFindings(ctx, []FindingInput{{FindingKey: "acl:one", AssessmentID: assessment, SourceTool: "RustHound-CE", FindingType: "ad_acl_genericall", Title: "Direct ACL GenericAll", Description: "observed again", Severity: "high", Confidence: "observed-direct-ace", AffectedObjectID: "S-1", RelatedObjectID: "S-2", EvidenceJSON: `{"right_name":"GenericAll"}`, ArtifactPath: "artifact.json", ArtifactRef: "/data/0/Aces/0", ObservedAt: time.Unix(2, 0), Status: "open", ParserVersion: "test"}}); err != nil {
		t.Fatal(err)
	}
	findings, err := db.ListFindings(ctx, assessment)
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	if count, err := db.FindingEvidenceCount(ctx, findings[0].ID); err != nil || count != 1 {
		t.Fatalf("evidence count=%d err=%v", count, err)
	}

	var executions, endpoints int
	if err := db.QueryRow(`SELECT COUNT(*) FROM executions`).Scan(&executions); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM endpoints`).Scan(&endpoints); err != nil {
		t.Fatal(err)
	}
	if executions != 0 || endpoints != 0 {
		t.Fatalf("existing tables changed: executions=%d endpoints=%d", executions, endpoints)
	}
}

func TestLegacyDatabaseGetsFindingsMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY); CREATE TABLE targets(id INTEGER PRIMARY KEY, domain TEXT NOT NULL, target_address TEXT NOT NULL, created_at TEXT NOT NULL); CREATE TABLE modules(id INTEGER PRIMARY KEY, name TEXT NOT NULL, tool TEXT NOT NULL, protocol TEXT NOT NULL, description TEXT NOT NULL, output_filename TEXT NOT NULL); CREATE TABLE executions(id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, module_id INTEGER NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, duration_ms INTEGER, status TEXT NOT NULL, exit_code INTEGER, output_path TEXT, error_summary TEXT); CREATE TABLE runs(id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL); CREATE TABLE endpoints(id INTEGER PRIMARY KEY, domain TEXT NOT NULL, address TEXT NOT NULL, hostname TEXT NOT NULL DEFAULT '', role TEXT NOT NULL, source TEXT NOT NULL, discovered_at TEXT NOT NULL, UNIQUE(domain,address,role,hostname)); INSERT INTO targets VALUES(9,'example.test','198.51.100.10','2026-01-01T00:00:00Z'); INSERT INTO schema_migrations VALUES(1);`)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Close()
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var target string
	if err := db.QueryRow(`SELECT target_address FROM targets WHERE id=9`).Scan(&target); err != nil || target != "198.51.100.10" {
		t.Fatalf("legacy target was not preserved: %q %v", target, err)
	}
	var version int
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version != 3 {
		t.Fatalf("migration version=%d err=%v", version, err)
	}
}

func TestFindingsPreserveSupportingExecutions(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "enumeration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertTarget(ctx, "example.test", "198.51.100.10"); err != nil {
		t.Fatal(err)
	}
	assessment, err := db.TargetID(ctx, "example.test", "198.51.100.10")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO modules(name,tool,protocol,description,output_filename) VALUES('RustHound','RustHound-CE','N/A','test','artifact.json')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO executions(id,target_id,module_id,started_at,status) VALUES(101,?,1,'2026-01-01T00:00:00Z','completed'),(102,?,1,'2026-01-02T00:00:00Z','completed')`, assessment, assessment); err != nil {
		t.Fatal(err)
	}
	base := FindingInput{FindingKey: "acl:supporting", AssessmentID: assessment, SourceTool: "RustHound-CE", FindingType: "ad_acl_genericall", Title: "ACL", Description: "observed", Severity: "medium", Confidence: "observed-direct-ace", AffectedObjectID: "S-1", RelatedObjectID: "S-2", EvidenceJSON: `{"right_name":"GenericAll"}`, ArtifactPath: "artifact.json", ObservedAt: time.Unix(1, 0), Status: "open", ParserVersion: "test"}
	base.SourceExecution, base.ArtifactRef = 101, "/data/0/Aces/0"
	if err := db.IngestFindings(ctx, []FindingInput{base}); err != nil {
		t.Fatal(err)
	}
	base.SourceExecution, base.ArtifactRef, base.ObservedAt = 102, "/data/0/Aces/1", time.Unix(2, 0)
	if err := db.IngestFindings(ctx, []FindingInput{base}); err != nil {
		t.Fatal(err)
	}
	findings, err := db.ListFindings(ctx, assessment)
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	if count, err := db.FindingEvidenceCount(ctx, findings[0].ID); err != nil || count != 2 {
		t.Fatalf("supporting evidence count=%d err=%v", count, err)
	}
}
