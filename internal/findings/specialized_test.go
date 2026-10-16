package findings

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func nowForTest() time.Time { return time.Unix(1, 0).UTC() }

func TestAnalyzeSpecializedMSSQLAndGhostSPN(t *testing.T) {
	dir := t.TempDir()
	mssql := filepath.Join(dir, "mssql.log")
	if err := os.WriteFile(mssql, []byte("[*] Version: SQL\n[*] Encryption: not enforced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := AnalyzeSpecialized(context.Background(), mssql, "mssqlrelay", 1, 2, nowForTest())
	if err != nil || len(findings) != 1 || findings[0].FindingType != "mssql_encryption_not_enforced" {
		t.Fatalf("unexpected mssql findings: %#v %v", findings, err)
	}
	ghost := filepath.Join(dir, "ghost.json")
	if err := os.WriteFile(ghost, []byte(`[{"spn":"MSSQLSvc/orphan.example.test:1433","account":"svc","orphan":true}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err = AnalyzeSpecialized(context.Background(), ghost, "ghostSPN", 1, 2, nowForTest())
	if err != nil || len(findings) != 1 || findings[0].FindingType != "ghostspn_orphaned_spn" {
		t.Fatalf("unexpected ghost findings: %#v %v", findings, err)
	}
}

func TestAnalyzeSpecializedGPORequiresExplicitEvidence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gpo.txt")
	if err := os.WriteFile(path, []byte("GPO name: baseline\nlocal group: Remote Desktop Users\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := AnalyzeSpecialized(context.Background(), path, "gpoParser", 1, 2, nowForTest())
	if err != nil || len(findings) != 1 || findings[0].FindingType != "gpo_security_configuration_observed" {
		t.Fatalf("unexpected GPO findings: %#v %v", findings, err)
	}
}
