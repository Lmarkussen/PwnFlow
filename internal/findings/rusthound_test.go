package findings

import (
	"archive/zip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestAnalyzeRustHoundACLsAndZIP(t *testing.T) {
	root := t.TempDir()
	collection := filepath.Join(root, "collection")
	if err := os.Mkdir(collection, 0o750); err != nil {
		t.Fatal(err)
	}
	writeExport(t, filepath.Join(collection, "sample_groups.json"), "groups", []map[string]any{
		{"ObjectIdentifier": "S-1-5-21-1-512", "Properties": map[string]any{"name": "Domain Admins", "highvalue": true}, "Aces": []map[string]any{{"PrincipalSID": "S-1-5-21-1-1101", "PrincipalType": "User", "RightName": "GenericAll", "IsInherited": false}, {"PrincipalSID": "S-1-5-21-foreign-1101", "PrincipalType": "User", "RightName": "UnknownRight"}}, "Members": []string{"S-1-5-21-1-1101"}},
	})
	writeExport(t, filepath.Join(collection, "sample_users.json"), "users", []map[string]any{
		{"ObjectIdentifier": "S-1-5-21-1-1101", "Properties": map[string]any{"name": "alice"}, "Aces": []map[string]any{{"PrincipalSID": "S-1-5-21-1-512", "PrincipalType": "Group", "RightName": "WriteDacl", "IsInherited": true, "InheritanceHash": "hash"}}},
	})

	findings, report, err := AnalyzeRustHound(context.Background(), collection, 7, 12, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != 6 || report.CollectorVersion != "RustHound-CE v2.5.25" || report.Objects != 2 || report.ACLs != 2 || len(report.ACLRecords) != 2 || len(findings) != 0 {
		t.Fatalf("unexpected report: %+v findings=%d", report, len(findings))
	}
	for _, finding := range findings {
		if finding.Severity != "informational" {
			t.Fatalf("raw ACL evidence was promoted to vulnerability severity: %+v", finding)
		}
	}
	if report.ACLRecords[1].PrincipalName != "Domain Admins" || report.ACLRecords[1].ArtifactRef != "/data/0/Aces/0" {
		t.Fatalf("principal or evidence reference was not resolved: %+v", report.ACLRecords[1])
	}
	if report.ACLRecords[0].Artifact == report.ACLRecords[1].Artifact && report.ACLRecords[0].ArtifactRef == report.ACLRecords[1].ArtifactRef {
		t.Fatal("distinct ACEs were merged")
	}

	archive := filepath.Join(root, "collection.zip")
	createZIP(t, archive, map[string][]byte{"nested/sample_groups.json": mustJSON(t, map[string]any{"meta": map[string]any{"collectorversion": "RustHound-CE v2.5.25", "version": 6, "type": "groups"}, "data": []any{map[string]any{"ObjectIdentifier": "S-1-5-21-1-512", "Properties": map[string]any{"name": "Domain Admins", "highvalue": true}, "Aces": []any{map[string]any{"PrincipalSID": "S-1-5-21-1-1101", "RightName": "GenericAll"}}}}})})
	zipFindings, zipReport, err := AnalyzeRustHound(context.Background(), archive, 7, 12, time.Now())
	if err != nil || zipReport.Files != 1 || len(zipFindings) != 0 || len(zipReport.ACLRecords) != 1 || !strings.HasSuffix(zipReport.ACLRecords[0].Artifact, "collection.zip!nested/sample_groups.json") {
		t.Fatalf("ZIP analysis failed: report=%+v findings=%+v err=%v", zipReport, zipFindings, err)
	}
}

func TestAnalyzeRustHoundEmitsDirectUserGenericAllFinding(t *testing.T) {
	root := t.TempDir()
	collection := filepath.Join(root, "collection")
	if err := os.Mkdir(collection, 0o750); err != nil {
		t.Fatal(err)
	}
	writeExport(t, filepath.Join(collection, "users.json"), "users", []map[string]any{
		{"ObjectIdentifier": "S-1-5-21-1-1101", "Properties": map[string]any{"name": "PF-ACL-Test-Operator", "domain": "SCCM.LAB"}},
		{"ObjectIdentifier": "S-1-5-21-1-1102", "Properties": map[string]any{"name": "PF-ACL-Test-Target"}, "Aces": []map[string]any{{
			"PrincipalSID": "S-1-5-21-1-1101", "PrincipalType": "User", "RightName": "GenericAll", "IsInherited": false,
		}}},
	})

	findings, report, err := AnalyzeRustHound(context.Background(), collection, 7, 12, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if report.ACLs != 1 || len(findings) != 1 {
		t.Fatalf("expected one direct GenericAll finding, report=%+v findings=%+v", report, findings)
	}
	finding := findings[0]
	if finding.FindingType != "ad_acl_genericall" || finding.Severity != "medium" || finding.Confidence != "observed-direct-ace" {
		t.Fatalf("unexpected GenericAll finding: %+v", finding)
	}
	if finding.RelatedObjectID != "S-1-5-21-1-1101" || finding.AffectedObjectID != "S-1-5-21-1-1102" {
		t.Fatalf("finding identity was not preserved: %+v", finding)
	}
	if !strings.Contains(finding.EvidenceJSON, `"effective_authorization":"not_verified"`) {
		t.Fatalf("finding overstated effective authorization: %s", finding.EvidenceJSON)
	}
}

func TestAnalyzeRustHoundRejectsUnsafeZIPEntry(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "unsafe.zip")
	createZIP(t, archive, map[string][]byte{"../escape.json": []byte(`{}`)})
	if _, _, err := AnalyzeRustHound(context.Background(), archive, 1, 0, time.Now()); err == nil {
		t.Fatal("path traversal entry was accepted")
	}
}

func writeExport(t *testing.T, path string, objectType string, data []map[string]any) {
	t.Helper()
	contents := map[string]any{"meta": map[string]any{"collectorversion": "RustHound-CE v2.5.25", "version": 6, "type": objectType}, "data": data}
	bytes := mustJSON(t, contents)
	if err := os.WriteFile(path, bytes, 0o600); err != nil {
		t.Fatal(err)
	}
}

func createZIP(t *testing.T, path string, files map[string][]byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	for name, contents := range files {
		entry, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	bytes, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return bytes
}

func TestAnalyzeRustHoundKerberosIdentityDetections(t *testing.T) {
	root := t.TempDir()
	collection := filepath.Join(root, "collection")
	if err := os.Mkdir(collection, 0o750); err != nil {
		t.Fatal(err)
	}
	writeExport(t, filepath.Join(collection, "users.json"), "users", []map[string]any{
		{"ObjectIdentifier": "S-1-5-21-100-1101", "Properties": map[string]any{
			"name": "svc-sql@EXAMPLE.TEST", "enabled": true, "hasspn": true,
			"serviceprincipalnames": []string{"MSSQLSvc/sql.example.test:1433"},
			"dontreqpreauth":        true,
		}},
		{"ObjectIdentifier": "S-1-5-21-100-1102", "Properties": map[string]any{
			"name": "disabled-service", "enabled": false, "hasspn": true,
			"serviceprincipalnames": []string{"HTTP/disabled.example.test"}, "dontreqpreauth": true,
		}},
		{"ObjectIdentifier": "S-1-5-21-100-1103", "Properties": map[string]any{
			"name": "uac-asrep", "enabled": true, "useraccountcontrol": 0x400000,
		}},
	})

	findings, _, err := AnalyzeRustHound(context.Background(), collection, 7, 12, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected three identity findings, got %d: %+v", len(findings), findings)
	}
	seen := map[string]storage.FindingInput{}
	for _, finding := range findings {
		seen[finding.FindingType] = finding
		if finding.ArtifactPath == "" || !strings.HasSuffix(finding.ArtifactPath, "users.json") {
			t.Fatalf("finding lost artifact provenance: %+v", finding)
		}
		if strings.Contains(finding.EvidenceJSON, "password") || strings.Contains(finding.EvidenceJSON, "hash") {
			t.Fatalf("identity evidence unexpectedly contains secret material: %s", finding.EvidenceJSON)
		}
	}
	if seen["kerberoastable_account"].AffectedObject != "svc-sql@EXAMPLE.TEST" {
		t.Fatalf("missing Kerberoastable finding: %+v", seen)
	}
	if seen["asrep_roastable_account"].AffectedObject != "svc-sql@EXAMPLE.TEST" && seen["asrep_roastable_account"].AffectedObject != "uac-asrep" {
		t.Fatalf("missing AS-REP finding: %+v", seen)
	}
	if seen["kerberoastable_account"].ArtifactRef == "" || !strings.Contains(seen["kerberoastable_account"].ArtifactRef, "/Properties/") {
		t.Fatalf("Kerberoastable evidence reference is not structural: %+v", seen["kerberoastable_account"])
	}
}
