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
	if report.SchemaVersion != 6 || report.CollectorVersion != "RustHound-CE v2.5.25" || report.Objects != 2 || report.ACLs != 2 || len(findings) != 2 {
		t.Fatalf("unexpected report: %+v findings=%d", report, len(findings))
	}
	if findings[0].Severity != "high" || findings[0].Confidence != "observed-direct-ace" {
		t.Fatalf("broad control was not conservatively classified: %+v", findings[0])
	}
	if findings[1].RelatedObject != "Domain Admins" || findings[1].ArtifactRef != "/data/0/Aces/0" {
		t.Fatalf("principal or evidence reference was not resolved: %+v", findings[1])
	}
	if findings[0].FindingKey == findings[1].FindingKey {
		t.Fatal("distinct ACEs were merged")
	}

	archive := filepath.Join(root, "collection.zip")
	createZIP(t, archive, map[string][]byte{"nested/sample_groups.json": mustJSON(t, map[string]any{"meta": map[string]any{"collectorversion": "RustHound-CE v2.5.25", "version": 6, "type": "groups"}, "data": []any{map[string]any{"ObjectIdentifier": "S-1-5-21-1-512", "Properties": map[string]any{"name": "Domain Admins", "highvalue": true}, "Aces": []any{map[string]any{"PrincipalSID": "S-1-5-21-1-1101", "RightName": "GenericAll"}}}}})})
	zipFindings, zipReport, err := AnalyzeRustHound(context.Background(), archive, 7, 12, time.Now())
	if err != nil || zipReport.Files != 1 || len(zipFindings) != 1 || !strings.HasSuffix(zipFindings[0].ArtifactPath, "collection.zip!nested/sample_groups.json") {
		t.Fatalf("ZIP analysis failed: report=%+v findings=%+v err=%v", zipReport, zipFindings, err)
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
