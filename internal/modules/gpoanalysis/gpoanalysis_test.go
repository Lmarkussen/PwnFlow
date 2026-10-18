package gpoanalysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteArtifactsAnalyzesConfiguredRelationshipsWithoutEffectiveClaims(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, outputRoot)
	if err := os.MkdirAll(filepath.Join(directory, "SYSVOL", "11111111-2222-3333-4444-555555555555", "Machine"), 0o700); err != nil {
		t.Fatal(err)
	}
	metadata := `{"schema_version":1,"domain":"example.test","source_dc":"dc01","gpos":[{"guid":"11111111-2222-3333-4444-555555555555","object_guid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","original_guid":"{11111111-2222-3333-4444-555555555555}","distinguished_name":"CN={11111111-2222-3333-4444-555555555555},CN=Policies,DC=example,DC=test","attributes":{"displayName":{"status":"present","values":["Workstation Policy"]},"gPCFileSysPath":{"status":"present","values":["\\\\example.test\\SYSVOL\\example.test\\Policies\\{11111111-2222-3333-4444-555555555555}"]},"gPCWQLFilter":{"status":"present","values":["msWMI-Som"]}}}]}`
	links := `{"sources":[{"distinguished_name":"OU=Workstations,DC=example,DC=test","object_type":"ou","gPOptions":{"status":"empty","values":[""]},"links":[{"gpo_guid":"11111111-2222-3333-4444-555555555555","raw":"[LDAP://CN={11111111-2222-3333-4444-555555555555};0]","enabled":true,"enforced":false,"order":0},{"gpo_guid":"99999999-8888-7777-6666-555555555555","raw":"[LDAP://CN={99999999-8888-7777-6666-555555555555};0]","enabled":true,"enforced":false,"order":1}]},{"distinguished_name":"OU=Blocked,OU=Workstations,DC=example,DC=test","object_type":"ou","gPOptions":{"status":"present","values":["1"]},"links":[]}]}`
	manifest := `{"gpos":[{"gpo_guid":"11111111-2222-3333-4444-555555555555","status":"complete","retrieved_files":1}],"files":[{"gpo_guid":"11111111-2222-3333-4444-555555555555","source_relative_path":"Machine/Registry.pol","stored_relative_path":"Enumeration/ActiveDirectory/GPO/SYSVOL/11111111-2222-3333-4444-555555555555/Machine/Registry.pol","sha256":"abc","bytes":3,"status":"complete"}]}`
	for name, data := range map[string]string{"GPO_metadata.json": metadata, "GPO_links.json": links, "GPO_evidence_manifest.json": manifest} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := WriteArtifacts(root, "example.test", 42, timeForTest()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "GPO_applicability.json"))
	if err != nil {
		t.Fatal(err)
	}
	var analysis Analysis
	if err := json.Unmarshal(data, &analysis); err != nil {
		t.Fatal(err)
	}
	if analysis.CollectionExecutionID != 42 || analysis.EffectiveApplicationVerified {
		t.Fatalf("unexpected provenance/application state: %#v", analysis)
	}
	if len(analysis.GPOs) != 1 || analysis.GPOs[0].SYSVOLFiles[0].Category != "Registry.pol" || analysis.GPOs[0].WMIStatus != "reference_unresolved" {
		t.Fatalf("unexpected GPO analysis: %#v", analysis.GPOs)
	}
	var direct, unresolved bool
	for _, relationship := range analysis.Links {
		direct = direct || relationship.Classification == "configured_direct" && relationship.Applicability == "confirmed_configured_relationship"
		unresolved = unresolved || relationship.Classification == "unresolved"
	}
	if !direct || !unresolved {
		t.Fatalf("missing direct/unresolved relationships: %#v", analysis.Links)
	}
	report, err := os.ReadFile(filepath.Join(root, "GPO_APPLICABILITY_SUMMARY.txt"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(report)
	for _, want := range []string{"Collection execution ID: 42", "Workstation Policy", "Effective client-side application verified: no", "WMI runtime results"} {
		if !strings.Contains(text, want) {
			t.Errorf("report missing %q", want)
		}
	}
	if strings.Contains(text, "password") {
		t.Fatal("report contains secret-related content")
	}
}

func TestInputReferenceUsesSHA256(t *testing.T) {
	data := []byte("fixture")
	reference := inputReference("fixture.json", data)
	sum := sha256.Sum256(data)
	if reference.SHA256 != hex.EncodeToString(sum[:]) || reference.Status != "complete" {
		t.Fatalf("reference=%#v", reference)
	}
}

func timeForTest() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
