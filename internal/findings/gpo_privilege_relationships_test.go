package findings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGPOPrivilegeRelationshipsUseCanonicalGUIDAndPreserveSnapshotCaveat(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "Enumeration", "ActiveDirectory", "GPO")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	metadata := `{"domain":"example.test","gpos":[{"guid":"{11111111-1111-1111-1111-111111111111}","object_guid":"22222222-2222-2222-2222-222222222222","original_guid":"{11111111-1111-1111-1111-111111111111}","distinguished_name":"CN={11111111-1111-1111-1111-111111111111},CN=Policies","attributes":{"displayName":{"values":["Baseline GPO"]}}}]}`
	applicability := `{"domain":"example.test","collection_execution_id":12,"gpos":[{"gpo_guid":"11111111-1111-1111-1111-111111111111","display_name":"Baseline GPO"}],"configured_relationships":[{"gpo_guid":"{11111111-1111-1111-1111-111111111111}","source_dn":"OU=Servers,DC=example,DC=test","source_type":"ou","target_container_dn":"OU=Servers,DC=example,DC=test","enabled":true,"enforced":false,"link_order":1,"classification":"configured_direct","applicability":"configured_only","source_artifact":"GPO_links.json"}],"limitations":["application not verified"]}`
	if err := os.WriteFile(filepath.Join(dir, "GPO_metadata.json"), []byte(metadata), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "GPO_applicability.json"), []byte(applicability), 0600); err != nil {
		t.Fatal(err)
	}
	inventory := ACLInventoryReport{Domain: "example.test", SourceExecutionID: 7, SourceArtifact: "rusthound/gpos.json", Relationships: []ACLInventoryRelationship{{PrincipalID: "S-1-5-21-1-1-1-1001", PrincipalName: "HELPDESK@EXAMPLE.TEST", PrincipalType: "group", TargetID: "22222222-2222-2222-2222-222222222222", TargetName: "Wrong display name is not used", TargetType: "gpos", TargetClass: "gpo_container", Permission: "WriteDacl", Decision: "unknown", Inheritance: "explicit", Artifact: "rusthound/gpos.json", ArtifactRef: "/data/0/Aces/1"}}}
	report, input, err := AnalyzeGPOPrivilegeRelationships(inventory, 3, time.Unix(0, 0), root)
	if err != nil {
		t.Fatal(err)
	}
	if input == nil || len(report.GPOs) != 1 {
		t.Fatalf("expected one finding and GPO, got input=%v gpos=%d", input != nil, len(report.GPOs))
	}
	if report.GPOs[0].GUID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("unexpected canonical GUID: %s", report.GPOs[0].GUID)
	}
	if !report.SnapshotMismatch || report.Status != "partial" {
		t.Fatalf("expected partial snapshot mismatch, got status=%s mismatch=%v", report.Status, report.SnapshotMismatch)
	}
	if !strings.Contains(input.Description, "not verified") {
		t.Fatalf("missing effective-right disclaimer: %s", input.Description)
	}
	var evidence map[string]any
	if err := json.Unmarshal([]byte(input.EvidenceJSON), &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence["gpo_source_execution_id"] != float64(12) {
		t.Fatalf("missing GPO execution provenance: %#v", evidence)
	}
}

func TestGPOPrivilegeRelationshipsRejectDisplayNameOnlyJoin(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "Enumeration", "ActiveDirectory", "GPO")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "GPO_metadata.json"), []byte(`{"domain":"example.test","gpos":[{"guid":"11111111-1111-1111-1111-111111111111","object_guid":"22222222-2222-2222-2222-222222222222","attributes":{"displayName":{"values":["Same Name"]}}}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "GPO_applicability.json"), []byte(`{"domain":"example.test","collection_execution_id":1,"configured_relationships":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	inventory := ACLInventoryReport{Domain: "example.test", SourceExecutionID: 1, Relationships: []ACLInventoryRelationship{{PrincipalID: "p", TargetID: "not-a-guid", TargetName: "Same Name", TargetClass: "gpo_container", Permission: "GenericWrite"}}}
	report, input, err := AnalyzeGPOPrivilegeRelationships(inventory, 1, time.Now(), root)
	if err != nil {
		t.Fatal(err)
	}
	if input != nil || len(report.GPOs) != 0 || len(report.Unresolved) != 1 {
		t.Fatalf("display-name join was accepted: input=%v gpos=%d unresolved=%d", input != nil, len(report.GPOs), len(report.Unresolved))
	}
}
