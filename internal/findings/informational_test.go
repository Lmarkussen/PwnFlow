package findings

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

func writeInformationalFixture(t *testing.T, dir, name, kind string, data []map[string]any) string {
	t.Helper()
	path := filepath.Join(dir, name)
	payload, err := json.Marshal(map[string]any{"meta": map[string]any{"type": kind}, "data": data})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDeriveInformationalFindingsFromHistoricalRustHound(t *testing.T) {
	dir := t.TempDir()
	domainSID := "S-1-5-21-1-2-3"
	groups := writeInformationalFixture(t, dir, "lab_groups.json", "groups", []map[string]any{
		{"ObjectIdentifier": domainSID + "-512", "Properties": map[string]any{"name": "DOMAIN ADMINS@LAB.TEST", "samaccountname": "Domain Admins", "domain": "LAB.TEST", "domainsid": domainSID}, "Members": []string{domainSID + "-1100", domainSID + "-2100"}},
		{"ObjectIdentifier": domainSID + "-2100", "Properties": map[string]any{"name": "HELPDESK@LAB.TEST", "samaccountname": "Helpdesk", "domain": "LAB.TEST", "domainsid": domainSID}, "Members": []string{domainSID + "-1101"}},
	})
	writeInformationalFixture(t, dir, "lab_users.json", "users", []map[string]any{
		{"ObjectIdentifier": domainSID + "-1100", "Properties": map[string]any{"name": "ADMIN@LAB.TEST", "domain": "LAB.TEST", "enabled": true}},
		{"ObjectIdentifier": domainSID + "-1100", "Properties": map[string]any{"name": "ADMIN@LAB.TEST", "domain": "LAB.TEST", "enabled": true}},
		{"ObjectIdentifier": domainSID + "-1101", "Properties": map[string]any{"name": "USER@LAB.TEST", "domain": "LAB.TEST", "enabled": false}},
	})
	writeInformationalFixture(t, dir, "lab_computers.json", "computers", []map[string]any{
		{"ObjectIdentifier": domainSID + "-1000", "Properties": map[string]any{"name": "DC01.LAB.TEST", "domain": "LAB.TEST", "isdc": true, "ipaddress": "10.0.0.10"}},
	})

	rows := []storage.Finding{{FindingInput: storage.FindingInput{
		AssessmentID: 7, SourceTool: "RustHound-CE", SourceExecution: 12, FindingType: "ad_privileged_group_membership_inventory",
		AffectedObjectID: domainSID + "-512", ArtifactPath: groups, ArtifactRef: "/data/0/Members", ObservedAt: time.Unix(10, 0),
	}, FirstSeen: time.Unix(10, 0), LastSeen: time.Unix(10, 0)}}
	derived := DeriveInformationalFindings(context.Background(), rows)
	if len(derived) != 3 {
		t.Fatalf("derived rows=%d, want group/user/DC summaries: %#v", len(derived), derived)
	}
	seen := map[string]storage.Finding{}
	for _, row := range derived {
		seen[row.FindingType] = row
	}
	groupEvidence := map[string]any{}
	if err := json.Unmarshal([]byte(seen["domain_information_privileged_group_membership"].EvidenceJSON), &groupEvidence); err != nil {
		t.Fatal(err)
	}
	if groupEvidence["effective_member_count"] != float64(2) || groupEvidence["domain_sid"] != domainSID {
		t.Fatalf("group evidence=%v", groupEvidence)
	}
	userEvidence := map[string]any{}
	if err := json.Unmarshal([]byte(seen["domain_information_user_inventory"].EvidenceJSON), &userEvidence); err != nil {
		t.Fatal(err)
	}
	if userEvidence["distinct_user_count"] != float64(2) || userEvidence["enabled_count"] != float64(1) || userEvidence["disabled_count"] != float64(1) {
		t.Fatalf("user evidence=%v", userEvidence)
	}
	controllerEvidence := map[string]any{}
	if err := json.Unmarshal([]byte(seen["domain_information_domain_controllers"].EvidenceJSON), &controllerEvidence); err != nil {
		t.Fatal(err)
	}
	if controllerEvidence["verified_domain_controller_count"] != float64(1) {
		t.Fatalf("controller evidence=%v", controllerEvidence)
	}
}
