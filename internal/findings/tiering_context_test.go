package findings

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeTierContextUsesDeclaredPolicyAndObservedMembership(t *testing.T) {
	root := t.TempDir()
	artifact := filepath.Join(root, "Enumeration", "RustHoundCE", "artifacts", "snapshot")
	if err := os.MkdirAll(artifact, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(name string, value any) {
		data, _ := json.Marshal(value)
		if err := os.WriteFile(filepath.Join(artifact, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	domainSID := "S-1-5-21-1-2-3"
	groupSID := domainSID + "-1152"
	userSID := domainSID + "-1156"
	bridgeSID := domainSID + "-1151"
	write("groups.json", map[string]any{"meta": map[string]string{"type": "groups"}, "data": []any{
		map[string]any{"ObjectIdentifier": groupSID, "Properties": map[string]any{"name": "PF-T1-Admins", "domain": "SCCM.LAB", "domainsid": domainSID, "distinguishedname": "CN=PF-T1-Admins,DC=SCCM,DC=LAB"}, "Members": []string{userSID}},
		map[string]any{"ObjectIdentifier": bridgeSID, "Properties": map[string]any{"name": "PF-T1-Bridge", "domain": "SCCM.LAB", "domainsid": domainSID}, "Members": []string{groupSID}},
	}})
	write("users.json", map[string]any{"meta": map[string]string{"type": "users"}, "data": []any{map[string]any{"ObjectIdentifier": userSID, "Properties": map[string]any{"name": "PF-T1-Admin", "domain": "SCCM.LAB", "domainsid": domainSID}}}})
	policyDir := filepath.Join(root, "Enumeration", "ActiveDirectory", "Tiering")
	if err := os.MkdirAll(policyDir, 0700); err != nil {
		t.Fatal(err)
	}
	policy := TierAssignmentPolicy{SchemaVersion: 1, PolicyID: "lab-tier-policy", Version: "1", Domain: "SCCM.LAB", DomainSID: domainSID, Source: "fixture-manifest", Assignments: []TierAssignment{{Tier: 1, GroupID: groupSID, Label: "server administration", Target: TierTarget{Name: "MSSQL.SCCM.LAB", IP: "10.1.10.42"}}}}
	data, _ := json.Marshal(policy)
	if err := os.WriteFile(filepath.Join(policyDir, "tier_policy.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	report, input, err := AnalyzeTierContext(context.Background(), artifact, root, ACLInventoryReport{Domain: "SCCM.LAB"}, 1, 82, 1, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if input == nil || input.FindingType != "ad_tier1_context_evidence" || len(report.DeclaredGroups) != 1 || len(report.MembershipPaths) != 1 {
		t.Fatalf("unexpected result: input=%+v groups=%d paths=%d", input, len(report.DeclaredGroups), len(report.MembershipPaths))
	}
	if report.MembershipPaths[0].Classification != "direct" || !strings.Contains(report.MembershipPaths[0].MemberName, "PF-T1-Admin") {
		t.Fatalf("membership not source-backed: %+v", report.MembershipPaths)
	}
	txt, _, err := WriteTierContextArtifacts(root, report)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(txt); err != nil {
		t.Fatal(err)
	}
}

func TestAnalyzeTierContextRequiresExplicitPolicy(t *testing.T) {
	root := t.TempDir()
	artifact := filepath.Join(root, "artifacts")
	os.MkdirAll(artifact, 0700)
	_, input, err := AnalyzeTierContext(context.Background(), artifact, root, ACLInventoryReport{Domain: "SCCM.LAB"}, 1, 1, 2, time.Now())
	if err != nil || input != nil {
		t.Fatalf("missing policy must be not assessed, err=%v input=%v", err, input)
	}
}
