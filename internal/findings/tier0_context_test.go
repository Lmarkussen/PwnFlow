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

func TestAnalyzeTier0ContextPublishesBoundedInformationalOverview(t *testing.T) {
	root := filepath.Join(t.TempDir(), "results", "sccm.lab", "Enumeration", "RustHoundCE", "artifacts", "snapshot-31")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	domainSID := "S-1-5-21-1-2-3"
	writeRustHoundFixture(t, filepath.Join(root, "domains.json"), "domains", []map[string]any{{
		"ObjectIdentifier": domainSID,
		"Properties":       map[string]any{"name": "SCCM.LAB", "domain": "SCCM.LAB", "domainsid": domainSID, "highvalue": true},
		"Aces":             []map[string]any{{"PrincipalSID": domainSID + "-1100", "RightName": "GetChangesAll", "IsAllowed": true}},
	}})
	writeRustHoundFixture(t, filepath.Join(root, "computers.json"), "computers", []map[string]any{{
		"ObjectIdentifier": domainSID + "-1001",
		"Properties":       map[string]any{"name": "DC.SCCM.LAB", "domain": "SCCM.LAB", "distinguishedname": "CN=DC,OU=DOMAIN CONTROLLERS,DC=SCCM,DC=LAB", "isdc": true},
	}})
	writeRustHoundFixture(t, filepath.Join(root, "users.json"), "users", []map[string]any{{
		"ObjectIdentifier": domainSID + "-1100",
		"Properties":       map[string]any{"name": "ALICE@SCCM.LAB", "samaccountname": "alice", "domain": "SCCM.LAB", "domainsid": domainSID, "admincount": true},
	}})
	writeRustHoundFixture(t, filepath.Join(root, "groups.json"), "groups", []map[string]any{{
		"ObjectIdentifier": domainSID + "-512",
		"Properties":       map[string]any{"name": "DOMAIN ADMINS@SCCM.LAB", "samaccountname": "Domain Admins", "domain": "SCCM.LAB", "domainsid": domainSID, "admincount": true},
		"Members":          []string{domainSID + "-1100"},
	}})
	writeRustHoundFixture(t, filepath.Join(root, "containers.json"), "containers", []map[string]any{{
		"ObjectIdentifier": "adminsdholder-guid",
		"Properties":       map[string]any{"name": "ADMINSDHOLDER@SCCM.LAB", "distinguishedname": "CN=ADMINSDHOLDER,CN=SYSTEM,DC=SCCM,DC=LAB", "domain": "SCCM.LAB"},
		"IsACLProtected":   true,
	}})

	protected, _, err := AnalyzeProtectedAccounts(context.Background(), root, 7, 31, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	inventory, _, err := AnalyzeRustHoundACLInventory(context.Background(), root, 7, 31, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	report, input, err := AnalyzeTier0Context(context.Background(), root, inventory, protected, 7, 31, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if input == nil || input.FindingType != "ad_tier0_context_evidence" || input.Severity != "informational" {
		t.Fatalf("unexpected tier 0 input: %#v", input)
	}
	if report.Domain != "SCCM.LAB" || len(report.DomainControllers) != 1 || len(report.Tier0Groups) != 1 || len(report.MembershipPaths) != 1 {
		t.Fatalf("unexpected tier 0 report: %+v", report)
	}
	if len(report.ACLRelationships) == 0 || len(report.Replication) == 0 || report.AdminSDHolder == nil {
		t.Fatalf("tier 0 context omitted supported relationships: %+v", report)
	}
	if !strings.Contains(input.Description, "do not establish effective administrative authorization") {
		t.Fatal("effective-authority disclaimer missing")
	}
	var evidence map[string]any
	if err := json.Unmarshal([]byte(input.EvidenceJSON), &evidence); err != nil {
		t.Fatal(err)
	}
	if _, ok := evidence["tier0_groups"]; !ok {
		t.Fatal("structured tier 0 group evidence missing")
	}
	if _, ok := evidence["membership_paths"]; !ok {
		t.Fatal("structured tier 0 identity evidence missing")
	}
	if _, err := os.Stat(input.ArtifactPath); err != nil {
		t.Fatalf("tier 0 report missing: %v", err)
	}
}

func TestTier0GroupPolicyDoesNotUseDisplayName(t *testing.T) {
	if _, ok := tier0GroupRole("S-1-5-21-1-2-3-512"); !ok {
		t.Fatal("authoritative Domain Admins RID was not recognized")
	}
	if _, ok := tier0GroupRole("display-name-domain-admins"); ok {
		t.Fatal("display name was incorrectly treated as authoritative")
	}
}
