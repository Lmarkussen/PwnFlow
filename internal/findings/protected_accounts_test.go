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

func TestAnalyzeProtectedAccountsCorrelatesSameSnapshot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "results", "sccm.lab", "Enumeration", "RustHoundCE", "artifacts", "run-1")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	domainSID := "S-1-5-21-1-2-3"
	writeRustHoundFixture(t, filepath.Join(root, "users.json"), "users", []map[string]any{
		{"ObjectIdentifier": domainSID + "-1100", "Properties": map[string]any{"name": "Alice@SCCM.LAB", "samaccountname": "Alice", "domain": "SCCM.LAB", "domainsid": domainSID, "admincount": true}},
		{"ObjectIdentifier": domainSID + "-1101", "Properties": map[string]any{"name": "Bob@SCCM.LAB", "samaccountname": "Bob", "domain": "SCCM.LAB", "domainsid": domainSID, "admincount": false}},
	})
	writeRustHoundFixture(t, filepath.Join(root, "groups.json"), "groups", []map[string]any{
		{"ObjectIdentifier": domainSID + "-512", "Properties": map[string]any{"name": "DOMAIN ADMINS@SCCM.LAB", "samaccountname": "Domain Admins", "domain": "SCCM.LAB", "domainsid": domainSID, "admincount": true}, "Members": []string{domainSID + "-1100"}},
		{"ObjectIdentifier": domainSID + "-520", "Properties": map[string]any{"name": "GROUP POLICY CREATOR OWNERS@SCCM.LAB", "samaccountname": "Group Policy Creator Owners", "domain": "SCCM.LAB", "domainsid": domainSID, "admincount": false}, "Members": []string{domainSID + "-1101"}},
	})
	writeRustHoundFixture(t, filepath.Join(root, "containers.json"), "containers", []map[string]any{
		{"ObjectIdentifier": "adminsdholder-guid", "Properties": map[string]any{"name": "ADMINSDHOLDER@SCCM.LAB", "distinguishedname": "CN=ADMINSDHOLDER,CN=SYSTEM,DC=SCCM,DC=LAB", "domain": "SCCM.LAB"}},
		{"ObjectIdentifier": "other-container", "Properties": map[string]any{"name": "OTHER", "domain": "SCCM.LAB"}, "IsACLProtected": false},
	})
	// Put the ACE on the matched AdminSDHolder record, not the first container.
	data, err := os.ReadFile(filepath.Join(root, "containers.json"))
	if err != nil {
		t.Fatal(err)
	}
	var export map[string]any
	if err := json.Unmarshal(data, &export); err != nil {
		t.Fatal(err)
	}
	rows := export["data"].([]any)
	rows[0].(map[string]any)["IsACLProtected"] = true
	rows[0].(map[string]any)["Aces"] = []map[string]any{{"PrincipalName": "DOMAIN ADMINS", "PrincipalSID": domainSID + "-512", "RightName": "WriteDacl", "IsInherited": false}}
	data, _ = json.Marshal(export)
	if err := os.WriteFile(filepath.Join(root, "containers.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	report, finding, err := AnalyzeProtectedAccounts(context.Background(), root, 7, 42, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.FindingType != "ad_protected_accounts_admincount_evidence" || finding.Severity != "informational" {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if report.SourceExecutionID != 42 || report.SourceSnapshot != "run-1" || report.Domain != "SCCM.LAB" {
		t.Fatalf("incorrect source identity: %#v", report)
	}
	if countAdmin(report.Users) != 1 || countAdmin(report.Groups) != 1 {
		t.Fatalf("unexpected adminCount inventory: users=%d groups=%d", countAdmin(report.Users), countAdmin(report.Groups))
	}
	if len(report.MembershipPaths) != 2 {
		t.Fatalf("expected two observed membership paths, got %d", len(report.MembershipPaths))
	}
	if report.AdminSDHolder == nil || report.AdminSDHolder.ACLProtected != "true" || len(report.AdminSDHolder.ACEs) != 1 || report.AdminSDHolder.ACEs[0].Rights != "WriteDacl" {
		t.Fatalf("matched AdminSDHolder record was not decoded: %#v", report.AdminSDHolder)
	}
	if report.EffectiveProtection != "NOT VERIFIED" || !strings.Contains(stringMust(finding.EvidenceJSON), "NOT VERIFIED") {
		t.Fatal("effective protection disclaimer missing")
	}
	if _, err := os.Stat(finding.ArtifactPath); err != nil {
		t.Fatalf("report was not written: %v", err)
	}
	reportText, err := os.ReadFile(finding.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"ADMINCOUNT=TRUE USERS", "ADMINCOUNT=TRUE GROUPS", "OBSERVED PROTECTED-GROUP MEMBERSHIP PATHS", "ATTRIBUTE / MEMBERSHIP DIFFERENCES", "ADMINSDHOLDER", "REMAINING USER/GROUP INVENTORY", "LIMITATIONS"} {
		if !strings.Contains(string(reportText), section) {
			t.Fatalf("report missing section %q", section)
		}
	}
	for _, name := range []string{"Alice", "Domain Admins", "ADMINSDHOLDER"} {
		if !strings.Contains(string(finding.EvidenceJSON), name) {
			t.Fatalf("finding preview missing source-backed identity %q", name)
		}
	}
}

func writeRustHoundFixture(t *testing.T, path, kind string, data []map[string]any) {
	t.Helper()
	payload := map[string]any{"meta": map[string]any{"type": kind}, "data": data}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func stringMust(value string) string { return value }
