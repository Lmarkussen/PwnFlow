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

func TestAnalyzeRustHoundGroupsNormalizesNestedAndUnresolvedMembership(t *testing.T) {
	dir := t.TempDir()
	writeRustHoundTestExport(t, dir, "groups", []map[string]any{
		{"ObjectIdentifier": "S-1-5-21-1-2-3-512", "Properties": map[string]any{"name": "DOMAIN ADMINS@EXAMPLE.TEST", "samaccountname": "Domain Admins", "domain": "EXAMPLE.TEST", "domainsid": "S-1-5-21-1-2-3"}, "Members": []any{map[string]any{"ObjectIdentifier": "S-1-5-21-1-2-3-900", "ObjectType": "Group"}, "S-1-5-21-1-2-3-999"}},
		{"ObjectIdentifier": "S-1-5-21-1-2-3-900", "Properties": map[string]any{"name": "Operations", "samaccountname": "Operations", "domain": "EXAMPLE.TEST", "domainsid": "S-1-5-21-1-2-3"}, "Members": []string{"S-1-5-21-1-2-3-901"}},
		{"ObjectIdentifier": "S-1-5-21-1-2-3-901", "Properties": map[string]any{"name": "Cycle", "samaccountname": "Cycle", "domain": "EXAMPLE.TEST", "domainsid": "S-1-5-21-1-2-3"}, "Members": []string{"S-1-5-21-1-2-3-900"}},
		{"ObjectIdentifier": "S-1-5-32-544", "Properties": map[string]any{"name": "Administrators", "samaccountname": "Administrators", "domain": "EXAMPLE.TEST"}, "Members": []string{}},
		{"ObjectIdentifier": "S-1-5-21-1-2-3-777", "Properties": map[string]any{"name": "Custom Admin", "samaccountname": "Custom Admin", "domain": "EXAMPLE.TEST"}, "Members": []string{}},
	})
	writeRustHoundTestExport(t, dir, "users", []map[string]any{
		{"ObjectIdentifier": "S-1-5-21-1-2-3-901", "Properties": map[string]any{"name": "svc-admin", "samaccountname": "svc-admin", "domain": "EXAMPLE.TEST", "enabled": false}},
	})
	report, inputs, err := AnalyzeRustHoundGroups(context.Background(), dir, 1, 2, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if report.GroupsExamined != 5 || report.DirectEdges != 4 {
		t.Fatalf("counts = %+v", report)
	}
	if len(report.PrivilegedGroups) != 2 {
		t.Fatalf("privileged groups = %d", len(report.PrivilegedGroups))
	}
	var domainAdmins PrivilegedGroup
	for _, group := range report.PrivilegedGroups {
		if group.Privilege == "Domain Admins" {
			domainAdmins = group
		}
	}
	if len(domainAdmins.NestedMembers) != 1 || domainAdmins.NestedMembers[0].Name != "svc-admin" || !domainAdmins.NestedMembers[0].Disabled {
		t.Fatalf("nested member = %+v", domainAdmins.NestedMembers)
	}
	if len(domainAdmins.Unresolved) != 1 {
		t.Fatalf("unresolved = %+v", domainAdmins.Unresolved)
	}
	if len(inputs) < 3 {
		t.Fatalf("expected observations, got %d", len(inputs))
	}
	for _, input := range inputs {
		if strings.Contains(input.EvidenceJSON, "password") || input.ArtifactPath == "" {
			t.Fatalf("unsafe or unlinked input: %+v", input)
		}
	}
}

func writeRustHoundTestExport(t *testing.T, dir, kind string, data []map[string]any) {
	t.Helper()
	value, err := json.Marshal(map[string]any{"meta": map[string]any{"type": kind, "version": 6}, "data": data})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, kind+".json"), value, 0o600); err != nil {
		t.Fatal(err)
	}
}
