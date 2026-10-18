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

func TestAnalyzeRustHoundACLInventoryPreservesDirectEvidence(t *testing.T) {
	root := t.TempDir()
	writeExport(t, filepath.Join(root, "groups.json"), "groups", []map[string]any{
		{
			"ObjectIdentifier": "S-1-5-21-100-512",
			"Properties":       map[string]any{"name": "Renamed Admins", "domainsid": "S-1-5-21-100"},
			"Aces": []map[string]any{
				{"PrincipalSID": "S-1-5-21-100-1101", "PrincipalType": "User", "RightName": "WriteDacl", "IsAllowed": true, "IsInherited": false},
				{"PrincipalSID": "S-1-5-21-100-1101", "PrincipalType": "User", "RightName": "WriteDacl", "IsAllowed": true, "IsInherited": false},
				{"PrincipalSID": "S-1-5-21-100-1102", "PrincipalType": "User", "RightName": "GenericAll", "AceType": "Deny", "IsInherited": true, "ObjectType": "object-guid"},
				{"PrincipalSID": "S-1-5-21-foreign-1103", "RightName": "UnsupportedRight"},
				{"PrincipalSID": "S-1-5-21-100-9999", "RightName": "AddMember"},
			},
		},
		{"ObjectIdentifier": "S-1-5-21-100-1101", "Properties": map[string]any{"name": "alice", "domain": "EXAMPLE.TEST"}},
		{"ObjectIdentifier": "S-1-5-21-100-1102", "Properties": map[string]any{"name": "bob", "domain": "EXAMPLE.TEST"}},
	})
	writeExport(t, filepath.Join(root, "domains.json"), "domains", []map[string]any{
		{"ObjectIdentifier": "S-1-5-21-100", "Properties": map[string]any{"name": "EXAMPLE.TEST", "domain": "EXAMPLE.TEST"}, "Aces": []map[string]any{{"PrincipalSID": "S-1-5-21-100-1101", "RightName": "GetChangesAll"}}},
	})

	report, inputs, err := AnalyzeRustHoundACLInventory(context.Background(), root, 7, 435, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "partial" || report.SupportedACLs != 5 || report.NormalizedRelations != 4 {
		t.Fatalf("unexpected inventory report: %+v", report)
	}
	if len(report.HighValueTargets) != 2 {
		t.Fatalf("expected privileged group and domain targets, got %+v", report.HighValueTargets)
	}
	if len(report.Unresolved) != 1 || report.Unresolved[0].ID != "S-1-5-21-100-9999" {
		t.Fatalf("unresolved principal was not retained: %+v", report.Unresolved)
	}
	if report.Relationships[2].Decision != "deny" || report.Relationships[2].Inheritance != "inherited" || report.Relationships[2].ObjectType != "object-guid" {
		t.Fatalf("ACE semantics were not preserved: %+v", report.Relationships)
	}
	if len(inputs) != 1 || inputs[0].SourceExecution != 435 || inputs[0].Severity != "informational" {
		t.Fatalf("unexpected finding input: %+v", inputs)
	}
	var evidence map[string]any
	if err := json.Unmarshal([]byte(inputs[0].EvidenceJSON), &evidence); err != nil {
		t.Fatal(err)
	}
	overview, ok := evidence["relationship_overview"].([]any)
	if !ok || len(overview) == 0 {
		t.Fatalf("finding did not retain a relationship overview: %+v", evidence)
	}
	if got, _ := evidence["structured_artifact"].(string); got != "Enumeration/ActiveDirectory/ACL/execution-435/AD_privileged_acl_inventory.json" {
		t.Fatalf("structured artifact path was not execution-specific: %q", got)
	}
	overviewJSON, _ := json.Marshal(overview)
	for _, expected := range []string{"alice", "WriteDacl", "S-1-5-21-100-512"} {
		if !strings.Contains(string(overviewJSON), expected) {
			t.Fatalf("relationship overview omitted %q: %s", expected, overviewJSON)
		}
	}
	if strings.Contains(strings.ToLower(inputs[0].Description), "effective") && strings.Contains(strings.ToLower(inputs[0].Description), "verified") {
		t.Fatal("inventory observation overclaimed effective access")
	}
}

func TestACLInventoryOutputIsProvenanceBoundAndSecretSafe(t *testing.T) {
	root := t.TempDir()
	report := ACLInventoryReport{SchemaVersion: 1, ParserVersion: aclInventoryParserVersion, Domain: "example.test", SourceExecutionID: 12, SourceArtifact: filepath.Join(root, "source"), AnalysisTimestamp: time.Unix(1, 0).UTC(), Status: "partial", Limitations: []string{"effective access not evaluated"}}
	path, err := WriteACLInventoryArtifact(root, report)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ACLInventoryReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SourceExecutionID != 12 || !strings.Contains(path, "execution-12") {
		t.Fatalf("artifact lost execution provenance: path=%s report=%+v", path, decoded)
	}
	if strings.Contains(string(data), "password") || strings.Contains(string(data), "cpassword") {
		t.Fatal("secret-bearing fields entered the inventory artifact")
	}
	text := FormatACLInventoryReport(report)
	for _, expected := range []string{"Observed relationships", "effective access", "exploitability"} {
		if !strings.Contains(strings.ToLower(text), strings.ToLower(expected)) {
			t.Fatalf("report omitted %q", expected)
		}
	}
	for _, forbidden := range []string{"verified attack path", "effective_admin", "dcsync_capable", "verified_exploitable"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Fatalf("report contains prohibited conclusion %q", forbidden)
		}
	}
}

func TestACLInventoryAddsSameExecutionMembershipContext(t *testing.T) {
	root := t.TempDir()
	writeExport(t, filepath.Join(root, "groups.json"), "groups", []map[string]any{
		{
			"ObjectIdentifier": "S-1-5-21-100-900",
			"Properties":       map[string]any{"name": "Helpdesk Operators", "domain": "EXAMPLE.TEST"},
			"Members":          []any{map[string]any{"ObjectIdentifier": "S-1-5-21-100-901"}, "S-1-5-21-100-901"},
		},
		{
			"ObjectIdentifier": "S-1-5-21-100-901",
			"Properties":       map[string]any{"name": "Tier 1 Support", "domain": "EXAMPLE.TEST"},
			"Members":          []string{"S-1-5-21-100-1101"},
		},
		{
			"ObjectIdentifier": "S-1-5-21-100-512",
			"Properties":       map[string]any{"name": "Domain Admins", "domain": "EXAMPLE.TEST", "highvalue": true},
			"Aces":             []map[string]any{{"PrincipalSID": "S-1-5-21-100-900", "PrincipalType": "Group", "RightName": "WriteDacl", "IsInherited": false}},
		},
	})
	writeExport(t, filepath.Join(root, "users.json"), "users", []map[string]any{
		{"ObjectIdentifier": "S-1-5-21-100-1101", "Properties": map[string]any{"name": "alice", "domain": "EXAMPLE.TEST"}},
	})

	report, inputs, err := AnalyzeRustHoundACLInventory(context.Background(), root, 7, 477, time.Unix(2, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 1 || report.NormalizedRelations != 1 {
		t.Fatalf("direct ACL evidence changed: report=%+v inputs=%d", report, len(inputs))
	}
	if report.MembershipEdges != 2 || report.DirectMembershipPaths != 0 || report.NestedMembershipPaths != 1 || report.MembershipContextualizedPrincipals != 1 {
		t.Fatalf("unexpected membership counts: %+v", report)
	}
	if len(report.MembershipContext) != 1 {
		t.Fatalf("expected one deduplicated nested path, got %+v", report.MembershipContext)
	}
	path := report.MembershipContext[0]
	if path.MemberID != "S-1-5-21-100-1101" || path.Classification != "observed_nested_membership_context" || path.EffectivePermission != "NOT VERIFIED" {
		t.Fatalf("unexpected context: %+v", path)
	}
	if len(path.GroupPath) != 2 || path.GroupPath[0].ID != "S-1-5-21-100-901" || path.GroupPath[1].ID != "S-1-5-21-100-900" {
		t.Fatalf("membership path direction was not preserved: %+v", path.GroupPath)
	}
	if path.ACLArtifact == "" || len(path.MembershipRefs) != 2 || path.ACLArtifactRef == "" {
		t.Fatalf("context lost evidence references: %+v", path)
	}
	if !strings.Contains(FormatACLInventoryReport(report), "Effective permission: NOT VERIFIED") {
		t.Fatal("TXT report omitted the effective-right limitation")
	}
	var evidence map[string]any
	if err := json.Unmarshal([]byte(inputs[0].EvidenceJSON), &evidence); err != nil {
		t.Fatal(err)
	}
	if _, ok := evidence["membership_context"].([]any); !ok {
		t.Fatalf("finding omitted membership context: %s", inputs[0].EvidenceJSON)
	}
}

func TestACLInventoryMembershipCyclesDoNotExpandIndefinitely(t *testing.T) {
	root := t.TempDir()
	writeExport(t, filepath.Join(root, "groups.json"), "groups", []map[string]any{
		{"ObjectIdentifier": "S-1-5-21-100-900", "Properties": map[string]any{"name": "ACL Group", "domain": "EXAMPLE.TEST"}, "Members": []string{"S-1-5-21-100-901"}},
		{"ObjectIdentifier": "S-1-5-21-100-901", "Properties": map[string]any{"name": "Nested Group", "domain": "EXAMPLE.TEST"}, "Members": []string{"S-1-5-21-100-900"}},
		{"ObjectIdentifier": "S-1-5-21-100-512", "Properties": map[string]any{"name": "Domain Admins", "highvalue": true}, "Aces": []map[string]any{{"PrincipalSID": "S-1-5-21-100-900", "RightName": "GenericAll"}}},
	})
	report, _, err := AnalyzeRustHoundACLInventory(context.Background(), root, 7, 478, time.Unix(2, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.MembershipContext) != 0 || !strings.Contains(strings.Join(report.MembershipLimitations, "\n"), "Cycle encountered") {
		t.Fatalf("cycle was not safely bounded: %+v", report)
	}
}
