package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeRustHoundWritableObjectsResolvesDirectAndNestedEvidence(t *testing.T) {
	root := t.TempDir()
	writeExport(t, root+"/groups.json", "groups", []map[string]any{
		{
			"ObjectIdentifier": "S-1-5-21-100-900",
			"Properties":       map[string]any{"name": "Helpdesk", "domain": "EXAMPLE.TEST"},
			"Members":          []string{"S-1-5-21-100-901"},
		},
		{
			"ObjectIdentifier": "S-1-5-21-100-901",
			"Properties":       map[string]any{"name": "Nested Support", "domain": "EXAMPLE.TEST"},
			"Members":          []string{"S-1-5-21-100-1101"},
		},
		{
			"ObjectIdentifier": "S-1-5-21-100-1101",
			"Properties":       map[string]any{"name": "alice", "domain": "EXAMPLE.TEST"},
		},
		{
			"ObjectIdentifier": "S-1-5-21-100-1102",
			"Properties":       map[string]any{"name": "target", "domain": "EXAMPLE.TEST"},
		},
	})
	writeExport(t, root+"/users.json", "users", []map[string]any{
		{"ObjectIdentifier": "S-1-5-21-100-1101", "Properties": map[string]any{"name": "alice", "domain": "EXAMPLE.TEST"}},
		{"ObjectIdentifier": "S-1-5-21-100-1102", "Properties": map[string]any{"name": "target", "domain": "EXAMPLE.TEST"}, "Aces": []map[string]any{{"PrincipalSID": "S-1-5-21-100-1101", "RightName": "WriteProperty", "IsAllowed": true, "ObjectType": "attribute-guid"}, {"PrincipalSID": "S-1-5-21-100-900", "PrincipalType": "Group", "RightName": "GenericWrite", "IsAllowed": true}}},
	})
	writeExport(t, root+"/domains.json", "domains", []map[string]any{{"ObjectIdentifier": "S-1-5-21-100", "Properties": map[string]any{"name": "EXAMPLE.TEST", "domain": "EXAMPLE.TEST"}}})

	report, err := AnalyzeRustHoundWritableObjects(context.Background(), root, "EXAMPLE.TEST", "alice", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "partial" || report.Coverage != "source-backed-potential" || report.SourceArtifact == "" {
		t.Fatalf("unexpected report metadata: %+v", report)
	}
	if len(report.Relationships) != 2 {
		t.Fatalf("relationships=%d, want direct and nested: %+v", len(report.Relationships), report.Relationships)
	}
	for _, relationship := range report.Relationships {
		if relationship.Evaluation != "potentially-applicable" || relationship.Artifact == "" || relationship.ArtifactRef == "" {
			t.Fatalf("relationship overclaimed or lost provenance: %+v", relationship)
		}
	}
	data, _ := json.Marshal(report)
	if strings.Contains(strings.ToLower(string(data)), "effective_access") || strings.Contains(strings.ToLower(string(data)), "verified modification") {
		t.Fatal("report used an effective or verified-access claim")
	}
}

func TestAnalyzeRustHoundWritableObjectsMarksDenyAsIndeterminate(t *testing.T) {
	report := WritableObjectReport{SourceArtifact: "rusthound", Domain: "EXAMPLE.TEST", AuthenticatedUser: "alice"}
	seen := map[string]bool{}
	denies := map[string]bool{writableRelationshipKey("target", "GenericWrite", "", ""): true}
	report.addRelationship(seen, ACLInventoryRelationship{PrincipalID: "alice", PrincipalName: "alice", TargetID: "target", Permission: "GenericWrite", Decision: "allow", Artifact: "users.json", ArtifactRef: "/data/0"}, nil, denies)
	if len(report.Relationships) != 1 || report.Relationships[0].Evaluation != "indeterminate-deny-present" {
		t.Fatalf("deny precedence was not surfaced conservatively: %+v", report.Relationships)
	}
}

func TestWritableObjectReportTracksBoundedRelationships(t *testing.T) {
	report := WritableObjectReport{SourceArtifact: "rusthound"}
	seen := map[string]bool{}
	for index := 0; index < writableObjectsMaxRelationships+3; index++ {
		report.addRelationship(seen, ACLInventoryRelationship{
			PrincipalID: "alice", TargetID: fmt.Sprintf("target-%d", index), Permission: "GenericWrite", Decision: "allow",
		}, nil, nil)
	}
	if report.QualifyingRelationships != writableObjectsMaxRelationships+3 || report.IncludedRelationships != writableObjectsMaxRelationships || report.OmittedRelationships != 3 {
		t.Fatalf("bounded counts incorrect: qualifying=%d included=%d omitted=%d", report.QualifyingRelationships, report.IncludedRelationships, report.OmittedRelationships)
	}
}
