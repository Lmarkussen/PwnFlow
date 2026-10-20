package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const writableObjectsParserVersion = "rusthound-writable-objects-v1"
const writableObjectsMaxRelationships = 500

type WritableObjectRelationship struct {
	PrincipalID         string             `json:"principal_id"`
	PrincipalName       string             `json:"principal_name,omitempty"`
	MembershipPath      []ACLMembershipHop `json:"membership_path,omitempty"`
	TargetID            string             `json:"target_id"`
	TargetName          string             `json:"target_name,omitempty"`
	TargetType          string             `json:"target_type"`
	Permission          string             `json:"permission"`
	Decision            string             `json:"decision"`
	Inheritance         string             `json:"inheritance"`
	ObjectType          string             `json:"object_type,omitempty"`
	InheritedObjectType string             `json:"inherited_object_type,omitempty"`
	Evaluation          string             `json:"evaluation"`
	Artifact            string             `json:"artifact"`
	ArtifactRef         string             `json:"artifact_ref"`
}

type WritableObjectReport struct {
	SchemaVersion      int                          `json:"schema_version"`
	ParserVersion      string                       `json:"parser_version"`
	Status             string                       `json:"status"`
	Coverage           string                       `json:"coverage"`
	Domain             string                       `json:"domain,omitempty"`
	AuthenticatedUser  string                       `json:"authenticated_user"`
	SourceArtifact     string                       `json:"source_artifact"`
	SourceArtifacts    []ACLInventorySourceArtifact `json:"source_artifacts,omitempty"`
	Relationships      []WritableObjectRelationship `json:"relationships,omitempty"`
	MembershipCoverage string                       `json:"membership_coverage"`
	UnresolvedCount    int                          `json:"unresolved_count"`
	Limitations        []string                     `json:"limitations"`
	AnalysisTimestamp  time.Time                    `json:"analysis_timestamp"`
}

// AnalyzeRustHoundWritableObjects evaluates only relationships that can be
// tied to the configured identity or one of its source-backed membership
// paths. It deliberately reports potential applicability, never effective
// Windows authorization or verified modification capability.
func AnalyzeRustHoundWritableObjects(ctx context.Context, inputPath, domain, username string, now time.Time) (WritableObjectReport, error) {
	inventory, _, err := AnalyzeRustHoundACLInventoryIncludingAll(ctx, inputPath, 1, 1, now)
	if err != nil {
		return WritableObjectReport{}, err
	}
	if sourceDomain := strings.TrimSpace(inventory.Domain); sourceDomain != "" && !strings.Contains(sourceDomain, "=") && !strings.EqualFold(sourceDomain, strings.TrimSpace(domain)) {
		return WritableObjectReport{}, fmt.Errorf("RustHound evidence domain %q does not match configured domain %q", sourceDomain, domain)
	}
	report := WritableObjectReport{
		SchemaVersion: 1, ParserVersion: writableObjectsParserVersion, Status: "partial", Coverage: "source-backed-potential",
		Domain: domain, AuthenticatedUser: username, SourceArtifact: inventory.SourceArtifact,
		SourceArtifacts:    append([]ACLInventorySourceArtifact(nil), inventory.InputArtifacts...),
		MembershipCoverage: inventory.MembershipCoverage, UnresolvedCount: len(inventory.Unresolved), AnalysisTimestamp: now.UTC(),
		Limitations: []string{
			"Results are observed or potentially applicable source ACL relationships, not verified effective access.",
			"Windows token construction, deny precedence across all ACEs, SIDHistory, protected groups, and schema applicability were not fully evaluated.",
			"A missing relationship does not establish that the authenticated identity cannot modify an object.",
		},
	}
	identityNames := identityVariants(domain, username)
	identityIDs := map[string]bool{}
	for _, relation := range inventory.Relationships {
		if matchesIdentity(relation.PrincipalName, identityNames) || strings.EqualFold(relation.PrincipalID, username) {
			identityIDs[strings.ToLower(relation.PrincipalID)] = true
		}
	}
	for _, context := range inventory.MembershipContext {
		if matchesIdentity(context.MemberName, identityNames) || matchesIdentity(context.MemberID, identityNames) {
			identityIDs[strings.ToLower(context.MemberID)] = true
		}
	}
	denyKeys := make(map[string]bool)
	for _, relation := range inventory.Relationships {
		if strings.EqualFold(relation.Decision, "deny") {
			denyKeys[writableRelationshipKey(relation.TargetID, relation.Permission, relation.ObjectType, relation.InheritedObjectType)] = true
		}
	}
	seen := make(map[string]bool)
	for _, relation := range inventory.Relationships {
		if !isWritablePermission(relation.Permission) {
			continue
		}
		if matchesIdentity(relation.PrincipalName, identityNames) || identityIDs[strings.ToLower(relation.PrincipalID)] {
			path := []ACLMembershipHop(nil)
			report.addRelationship(seen, relation, path, denyKeys)
		}
	}
	for _, context := range inventory.MembershipContext {
		if !matchesIdentity(context.MemberName, identityNames) && !matchesIdentity(context.MemberID, identityNames) {
			continue
		}
		if !isWritablePermission(context.Permission) {
			continue
		}
		relation := ACLInventoryRelationship{PrincipalID: context.ACLPrincipalID, PrincipalName: context.ACLPrincipalName, TargetID: context.TargetID, TargetName: context.TargetName, TargetType: context.TargetClass, Permission: context.Permission, Decision: context.Decision, Inheritance: context.Inheritance, Classification: context.Classification, Artifact: context.ACLArtifact, ArtifactRef: context.ACLArtifactRef}
		report.addRelationship(seen, relation, context.GroupPath, denyKeys)
	}
	sort.SliceStable(report.Relationships, func(i, j int) bool {
		left := report.Relationships[i]
		right := report.Relationships[j]
		return strings.Join([]string{left.TargetID, left.Permission, left.PrincipalID, left.ArtifactRef}, "\x00") < strings.Join([]string{right.TargetID, right.Permission, right.PrincipalID, right.ArtifactRef}, "\x00")
	})
	return report, nil
}

func (report *WritableObjectReport) addRelationship(seen map[string]bool, relation ACLInventoryRelationship, path []ACLMembershipHop, denyKeys map[string]bool) {
	if len(report.Relationships) >= writableObjectsMaxRelationships {
		return
	}
	key := strings.Join([]string{relation.PrincipalID, relation.TargetID, relation.Permission, relation.Decision, relation.Inheritance, relation.ObjectType, relation.InheritedObjectType, pathKey(path)}, "\x00")
	if seen[key] {
		return
	}
	seen[key] = true
	evaluation := "indeterminate"
	switch strings.ToLower(relation.Decision) {
	case "deny":
		evaluation = "explicit-deny-observed"
	case "allow":
		evaluation = "potentially-applicable"
		if denyKeys[writableRelationshipKey(relation.TargetID, relation.Permission, relation.ObjectType, relation.InheritedObjectType)] {
			evaluation = "indeterminate-deny-present"
		}
	}
	report.Relationships = append(report.Relationships, WritableObjectRelationship{PrincipalID: relation.PrincipalID, PrincipalName: relation.PrincipalName, MembershipPath: append([]ACLMembershipHop(nil), path...), TargetID: relation.TargetID, TargetName: relation.TargetName, TargetType: relation.TargetType, Permission: relation.Permission, Decision: relation.Decision, Inheritance: relation.Inheritance, ObjectType: relation.ObjectType, InheritedObjectType: relation.InheritedObjectType, Evaluation: evaluation, Artifact: relation.Artifact, ArtifactRef: relation.ArtifactRef})
}

func isWritablePermission(value string) bool {
	switch strings.ToLower(strings.ReplaceAll(value, " ", "")) {
	case "genericall", "genericwrite", "writedacl", "writeowner", "writeproperty", "addmember", "addself", "forcechangepassword", "validatedwrite", "createchild", "writespn", "addkeycredentiallink", "addallowedtoact":
		return true
	default:
		return false
	}
}

func writableRelationshipKey(target, permission, objectType, inheritedObjectType string) string {
	return strings.Join([]string{target, permission, objectType, inheritedObjectType}, "\x00")
}

func pathKey(path []ACLMembershipHop) string {
	parts := make([]string, len(path))
	for index, hop := range path {
		parts[index] = hop.ID + "@" + hop.ArtifactRef
	}
	return strings.Join(parts, "/")
}

func identityVariants(domain, username string) []string {
	username = strings.TrimSpace(username)
	domain = strings.TrimSpace(domain)
	return []string{strings.ToLower(username), strings.ToLower(domain + "\\" + username), strings.ToLower(username + "@" + domain)}
}

func matchesIdentity(value string, variants []string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, variant := range variants {
		if value != "" && value == variant {
			return true
		}
	}
	return false
}

func WriteWritableObjectReport(resultsRoot string, report WritableObjectReport) (string, error) {
	if report.SourceArtifact == "" {
		return "", fmt.Errorf("writable-object report has no RustHound source artifact")
	}
	directory := filepath.Join(resultsRoot, "Enumeration", "PwnTools", "ADWritableObjects")
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(directory, "writable-objects.json")
	return WriteWritableObjectReportAt(path, report)
}

func WriteWritableObjectReportAt(path string, report WritableObjectReport) (string, error) {
	if report.SourceArtifact == "" {
		return "", fmt.Errorf("writable-object report has no RustHound source artifact")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", err
	}
	return path, nil
}

func AnalyzeWritableObjectReport(ctx context.Context, path string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var report WritableObjectReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	if report.ParserVersion != writableObjectsParserVersion || report.SourceArtifact == "" {
		return nil, fmt.Errorf("unsupported writable-object report")
	}
	evidence, _ := json.Marshal(report)
	keyHash := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%d\x00%s", assessmentID, executionID, report.SourceArtifact)))
	description := "RustHound evidence identifies source-backed write-capable relationships for the configured identity. Effective modification access is not verified."
	if len(report.Relationships) == 0 {
		description = "RustHound evidence did not yield a source-backed writable relationship for the configured identity; collection and analysis limitations mean this does not establish that no writable objects exist."
	}
	finding := storage.FindingInput{FindingKey: "adwritable:" + hex.EncodeToString(keyHash[:]), AssessmentID: assessmentID, SourceTool: "AD Writable Object Assessment", SourceExecution: executionID, FindingType: "ad_writable_object_assessment", Title: "AD Writable Object Assessment", Description: description, Severity: "informational", Confidence: "source-backed-potential", AffectedObjectID: report.AuthenticatedUser, AffectedObject: report.AuthenticatedUser, EvidenceJSON: string(evidence), ArtifactPath: path, ArtifactRef: "/", ObservedAt: now, Status: "open", ParserVersion: writableObjectsParserVersion}
	return []storage.FindingInput{finding}, nil
}
