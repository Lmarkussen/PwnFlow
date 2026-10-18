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

const aclInventoryParserVersion = "rusthound-acl-inventory-v1"

const aclInventoryObservationMaxRelationships = 12

const (
	aclInventoryMaxObjects         = 100000
	aclInventoryMaxACEs            = 250000
	aclInventoryMaxRelationships   = 1000
	aclInventoryMaxUnresolved      = 256
	aclInventoryMaxArtifacts       = 512
	aclInventoryMaxMembershipDepth = 8
	aclInventoryMaxMembershipPaths = 256
	aclInventoryMaxPathsPerGroup   = 16
)

var inventoryRights = map[string]bool{
	"genericall": true, "genericwrite": true, "writedacl": true, "writeowner": true,
	"owns": true, "writeproperty": true, "addmember": true, "addself": true,
	"forcechangepassword": true, "allextendedrights": true, "addkeycredentiallink": true,
	"writespn": true, "getchanges": true, "getchangesall": true,
	"getchangesinfilteredset": true, "addallowedtoact": true,
}

type ACLInventoryReport struct {
	SchemaVersion                      int                          `json:"schema_version"`
	ParserVersion                      string                       `json:"parser_version"`
	Domain                             string                       `json:"domain,omitempty"`
	SourceExecutionID                  int64                        `json:"source_execution_id"`
	SourceArtifact                     string                       `json:"source_artifact"`
	AnalysisTimestamp                  time.Time                    `json:"analysis_timestamp"`
	Status                             string                       `json:"status"`
	ObjectsInspected                   int                          `json:"objects_inspected"`
	RawACLsInspected                   int                          `json:"raw_acls_inspected"`
	SupportedACLs                      int                          `json:"supported_acls"`
	NormalizedRelations                int                          `json:"normalized_relationships"`
	OmittedRelations                   int                          `json:"omitted_relationships"`
	HighValueTargets                   []ACLInventoryTarget         `json:"high_value_targets"`
	Relationships                      []ACLInventoryRelationship   `json:"relationships"`
	Unresolved                         []ACLInventoryUnresolved     `json:"unresolved_identities"`
	UnsupportedRights                  map[string]int               `json:"unsupported_rights,omitempty"`
	MalformedEntries                   int                          `json:"malformed_entries"`
	InputArtifacts                     []ACLInventorySourceArtifact `json:"input_artifacts"`
	Limits                             ACLInventoryLimits           `json:"limits"`
	Limitations                        []string                     `json:"limitations"`
	MembershipContext                  []ACLMembershipContext       `json:"membership_context,omitempty"`
	MembershipEdges                    int                          `json:"membership_edges"`
	MembershipContextualizedPrincipals int                          `json:"membership_contextualized_principals"`
	DirectMembershipPaths              int                          `json:"direct_membership_paths"`
	NestedMembershipPaths              int                          `json:"nested_membership_paths"`
	UnresolvedMembershipPaths          int                          `json:"unresolved_membership_paths"`
	OmittedMembershipPaths             int                          `json:"omitted_membership_paths"`
	MembershipTruncated                bool                         `json:"membership_truncated"`
	MembershipCoverage                 string                       `json:"membership_coverage"`
	MembershipLimitations              []string                     `json:"membership_limitations,omitempty"`
}

type ACLMembershipHop struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Type        string `json:"type,omitempty"`
	Artifact    string `json:"artifact"`
	ArtifactRef string `json:"artifact_ref"`
}

type ACLMembershipContext struct {
	MemberID            string             `json:"member_id"`
	MemberName          string             `json:"member_name,omitempty"`
	MemberType          string             `json:"member_type,omitempty"`
	GroupPath           []ACLMembershipHop `json:"group_path"`
	ACLPrincipalID      string             `json:"acl_principal_id"`
	ACLPrincipalName    string             `json:"acl_principal_name,omitempty"`
	TargetID            string             `json:"target_id"`
	TargetName          string             `json:"target_name,omitempty"`
	TargetClass         string             `json:"target_class"`
	Permission          string             `json:"permission"`
	Decision            string             `json:"decision"`
	Inheritance         string             `json:"inheritance"`
	Classification      string             `json:"classification"`
	EffectivePermission string             `json:"effective_permission"`
	MembershipArtifacts []string           `json:"membership_artifacts,omitempty"`
	MembershipRefs      []string           `json:"membership_refs,omitempty"`
	ACLArtifact         string             `json:"acl_artifact"`
	ACLArtifactRef      string             `json:"acl_artifact_ref"`
}

type aclMembershipEdge struct {
	MemberID string
	Artifact string
	Ref      string
}

type ACLInventoryTarget struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	ObjectType  string `json:"object_type"`
	Class       string `json:"classification"`
	HighValue   bool   `json:"high_value"`
	Artifact    string `json:"artifact"`
	ArtifactRef string `json:"artifact_ref"`
}

type ACLInventoryRelationship struct {
	PrincipalID         string `json:"principal_id"`
	PrincipalName       string `json:"principal_name,omitempty"`
	PrincipalType       string `json:"principal_type,omitempty"`
	TargetID            string `json:"target_id"`
	TargetName          string `json:"target_name,omitempty"`
	TargetType          string `json:"target_type"`
	TargetClass         string `json:"target_class"`
	Permission          string `json:"permission"`
	Decision            string `json:"decision"`
	Inheritance         string `json:"inheritance"`
	ObjectType          string `json:"object_type,omitempty"`
	InheritedObjectType string `json:"inherited_object_type,omitempty"`
	Classification      string `json:"classification"`
	Occurrences         int    `json:"occurrences"`
	Artifact            string `json:"artifact"`
	ArtifactRef         string `json:"artifact_ref"`
}

type ACLInventoryUnresolved struct {
	ID          string `json:"id"`
	Role        string `json:"role"`
	TargetID    string `json:"target_id,omitempty"`
	Permission  string `json:"permission,omitempty"`
	Artifact    string `json:"artifact"`
	ArtifactRef string `json:"artifact_ref"`
}

type ACLInventorySourceArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type ACLInventoryLimits struct {
	MaxObjects       int `json:"max_objects"`
	MaxACLs          int `json:"max_acls"`
	MaxRelationships int `json:"max_relationships"`
	MaxUnresolved    int `json:"max_unresolved"`
}

// ACLInventoryObservationRelationships returns a stable, bounded selection for
// the Findings detail view. The complete relationship set remains in the
// execution-associated JSON and TXT report.
func ACLInventoryObservationRelationships(report ACLInventoryReport) []ACLInventoryRelationship {
	relations := append([]ACLInventoryRelationship(nil), report.Relationships...)
	sort.SliceStable(relations, func(left, right int) bool {
		leftPriority := aclInventoryTargetPriority(relations[left].TargetClass)
		rightPriority := aclInventoryTargetPriority(relations[right].TargetClass)
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		for _, pair := range [][2]string{{relations[left].TargetName, relations[right].TargetName}, {relations[left].TargetID, relations[right].TargetID}, {relations[left].Permission, relations[right].Permission}, {relations[left].PrincipalName, relations[right].PrincipalName}, {relations[left].PrincipalID, relations[right].PrincipalID}, {relations[left].Decision, relations[right].Decision}, {relations[left].Inheritance, relations[right].Inheritance}} {
			if pair[0] != pair[1] {
				return pair[0] < pair[1]
			}
		}
		return relations[left].ArtifactRef < relations[right].ArtifactRef
	})
	selected := make([]ACLInventoryRelationship, 0, minInt(aclInventoryObservationMaxRelationships, len(relations)))
	seenTargets := map[string]bool{}
	for _, relation := range relations {
		if len(selected) >= aclInventoryObservationMaxRelationships {
			break
		}
		if !seenTargets[relation.TargetID] {
			selected = append(selected, relation)
			seenTargets[relation.TargetID] = true
		}
	}
	if len(selected) < aclInventoryObservationMaxRelationships {
		selectedKeys := make(map[string]bool, len(selected))
		for _, relation := range selected {
			selectedKeys[aclInventoryRelationshipKey(relation)] = true
		}
		for _, relation := range relations {
			if len(selected) >= aclInventoryObservationMaxRelationships {
				break
			}
			if !selectedKeys[aclInventoryRelationshipKey(relation)] {
				selected = append(selected, relation)
				selectedKeys[aclInventoryRelationshipKey(relation)] = true
			}
		}
	}
	return selected
}

func aclInventoryTargetPriority(class string) int {
	class = strings.ToLower(class)
	switch {
	case class == "domain_root", strings.HasPrefix(class, "privileged_group"):
		return 0
	case class == "domain_controller":
		return 1
	case class == "high_value_ou", class == "gpo_container":
		return 2
	default:
		return 3
	}
}

func aclInventoryRelationshipKey(relation ACLInventoryRelationship) string {
	return strings.Join([]string{relation.PrincipalID, relation.TargetID, relation.Permission, relation.Decision, relation.Inheritance, relation.ObjectType, relation.InheritedObjectType}, "\x00")
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

type aclInventoryObject struct {
	collectedObject
	Class string
}

func AnalyzeRustHoundACLInventory(ctx context.Context, inputPath string, assessmentID, executionID int64, now time.Time) (ACLInventoryReport, []storage.FindingInput, error) {
	if assessmentID <= 0 || executionID <= 0 {
		return ACLInventoryReport{}, nil, fmt.Errorf("ACL inventory requires positive assessment and execution IDs")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	files, err := rustHoundGroupFiles(inputPath)
	if err != nil {
		return ACLInventoryReport{}, nil, err
	}
	report := ACLInventoryReport{
		SchemaVersion: 1, ParserVersion: aclInventoryParserVersion, SourceExecutionID: executionID,
		SourceArtifact: inputPath, AnalysisTimestamp: now.UTC(), Status: "complete",
		UnsupportedRights: map[string]int{}, Limits: ACLInventoryLimits{aclInventoryMaxObjects, aclInventoryMaxACEs, aclInventoryMaxRelationships, aclInventoryMaxUnresolved},
		Limitations: []string{"Observed direct ACL relationships do not establish effective access or exploitability.", "Deny precedence, group-expanded rights and object-specific effective semantics are not calculated."},
	}
	objects := map[string]aclInventoryObject{}
	membershipEdges := map[string][]aclMembershipEdge{}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return report, nil, err
		}
		data, readErr := os.ReadFile(file)
		if readErr != nil {
			return report, nil, readErr
		}
		if len(report.InputArtifacts) < aclInventoryMaxArtifacts {
			hash := sha256.Sum256(data)
			report.InputArtifacts = append(report.InputArtifacts, ACLInventorySourceArtifact{Path: file, SHA256: hex.EncodeToString(hash[:]), Bytes: int64(len(data))})
		}
		var export rustHoundExport
		if err := json.Unmarshal(data, &export); err != nil {
			return report, nil, fmt.Errorf("parse ACL artifact %s: %w", file, err)
		}
		for index, raw := range export.Data {
			if report.ObjectsInspected >= aclInventoryMaxObjects {
				report.Status = "partial"
				report.Limitations = append(report.Limitations, "Maximum object limit reached; remaining objects were not inspected.")
				break
			}
			object, _, decodeErr := decodeObject(raw, strings.ToLower(export.Meta.Type))
			if decodeErr != nil {
				report.MalformedEntries++
				continue
			}
			if object.ID == "" {
				report.MalformedEntries++
				continue
			}
			object.Artifact = file
			object.RefPrefix = fmt.Sprintf("/data/%d", index)
			objects[strings.ToLower(strings.TrimSpace(object.ID))] = aclInventoryObject{collectedObject: object, Class: classifyACLTarget(object)}
			if report.Domain == "" {
				report.Domain = firstString(object.Properties, "domain", "distinguishedname")
			}
			report.ObjectsInspected++
			if strings.EqualFold(export.Meta.Type, "groups") {
				var fields map[string]json.RawMessage
				_ = json.Unmarshal(raw, &fields)
				memberIDs, malformedMembers := rawMembershipIDs(fields)
				report.MalformedEntries += malformedMembers
				for memberIndex, memberID := range memberIDs {
					if strings.TrimSpace(memberID) == "" {
						continue
					}
					membershipEdges[strings.ToLower(strings.TrimSpace(object.ID))] = append(membershipEdges[strings.ToLower(strings.TrimSpace(object.ID))], aclMembershipEdge{MemberID: memberID, Artifact: file, Ref: fmt.Sprintf("/data/%d/Members/%d", index, memberIndex)})
				}
			}
		}
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return report, nil, err
		}
		data, readErr := os.ReadFile(file)
		if readErr != nil {
			return report, nil, readErr
		}
		var export rustHoundExport
		if err := json.Unmarshal(data, &export); err != nil {
			continue
		}
		for objectIndex, raw := range export.Data {
			object, aces, decodeErr := decodeObject(raw, strings.ToLower(export.Meta.Type))
			if decodeErr != nil || object.ID == "" {
				continue
			}
			target := objects[strings.ToLower(strings.TrimSpace(object.ID))]
			if target.Class == "" {
				continue
			}
			for aceIndex, ace := range aces {
				if err := ctx.Err(); err != nil {
					return report, nil, err
				}
				if report.RawACLsInspected >= aclInventoryMaxACEs {
					report.Status = "partial"
					report.Limitations = append(report.Limitations, "Maximum ACL-record limit reached; remaining ACL records were not inspected.")
					break
				}
				report.RawACLsInspected++
				right := aceString(ace, "RightName")
				if strings.TrimSpace(right) == "" {
					report.MalformedEntries++
					continue
				}
				key := normalize(right)
				if !inventoryRights[key] {
					report.UnsupportedRights[right]++
					continue
				}
				report.SupportedACLs++
				principalID := aceString(ace, "PrincipalSID")
				principal, resolved := objects[strings.ToLower(strings.TrimSpace(principalID))]
				principalName, principalType := "", ""
				if resolved {
					principalName = objectLabel(principal.collectedObject)
				} else if principalID != "" {
					principalName = principalID
				}
				principalType = aceString(ace, "PrincipalType")
				if principalType == "" && resolved {
					principalType = principal.Type
				}
				artifactRef := fmt.Sprintf("/data/%d/Aces/%d", objectIndex, aceIndex)
				if principalID == "" {
					report.MalformedEntries++
					addUnresolved(&report, ACLInventoryUnresolved{ID: "", Role: "unresolved_principal", TargetID: target.ID, Permission: right, Artifact: file, ArtifactRef: artifactRef})
					continue
				}
				decision := aclDecision(ace)
				inheritance := "unknown"
				if inherited, known := rawBoolValue(ace, "IsInherited"); known {
					if inherited {
						inheritance = "inherited"
					} else {
						inheritance = "explicit"
					}
				}
				objectType := firstString(ace, "ObjectType", "ObjectTypeGuid", "ObjectTypeGUID")
				inheritedObjectType := firstString(ace, "InheritedObjectType", "InheritedObjectTypeGuid", "InheritedObjectTypeGUID")
				classification := "direct_permission_evidence"
				if inheritance == "inherited" {
					classification = "inherited_permission_evidence"
				}
				if decision == "deny" {
					classification = "deny_permission_evidence"
				}
				if !resolved {
					classification = "unresolved_identity"
					addUnresolved(&report, ACLInventoryUnresolved{ID: principalID, Role: "unresolved_principal", TargetID: target.ID, Permission: right, Artifact: file, ArtifactRef: artifactRef})
				}
				rel := ACLInventoryRelationship{PrincipalID: principalID, PrincipalName: principalName, PrincipalType: principalType, TargetID: target.ID, TargetName: objectLabel(target.collectedObject), TargetType: target.Type, TargetClass: target.Class, Permission: right, Decision: decision, Inheritance: inheritance, ObjectType: objectType, InheritedObjectType: inheritedObjectType, Classification: classification, Occurrences: 1, Artifact: file, ArtifactRef: artifactRef}
				if !appendRelationship(&report, rel) {
					report.OmittedRelations++
					report.Status = "partial"
					report.Limitations = append(report.Limitations, "Maximum relationship-detail limit reached; additional normalized relationships were counted but not listed.")
				}
			}
		}
	}
	if report.Status == "complete" && (report.MalformedEntries > 0 || len(report.UnsupportedRights) > 0 || len(report.Unresolved) > 0) {
		report.Status = "partial"
	}
	for groupID, values := range membershipEdges {
		membershipEdges[groupID] = dedupeMembershipEdges(values)
	}
	report.MembershipEdges = membershipEdgeCount(membershipEdges)
	enrichACLInventoryMembershipContext(&report, objects, membershipEdges)
	if report.SupportedACLs == 0 {
		return report, nil, nil
	}
	overview := ACLInventoryObservationRelationships(report)
	membershipOverview := aclMembershipObservation(report)
	evidence, _ := json.Marshal(map[string]any{"source_execution_id": executionID, "source_artifact": inputPath, "structured_artifact": "Enumeration/ActiveDirectory/ACL/execution-<execution-id>/AD_privileged_acl_inventory.json", "human_report": "AD_PRIVILEGED_ACL_EVIDENCE.txt", "relationship_overview": overview, "relationship_overview_limit": aclInventoryObservationMaxRelationships, "membership_context": membershipOverview, "membership_context_limit": aclInventoryObservationMaxRelationships, "membership_edges": report.MembershipEdges, "membership_contextualized_principals": report.MembershipContextualizedPrincipals, "direct_membership_paths": report.DirectMembershipPaths, "nested_membership_paths": report.NestedMembershipPaths, "unresolved_membership_paths": report.UnresolvedMembershipPaths, "omitted_membership_paths": report.OmittedMembershipPaths, "membership_coverage": report.MembershipCoverage, "membership_limitations": report.MembershipLimitations, "high_value_targets": len(report.HighValueTargets), "normalized_relationships": report.NormalizedRelations, "unresolved_principals": len(report.Unresolved), "unsupported_relationships": unsupportedCount(report.UnsupportedRights), "omitted_relationships": report.OmittedRelations, "malformed_entries": report.MalformedEntries, "status": report.Status})
	description := fmt.Sprintf("RustHound execution %d contains %d normalized direct ACL relationships affecting %d classified high-value targets and %d observed membership-context paths. These are informational directory relationships; effective permission and exploitability were not evaluated.", executionID, report.NormalizedRelations, len(report.HighValueTargets), len(report.MembershipContext))
	input := storage.FindingInput{FindingKey: aclInventoryFindingKey(assessmentID, executionID, inputPath), AssessmentID: assessmentID, SourceTool: "RustHound-CE", SourceExecution: executionID, FindingType: "ad_privileged_acl_evidence_inventory", Title: "AD Privileged ACL Evidence Inventory", Description: description, Severity: "informational", Confidence: "observed-direct-acl-coverage-partial", AffectedObjectID: inputPath, AffectedObject: "RustHound direct ACL inventory", EvidenceJSON: string(evidence), ArtifactPath: inputPath, ArtifactRef: "/", ObservedAt: now, Status: "open", ParserVersion: aclInventoryParserVersion}
	return report, []storage.FindingInput{input}, nil
}

func classifyACLTarget(object collectedObject) string {
	if object.HighValue {
		return "high_value"
	}
	props := object.Properties
	if object.Type == "domains" {
		return "domain_root"
	}
	if object.Type == "gpos" {
		return "gpo_container"
	}
	if object.Type == "ous" && rawBool(props, "highvalue") {
		return "high_value_ou"
	}
	if object.Type == "computers" && rawBool(props, "isdc") {
		return "domain_controller"
	}
	if object.Type == "groups" {
		if privilege, ok := privilegedGroupName(groupObject{ID: object.ID, DomainSID: rawString(props, "domainsid")}); ok {
			return "privileged_group:" + privilege
		}
	}
	return ""
}

func aclDecision(ace map[string]json.RawMessage) string {
	for _, key := range []string{"IsAllowed", "Allowed", "Allow"} {
		if value, known := rawBoolValue(ace, key); known {
			if value {
				return "allow"
			}
			return "deny"
		}
	}
	value := strings.ToLower(firstString(ace, "AceType", "AccessType", "Type"))
	if strings.Contains(value, "deny") {
		return "deny"
	}
	if strings.Contains(value, "allow") {
		return "allow"
	}
	return "unknown"
}

func appendRelationship(report *ACLInventoryReport, relationship ACLInventoryRelationship) bool {
	for index := range report.Relationships {
		existing := &report.Relationships[index]
		if existing.PrincipalID == relationship.PrincipalID && existing.TargetID == relationship.TargetID && existing.Permission == relationship.Permission && existing.Decision == relationship.Decision && existing.Inheritance == relationship.Inheritance && existing.ObjectType == relationship.ObjectType && existing.InheritedObjectType == relationship.InheritedObjectType {
			existing.Occurrences++
			return true
		}
	}
	if len(report.Relationships) >= aclInventoryMaxRelationships {
		return false
	}
	report.Relationships = append(report.Relationships, relationship)
	report.NormalizedRelations++
	ensureTarget(report, relationship)
	return true
}

func ensureTarget(report *ACLInventoryReport, relationship ACLInventoryRelationship) {
	for _, target := range report.HighValueTargets {
		if target.ID == relationship.TargetID {
			return
		}
	}
	for _, artifact := range report.InputArtifacts {
		_ = artifact
	}
	// Target details are filled from relationship data; the source reference is the ACE.
	report.HighValueTargets = append(report.HighValueTargets, ACLInventoryTarget{ID: relationship.TargetID, Name: relationship.TargetName, ObjectType: relationship.TargetType, Class: relationship.TargetClass, HighValue: true, Artifact: relationship.Artifact, ArtifactRef: relationship.ArtifactRef})
}

func addUnresolved(report *ACLInventoryReport, unresolved ACLInventoryUnresolved) {
	for _, existing := range report.Unresolved {
		if existing.ID == unresolved.ID && existing.TargetID == unresolved.TargetID && existing.Permission == unresolved.Permission {
			return
		}
	}
	if len(report.Unresolved) < aclInventoryMaxUnresolved {
		report.Unresolved = append(report.Unresolved, unresolved)
	}
}
func unsupportedCount(values map[string]int) int {
	total := 0
	for _, value := range values {
		total += value
	}
	return total
}
func aclInventoryFindingKey(assessmentID, executionID int64, artifact string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%d\x00%s\x00%s", assessmentID, executionID, aclInventoryParserVersion, artifact)))
	return "adprivacl:" + hex.EncodeToString(sum[:])
}

func WriteACLInventoryArtifact(resultsRoot string, report ACLInventoryReport) (string, error) {
	if report.SourceExecutionID <= 0 {
		return "", fmt.Errorf("ACL inventory source execution is missing")
	}
	directory := filepath.Join(resultsRoot, "Enumeration", "ActiveDirectory", "ACL", fmt.Sprintf("execution-%d", report.SourceExecutionID))
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(directory, "AD_privileged_acl_inventory.json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	temporary, err := os.CreateTemp(directory, ".acl-inventory-*.tmp")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return "", err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return "", err
	}
	return path, nil
}

func FormatACLInventoryReport(report ACLInventoryReport) string {
	var b strings.Builder
	fmt.Fprintln(&b, "======================================================================")
	fmt.Fprintln(&b, "             PWNFLOW AD PRIVILEGED ACL EVIDENCE INVENTORY")
	fmt.Fprintln(&b, "======================================================================")
	fmt.Fprintf(&b, "\nDOMAIN: %s\nSOURCE EXECUTION: %d\nSOURCE ARTIFACT: %s\nSTATUS: %s\nANALYZED: %s\n", report.Domain, report.SourceExecutionID, report.SourceArtifact, report.Status, report.AnalysisTimestamp.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "\nObjects inspected: %d\nRaw ACL records inspected: %d\nSupported ACL records: %d\nNormalized relationships: %d\nOmitted relationships: %d\nHigh-value targets: %d\nUnresolved identities: %d\nUnsupported rights: %d\nMalformed entries: %d\n", report.ObjectsInspected, report.RawACLsInspected, report.SupportedACLs, report.NormalizedRelations, report.OmittedRelations, len(report.HighValueTargets), len(report.Unresolved), unsupportedCount(report.UnsupportedRights), report.MalformedEntries)
	fmt.Fprintln(&b, "\n----------------------------------------------------------------------\nOBSERVED RELATIONSHIPS\n----------------------------------------------------------------------")
	for _, target := range report.HighValueTargets {
		fmt.Fprintf(&b, "\nTarget: %s\nIdentity: %s\nType: %s\n", target.Name, target.ID, target.ObjectType)
		for _, rel := range report.Relationships {
			if rel.TargetID == target.ID {
				principal := rel.PrincipalName
				if principal == "" {
					principal = "(unresolved)"
				}
				fmt.Fprintf(&b, "  %s -> %s -> %s [%s]\n", principal, rel.Permission, target.Name, target.ID)
				fmt.Fprintf(&b, "    Decision: %s | Inheritance: %s | Principal ID: %s | Target type: %s\n", rel.Decision, rel.Inheritance, rel.PrincipalID, rel.TargetType)
				if rel.ObjectType != "" || rel.InheritedObjectType != "" {
					fmt.Fprintf(&b, "    Object restriction: object_type=%s inherited_object_type=%s\n", rel.ObjectType, rel.InheritedObjectType)
				}
				fmt.Fprintf(&b, "    Source: %s#%s\n", rel.Artifact, rel.ArtifactRef)
			}
		}
	}
	fmt.Fprintln(&b, "\n----------------------------------------------------------------------\nMEMBERSHIP CONTEXT\n----------------------------------------------------------------------")
	fmt.Fprintf(&b, "Membership edges observed: %d\nContextualized ACL principals: %d\nDirect membership paths: %d\nNested membership paths: %d\nUnresolved membership paths: %d\nCoverage: %s\n", report.MembershipEdges, report.MembershipContextualizedPrincipals, report.DirectMembershipPaths, report.NestedMembershipPaths, report.UnresolvedMembershipPaths, fallbackReportText(report.MembershipCoverage, "unknown"))
	if len(report.MembershipContext) == 0 {
		fmt.Fprintln(&b, "No membership context observed in this collection.")
	} else {
		for _, context := range report.MembershipContext {
			fmt.Fprintf(&b, "\nTarget: %s [%s]\nObserved ACL: %s -> %s\nACL principal: %s [%s]\n", context.TargetName, context.TargetID, fallbackReportText(context.ACLPrincipalName, context.ACLPrincipalID), context.Permission, fallbackReportText(context.ACLPrincipalName, context.ACLPrincipalID), context.ACLPrincipalID)
			fmt.Fprintf(&b, "Member: %s [%s]\nPath: %s\nClassification: %s\nEffective permission: %s\n", fallbackReportText(context.MemberName, context.MemberID), context.MemberID, formatMembershipPath(context), context.Classification, context.EffectivePermission)
			fmt.Fprintf(&b, "Membership evidence: %s\nACL evidence: %s#%s\n", formatMembershipEvidence(context), context.ACLArtifact, context.ACLArtifactRef)
		}
	}
	for _, limitation := range report.MembershipLimitations {
		fmt.Fprintf(&b, "- Membership limitation: %s\n", limitation)
	}
	if len(report.Unresolved) > 0 {
		fmt.Fprintln(&b, "\n----------------------------------------------------------------------\nUNRESOLVED IDENTITIES\n----------------------------------------------------------------------")
		for _, item := range report.Unresolved {
			fmt.Fprintf(&b, "- %s: %s target=%s permission=%s\n", item.Role, item.ID, item.TargetID, item.Permission)
		}
	}
	if len(report.UnsupportedRights) > 0 {
		fmt.Fprintln(&b, "\n----------------------------------------------------------------------\nUNSUPPORTED RIGHTS\n----------------------------------------------------------------------")
		rights := make([]string, 0, len(report.UnsupportedRights))
		for right := range report.UnsupportedRights {
			rights = append(rights, right)
		}
		sort.Strings(rights)
		for _, right := range rights {
			count := report.UnsupportedRights[right]
			fmt.Fprintf(&b, "- %s: %d\n", right, count)
		}
	}
	fmt.Fprintln(&b, "\n----------------------------------------------------------------------\nLIMITATIONS\n----------------------------------------------------------------------")
	for _, limitation := range report.Limitations {
		fmt.Fprintf(&b, "- %s\n", limitation)
	}
	fmt.Fprintln(&b, "- This report contains observed ACL relationships only; it does not verify effective access, DCSync capability, an attack path or exploitability.")
	return b.String()
}

func fallbackReportText(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func formatMembershipPath(context ACLMembershipContext) string {
	parts := []string{fallbackReportText(context.MemberName, context.MemberID)}
	for _, hop := range context.GroupPath {
		parts = append(parts, "MemberOf: "+fallbackReportText(hop.Name, hop.ID))
	}
	return strings.Join(parts, " -> ")
}

func formatMembershipEvidence(context ACLMembershipContext) string {
	values := make([]string, 0, len(context.MembershipRefs))
	for index, ref := range context.MembershipRefs {
		artifact := ""
		if index < len(context.MembershipArtifacts) {
			artifact = context.MembershipArtifacts[index]
		}
		if artifact != "" {
			values = append(values, artifact+"#"+ref)
		} else {
			values = append(values, ref)
		}
	}
	return strings.Join(values, ", ")
}

func membershipEdgeCount(edges map[string][]aclMembershipEdge) int {
	count := 0
	for _, values := range edges {
		count += len(values)
	}
	return count
}

func rawMembershipIDs(fields map[string]json.RawMessage) ([]string, int) {
	var raw json.RawMessage
	for key, value := range fields {
		if strings.EqualFold(key, "Members") {
			raw = value
			break
		}
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, 0
	}
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		var single string
		if json.Unmarshal(raw, &single) == nil && strings.TrimSpace(single) != "" {
			return []string{single}, 0
		}
		return nil, 1
	}
	ids := make([]string, 0, len(values))
	malformed := 0
	for _, value := range values {
		var id string
		if json.Unmarshal(value, &id) == nil {
			if strings.TrimSpace(id) != "" {
				ids = append(ids, id)
			} else {
				malformed++
			}
			continue
		}
		var member map[string]json.RawMessage
		if json.Unmarshal(value, &member) == nil {
			id = rawString(member, "ObjectIdentifier")
			if strings.TrimSpace(id) != "" {
				ids = append(ids, id)
			} else {
				malformed++
			}
			continue
		}
		malformed++
	}
	return ids, malformed
}

func dedupeMembershipEdges(values []aclMembershipEdge) []aclMembershipEdge {
	result := make([]aclMembershipEdge, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		key := strings.ToLower(strings.TrimSpace(value.MemberID))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, value)
	}
	return result
}

type aclMembershipCandidate struct {
	Member    collectedObject
	Groups    []ACLMembershipHop
	Refs      []string
	Artifacts []string
}

func enrichACLInventoryMembershipContext(report *ACLInventoryReport, objects map[string]aclInventoryObject, edges map[string][]aclMembershipEdge) {
	report.MembershipCoverage = "complete-observed"
	cache := map[string][]aclMembershipCandidate{}
	seenPrincipals := map[string]bool{}
	seenContexts := map[string]bool{}
	for _, relationship := range report.Relationships {
		principal, ok := objects[strings.ToLower(strings.TrimSpace(relationship.PrincipalID))]
		if !ok || !strings.EqualFold(principal.Type, "groups") {
			continue
		}
		principalKey := strings.ToLower(strings.TrimSpace(principal.ID))
		seenPrincipals[principalKey] = true
		candidates, cached := cache[principalKey]
		if !cached {
			candidates = membershipCandidates(principalKey, objects, edges, report)
			cache[principalKey] = candidates
		}
		for _, candidate := range candidates {
			classification := "observed_membership_context"
			if len(candidate.Groups) > 1 {
				classification = "observed_nested_membership_context"
				report.NestedMembershipPaths++
			} else {
				report.DirectMembershipPaths++
			}
			if candidate.Member.Type == "unknown" {
				report.UnresolvedMembershipPaths++
			}
			key := strings.Join([]string{candidate.Member.ID, relationship.PrincipalID, relationship.TargetID, relationship.Permission, strings.Join(candidate.Refs, "\x00")}, "\x00")
			if seenContexts[key] {
				continue
			}
			seenContexts[key] = true
			if len(report.MembershipContext) >= aclInventoryMaxMembershipPaths {
				report.MembershipTruncated = true
				report.OmittedMembershipPaths++
				continue
			}
			report.MembershipContext = append(report.MembershipContext, ACLMembershipContext{
				MemberID: candidate.Member.ID, MemberName: objectLabel(candidate.Member), MemberType: candidate.Member.Type,
				GroupPath: candidate.Groups, ACLPrincipalID: relationship.PrincipalID, ACLPrincipalName: relationship.PrincipalName,
				TargetID: relationship.TargetID, TargetName: relationship.TargetName, TargetClass: relationship.TargetClass,
				Permission: relationship.Permission, Decision: relationship.Decision, Inheritance: relationship.Inheritance,
				Classification: classification, EffectivePermission: "NOT VERIFIED", MembershipArtifacts: candidate.Artifacts,
				MembershipRefs: candidate.Refs, ACLArtifact: relationship.Artifact, ACLArtifactRef: relationship.ArtifactRef,
			})
		}
	}
	report.MembershipContextualizedPrincipals = len(seenPrincipals)
	if report.MembershipTruncated {
		report.MembershipCoverage = "partial"
		report.MembershipLimitations = append(report.MembershipLimitations, "Membership context path limit reached; additional observed paths were not materialized.")
	}
	if report.MembershipEdges == 0 {
		report.MembershipCoverage = "unavailable"
		report.MembershipLimitations = append(report.MembershipLimitations, "No group membership edges were available in this RustHound execution; membership context is unavailable for ACL principals.")
	}
	if len(report.MembershipLimitations) == 0 {
		report.MembershipLimitations = append(report.MembershipLimitations, "Membership paths describe observed directory relationships only; effective permission was not evaluated.")
	}
}

func membershipCandidates(root string, objects map[string]aclInventoryObject, edges map[string][]aclMembershipEdge, report *ACLInventoryReport) []aclMembershipCandidate {
	result := make([]aclMembershipCandidate, 0)
	var walk func(group string, groupPath []ACLMembershipHop, refs, artifacts []string, visiting map[string]bool)
	walk = func(group string, groupPath []ACLMembershipHop, refs, artifacts []string, visiting map[string]bool) {
		if len(groupPath) > aclInventoryMaxMembershipDepth {
			report.MembershipTruncated = true
			return
		}
		key := strings.ToLower(strings.TrimSpace(group))
		if visiting[key] {
			report.MembershipLimitations = appendUniqueString(report.MembershipLimitations, "Cycle encountered while traversing observed group membership; cyclic edge was not expanded.")
			return
		}
		visiting[key] = true
		defer delete(visiting, key)
		values := append([]aclMembershipEdge(nil), edges[key]...)
		sort.SliceStable(values, func(i, j int) bool {
			return strings.ToLower(values[i].MemberID)+values[i].Ref < strings.ToLower(values[j].MemberID)+values[j].Ref
		})
		for _, edge := range values {
			memberKey := strings.ToLower(strings.TrimSpace(edge.MemberID))
			member, ok := objects[memberKey]
			if !ok {
				member = aclInventoryObject{collectedObject: collectedObject{ID: edge.MemberID, Type: "unknown"}}
			}
			hop := membershipHop(member.collectedObject, edge.Artifact, edge.Ref)
			if strings.EqualFold(member.Type, "groups") {
				if len(result) >= aclInventoryMaxPathsPerGroup {
					report.MembershipTruncated = true
					return
				}
				walk(member.ID, append(groupPath, hop), append(refs, edge.Ref), append(artifacts, edge.Artifact), visiting)
				continue
			}
			groups := append([]ACLMembershipHop(nil), groupPath...)
			// The walk is root-to-leaf; presentation is member-to-root.
			reverseMembershipHops(groups)
			allRefs := append(append([]string(nil), refs...), edge.Ref)
			allArtifacts := append(append([]string(nil), artifacts...), edge.Artifact)
			reverseStrings(allRefs)
			reverseStrings(allArtifacts)
			result = append(result, aclMembershipCandidate{Member: member.collectedObject, Groups: groups, Refs: allRefs, Artifacts: uniqueStrings(allArtifacts)})
			if len(result) >= aclInventoryMaxPathsPerGroup {
				report.MembershipTruncated = true
				return
			}
		}
	}
	rootObject, ok := objects[strings.ToLower(strings.TrimSpace(root))]
	if !ok {
		return nil
	}
	walk(root, []ACLMembershipHop{membershipHop(rootObject.collectedObject, rootObject.Artifact, rootObject.RefPrefix+"/Members")}, nil, nil, map[string]bool{})
	return result
}

func membershipHop(member collectedObject, artifact, ref string) ACLMembershipHop {
	name := objectLabel(member)
	if name == "" {
		name = member.ID
	}
	return ACLMembershipHop{ID: member.ID, Name: name, Type: member.Type, Artifact: artifact, ArtifactRef: ref}
}
func membershipGroupHopForRoot(id string, objects map[string]aclInventoryObject, artifact, ref string) ACLMembershipHop {
	object, ok := objects[strings.ToLower(strings.TrimSpace(id))]
	if !ok {
		return ACLMembershipHop{ID: id, Name: id, Type: "group", Artifact: artifact, ArtifactRef: ref}
	}
	return membershipHop(object.collectedObject, artifact, ref)
}
func reverseMembershipHops(values []ACLMembershipHop) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}
func reverseStrings(values []string) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}
func uniqueStrings(values []string) []string {
	result := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func aclMembershipObservation(report ACLInventoryReport) []ACLMembershipContext {
	values := append([]ACLMembershipContext(nil), report.MembershipContext...)
	sort.SliceStable(values, func(i, j int) bool {
		a, b := values[i], values[j]
		for _, pair := range [][2]string{{a.TargetName, b.TargetName}, {a.TargetID, b.TargetID}, {a.Permission, b.Permission}, {a.MemberName, b.MemberName}, {a.MemberID, b.MemberID}, {a.Classification, b.Classification}} {
			if pair[0] != pair[1] {
				return pair[0] < pair[1]
			}
		}
		return strings.Join(a.MembershipRefs, "\x00") < strings.Join(b.MembershipRefs, "\x00")
	})
	if len(values) > aclInventoryObservationMaxRelationships {
		values = values[:aclInventoryObservationMaxRelationships]
	}
	return values
}
