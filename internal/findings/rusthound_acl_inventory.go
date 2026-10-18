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
	aclInventoryMaxObjects       = 100000
	aclInventoryMaxACEs          = 250000
	aclInventoryMaxRelationships = 1000
	aclInventoryMaxUnresolved    = 256
	aclInventoryMaxArtifacts     = 512
)

var inventoryRights = map[string]bool{
	"genericall": true, "genericwrite": true, "writedacl": true, "writeowner": true,
	"owns": true, "writeproperty": true, "addmember": true, "addself": true,
	"forcechangepassword": true, "allextendedrights": true, "addkeycredentiallink": true,
	"writespn": true, "getchanges": true, "getchangesall": true,
	"getchangesinfilteredset": true, "addallowedtoact": true,
}

type ACLInventoryReport struct {
	SchemaVersion       int                          `json:"schema_version"`
	ParserVersion       string                       `json:"parser_version"`
	Domain              string                       `json:"domain,omitempty"`
	SourceExecutionID   int64                        `json:"source_execution_id"`
	SourceArtifact      string                       `json:"source_artifact"`
	AnalysisTimestamp   time.Time                    `json:"analysis_timestamp"`
	Status              string                       `json:"status"`
	ObjectsInspected    int                          `json:"objects_inspected"`
	RawACLsInspected    int                          `json:"raw_acls_inspected"`
	SupportedACLs       int                          `json:"supported_acls"`
	NormalizedRelations int                          `json:"normalized_relationships"`
	OmittedRelations    int                          `json:"omitted_relationships"`
	HighValueTargets    []ACLInventoryTarget         `json:"high_value_targets"`
	Relationships       []ACLInventoryRelationship   `json:"relationships"`
	Unresolved          []ACLInventoryUnresolved     `json:"unresolved_identities"`
	UnsupportedRights   map[string]int               `json:"unsupported_rights,omitempty"`
	MalformedEntries    int                          `json:"malformed_entries"`
	InputArtifacts      []ACLInventorySourceArtifact `json:"input_artifacts"`
	Limits              ACLInventoryLimits           `json:"limits"`
	Limitations         []string                     `json:"limitations"`
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
			objects[strings.ToLower(strings.TrimSpace(object.ID))] = aclInventoryObject{collectedObject: object, Class: classifyACLTarget(object)}
			if report.Domain == "" {
				report.Domain = firstString(object.Properties, "domain", "distinguishedname")
			}
			report.ObjectsInspected++
			_ = index
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
	if report.SupportedACLs == 0 {
		return report, nil, nil
	}
	overview := ACLInventoryObservationRelationships(report)
	evidence, _ := json.Marshal(map[string]any{"source_execution_id": executionID, "source_artifact": inputPath, "structured_artifact": "Enumeration/ActiveDirectory/ACL/execution-<execution-id>/AD_privileged_acl_inventory.json", "human_report": "AD_PRIVILEGED_ACL_EVIDENCE.txt", "relationship_overview": overview, "relationship_overview_limit": aclInventoryObservationMaxRelationships, "high_value_targets": len(report.HighValueTargets), "normalized_relationships": report.NormalizedRelations, "unresolved_principals": len(report.Unresolved), "unsupported_relationships": unsupportedCount(report.UnsupportedRights), "omitted_relationships": report.OmittedRelations, "malformed_entries": report.MalformedEntries, "status": report.Status})
	input := storage.FindingInput{FindingKey: aclInventoryFindingKey(assessmentID, executionID, inputPath), AssessmentID: assessmentID, SourceTool: "RustHound-CE", SourceExecution: executionID, FindingType: "ad_privileged_acl_evidence_inventory", Title: "AD Privileged ACL Evidence Inventory", Description: fmt.Sprintf("RustHound execution %d contains %d normalized direct ACL relationships affecting %d classified high-value targets. This is an informational evidence inventory; effective access and exploitability were not evaluated.", executionID, report.NormalizedRelations, len(report.HighValueTargets)), Severity: "informational", Confidence: "observed-direct-acl-coverage-partial", AffectedObjectID: inputPath, AffectedObject: "RustHound direct ACL inventory", EvidenceJSON: string(evidence), ArtifactPath: inputPath, ArtifactRef: "/", ObservedAt: now, Status: "open", ParserVersion: aclInventoryParserVersion}
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
