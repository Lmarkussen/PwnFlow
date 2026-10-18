package findings

import (
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

const replicationRightsParserVersion = "rusthound-replication-rights-v1"

var trackedReplicationRights = []string{"GetChanges", "GetChangesAll", "GetChangesInFilteredSet"}

type ReplicationRightsReport struct {
	SchemaVersion             int                          `json:"schema_version"`
	ParserVersion             string                       `json:"parser_version"`
	Domain                    string                       `json:"domain,omitempty"`
	SourceExecutionID         int64                        `json:"source_execution_id"`
	SourceArtifact            string                       `json:"source_artifact"`
	AnalysisTimestamp         time.Time                    `json:"analysis_timestamp"`
	Status                    string                       `json:"status"`
	Coverage                  string                       `json:"coverage"`
	EffectiveRightState       string                       `json:"effective_replication_authorization"`
	DomainRoots               []ReplicationDomainRoot      `json:"domain_roots"`
	InputArtifacts            []ACLInventorySourceArtifact `json:"input_artifacts,omitempty"`
	Limitations               []string                     `json:"limitations"`
	Unresolved                []ACLInventoryRelationship   `json:"unresolved_relationships,omitempty"`
	OmittedRelationships      int                          `json:"omitted_relationships"`
	MembershipPathsShown      int                          `json:"membership_paths_shown"`
	MembershipEvidenceRecords int                          `json:"membership_evidence_records"`
	MembershipPathsOmitted    int                          `json:"membership_paths_omitted"`
}

type ReplicationDomainRoot struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name,omitempty"`
	ObjectType string                 `json:"object_type"`
	Principals []ReplicationPrincipal `json:"principals"`
}

type ReplicationPrincipal struct {
	ID                 string                  `json:"id"`
	Name               string                  `json:"name,omitempty"`
	Type               string                  `json:"type,omitempty"`
	Rights             []ReplicationRightState `json:"rights"`
	MembershipContext  []ACLMembershipContext  `json:"membership_context,omitempty"`
	MembershipEvidence []ACLMembershipContext  `json:"membership_evidence,omitempty"`
}

type ReplicationRightState struct {
	Right    string                     `json:"right"`
	Status   string                     `json:"status"`
	Evidence []ACLInventoryRelationship `json:"evidence,omitempty"`
}

func AnalyzeReplicationRights(report ACLInventoryReport, assessmentID int64, now time.Time) (ReplicationRightsReport, *storage.FindingInput) {
	result := ReplicationRightsReport{
		SchemaVersion: 1, ParserVersion: replicationRightsParserVersion,
		Domain: report.Domain, SourceExecutionID: report.SourceExecutionID,
		SourceArtifact: report.SourceArtifact, AnalysisTimestamp: now.UTC(),
		Status: report.Status, Coverage: "complete", EffectiveRightState: "NOT VERIFIED",
		InputArtifacts: append([]ACLInventorySourceArtifact(nil), report.InputArtifacts...),
		Limitations: []string{
			"NOT OBSERVED means no matching supported relationship was found in the inspected evidence; it does not mean denied or absent.",
			"Allow/deny precedence, inheritance applicability, object-specific restrictions, group scope, SIDHistory, cross-domain authorization and token semantics were not evaluated.",
			"Observed replication-right relationships do not establish effective replication authorization or DCSync capability.",
		},
		OmittedRelationships: report.OmittedRelations,
	}
	if result.Status != "complete" || report.OmittedRelations > 0 {
		result.Coverage = "partial"
	}
	roots := map[string]*ReplicationDomainRoot{}
	principals := map[string]*ReplicationPrincipal{}
	for _, relation := range report.Relationships {
		right := canonicalReplicationRight(relation.Permission)
		if right == "" {
			continue
		}
		if relation.TargetClass != "domain_root" || strings.TrimSpace(relation.TargetID) == "" {
			if relation.TargetClass == "domain_root" {
				result.Unresolved = append(result.Unresolved, relation)
			}
			continue
		}
		root := roots[relation.TargetID]
		if root == nil {
			root = &ReplicationDomainRoot{ID: relation.TargetID, Name: relation.TargetName, ObjectType: relation.TargetType}
			roots[relation.TargetID] = root
		}
		key := relation.TargetID + "\x00" + relation.PrincipalID + "\x00" + relation.PrincipalName
		principal := principals[key]
		if principal == nil {
			principal = &ReplicationPrincipal{ID: relation.PrincipalID, Name: relation.PrincipalName, Type: relation.PrincipalType}
			principals[key] = principal
			root.Principals = append(root.Principals, *principal)
		}
		state := replicationState(principal.Rights, right)
		if state == nil {
			principal.Rights = append(principal.Rights, ReplicationRightState{Right: right, Status: "not_observed"})
			state = &principal.Rights[len(principal.Rights)-1]
		}
		state.Status = "observed"
		state.Evidence = appendUniqueReplicationEvidence(state.Evidence, relation)
		for index := range root.Principals {
			if root.Principals[index].ID == principal.ID && root.Principals[index].Name == principal.Name {
				root.Principals[index] = *principal
			}
		}
	}
	for _, root := range roots {
		for index := range root.Principals {
			principal := &root.Principals[index]
			for _, right := range trackedReplicationRights {
				if replicationState(principal.Rights, right) == nil {
					principal.Rights = append(principal.Rights, ReplicationRightState{Right: right, Status: "not_observed"})
				}
			}
			for _, membership := range report.MembershipContext {
				if membership.TargetID == root.ID && membership.ACLPrincipalID == principal.ID && canonicalReplicationRight(membership.Permission) != "" {
					principal.MembershipEvidence = appendUniqueMembershipEvidence(principal.MembershipEvidence, membership)
					principal.MembershipContext = appendUniqueMembershipPath(principal.MembershipContext, membership, report.SourceExecutionID)
				}
			}
			sortReplicationPrincipal(principal)
		}
		sort.SliceStable(root.Principals, func(i, j int) bool { return replicationPrincipalLess(root.Principals[i], root.Principals[j]) })
	}
	for _, root := range roots {
		for _, principal := range root.Principals {
			result.MembershipPathsShown += len(principal.MembershipContext)
			result.MembershipEvidenceRecords += len(principal.MembershipEvidence)
		}
	}
	result.MembershipPathsOmitted = report.OmittedMembershipPaths
	for _, root := range roots {
		sort.SliceStable(root.Principals, func(i, j int) bool { return replicationPrincipalLess(root.Principals[i], root.Principals[j]) })
		result.DomainRoots = append(result.DomainRoots, *root)
	}
	sort.SliceStable(result.DomainRoots, func(i, j int) bool {
		if result.DomainRoots[i].Name != result.DomainRoots[j].Name {
			return result.DomainRoots[i].Name < result.DomainRoots[j].Name
		}
		return result.DomainRoots[i].ID < result.DomainRoots[j].ID
	})
	if len(result.DomainRoots) == 0 {
		return result, nil
	}
	structured := fmt.Sprintf("Enumeration/ActiveDirectory/ACL/execution-%d/AD_replication_rights_evidence.json", report.SourceExecutionID)
	evidence, _ := json.Marshal(map[string]any{
		"source_execution_id": report.SourceExecutionID, "source_artifact": report.SourceArtifact,
		"structured_artifact": structured, "human_report": "AD_REPLICATION_RIGHTS_EVIDENCE.txt",
		"domain_roots": result.DomainRoots, "coverage": result.Coverage,
		"effective_replication_authorization": result.EffectiveRightState,
		"limitations":                         result.Limitations, "omitted_relationships": result.OmittedRelationships,
		"membership_paths_shown": result.MembershipPathsShown, "membership_evidence_records": result.MembershipEvidenceRecords, "membership_paths_omitted": result.MembershipPathsOmitted,
	})
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%d\x00%s", assessmentID, report.SourceExecutionID, report.SourceArtifact)))
	input := &storage.FindingInput{
		FindingKey: "adrep:" + hex.EncodeToString(hash[:]), AssessmentID: assessmentID,
		SourceTool: "RustHound-CE", SourceExecution: report.SourceExecutionID,
		FindingType: "ad_replication_rights_evidence_overview", Title: "AD Replication Rights Evidence Overview",
		Description: fmt.Sprintf("RustHound recorded replication-related ACL relationships for %d principal/domain-root combinations. Effective replication authorization and DCSync capability were not verified.", replicationPrincipalCount(result)),
		Severity:    "informational", Confidence: "observed-replication-right-evidence",
		AffectedObjectID: report.Domain, AffectedObject: fallbackReportText(report.Domain, "domain root evidence"),
		EvidenceJSON: string(evidence), ArtifactPath: report.SourceArtifact, ArtifactRef: "/", ObservedAt: now.UTC(), Status: "open", ParserVersion: replicationRightsParserVersion,
	}
	return result, input
}

func canonicalReplicationRight(value string) string {
	switch normalize(value) {
	case "getchanges":
		return "GetChanges"
	case "getchangesall":
		return "GetChangesAll"
	case "getchangesinfilteredset":
		return "GetChangesInFilteredSet"
	default:
		return ""
	}
}

func replicationState(states []ReplicationRightState, right string) *ReplicationRightState {
	for index := range states {
		if states[index].Right == right {
			return &states[index]
		}
	}
	return nil
}

func appendUniqueReplicationEvidence(values []ACLInventoryRelationship, relation ACLInventoryRelationship) []ACLInventoryRelationship {
	key := aclInventoryRelationshipKey(relation) + "\x00" + relation.Artifact + "\x00" + relation.ArtifactRef
	for _, existing := range values {
		if aclInventoryRelationshipKey(existing)+"\x00"+existing.Artifact+"\x00"+existing.ArtifactRef == key {
			return values
		}
	}
	return append(values, relation)
}

func appendUniqueMembershipPath(values []ACLMembershipContext, item ACLMembershipContext, executionID int64) []ACLMembershipContext {
	key := membershipPathKey(item, executionID)
	for _, existing := range values {
		if membershipPathKey(existing, executionID) == key {
			return values
		}
	}
	return append(values, item)
}

func appendUniqueMembershipEvidence(values []ACLMembershipContext, item ACLMembershipContext) []ACLMembershipContext {
	key := membershipEvidenceKey(item)
	for _, existing := range values {
		if membershipEvidenceKey(existing) == key {
			return values
		}
	}
	return append(values, item)
}

func membershipPathKey(item ACLMembershipContext, executionID int64) string {
	parts := []string{fmt.Sprintf("%d", executionID), item.TargetID, item.ACLPrincipalID, item.MemberID, item.Classification}
	if item.MemberID == "" {
		parts = append(parts, item.MemberName, strings.Join(item.MembershipRefs, "\x00"), strings.Join(item.MembershipArtifacts, "\x00"))
	}
	for _, hop := range item.GroupPath {
		identity := hop.ID
		if identity == "" {
			identity = hop.Name + "\x00" + hop.Artifact + "\x00" + hop.ArtifactRef
		}
		parts = append(parts, identity)
	}
	return strings.Join(parts, "\x00")
}

func membershipEvidenceKey(item ACLMembershipContext) string {
	return strings.Join([]string{
		membershipPathKey(item, 0), item.Permission, item.Decision, item.Inheritance,
		item.ACLArtifact, item.ACLArtifactRef, strings.Join(item.MembershipArtifacts, "\x00"), strings.Join(item.MembershipRefs, "\x00"),
	}, "\x00")
}

func sortReplicationPrincipal(principal *ReplicationPrincipal) {
	sort.SliceStable(principal.Rights, func(i, j int) bool {
		return replicationRightIndex(principal.Rights[i].Right) < replicationRightIndex(principal.Rights[j].Right)
	})
	sort.SliceStable(principal.MembershipContext, func(i, j int) bool {
		if principal.MembershipContext[i].MemberName != principal.MembershipContext[j].MemberName {
			return principal.MembershipContext[i].MemberName < principal.MembershipContext[j].MemberName
		}
		return principal.MembershipContext[i].MemberID < principal.MembershipContext[j].MemberID
	})
	sort.SliceStable(principal.MembershipEvidence, func(i, j int) bool {
		left, right := principal.MembershipEvidence[i], principal.MembershipEvidence[j]
		if left.MemberName != right.MemberName {
			return left.MemberName < right.MemberName
		}
		if left.MemberID != right.MemberID {
			return left.MemberID < right.MemberID
		}
		return membershipEvidenceKey(left) < membershipEvidenceKey(right)
	})
}

func replicationRightIndex(value string) int {
	for index, right := range trackedReplicationRights {
		if right == value {
			return index
		}
	}
	return len(trackedReplicationRights)
}
func replicationPrincipalLess(left, right ReplicationPrincipal) bool {
	if left.Name != right.Name {
		return left.Name < right.Name
	}
	return left.ID < right.ID
}
func replicationPrincipalCount(report ReplicationRightsReport) int {
	total := 0
	for _, root := range report.DomainRoots {
		total += len(root.Principals)
	}
	return total
}

func WriteReplicationRightsArtifact(resultsRoot string, report ReplicationRightsReport) (string, error) {
	if report.SourceExecutionID <= 0 {
		return "", fmt.Errorf("replication-rights source execution is missing")
	}
	directory := filepath.Join(resultsRoot, "Enumeration", "ActiveDirectory", "ACL", fmt.Sprintf("execution-%d", report.SourceExecutionID))
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(directory, "AD_replication_rights_evidence.json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	temporary, err := os.CreateTemp(directory, ".replication-rights-*.tmp")
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

func WriteReplicationRightsReport(resultsRoot string, report ReplicationRightsReport) (string, error) {
	if report.SourceExecutionID <= 0 {
		return "", fmt.Errorf("replication-rights source execution is missing")
	}
	path := filepath.Join(resultsRoot, "AD_REPLICATION_RIGHTS_EVIDENCE.txt")
	temporary, err := os.CreateTemp(resultsRoot, ".replication-rights-report-*.tmp")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return "", err
	}
	if _, err := temporary.WriteString(FormatReplicationRightsReport(report)); err != nil {
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

func FormatReplicationRightsReport(report ReplicationRightsReport) string {
	var b strings.Builder
	fmt.Fprintln(&b, "======================================================================")
	fmt.Fprintln(&b, "             PWNFLOW AD REPLICATION RIGHTS EVIDENCE")
	fmt.Fprintln(&b, "======================================================================")
	fmt.Fprintf(&b, "\nDOMAIN: %s\nSOURCE EXECUTION: %d\nSOURCE ARTIFACT: %s\nSTATUS: %s\nCOVERAGE: %s\nEFFECTIVE REPLICATION AUTHORIZATION: NOT VERIFIED\n", report.Domain, report.SourceExecutionID, report.SourceArtifact, report.Status, report.Coverage)
	fmt.Fprintf(&b, "DISTINCT MEMBERSHIP PATHS SHOWN: %d\nMEMBERSHIP EVIDENCE RECORDS RETAINED: %d\nMEMBERSHIP PATHS OMITTED BEFORE MATERIALIZATION: %d\n", report.MembershipPathsShown, report.MembershipEvidenceRecords, report.MembershipPathsOmitted)
	fmt.Fprintln(&b, "\nRIGHT STATE: NOT_OBSERVED means no matching supported relationship was found in this inspected evidence; it does not mean denied or absent.")
	for _, root := range report.DomainRoots {
		fmt.Fprintf(&b, "\n----------------------------------------------------------------------\nDOMAIN ROOT: %s\nIDENTITY: %s\nTYPE: %s\n----------------------------------------------------------------------\n", fallbackReportText(root.Name, root.ID), root.ID, root.ObjectType)
		for _, principal := range root.Principals {
			fmt.Fprintf(&b, "\nPrincipal: %s\nIdentity: %s\nType: %s\n", fallbackReportText(principal.Name, principal.ID), principal.ID, fallbackReportText(principal.Type, "unknown"))
			for _, state := range principal.Rights {
				fmt.Fprintf(&b, "  %-28s %s\n", state.Right, strings.ToUpper(state.Status))
				for _, evidence := range state.Evidence {
					fmt.Fprintf(&b, "    Evidence: %s#%s | decision=%s | inheritance=%s\n", evidence.Artifact, evidence.ArtifactRef, evidence.Decision, evidence.Inheritance)
				}
			}
			if len(principal.MembershipContext) == 0 {
				fmt.Fprintln(&b, "  Membership context: No membership context observed in this execution.")
			} else {
				fmt.Fprintln(&b, "  Membership context:")
				for _, context := range principal.MembershipContext {
					fmt.Fprintf(&b, "    - %s\n", formatMembershipPath(context))
				}
			}
			if len(principal.MembershipEvidence) > 0 {
				fmt.Fprintln(&b, "  Membership evidence references:")
				for _, context := range principal.MembershipEvidence {
					fmt.Fprintf(&b, "    - %s | permission=%s | ACL evidence=%s#%s\n", formatMembershipEvidence(context), context.Permission, context.ACLArtifact, context.ACLArtifactRef)
				}
			}
			fmt.Fprintln(&b, "  Effective replication authorization: NOT VERIFIED")
		}
	}
	if len(report.Unresolved) > 0 {
		fmt.Fprintf(&b, "\nUNRESOLVED REPLICATION RELATIONSHIPS: %d\n", len(report.Unresolved))
	}
	if report.OmittedRelationships > 0 {
		fmt.Fprintf(&b, "\nOMITTED RELATIONSHIPS: %d due to existing ACL inventory bounds.\n", report.OmittedRelationships)
	}
	fmt.Fprintln(&b, "\nLIMITATIONS")
	for _, limitation := range report.Limitations {
		fmt.Fprintf(&b, "- %s\n", limitation)
	}
	return b.String()
}
