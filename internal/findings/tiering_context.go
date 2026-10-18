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

const tierContextParserVersion = "rusthound-tier-context-v1"
const tierPolicyRelativePath = "Enumeration/ActiveDirectory/Tiering/tier_policy.json"

type TierAssignmentPolicy struct {
	SchemaVersion int              `json:"schema_version"`
	PolicyID      string           `json:"policy_id"`
	Version       string           `json:"version"`
	Domain        string           `json:"domain"`
	DomainSID     string           `json:"domain_sid"`
	Source        string           `json:"source"`
	Assignments   []TierAssignment `json:"assignments"`
}
type TierAssignment struct {
	Tier    int        `json:"tier"`
	GroupID string     `json:"group_id"`
	Label   string     `json:"label"`
	Target  TierTarget `json:"target"`
}
type TierTarget struct {
	Name       string `json:"name,omitempty"`
	IP         string `json:"ip,omitempty"`
	ComputerID string `json:"computer_id,omitempty"`
	DN         string `json:"distinguished_name,omitempty"`
}
type TierGroup struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	Domain   string `json:"domain,omitempty"`
	DN       string `json:"distinguished_name,omitempty"`
	Artifact string `json:"source_artifact,omitempty"`
	Ref      string `json:"source_ref,omitempty"`
}
type TierPath struct {
	MemberID       string   `json:"member_id"`
	MemberName     string   `json:"member_name"`
	MemberType     string   `json:"member_type"`
	Path           []string `json:"path"`
	Classification string   `json:"classification"`
	SourceRefs     []string `json:"source_refs"`
}
type TierTargetEvidence struct {
	Declared         TierTarget `json:"declared"`
	ObservedID       string     `json:"observed_id,omitempty"`
	ObservedName     string     `json:"observed_name,omitempty"`
	ObservedDN       string     `json:"observed_dn,omitempty"`
	ObservedArtifact string     `json:"observed_artifact,omitempty"`
	Status           string     `json:"status"`
	Verification     string     `json:"verification"`
}
type TierContextReport struct {
	SchemaVersion     int                        `json:"schema_version"`
	ParserVersion     string                     `json:"parser_version"`
	Status            string                     `json:"status"`
	Coverage          string                     `json:"coverage"`
	Tier              int                        `json:"tier"`
	Domain            string                     `json:"domain,omitempty"`
	DomainID          string                     `json:"domain_id,omitempty"`
	SourceExecutionID int64                      `json:"source_execution_id"`
	SourceSnapshot    string                     `json:"source_snapshot"`
	SourceArtifacts   []string                   `json:"source_artifacts"`
	SourceHashes      map[string]string          `json:"source_hashes,omitempty"`
	AnalysisTimestamp time.Time                  `json:"analysis_timestamp"`
	PolicyID          string                     `json:"policy_id,omitempty"`
	PolicyVersion     string                     `json:"policy_version,omitempty"`
	PolicySource      string                     `json:"policy_source,omitempty"`
	PolicyHash        string                     `json:"policy_hash,omitempty"`
	DeclaredGroups    []TierGroup                `json:"declared_groups"`
	MembershipPaths   []TierPath                 `json:"membership_paths,omitempty"`
	Targets           []TierTargetEvidence       `json:"targets,omitempty"`
	ACLRelationships  []ACLInventoryRelationship `json:"acl_relationships,omitempty"`
	Unresolved        []string                   `json:"unresolved_references,omitempty"`
	OmittedMembership int                        `json:"omitted_membership_paths"`
	OmittedACL        int                        `json:"omitted_acl_relationships"`
	Limits            map[string]int             `json:"limits"`
	Limitations       []string                   `json:"limitations"`
}

func tierPolicyPath(root string) string {
	return filepath.Join(root, filepath.FromSlash(tierPolicyRelativePath))
}
func loadTierPolicy(root string) (TierAssignmentPolicy, string, string, bool, error) {
	path := tierPolicyPath(root)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return TierAssignmentPolicy{}, path, "", false, nil
	}
	if err != nil {
		return TierAssignmentPolicy{}, path, "", true, err
	}
	if len(data) > 1<<20 {
		return TierAssignmentPolicy{}, path, "", true, fmt.Errorf("tier policy exceeds size limit")
	}
	var policy TierAssignmentPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return policy, path, "", true, err
	}
	if policy.SchemaVersion < 1 || strings.TrimSpace(policy.PolicyID) == "" || strings.TrimSpace(policy.DomainSID) == "" {
		return policy, path, "", true, fmt.Errorf("tier policy requires schema_version, policy_id and domain_sid")
	}
	if len(policy.Assignments) == 0 {
		return policy, path, "", true, fmt.Errorf("tier policy has no assignments")
	}
	h := sha256.Sum256(data)
	return policy, path, hex.EncodeToString(h[:]), true, nil
}

func AnalyzeTierContext(ctx context.Context, inputPath, resultsRoot string, inventory ACLInventoryReport, assessmentID, executionID int64, tier int, now time.Time) (TierContextReport, *storage.FindingInput, error) {
	var result TierContextReport
	if tier != 1 && tier != 2 {
		return result, nil, fmt.Errorf("unsupported administrative tier %d", tier)
	}
	policy, policyPath, policyHash, present, err := loadTierPolicy(resultsRoot)
	if err != nil || !present {
		return result, nil, err
	}
	if err := ctx.Err(); err != nil {
		return result, nil, err
	}
	files, err := rustHoundGroupFiles(inputPath)
	if err != nil {
		return result, nil, err
	}
	objects := map[string]groupObject{}
	groups := map[string]groupObject{}
	edges := []groupEdge{}
	artifacts := map[string]bool{}
	for _, file := range files {
		data, readErr := os.ReadFile(file)
		if readErr != nil {
			return result, nil, readErr
		}
		var export struct {
			Meta struct {
				Type string `json:"type"`
			} `json:"meta"`
			Data []json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(data, &export); err != nil {
			return result, nil, fmt.Errorf("parse tier evidence %s: %w", file, err)
		}
		kind := strings.ToLower(export.Meta.Type)
		if kind != "groups" && kind != "users" && kind != "computers" {
			continue
		}
		artifacts[file] = true
		for index, raw := range export.Data {
			o, decodeErr := decodeGroupObject(raw, kind, file, index)
			if decodeErr != nil {
				return result, nil, decodeErr
			}
			if o.ID == "" {
				continue
			}
			objects[groupIdentity(o.ID)] = o
			if kind == "groups" {
				groups[groupIdentity(o.ID)] = o
				for _, member := range o.Members {
					if member != "" {
						edges = append(edges, groupEdge{Parent: o.ID, Member: member, Artifact: file, Ref: o.Ref + "/Members"})
					}
				}
			}
		}
	}
	if !strings.EqualFold(policy.Domain, "") && inventory.Domain != "" && !strings.EqualFold(policy.Domain, inventory.Domain) {
		return result, nil, fmt.Errorf("tier policy domain %q does not match source domain %q", policy.Domain, inventory.Domain)
	}
	seenAssignments := map[string]bool{}
	selected := map[string]bool{}
	result = TierContextReport{SchemaVersion: 1, ParserVersion: tierContextParserVersion, Status: "complete", Coverage: "partial", Tier: tier, Domain: inventory.Domain, SourceExecutionID: executionID, SourceSnapshot: filepath.Base(filepath.Clean(inputPath)), SourceHashes: map[string]string{}, AnalysisTimestamp: now.UTC(), PolicyID: policy.PolicyID, PolicyVersion: policy.Version, PolicySource: policyPath, PolicyHash: policyHash, Limits: map[string]int{"membership_paths": 256, "acl_relationships": 24, "depth": 8}, Limitations: []string{"Declared tier assignments and observed directory memberships do not establish host-local administrator membership or effective administrative authorization.", "ACL decision precedence, inheritance applicability, token construction and SIDHistory were not evaluated.", "Cross-tier policy violations and applied GPO effects were not assessed."}}
	for _, assignment := range policy.Assignments {
		if assignment.Tier != tier {
			continue
		}
		id := groupIdentity(assignment.GroupID)
		if seenAssignments[id] {
			result.Unresolved = append(result.Unresolved, "duplicate tier assignment: "+assignment.GroupID)
			continue
		}
		seenAssignments[id] = true
		group, ok := groups[id]
		if !ok || !strings.EqualFold(group.DomainSID, policy.DomainSID) {
			result.Unresolved = append(result.Unresolved, "declared group not observed in validated source: "+assignment.GroupID)
			continue
		}
		selected[id] = true
		result.DeclaredGroups = append(result.DeclaredGroups, TierGroup{ID: group.ID, Name: principalName(group), Type: group.Type, Domain: group.Domain, DN: group.DN, Artifact: group.Artifact, Ref: group.Ref})
		result.Targets = append(result.Targets, matchTierTarget(assignment.Target, objects))
	}
	if len(result.DeclaredGroups) == 0 {
		return result, nil, fmt.Errorf("tier %d has no policy group observed in source", tier)
	}
	children := map[string][]groupEdge{}
	edgeSeen := map[string]bool{}
	for _, e := range edges {
		key := groupIdentity(e.Parent) + "\x00" + groupIdentity(e.Member)
		if !edgeSeen[key] {
			edgeSeen[key] = true
			children[groupIdentity(e.Parent)] = append(children[groupIdentity(e.Parent)], e)
		}
	}
	for groupID := range selected {
		collectTierPaths(groupID, groupID, children, objects, nil, map[string]bool{}, &result)
	}
	sort.Slice(result.DeclaredGroups, func(i, j int) bool {
		return strings.ToLower(result.DeclaredGroups[i].ID) < strings.ToLower(result.DeclaredGroups[j].ID)
	})
	sort.Slice(result.MembershipPaths, func(i, j int) bool {
		return strings.Join(result.MembershipPaths[i].Path, "\x00") < strings.Join(result.MembershipPaths[j].Path, "\x00")
	})
	for _, rel := range inventory.Relationships {
		if len(result.ACLRelationships) >= 24 {
			result.OmittedACL++
			break
		}
		if selected[groupIdentity(rel.PrincipalID)] {
			result.ACLRelationships = append(result.ACLRelationships, rel)
		}
	}
	for file := range artifacts {
		result.SourceArtifacts = append(result.SourceArtifacts, file)
		if data, hashErr := os.ReadFile(file); hashErr == nil {
			hash := sha256.Sum256(data)
			result.SourceHashes[file] = hex.EncodeToString(hash[:])
		}
	}
	sort.Strings(result.SourceArtifacts)
	result.DomainID = policy.DomainSID
	data, _ := json.Marshal(result)
	keyHash := sha256.Sum256([]byte(fmt.Sprintf("%d:%s:%d", executionID, policyHash, tier)))
	input := &storage.FindingInput{FindingKey: "adtier" + fmt.Sprint(tier) + ":" + hex.EncodeToString(keyHash[:]), AssessmentID: assessmentID, SourceTool: "RustHound-CE", SourceExecution: executionID, FindingType: fmt.Sprintf("ad_tier%d_context_evidence", tier), Title: fmt.Sprintf("AD Tier %d Administrative Context Evidence Overview", tier), Description: fmt.Sprintf("Collected directory evidence and a declared Tier %d policy identify administrative context; effective host authorization is not verified.", tier), Severity: "informational", Confidence: "observed-declared-context", AffectedObjectID: policy.DomainSID, AffectedObject: fmt.Sprintf("Tier %d administrative context", tier), EvidenceJSON: string(data), ArtifactRef: "/", ObservedAt: now.UTC(), Status: "open", ParserVersion: tierContextParserVersion}
	return result, input, nil
}

func collectTierPaths(root string, groupID string, children map[string][]groupEdge, objects map[string]groupObject, suffix []string, visiting map[string]bool, result *TierContextReport) {
	if len(result.MembershipPaths) >= result.Limits["membership_paths"] {
		result.OmittedMembership++
		return
	}
	if len(suffix) >= result.Limits["depth"] {
		result.OmittedMembership++
		return
	}
	if visiting[groupIdentity(root)] {
		result.Unresolved = append(result.Unresolved, "membership cycle at "+root)
		return
	}
	visiting[groupIdentity(root)] = true
	defer delete(visiting, groupIdentity(root))
	for _, edge := range children[groupIdentity(groupID)] {
		o, ok := objects[groupIdentity(edge.Member)]
		name := edge.Member
		typ := "unknown"
		if ok {
			name = principalName(o)
			typ = o.Type
		}
		path := append(append([]string{}, suffix...), name)
		path = append(path, principalName(objects[groupIdentity(root)]))
		classification := "nested"
		if len(suffix) == 0 {
			classification = "direct"
		}
		result.MembershipPaths = append(result.MembershipPaths, TierPath{MemberID: edge.Member, MemberName: name, MemberType: typ, Path: path, Classification: classification, SourceRefs: []string{edge.Artifact + "#" + edge.Ref}})
		if ok && typ == "group" {
			collectTierPaths(root, edge.Member, children, objects, path, visiting, result)
		}
	}
}
func matchTierTarget(target TierTarget, objects map[string]groupObject) TierTargetEvidence {
	out := TierTargetEvidence{Declared: target, Status: "unresolved", Verification: "not_verified"}
	if target.ComputerID != "" {
		if o, ok := objects[groupIdentity(target.ComputerID)]; ok {
			out.ObservedID = o.ID
			out.ObservedName = principalName(o)
			out.ObservedDN = o.DN
			out.ObservedArtifact = o.Artifact
			out.Status = "matched"
		}
		return out
	}
	for _, o := range objects {
		if o.Type == "computer" && (strings.EqualFold(target.Name, o.Name) || strings.EqualFold(target.DN, o.DN)) {
			out.ObservedID = o.ID
			out.ObservedName = principalName(o)
			out.ObservedDN = o.DN
			out.ObservedArtifact = o.Artifact
			out.Status = "matched"
			break
		}
	}
	return out
}

func WriteTierContextArtifacts(resultsRoot string, report TierContextReport) (string, string, error) {
	if resultsRoot == "" {
		return "", "", fmt.Errorf("tier results root unavailable")
	}
	dir := filepath.Join(resultsRoot, "Enumeration", "ActiveDirectory", "Tiering", fmt.Sprintf("Tier%d", report.Tier), fmt.Sprintf("execution-%d", report.SourceExecutionID))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", err
	}
	data, _ := json.MarshalIndent(report, "", "  ")
	jsonPath := filepath.Join(dir, fmt.Sprintf("AD_TIER%d_CONTEXT_EVIDENCE.json", report.Tier))
	if err := os.WriteFile(jsonPath, append(data, '\n'), 0600); err != nil {
		return "", "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "AD TIER %d ADMINISTRATIVE CONTEXT EVIDENCE\n\nSource execution: %d\nSource snapshot: %s\nDomain: %s\nPolicy: %s (%s)\n\nDECLARED GROUPS\n", report.Tier, report.SourceExecutionID, report.SourceSnapshot, report.Domain, report.PolicyID, report.PolicyHash)
	for _, g := range report.DeclaredGroups {
		fmt.Fprintf(&b, "%s [%s]\n", g.Name, g.ID)
	}
	b.WriteString("\nOBSERVED MEMBERSHIP\n")
	for _, p := range report.MembershipPaths {
		fmt.Fprintf(&b, "%s (%s)\n", strings.Join(p.Path, " -> "), p.Classification)
		for _, r := range p.SourceRefs {
			fmt.Fprintf(&b, "  source: %s\n", r)
		}
	}
	b.WriteString("\nDECLARED ADMINISTRATIVE SCOPE\n")
	for _, t := range report.Targets {
		fmt.Fprintf(&b, "%s status=%s observed=%s verification=%s\n", t.Declared.Name, t.Status, t.ObservedName, t.Verification)
	}
	b.WriteString("\nADMINISTRATIVE ACCESS VERIFICATION\nHost-local Administrators membership: NOT VERIFIED\nEffective administrative authorization: NOT VERIFIED\n\nLIMITATIONS\n")
	for _, l := range report.Limitations {
		fmt.Fprintf(&b, "- %s\n", l)
	}
	reportPath := filepath.Join(dir, fmt.Sprintf("AD_TIER%d_CONTEXT_EVIDENCE.txt", report.Tier))
	if err := os.WriteFile(reportPath, []byte(b.String()), 0600); err != nil {
		return "", "", err
	}
	return reportPath, jsonPath, nil
}
