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

const tier0ContextParserVersion = "rusthound-tier0-context-v1"

const (
	tier0MaxGroups      = 32
	tier0MaxPrincipals  = 128
	tier0MaxMembership  = 256
	tier0MaxACLs        = 24
	tier0MaxControllers = 32
	tier0MaxUnresolved  = 128
)

type Tier0ContextReport struct {
	SchemaVersion     int                        `json:"schema_version"`
	ParserVersion     string                     `json:"parser_version"`
	Status            string                     `json:"status"`
	Coverage          string                     `json:"coverage"`
	Domain            string                     `json:"domain,omitempty"`
	DomainID          string                     `json:"domain_id,omitempty"`
	SourceExecutionID int64                      `json:"source_execution_id"`
	SourceSnapshot    string                     `json:"source_snapshot"`
	SourceArtifacts   []string                   `json:"source_artifacts"`
	SourceHashes      map[string]string          `json:"source_hashes,omitempty"`
	AnalysisTimestamp time.Time                  `json:"analysis_timestamp"`
	Tier0GroupPolicy  string                     `json:"tier0_group_policy"`
	Tier0Groups       []Tier0Group               `json:"tier0_groups"`
	Tier0Principals   []Tier0Principal           `json:"tier0_principals"`
	DomainControllers []Tier0Controller          `json:"domain_controllers"`
	MembershipPaths   []ProtectedMembershipPath  `json:"membership_paths,omitempty"`
	ACLRelationships  []ACLInventoryRelationship `json:"acl_relationships,omitempty"`
	Replication       []ReplicationDomainRoot    `json:"replication_rights,omitempty"`
	AdminCountUsers   []ProtectedAccountObject   `json:"admincount_users,omitempty"`
	AdminCountGroups  []ProtectedAccountObject   `json:"admincount_groups,omitempty"`
	AdminSDHolder     *AdminSDHolderEvidence     `json:"admin_sd_holder,omitempty"`
	Unresolved        []string                   `json:"unresolved_identities,omitempty"`
	OmittedMembership int                        `json:"omitted_membership_paths"`
	OmittedACL        int                        `json:"omitted_acl_relationships"`
	Limits            map[string]int             `json:"limits"`
	Limitations       []string                   `json:"limitations"`
}

type Tier0Group struct {
	ID             string `json:"id"`
	Name           string `json:"name,omitempty"`
	Type           string `json:"type"`
	DN             string `json:"distinguished_name,omitempty"`
	Role           string `json:"role"`
	SourceArtifact string `json:"source_artifact"`
	SourceRef      string `json:"source_ref"`
}

type Tier0Principal struct {
	ID             string `json:"id"`
	Name           string `json:"name,omitempty"`
	Type           string `json:"type,omitempty"`
	AdminCount     string `json:"admin_count,omitempty"`
	SourceArtifact string `json:"source_artifact,omitempty"`
	SourceRef      string `json:"source_ref,omitempty"`
}

type Tier0Controller struct {
	ID             string `json:"id"`
	Name           string `json:"name,omitempty"`
	DN             string `json:"distinguished_name,omitempty"`
	ObjectType     string `json:"object_type"`
	SourceArtifact string `json:"source_artifact"`
	SourceRef      string `json:"source_ref"`
}

func AnalyzeTier0Context(ctx context.Context, inputPath string, inventory ACLInventoryReport, protected ProtectedAccountsReport, assessmentID, executionID int64, now time.Time) (Tier0ContextReport, *storage.FindingInput, error) {
	result := Tier0ContextReport{
		SchemaVersion: 1, ParserVersion: tier0ContextParserVersion, Status: "complete", Coverage: "partial",
		Domain: inventory.Domain, SourceExecutionID: executionID, SourceSnapshot: filepath.Base(filepath.Clean(inputPath)),
		AnalysisTimestamp: now.UTC(), SourceHashes: map[string]string{}, Tier0GroupPolicy: "Domain Admins (RID 512), Enterprise Admins (RID 519), Schema Admins (RID 518), Domain Controllers (RID 516), Read-only Domain Controllers (RID 521), Key Admins (RID 526), Enterprise Key Admins (RID 527), and validated well-known Administrators (S-1-5-32-544). Display names alone are never sufficient.",
		Limits: map[string]int{"groups": tier0MaxGroups, "principals": tier0MaxPrincipals, "membership_paths": tier0MaxMembership, "acl_relationships": tier0MaxACLs, "controllers": tier0MaxControllers},
		Limitations: []string{
			"Tier 0-associated context is observed evidence, not effective administrative authorization.",
			"Tier 1/2 authority, local Administrators membership, applied GPO and organization-specific tier policy were not assessed.",
			"ACL allow/deny precedence, inheritance applicability, object-specific rights, token construction and SIDHistory were not evaluated.",
			"Observed replication rights do not establish effective replication authorization or DCSync capability.",
			"AdminCount, AdminSDHolder and membership evidence do not establish current SDProp protection.",
		},
	}
	if executionID <= 0 || assessmentID <= 0 {
		return result, nil, fmt.Errorf("tier-0 analysis requires assessment and execution IDs")
	}
	if inventory.SourceExecutionID != 0 && inventory.SourceExecutionID != executionID {
		return result, nil, fmt.Errorf("ACL inventory execution %d does not match RustHound execution %d", inventory.SourceExecutionID, executionID)
	}
	if protected.SourceExecutionID != 0 && protected.SourceExecutionID != executionID {
		return result, nil, fmt.Errorf("protected-account evidence execution %d does not match RustHound execution %d", protected.SourceExecutionID, executionID)
	}
	if now.IsZero() {
		result.AnalysisTimestamp = time.Now().UTC()
	}
	info, err := os.Stat(inputPath)
	if err != nil || !info.IsDir() {
		if err == nil {
			err = fmt.Errorf("not a directory")
		}
		return result, nil, fmt.Errorf("RustHound source snapshot unavailable: %w", err)
	}
	files, err := rustHoundGroupFiles(inputPath)
	if err != nil || len(files) == 0 {
		if err == nil {
			err = fmt.Errorf("no JSON artifacts")
		}
		return result, nil, fmt.Errorf("RustHound source snapshot unavailable: %w", err)
	}
	objects := map[string]groupObject{}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return result, nil, err
		}
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
			return result, nil, fmt.Errorf("parse RustHound artifact %s: %w", file, err)
		}
		kind := strings.ToLower(export.Meta.Type)
		if kind != "users" && kind != "groups" && kind != "computers" && kind != "domains" {
			continue
		}
		result.SourceArtifacts = append(result.SourceArtifacts, file)
		if hash, hashErr := fileSHA256(file); hashErr == nil {
			result.SourceHashes[file] = hash
		}
		for index, raw := range export.Data {
			object, decodeErr := decodeGroupObject(raw, kind, file, index)
			if decodeErr != nil {
				return result, nil, decodeErr
			}
			if object.ID == "" {
				continue
			}
			objects[groupIdentity(object.ID)] = object
			if kind == "domains" && result.DomainID == "" {
				result.DomainID = object.ID
				result.Domain = object.Name
			}
			if result.Domain == "" {
				result.Domain = object.Domain
			}
			if kind == "computers" && isTier0Controller(raw, object) && len(result.DomainControllers) < tier0MaxControllers {
				result.DomainControllers = append(result.DomainControllers, Tier0Controller{ID: object.ID, Name: object.Name, DN: rawPropertyString(raw, "distinguishedname"), ObjectType: "computer", SourceArtifact: file, SourceRef: object.Ref})
			}
		}
	}
	if result.Domain == "" {
		result.Domain = protected.Domain
	}
	if result.Domain == "" {
		result.Status = "partial"
		result.Limitations = append(result.Limitations, "Domain identity was not resolved from the selected RustHound snapshot.")
	}
	groupByID := map[string]Tier0Group{}
	for _, object := range objects {
		if object.Type != "group" {
			continue
		}
		if role, ok := tier0GroupRole(object.ID); ok && len(groupByID) < tier0MaxGroups {
			groupByID[groupIdentity(object.ID)] = Tier0Group{ID: object.ID, Name: object.Name, Type: object.Type, Role: role, DN: objectDN(objects, object.ID), SourceArtifact: object.Artifact, SourceRef: object.Ref}
		}
	}
	for _, group := range groupByID {
		result.Tier0Groups = append(result.Tier0Groups, group)
	}
	sort.Slice(result.Tier0Groups, func(i, j int) bool {
		return groupIdentity(result.Tier0Groups[i].ID) < groupIdentity(result.Tier0Groups[j].ID)
	})
	tierIDs := map[string]bool{}
	for _, group := range result.Tier0Groups {
		tierIDs[groupIdentity(group.ID)] = true
	}
	associated := map[string]bool{}
	for _, group := range result.Tier0Groups {
		associated[groupIdentity(group.ID)] = true
	}
	for _, path := range protected.MembershipPaths {
		if tierIDs[groupIdentity(path.GroupID)] {
			if len(result.MembershipPaths) < tier0MaxMembership {
				result.MembershipPaths = append(result.MembershipPaths, path)
			} else {
				result.OmittedMembership++
			}
			associated[groupIdentity(path.MemberID)] = true
		}
	}
	for _, object := range objects {
		if (object.Type == "user" || object.Type == "group") && associated[groupIdentity(object.ID)] {
			result.Tier0Principals = append(result.Tier0Principals, Tier0Principal{ID: object.ID, Name: object.Name, Type: object.Type, SourceArtifact: object.Artifact, SourceRef: object.Ref})
		}
	}
	for _, object := range append(append([]ProtectedAccountObject{}, protected.Users...), protected.Groups...) {
		if object.AdminCount == "true" && associated[groupIdentity(object.ID)] {
			for index := range result.Tier0Principals {
				if groupIdentity(result.Tier0Principals[index].ID) == groupIdentity(object.ID) {
					result.Tier0Principals[index].AdminCount = object.AdminCount
				}
			}
		}
	}
	seenPrincipal := map[string]bool{}
	filtered := result.Tier0Principals[:0]
	for _, principal := range result.Tier0Principals {
		key := groupIdentity(principal.ID)
		if !seenPrincipal[key] {
			seenPrincipal[key] = true
			filtered = append(filtered, principal)
		}
	}
	result.Tier0Principals = filtered
	sort.Slice(result.Tier0Principals, func(i, j int) bool {
		return groupIdentity(result.Tier0Principals[i].ID) < groupIdentity(result.Tier0Principals[j].ID)
	})
	for _, relation := range inventory.Relationships {
		if len(result.ACLRelationships) >= tier0MaxACLs {
			result.OmittedACL++
			continue
		}
		if associated[groupIdentity(relation.PrincipalID)] || relation.TargetClass == "domain_root" || isControllerTarget(relation, result.DomainControllers) {
			result.ACLRelationships = append(result.ACLRelationships, relation)
		}
	}
	sort.SliceStable(result.ACLRelationships, func(i, j int) bool {
		return tier0ACLKey(result.ACLRelationships[i]) < tier0ACLKey(result.ACLRelationships[j])
	})
	replication, _ := AnalyzeReplicationRights(inventory, assessmentID, now)
	result.Replication = replication.DomainRoots
	if protected.AdminSDHolder != nil {
		result.AdminSDHolder = protected.AdminSDHolder
	}
	for _, object := range append(append([]ProtectedAccountObject{}, protected.Users...), protected.Groups...) {
		if object.AdminCount == "true" && associated[groupIdentity(object.ID)] {
			if object.Type == "user" {
				result.AdminCountUsers = append(result.AdminCountUsers, object)
			} else {
				result.AdminCountGroups = append(result.AdminCountGroups, object)
			}
		}
	}
	if len(result.Tier0Groups) == 0 && len(result.DomainControllers) == 0 && len(result.ACLRelationships) == 0 {
		return result, nil, nil
	}
	if protected.Status == "partial" || inventory.Status != "complete" || inventory.OmittedRelations > 0 || result.OmittedACL > 0 || result.OmittedMembership > 0 {
		result.Status = "partial"
	}
	result.Coverage = "partial; bounded source-backed Tier 0 context, effective authority not assessed"
	reportPath, jsonPath, err := WriteTier0ContextArtifacts(rustHoundResultsRoot(inputPath), result)
	if err != nil {
		return result, nil, err
	}
	evidence, _ := json.Marshal(map[string]any{"source_execution_id": executionID, "source_snapshot": result.SourceSnapshot, "structured_artifact": jsonPath, "human_report": "AD_TIER0_CONTEXT_EVIDENCE.txt", "domain": result.Domain, "domain_controllers": result.DomainControllers, "tier0_groups": result.Tier0Groups, "tier0_principals": result.Tier0Principals, "membership_paths": result.MembershipPaths, "acl_relationships": result.ACLRelationships, "replication_rights": result.Replication, "admincount_users": result.AdminCountUsers, "admincount_groups": result.AdminCountGroups, "admin_sd_holder": result.AdminSDHolder, "coverage": result.Coverage, "limitations": result.Limitations})
	h := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%d\x00%s", assessmentID, executionID, inputPath)))
	input := &storage.FindingInput{FindingKey: "adtier0:" + hex.EncodeToString(h[:]), AssessmentID: assessmentID, SourceTool: "RustHound-CE", SourceExecution: executionID, FindingType: "ad_tier0_context_evidence", Title: "AD Tier 0 Administrative Context Evidence Overview", Description: "Collected directory evidence identifies accounts, groups and configured relationships associated with Active Directory's identity-control plane. These relationships support privilege-boundary review but do not establish effective administrative authorization, compromise or tier-policy violations.", Severity: "informational", Confidence: "observed-partial-tier0-context", AffectedObjectID: result.DomainID, AffectedObject: "Tier 0 administrative context", EvidenceJSON: string(evidence), ArtifactPath: reportPath, ArtifactRef: "/", ObservedAt: now.UTC(), Status: "open", ParserVersion: tier0ContextParserVersion}
	return result, input, nil
}

func tier0GroupRole(id string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(id))
	roles := map[string]string{"-512": "Domain Admins", "-519": "Enterprise Admins", "-518": "Schema Admins", "-516": "Domain Controllers", "-521": "Read-only Domain Controllers", "-526": "Key Admins", "-527": "Enterprise Key Admins", "s-1-5-32-544": "Administrators"}
	for suffix, role := range roles {
		if strings.HasSuffix(key, suffix) {
			return role, true
		}
	}
	return "", false
}

func isTier0Controller(raw json.RawMessage, object groupObject) bool {
	return strings.EqualFold(rawPropertyString(raw, "isdc"), "true") || strings.Contains(strings.ToLower(rawPropertyString(raw, "distinguishedname")), "ou=domain controllers") || strings.Contains(strings.ToLower(object.Name), "dc.") && strings.EqualFold(object.Type, "computer")
}
func rawPropertyString(raw json.RawMessage, key string) string {
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	props := rawObject(fields, "Properties")
	return rawString(props, key)
}
func objectDN(objects map[string]groupObject, id string) string { return objects[groupIdentity(id)].DN }
func isControllerTarget(relation ACLInventoryRelationship, controllers []Tier0Controller) bool {
	for _, controller := range controllers {
		if groupIdentity(controller.ID) == groupIdentity(relation.TargetID) {
			return true
		}
	}
	return false
}
func tier0ACLKey(r ACLInventoryRelationship) string {
	return strings.Join([]string{r.TargetID, r.PrincipalID, r.Permission, r.ArtifactRef}, "\x00")
}

func WriteTier0ContextArtifacts(resultsRoot string, report Tier0ContextReport) (string, string, error) {
	if resultsRoot == "" {
		return "", "", fmt.Errorf("tier-0 results root unavailable")
	}
	dir := filepath.Join(resultsRoot, "Enumeration", "ActiveDirectory", "Tier0", fmt.Sprintf("execution-%d", report.SourceExecutionID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	jsonPath := filepath.Join(dir, "AD_tier0_context_evidence.json")
	data, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(jsonPath, append(data, '\n'), 0o600); err != nil {
		return "", "", err
	}
	reportPath := filepath.Join(dir, "AD_TIER0_CONTEXT_EVIDENCE.txt")
	var b strings.Builder
	fmt.Fprintf(&b, "AD TIER 0 ADMINISTRATIVE CONTEXT EVIDENCE\n\nSource execution: %d\nSource snapshot: %s\nDomain: %s\nStatus: %s\nCoverage: %s\n\n", report.SourceExecutionID, report.SourceSnapshot, report.Domain, report.Status, report.Coverage)
	b.WriteString("DOMAIN CONTROLLERS\n")
	for _, c := range report.DomainControllers {
		fmt.Fprintf(&b, "%s [%s] %s\n", c.Name, c.ID, c.DN)
	}
	b.WriteString("\nTIER 0-ASSOCIATED GROUPS\n")
	for _, g := range report.Tier0Groups {
		fmt.Fprintf(&b, "%s [%s] role=%s\n", g.Name, g.ID, g.Role)
	}
	b.WriteString("\nOBSERVED MEMBERSHIP\n")
	for _, p := range report.MembershipPaths {
		fmt.Fprintf(&b, "%s (%s)\n", strings.Join(p.Path, " -> "), p.Classification)
		for _, ref := range p.SourceRefs {
			fmt.Fprintf(&b, "  membership source: %s\n", ref)
		}
	}
	b.WriteString("\nOBSERVED ACL CONFIGURATION\n")
	for _, r := range report.ACLRelationships {
		fmt.Fprintf(&b, "%s -> %s -> %s [%s] (%s; %s) source=%s#%s\n", r.PrincipalName, r.Permission, r.TargetName, r.TargetID, r.Decision, r.Inheritance, r.Artifact, r.ArtifactRef)
	}
	b.WriteString("\nREPLICATION RIGHTS\n")
	for _, root := range report.Replication {
		fmt.Fprintf(&b, "Domain root: %s [%s]\n", root.Name, root.ID)
		for _, p := range root.Principals {
			for _, right := range p.Rights {
				fmt.Fprintf(&b, "  %s - %s: %s\n", p.Name, right.Right, strings.ToUpper(right.Status))
			}
		}
	}
	b.WriteString("\nADMINCOUNT CONTEXT\n")
	for _, o := range append(append([]ProtectedAccountObject{}, report.AdminCountUsers...), report.AdminCountGroups...) {
		fmt.Fprintf(&b, "%s [%s] type=%s adminCount=%s membership=%s\n", o.Name, o.ID, o.Type, o.AdminCount, o.Membership)
	}
	b.WriteString("\nADMINSDHOLDER\n")
	if report.AdminSDHolder != nil {
		fmt.Fprintf(&b, "%s [%s] ACEs=%d descriptor=%s\n", report.AdminSDHolder.DN, report.AdminSDHolder.ID, len(report.AdminSDHolder.ACEs), report.AdminSDHolder.Descriptor)
	} else {
		b.WriteString("AdminSDHolder object: NOT OBSERVED\n")
	}
	b.WriteString("\nLIMITATIONS\n- Effective administrative authority: NOT VERIFIED\n- Tier 1/2 authority: NOT ASSESSED\n- Cross-tier violations: NOT ESTABLISHED\n- DCSync capability: NOT VERIFIED\n")
	for _, l := range report.Limitations {
		fmt.Fprintf(&b, "- %s\n", l)
	}
	b.WriteString("\nSOURCE ARTIFACTS\n")
	for _, source := range report.SourceArtifacts {
		fmt.Fprintln(&b, source)
	}
	tmp := reportPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return "", "", err
	}
	if err := os.Rename(tmp, reportPath); err != nil {
		return "", "", err
	}
	return reportPath, jsonPath, nil
}
