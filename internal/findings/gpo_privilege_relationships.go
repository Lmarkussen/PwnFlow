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

const gpoPrivilegeParserVersion = "rusthound-gpo-privilege-context-v1"

var gpoPrivilegePermissions = map[string]bool{"genericall": true, "genericwrite": true, "writedacl": true, "writeowner": true, "writeproperty": true}

type GPOPrivilegeReport struct {
	SchemaVersion      int                  `json:"schema_version"`
	ParserVersion      string               `json:"parser_version"`
	Status             string               `json:"status"`
	Domain             string               `json:"domain"`
	ACLExecutionID     int64                `json:"acl_execution_id"`
	GPOExecutionID     int64                `json:"gpo_execution_id,omitempty"`
	AnalysisTimestamp  time.Time            `json:"analysis_timestamp"`
	ACLSourceArtifact  string               `json:"acl_source_artifact"`
	GPOSourceArtifacts []string             `json:"gpo_source_artifacts,omitempty"`
	SnapshotMismatch   bool                 `json:"snapshot_mismatch"`
	GPOs               []GPOPrivilegeObject `json:"gpos"`
	Unresolved         []string             `json:"unresolved_joins,omitempty"`
	Omitted            int                  `json:"omitted_relationships"`
	Limitations        []string             `json:"limitations"`
}

type GPOPrivilegeObject struct {
	GUID              string                 `json:"gpo_guid"`
	ObjectGUID        string                 `json:"directory_object_guid,omitempty"`
	Name              string                 `json:"display_name,omitempty"`
	DN                string                 `json:"distinguished_name,omitempty"`
	ACLs              []GPOPrivilegeACL      `json:"observed_acl_relationships"`
	Membership        []ACLMembershipContext `json:"membership_context,omitempty"`
	Links             []GPOPrivilegeLink     `json:"configured_links,omitempty"`
	Applicability     string                 `json:"configured_applicability,omitempty"`
	SourceExecutionID int64                  `json:"gpo_source_execution_id,omitempty"`
	SnapshotCaveat    string                 `json:"snapshot_caveat,omitempty"`
}

type GPOPrivilegeACL struct {
	PrincipalID   string `json:"principal_id"`
	PrincipalName string `json:"principal_name,omitempty"`
	PrincipalType string `json:"principal_type,omitempty"`
	Permission    string `json:"permission"`
	Decision      string `json:"decision"`
	Inheritance   string `json:"inheritance"`
	ObjectType    string `json:"object_type,omitempty"`
	Artifact      string `json:"artifact"`
	ArtifactRef   string `json:"artifact_ref"`
	Occurrences   int    `json:"occurrences"`
}

type GPOPrivilegeLink struct {
	SourceDN       string `json:"source_dn"`
	SourceType     string `json:"source_type"`
	TargetDN       string `json:"target_container_dn,omitempty"`
	Enabled        *bool  `json:"enabled,omitempty"`
	Enforced       *bool  `json:"enforced,omitempty"`
	Order          *int   `json:"link_order,omitempty"`
	Classification string `json:"classification"`
	Applicability  string `json:"applicability"`
	SourceArtifact string `json:"source_artifact"`
}

type gpoMetadataFile struct {
	Domain string `json:"domain"`
	GPOs   []struct {
		GUID         string `json:"guid"`
		ObjectGUID   string `json:"object_guid"`
		OriginalGUID string `json:"original_guid"`
		DN           string `json:"distinguished_name"`
		Attributes   map[string]struct {
			Values []string `json:"values"`
		} `json:"attributes"`
	} `json:"gpos"`
}
type gpoApplicabilityFile struct {
	CollectionExecutionID  int64   `json:"collection_execution_id"`
	SupportingExecutionIDs []int64 `json:"supporting_execution_ids"`
	Domain                 string  `json:"domain"`
	GPOs                   []struct {
		GUID       string `json:"gpo_guid"`
		Name       string `json:"display_name"`
		DN         string `json:"distinguished_name"`
		ObjectGUID string `json:"directory_object_guid"`
	} `json:"gpos"`
	Links []struct {
		GUID           string `json:"gpo_guid"`
		Name           string `json:"gpo_name"`
		SourceDN       string `json:"source_dn"`
		SourceType     string `json:"source_type"`
		TargetDN       string `json:"target_container_dn"`
		Enabled        *bool  `json:"enabled"`
		Enforced       *bool  `json:"enforced"`
		Order          *int   `json:"link_order"`
		Classification string `json:"classification"`
		Applicability  string `json:"applicability"`
		SourceArtifact string `json:"source_artifact"`
	} `json:"configured_relationships"`
	Limitations []string `json:"limitations"`
}

type gpoJoinSnapshot struct {
	Metadata          gpoMetadataFile
	Applicability     gpoApplicabilityFile
	MetadataPath      string
	ApplicabilityPath string
	LinksPath         string
}

func canonicalGPOGUID(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "{}")
	parts := strings.Split(value, "-")
	if len(parts) != 5 || len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 || len(parts[4]) != 12 {
		return ""
	}
	for _, p := range parts {
		if len(p) == 0 {
			return ""
		}
		for _, r := range p {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				return ""
			}
		}
	}
	return strings.ToLower(value)
}

func loadGPOJoinSnapshot(root string) (gpoJoinSnapshot, error) {
	dir := filepath.Join(root, "Enumeration", "ActiveDirectory", "GPO")
	s := gpoJoinSnapshot{MetadataPath: filepath.Join(dir, "GPO_metadata.json"), ApplicabilityPath: filepath.Join(dir, "GPO_applicability.json"), LinksPath: filepath.Join(dir, "GPO_links.json")}
	metadata, err := os.ReadFile(s.MetadataPath)
	if err != nil {
		return s, err
	}
	if err = json.Unmarshal(metadata, &s.Metadata); err != nil {
		return s, err
	}
	applicability, err := os.ReadFile(s.ApplicabilityPath)
	if err != nil {
		return s, err
	}
	if err = json.Unmarshal(applicability, &s.Applicability); err != nil {
		return s, err
	}
	if _, err = os.Stat(s.LinksPath); err != nil {
		s.LinksPath = ""
	}
	return s, nil
}

func AnalyzeGPOPrivilegeRelationships(inventory ACLInventoryReport, assessmentID int64, now time.Time, resultsRoot string) (GPOPrivilegeReport, *storage.FindingInput, error) {
	report := GPOPrivilegeReport{SchemaVersion: 1, ParserVersion: gpoPrivilegeParserVersion, Status: "source_unavailable", Domain: inventory.Domain, ACLExecutionID: inventory.SourceExecutionID, AnalysisTimestamp: now.UTC(), ACLSourceArtifact: inventory.SourceArtifact, Limitations: []string{"Effective AD authorization, GPC/SYSVOL write access and policy application were not evaluated.", "Configured links are cross-snapshot context and do not prove simultaneous existence or client-side application.", "Observed ACL decisions, inheritance and property-specific restrictions remain source-scoped and are not resolved effective rights."}}
	if resultsRoot == "" {
		return report, nil, nil
	}
	snapshot, err := loadGPOJoinSnapshot(resultsRoot)
	if err != nil {
		report.Limitations = append(report.Limitations, "GPO metadata or applicability evidence was unavailable; no GPO join was asserted.")
		return report, nil, nil
	}
	if snapshot.Metadata.Domain != "" && inventory.Domain != "" && !strings.EqualFold(snapshot.Metadata.Domain, inventory.Domain) {
		report.Limitations = append(report.Limitations, "GPO source domain differs from the ACL source domain; joins were rejected.")
		return report, nil, nil
	}
	report.GPOExecutionID = snapshot.Applicability.CollectionExecutionID
	report.GPOSourceArtifacts = []string{snapshot.MetadataPath, snapshot.ApplicabilityPath}
	if snapshot.LinksPath != "" {
		report.GPOSourceArtifacts = append(report.GPOSourceArtifacts, snapshot.LinksPath)
	}
	if report.GPOExecutionID == 0 || report.GPOExecutionID != inventory.SourceExecutionID {
		report.SnapshotMismatch = true
		report.Limitations = append(report.Limitations, "ACL and GPO evidence were produced by different or unspecified executions; identity correlation is not temporal consistency.")
	}
	byID := map[string]*GPOPrivilegeObject{}
	aliases := map[string]string{}
	for _, g := range snapshot.Metadata.GPOs {
		policy := canonicalGPOGUID(g.GUID)
		object := canonicalGPOGUID(g.ObjectGUID)
		original := canonicalGPOGUID(g.OriginalGUID)
		if policy == "" {
			policy = original
		}
		if policy == "" {
			continue
		}
		item := &GPOPrivilegeObject{GUID: policy, ObjectGUID: g.ObjectGUID, DN: g.DN}
		if v := g.Attributes["displayName"]; len(v.Values) > 0 {
			item.Name = v.Values[0]
		}
		if item.Name == "" {
			if v := g.Attributes["displayname"]; len(v.Values) > 0 {
				item.Name = v.Values[0]
			}
		}
		byID[policy] = item
		if object != "" {
			aliases[object] = policy
		}
		aliases[policy] = policy
		if original != "" {
			aliases[original] = policy
		}
	}
	for _, link := range snapshot.Applicability.Links {
		id := canonicalGPOGUID(link.GUID)
		if id == "" {
			continue
		}
		if item := byID[id]; item != nil {
			item.Links = append(item.Links, GPOPrivilegeLink{SourceDN: link.SourceDN, SourceType: link.SourceType, TargetDN: link.TargetDN, Enabled: link.Enabled, Enforced: link.Enforced, Order: link.Order, Classification: link.Classification, Applicability: link.Applicability, SourceArtifact: link.SourceArtifact})
			if item.Applicability == "" {
				item.Applicability = link.Applicability
			}
		}
	}
	for _, g := range snapshot.Applicability.GPOs {
		if id := canonicalGPOGUID(g.GUID); id != "" {
			if item := byID[id]; item != nil && item.Name == "" {
				item.Name = g.Name
			}
			if item := byID[id]; item != nil && item.DN == "" {
				item.DN = g.DN
			}
		}
	}
	seen := map[string]bool{}
	for _, rel := range inventory.Relationships {
		if rel.TargetClass != "gpo_container" || !gpoPrivilegePermissions[normalize(rel.Permission)] {
			continue
		}
		id := aliases[canonicalGPOGUID(rel.TargetID)]
		if id == "" {
			report.Unresolved = append(report.Unresolved, "GPO target identity could not be matched by authoritative GUID: "+rel.TargetID)
			continue
		}
		item := byID[id]
		key := id + "\x00" + rel.PrincipalID + "\x00" + normalize(rel.Permission) + "\x00" + rel.ArtifactRef
		if !seen[key] {
			item.ACLs = append(item.ACLs, GPOPrivilegeACL{PrincipalID: rel.PrincipalID, PrincipalName: rel.PrincipalName, PrincipalType: rel.PrincipalType, Permission: rel.Permission, Decision: rel.Decision, Inheritance: rel.Inheritance, ObjectType: rel.ObjectType, Artifact: rel.Artifact, ArtifactRef: rel.ArtifactRef, Occurrences: rel.Occurrences})
			seen[key] = true
		}
		for _, ctx := range inventory.MembershipContext {
			if ctx.TargetID == rel.TargetID && ctx.ACLPrincipalID == rel.PrincipalID {
				found := false
				for _, old := range item.Membership {
					if membershipPathKey(old, inventory.SourceExecutionID) == membershipPathKey(ctx, inventory.SourceExecutionID) {
						found = true
						break
					}
				}
				if !found {
					item.Membership = append(item.Membership, ctx)
				}
			}
		}
	}
	for id, item := range byID {
		if len(item.ACLs) == 0 {
			continue
		}
		item.SourceExecutionID = report.GPOExecutionID
		item.SnapshotCaveat = "ACL and configured-link evidence are identity-correlated snapshots; effective authorization and application are not verified."
		report.GPOs = append(report.GPOs, *item)
		_ = id
	}
	if len(report.GPOs) == 0 {
		report.Status = "complete"
		report.Limitations = append(report.Limitations, "No supported GPO-targeted ACL relationships were matched to authoritative GPO identities in this execution.")
		return report, nil, nil
	}
	sort.SliceStable(report.GPOs, func(i, j int) bool { return report.GPOs[i].GUID < report.GPOs[j].GUID })
	for i := range report.GPOs {
		sort.SliceStable(report.GPOs[i].ACLs, func(a, b int) bool {
			if report.GPOs[i].ACLs[a].Permission != report.GPOs[i].ACLs[b].Permission {
				return report.GPOs[i].ACLs[a].Permission < report.GPOs[i].ACLs[b].Permission
			}
			return report.GPOs[i].ACLs[a].PrincipalID < report.GPOs[i].ACLs[b].PrincipalID
		})
	}
	if len(report.Unresolved) > 0 || report.SnapshotMismatch {
		report.Status = "partial"
	} else {
		report.Status = "complete"
	}
	sort.Strings(report.Unresolved)
	structured := fmt.Sprintf("Enumeration/ActiveDirectory/GPO/execution-%d/AD_gpo_privilege_relationships.json", inventory.SourceExecutionID)
	evidence, _ := json.Marshal(map[string]any{"source_execution_id": inventory.SourceExecutionID, "gpo_source_execution_id": report.GPOExecutionID, "structured_artifact": structured, "human_report": "AD_GPO_PRIVILEGE_RELATIONSHIPS.txt", "status": report.Status, "snapshot_mismatch": report.SnapshotMismatch, "gpos": report.GPOs, "unresolved_joins": report.Unresolved, "limitations": report.Limitations})
	h := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%d\x00%s", assessmentID, inventory.SourceExecutionID, structured)))
	input := &storage.FindingInput{FindingKey: "adgporel:" + hex.EncodeToString(h[:]), AssessmentID: assessmentID, SourceTool: "RustHound-CE", SourceExecution: inventory.SourceExecutionID, FindingType: "ad_gpo_privilege_relationship_evidence", Title: "AD GPO Privilege Relationship Evidence", Description: fmt.Sprintf("RustHound recorded %d supported GPO ACL relationship(s) matched to configured GPO identity context. Effective authorization and policy application were not verified.", gpoACLCount(report)), Severity: "informational", Confidence: "observed-cross-snapshot-evidence", AffectedObjectID: inventory.Domain, AffectedObject: inventory.Domain, EvidenceJSON: string(evidence), ArtifactRef: "/", ObservedAt: now.UTC(), Status: "open", ParserVersion: gpoPrivilegeParserVersion}
	return report, input, nil
}

func gpoACLCount(report GPOPrivilegeReport) int {
	total := 0
	for _, g := range report.GPOs {
		total += len(g.ACLs)
	}
	return total
}

func WriteGPOPrivilegeArtifacts(resultsRoot string, report GPOPrivilegeReport) (string, error) {
	dir := filepath.Join(resultsRoot, "Enumeration", "ActiveDirectory", "GPO", fmt.Sprintf("execution-%d", report.ACLExecutionID))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "AD_gpo_privilege_relationships.json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	if err = writePrivateAtomic(path, data); err != nil {
		return "", err
	}
	return path, nil
}

func WriteGPOPrivilegeReport(resultsRoot string, report GPOPrivilegeReport) (string, error) {
	path := filepath.Join(resultsRoot, "AD_GPO_PRIVILEGE_RELATIONSHIPS.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintln(&b, "======================================================================\nPWNFlow AD GPO PRIVILEGE RELATIONSHIPS\n======================================================================")
	fmt.Fprintf(&b, "\nDOMAIN: %s\nACL SOURCE EXECUTION: %d\nGPO SOURCE EXECUTION: %d\nSTATUS: %s\nSNAPSHOT MISMATCH: %t\nANALYZED: %s\n", report.Domain, report.ACLExecutionID, report.GPOExecutionID, report.Status, report.SnapshotMismatch, report.AnalysisTimestamp.UTC().Format(time.RFC3339))
	for _, g := range report.GPOs {
		fmt.Fprintf(&b, "\nGPO: %s [%s]\nDN: %s\n", g.Name, g.GUID, g.DN)
		for _, a := range g.ACLs {
			fmt.Fprintf(&b, "  Principal: %s [%s]\n  Permission: %s\n  Decision: %s; Inheritance: %s\n  Effective permission: NOT VERIFIED\n  Evidence: %s#%s\n", a.PrincipalName, a.PrincipalID, a.Permission, a.Decision, a.Inheritance, a.Artifact, a.ArtifactRef)
		}
		if len(g.Links) == 0 {
			fmt.Fprintln(&b, "  Configured links: no link context observed in this snapshot.")
		} else {
			fmt.Fprintln(&b, "  Configured links:")
			for _, l := range g.Links {
				enabled := "UNKNOWN"
				if l.Enabled != nil {
					enabled = fmt.Sprintf("%t", *l.Enabled)
				}
				fmt.Fprintf(&b, "    %s -> %s enabled=%s enforced=%v order=%v (%s)\n", l.SourceType, l.TargetDN, enabled, l.Enforced, l.Order, l.Applicability)
			}
		}
		if len(g.Membership) > 0 {
			fmt.Fprintln(&b, "  Membership context:")
			for _, m := range g.Membership {
				names := []string{m.MemberName}
				for _, h := range m.GroupPath {
					names = append(names, h.Name)
				}
				fmt.Fprintf(&b, "    %s\n", strings.Join(names, " -> "))
			}
		}
	}
	fmt.Fprintln(&b, "\nLIMITATIONS:\n- Effective AD authorization, GPC/SYSVOL write access and client-side policy application were not verified.\n- Configured links are source-backed context, not proof of effective policy processing.\n- Cross-snapshot identity correlation does not establish temporal consistency.\n\nSOURCE ARTIFACTS:")
	for _, p := range append([]string{report.ACLSourceArtifact}, report.GPOSourceArtifacts...) {
		fmt.Fprintf(&b, "- %s\n", p)
	}
	if len(report.Unresolved) > 0 {
		fmt.Fprintln(&b, "\nUNRESOLVED JOINS:")
		for _, u := range report.Unresolved {
			fmt.Fprintf(&b, "- %s\n", u)
		}
	}
	if err := writePrivateAtomic(path, []byte(b.String())); err != nil {
		return "", err
	}
	return path, nil
}

func writePrivateAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".gpo-priv-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
