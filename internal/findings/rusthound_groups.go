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

const groupParserVersion = "rusthound-groups-v1"

type GroupMembershipReport struct {
	Artifact             string
	GroupsExamined       int
	DirectEdges          int
	NestedRelationships  int
	PrivilegedGroups     []PrivilegedGroup
	UnresolvedReferences int
	Coverage             string
}

type PrivilegedGroup struct {
	ID, Name, Domain, DomainSID string
	Privilege                   string
	Artifact                    string
	ArtifactRef                 string
	DirectMembers               []GroupPrincipal
	NestedMembers               []GroupPrincipal
	Unresolved                  []GroupPrincipal
}

type GroupPrincipal struct {
	ID, Name, Domain, Type string
	Deleted, Disabled      bool
	Path                   []string
}

type groupObject struct {
	ID, Name, SAM, Domain, DomainSID, Type, Artifact, Ref, DN string
	Deleted, Disabled                                         bool
	Members                                                   []string
}

type groupEdge struct{ Parent, Member, Artifact, Ref string }

// AnalyzeRustHoundGroups normalizes only the allow-listed identity and
// membership fields from RustHound exports. It never writes the source.
func AnalyzeRustHoundGroups(ctx context.Context, inputPath string, assessmentID, executionID int64, now time.Time) (GroupMembershipReport, []storage.FindingInput, error) {
	if assessmentID <= 0 {
		return GroupMembershipReport{}, nil, fmt.Errorf("assessment id must be positive")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	files, err := rustHoundGroupFiles(inputPath)
	if err != nil {
		return GroupMembershipReport{}, nil, err
	}
	objects := map[string]groupObject{}
	var groups []groupObject
	var edges []groupEdge
	report := GroupMembershipReport{Coverage: "Partial / not fully verified"}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return report, nil, err
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return report, nil, err
		}
		var export struct {
			Meta struct {
				Type string `json:"type"`
			} `json:"meta"`
			Data []json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(data, &export); err != nil {
			return report, nil, fmt.Errorf("parse RustHound group artifact %s: %w", file, err)
		}
		kind := strings.ToLower(export.Meta.Type)
		if kind != "groups" && kind != "users" && kind != "computers" {
			continue
		}
		for index, raw := range export.Data {
			object, err := decodeGroupObject(raw, kind, file, index)
			if err != nil {
				return report, nil, err
			}
			if object.ID == "" {
				continue
			}
			objects[groupIdentity(object.ID)] = object
			if kind == "groups" {
				groups = append(groups, object)
				report.GroupsExamined++
			}
			if kind == "groups" {
				for _, member := range object.Members {
					if member != "" {
						edges = append(edges, groupEdge{Parent: object.ID, Member: member, Artifact: file, Ref: object.Ref + "/Members"})
					}
				}
			}
		}
	}
	seenEdges := map[string]bool{}
	groupMembers := map[string][]groupEdge{}
	for _, edge := range edges {
		key := groupIdentity(edge.Parent) + "\x00" + groupIdentity(edge.Member)
		if seenEdges[key] {
			continue
		}
		seenEdges[key] = true
		groupMembers[groupIdentity(edge.Parent)] = append(groupMembers[groupIdentity(edge.Parent)], edge)
		report.DirectEdges++
	}
	privileged := make([]PrivilegedGroup, 0)
	for _, group := range groups {
		privilege, ok := privilegedGroupName(group)
		if !ok {
			continue
		}
		item := PrivilegedGroup{ID: group.ID, Name: principalName(group), Domain: group.Domain, DomainSID: group.DomainSID, Privilege: privilege, Artifact: group.Artifact, ArtifactRef: group.Ref + "/Members"}
		for _, edge := range groupMembers[groupIdentity(group.ID)] {
			principal := resolveGroupPrincipal(objects, edge.Member)
			if foreignReference(principal.ID, group.DomainSID) {
				principal.Type = "foreign"
			}
			if principal.Domain != "" && group.Domain != "" && !strings.EqualFold(principal.Domain, group.Domain) {
				principal.Type = "foreign"
			}
			if principal.Type == "unknown" || principal.Type == "foreign" || principal.Deleted {
				item.Unresolved = appendUniquePrincipal(item.Unresolved, principal)
				continue
			}
			if principal.Type == "group" {
				walkNested(group, principal.ID, []string{group.ID, principal.ID}, groupMembers, objects, &item, map[string]bool{groupIdentity(group.ID): true}, &report)
				item.DirectMembers = appendUniquePrincipal(item.DirectMembers, principal)
			} else {
				item.DirectMembers = appendUniquePrincipal(item.DirectMembers, principal)
			}
		}
		privileged = append(privileged, item)
	}
	sort.Slice(privileged, func(i, j int) bool {
		return strings.ToLower(privileged[i].Privilege+privileged[i].ID) < strings.ToLower(privileged[j].Privilege+privileged[j].ID)
	})
	report.PrivilegedGroups = privileged
	for _, group := range privileged {
		report.UnresolvedReferences += len(group.Unresolved)
	}
	var inputs []storage.FindingInput
	for _, group := range privileged {
		evidence, _ := json.Marshal(map[string]any{"group_id": group.ID, "group_name": group.Name, "privilege": group.Privilege, "direct_members": len(group.DirectMembers), "nested_members": len(group.NestedMembers), "unresolved": len(group.Unresolved), "coverage": report.Coverage})
		inputs = append(inputs, groupFinding(assessmentID, executionID, group, "ad_privileged_group_membership_inventory", "Privileged AD group membership inventory", string(evidence), now))
		effective := uniqueResolvedMembers(group.DirectMembers, group.NestedMembers)
		summaryEvidence, _ := json.Marshal(map[string]any{
			"domain":                 group.Domain,
			"domain_sid":             group.DomainSID,
			"group_id":               group.ID,
			"group_name":             group.Name,
			"direct_member_count":    len(group.DirectMembers),
			"effective_member_count": len(effective),
			"unresolved_count":       len(group.Unresolved),
			"coverage":               report.Coverage,
			"collection_timestamp":   now.UTC(),
		})
		inputs = append(inputs, groupFinding(assessmentID, executionID, group, "domain_information_privileged_group_membership", "Domain Privileged Group Membership Summary", string(summaryEvidence), now))
		if len(group.NestedMembers) > 0 {
			paths := make([]string, 0, len(group.NestedMembers))
			for _, member := range group.NestedMembers {
				paths = append(paths, strings.Join(member.Path, " <- "))
			}
			value, _ := json.Marshal(map[string]any{"group_id": group.ID, "nested_paths": paths, "coverage": report.Coverage})
			input := groupFinding(assessmentID, executionID, group, "ad_nested_privileged_group_membership", "Nested privileged AD group membership", string(value), now)
			input.FindingKey = stableSourceKey(assessmentID, input.FindingType, group.ID, paths)
			inputs = append(inputs, input)
		}
		if len(group.Unresolved) > 0 {
			ids := make([]string, 0, len(group.Unresolved))
			for _, member := range group.Unresolved {
				ids = append(ids, member.ID)
			}
			value, _ := json.Marshal(map[string]any{"group_id": group.ID, "unresolved_ids": ids, "coverage": report.Coverage})
			input := groupFinding(assessmentID, executionID, group, "ad_unresolved_privileged_group_principal", "Unresolved privileged AD group principal", string(value), now)
			input.FindingKey = stableSourceKey(assessmentID, input.FindingType, group.ID, ids)
			inputs = append(inputs, input)
		}
	}
	if len(files) > 0 {
		report.Artifact = files[0]
	}
	return report, inputs, nil
}

func uniqueResolvedMembers(groups ...[]GroupPrincipal) []GroupPrincipal {
	seen := map[string]bool{}
	result := make([]GroupPrincipal, 0)
	for _, principals := range groups {
		for _, principal := range principals {
			if principal.Type == "group" || principal.Type == "unknown" || principal.Type == "foreign" || principal.Deleted || seen[groupIdentity(principal.ID)] {
				continue
			}
			seen[groupIdentity(principal.ID)] = true
			result = append(result, principal)
		}
	}
	return result
}

func rustHoundGroupFiles(inputPath string) ([]string, error) {
	info, err := os.Stat(inputPath)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{inputPath}, nil
	}
	var files []string
	err = filepath.WalkDir(inputPath, func(file string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(file), ".json") {
			files = append(files, file)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func decodeGroupObject(raw json.RawMessage, kind, artifact string, index int) (groupObject, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return groupObject{}, err
	}
	props := rawObject(fields, "Properties")
	object := groupObject{ID: rawString(fields, "ObjectIdentifier"), Name: rawString(props, "name"), SAM: rawString(props, "samaccountname"), Domain: rawString(props, "domain"), DomainSID: rawString(props, "domainsid"), Type: strings.TrimSuffix(kind, "s"), Artifact: artifact, Ref: fmt.Sprintf("/data/%d", index), DN: firstString(props, "distinguishedname", "distinguishedName", "dn"), Deleted: rawBool(props, "isdeleted") || rawBool(fields, "IsDeleted")}
	if object.Type == "user" {
		if value, known := rawBoolValue(props, "enabled"); !known {
			object.Disabled = false
		} else {
			object.Disabled = !value
		}
	}
	if kind == "groups" {
		var members []json.RawMessage
		_ = json.Unmarshal(fields["Members"], &members)
		for _, rawMember := range members {
			var value string
			if json.Unmarshal(rawMember, &value) == nil {
				object.Members = append(object.Members, value)
				continue
			}
			var member map[string]json.RawMessage
			if json.Unmarshal(rawMember, &member) == nil {
				value = firstString(member, "ObjectIdentifier", "objectidentifier", "id", "sid")
				if value != "" {
					object.Members = append(object.Members, value)
				}
			}
		}
	}
	return object, nil
}

func groupIdentity(id string) string { return strings.ToLower(strings.TrimSpace(id)) }
func principalName(object groupObject) string {
	if object.SAM != "" {
		return object.SAM
	}
	if object.Name != "" {
		return object.Name
	}
	return object.ID
}
func resolveGroupPrincipal(objects map[string]groupObject, id string) GroupPrincipal {
	if object, ok := objects[groupIdentity(id)]; ok {
		typ := object.Type
		return GroupPrincipal{ID: object.ID, Name: principalName(object), Domain: object.Domain, Type: typ, Deleted: object.Deleted, Disabled: object.Disabled}
	}
	return GroupPrincipal{ID: id, Name: id, Type: "unknown"}
}
func appendUniquePrincipal(values []GroupPrincipal, value GroupPrincipal) []GroupPrincipal {
	for _, existing := range values {
		if groupIdentity(existing.ID) == groupIdentity(value.ID) {
			return values
		}
	}
	return append(values, value)
}

func walkNested(root groupObject, groupID string, path []string, members map[string][]groupEdge, objects map[string]groupObject, result *PrivilegedGroup, visiting map[string]bool, report *GroupMembershipReport) {
	key := groupIdentity(groupID)
	if visiting[key] {
		return
	}
	visiting[key] = true
	defer delete(visiting, key)
	for _, edge := range members[key] {
		principal := resolveGroupPrincipal(objects, edge.Member)
		if foreignReference(principal.ID, root.DomainSID) {
			principal.Type = "foreign"
		}
		if principal.Domain != "" && root.Domain != "" && !strings.EqualFold(principal.Domain, root.Domain) {
			principal.Type = "foreign"
		}
		principal.Path = append(append([]string{}, path...), principal.ID)
		if principal.Type == "unknown" || principal.Type == "foreign" || principal.Deleted {
			result.Unresolved = appendUniquePrincipal(result.Unresolved, principal)
			continue
		}
		if principal.Type == "group" {
			walkNested(root, principal.ID, principal.Path, members, objects, result, visiting, report)
			continue
		}
		if !containsPrincipal(result.DirectMembers, principal.ID) {
			result.NestedMembers = appendUniquePrincipal(result.NestedMembers, principal)
			report.NestedRelationships++
		}
	}
}
func containsPrincipal(values []GroupPrincipal, id string) bool {
	for _, value := range values {
		if groupIdentity(value.ID) == groupIdentity(id) {
			return true
		}
	}
	return false
}

func foreignReference(id, domainSID string) bool {
	id = strings.ToUpper(strings.TrimSpace(id))
	domainSID = strings.ToUpper(strings.TrimSpace(domainSID))
	return strings.HasPrefix(id, "S-1-5-21-") && domainSID != "" && !strings.HasPrefix(id, domainSID+"-")
}

func privilegedGroupName(group groupObject) (string, bool) {
	sid := strings.ToUpper(strings.TrimSpace(group.ID))
	builtins := map[string]string{"S-1-5-32-544": "Administrators", "S-1-5-32-548": "Account Operators", "S-1-5-32-549": "Server Operators", "S-1-5-32-550": "Print Operators", "S-1-5-32-551": "Backup Operators"}
	if name, ok := builtins[sid]; ok {
		return name, true
	}
	parts := strings.Split(sid, "-")
	if len(parts) < 2 {
		return "", false
	}
	rid := parts[len(parts)-1]
	domainSID := strings.ToUpper(strings.TrimSpace(group.DomainSID))
	if domainSID == "" {
		domainSID = strings.Join(parts[:len(parts)-1], "-")
	}
	if !strings.HasPrefix(sid, domainSID+"-") {
		return "", false
	}
	known := map[string]string{"512": "Domain Admins", "518": "Schema Admins", "519": "Enterprise Admins", "520": "Group Policy Creator Owners"}
	privilege, ok := known[rid]
	return privilege, ok
}

func groupFinding(assessmentID, executionID int64, group PrivilegedGroup, typ, title, evidence string, now time.Time) storage.FindingInput {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s", assessmentID, typ, group.ID)))
	return storage.FindingInput{FindingKey: "adgroup:" + hex.EncodeToString(hash[:]), AssessmentID: assessmentID, SourceTool: "RustHound-CE", SourceExecution: executionID, FindingType: typ, Title: title + ": " + group.Name, Description: "RustHound directly records membership relationships for an established privileged AD group. This is an informational inventory observation; it does not establish active use or exploitability. Membership coverage is not independently verified.", Severity: "informational", Confidence: "observed-membership-coverage-partial", AffectedObjectID: group.ID, AffectedObject: group.Name, EvidenceJSON: evidence, ArtifactPath: group.Artifact, ArtifactRef: group.ArtifactRef, ObservedAt: now, Status: "open", ParserVersion: groupParserVersion}
}
