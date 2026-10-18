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
	"strconv"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const protectedAccountsParserVersion = "rusthound-protected-accounts-v1"

const (
	protectedAccountsMaxObjects = 5000
	protectedAccountsMaxPaths   = 256
	protectedAccountsMaxACEs    = 32
)

type ProtectedAccountsReport struct {
	SchemaVersion       int                       `json:"schema_version"`
	ParserVersion       string                    `json:"parser_version"`
	Domain              string                    `json:"domain,omitempty"`
	SourceExecutionID   int64                     `json:"source_execution_id"`
	SourceSnapshot      string                    `json:"source_snapshot"`
	SourceArtifacts     []string                  `json:"source_artifacts"`
	SourceHashes        map[string]string         `json:"source_hashes,omitempty"`
	AnalysisTimestamp   time.Time                 `json:"analysis_timestamp"`
	Status              string                    `json:"status"`
	Users               []ProtectedAccountObject  `json:"users"`
	Groups              []ProtectedAccountObject  `json:"groups"`
	MembershipPaths     []ProtectedMembershipPath `json:"membership_paths,omitempty"`
	AdminSDHolder       *AdminSDHolderEvidence    `json:"admin_sd_holder,omitempty"`
	Unresolved          []string                  `json:"unresolved_identities,omitempty"`
	OmittedPaths        int                       `json:"omitted_membership_paths"`
	OmittedObjects      int                       `json:"omitted_objects"`
	Limits              map[string]int            `json:"limits"`
	Coverage            string                    `json:"coverage"`
	Limitations         []string                  `json:"limitations"`
	EffectiveProtection string                    `json:"effective_protection"`
}

type ProtectedAccountObject struct {
	ID             string `json:"id"`
	Name           string `json:"name,omitempty"`
	DN             string `json:"distinguished_name,omitempty"`
	Type           string `json:"type"`
	AdminCount     string `json:"admin_count"`
	SourceArtifact string `json:"source_artifact"`
	SourceRef      string `json:"source_ref"`
	Membership     string `json:"membership"`
}

type ProtectedMembershipPath struct {
	MemberID       string   `json:"member_id"`
	MemberName     string   `json:"member_name,omitempty"`
	MemberType     string   `json:"member_type,omitempty"`
	GroupID        string   `json:"protected_group_id"`
	GroupName      string   `json:"protected_group_name,omitempty"`
	Classification string   `json:"classification"`
	Path           []string `json:"path"`
	SourceRefs     []string `json:"source_refs,omitempty"`
}

type AdminSDHolderEvidence struct {
	ID             string         `json:"id"`
	Name           string         `json:"name,omitempty"`
	DN             string         `json:"distinguished_name,omitempty"`
	Type           string         `json:"type"`
	SourceArtifact string         `json:"source_artifact"`
	SourceRef      string         `json:"source_ref"`
	ACLProtected   string         `json:"acl_protected"`
	ACEs           []ProtectedACE `json:"aces,omitempty"`
	Descriptor     string         `json:"descriptor_status"`
	Limitations    []string       `json:"limitations"`
}

type ProtectedACE struct {
	PrincipalID string `json:"principal_id,omitempty"`
	Principal   string `json:"principal,omitempty"`
	Rights      string `json:"rights,omitempty"`
	Decision    string `json:"decision"`
	Inheritance string `json:"inheritance"`
	SourceRef   string `json:"source_ref"`
}

type protectedObject struct {
	groupObject
	AdminCount string
	DN         string
	Ref        string
}

type protectedEdge struct {
	Parent, Member, Artifact, Ref string
}

func AnalyzeProtectedAccounts(ctx context.Context, inputPath string, assessmentID, executionID int64, now time.Time) (ProtectedAccountsReport, *storage.FindingInput, error) {
	result := ProtectedAccountsReport{SchemaVersion: 1, ParserVersion: protectedAccountsParserVersion, SourceExecutionID: executionID, SourceSnapshot: filepath.Base(filepath.Clean(inputPath)), AnalysisTimestamp: now.UTC(), Status: "complete", Coverage: "partial", EffectiveProtection: "NOT VERIFIED", Limits: map[string]int{"objects": protectedAccountsMaxObjects, "membership_paths": protectedAccountsMaxPaths, "admin_sdholder_aces": protectedAccountsMaxACEs}, SourceHashes: map[string]string{}, Limitations: []string{
		"adminCount is an observed attribute and does not prove current protected membership.",
		"Membership not observed is not proof of nonmembership or stale adminCount.",
		"AdminSDHolder identity and observed ACEs do not establish a complete security descriptor or SDProp application.",
		"Effective authorization, deny precedence, token construction, SIDHistory, cross-domain membership and SDProp timing were not evaluated.",
	}}
	if executionID <= 0 || assessmentID <= 0 {
		return result, nil, fmt.Errorf("protected-account analysis requires assessment and execution IDs")
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
	objects := map[string]protectedObject{}
	groups := make([]protectedObject, 0)
	edges := make([]protectedEdge, 0)
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
		if kind != "users" && kind != "groups" && kind != "computers" && kind != "containers" {
			continue
		}
		result.SourceArtifacts = append(result.SourceArtifacts, file)
		if hash, hashErr := fileSHA256(file); hashErr == nil {
			result.SourceHashes[file] = hash
		}
		for index, raw := range export.Data {
			if len(objects) >= protectedAccountsMaxObjects {
				result.OmittedObjects++
				result.Status = "partial"
				break
			}
			decoded, decodeErr := decodeGroupObject(raw, kind, file, index)
			if decodeErr != nil {
				return result, nil, decodeErr
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				return result, nil, err
			}
			props := rawObject(fields, "Properties")
			obj := protectedObject{groupObject: decoded, AdminCount: protectedAdminCount(fields, props), DN: firstString(props, "distinguishedname", "distinguishedName", "dn"), Ref: decoded.Ref}
			key := groupIdentity(obj.ID)
			if key == "" {
				continue
			}
			objects[key] = obj
			if kind == "groups" {
				groups = append(groups, obj)
			}
			if kind == "groups" {
				var members []json.RawMessage
				_ = json.Unmarshal(fields["Members"], &members)
				for _, member := range members {
					id := ""
					if json.Unmarshal(member, &id) != nil {
						var m map[string]json.RawMessage
						_ = json.Unmarshal(member, &m)
						id = firstString(m, "ObjectIdentifier", "objectidentifier", "id", "sid")
					}
					if id != "" {
						edges = append(edges, protectedEdge{Parent: obj.ID, Member: id, Artifact: file, Ref: obj.Ref + "/Members"})
					}
				}
			}
		}
	}
	for _, obj := range objects {
		if result.Domain == "" && obj.Domain != "" {
			result.Domain = obj.Domain
		}
	}
	sort.Strings(result.SourceArtifacts)
	result.SourceArtifacts = uniqueProtectedStrings(result.SourceArtifacts)
	objectsByGroup := map[string][]protectedEdge{}
	seenEdges := map[string]bool{}
	for _, edge := range edges {
		key := groupIdentity(edge.Parent) + "\x00" + groupIdentity(edge.Member)
		if seenEdges[key] {
			continue
		}
		seenEdges[key] = true
		objectsByGroup[groupIdentity(edge.Member)] = append(objectsByGroup[groupIdentity(edge.Member)], edge)
	}
	protectedGroups := make([]protectedObject, 0)
	for _, group := range groups {
		if _, ok := privilegedGroupName(group.groupObject); ok {
			protectedGroups = append(protectedGroups, group)
		}
	}
	for _, obj := range objects {
		if obj.Type != "user" && obj.Type != "group" {
			continue
		}
		item := ProtectedAccountObject{ID: obj.ID, Name: principalName(obj.groupObject), DN: obj.DN, Type: obj.Type, AdminCount: obj.AdminCount, SourceArtifact: obj.Artifact, SourceRef: obj.Ref, Membership: "not_observed"}
		paths := findProtectedPaths(obj.ID, protectedGroups, objectsByGroup, objects, protectedAccountsMaxPaths-len(result.MembershipPaths))
		if len(paths) > 0 {
			item.Membership = "observed"
			result.MembershipPaths = append(result.MembershipPaths, paths...)
		}
		if obj.AdminCount == "unknown" {
			item.Membership = "unknown"
		}
		if obj.Type == "user" {
			result.Users = append(result.Users, item)
		} else {
			result.Groups = append(result.Groups, item)
		}
	}
	for _, group := range groups {
		if group.AdminCount == "true" { /* represented above */
		}
	}
	if len(result.MembershipPaths) >= protectedAccountsMaxPaths {
		result.OmittedPaths = 1
		result.Status = "partial"
	}
	result.AdminSDHolder = findAdminSDHolder(objects)
	if result.AdminSDHolder == nil {
		result.Status = "partial"
		result.Limitations = append(result.Limitations, "AdminSDHolder object was not found in this source snapshot.")
	}
	sort.Slice(result.Users, func(i, j int) bool { return groupIdentity(result.Users[i].ID) < groupIdentity(result.Users[j].ID) })
	sort.Slice(result.Groups, func(i, j int) bool { return groupIdentity(result.Groups[i].ID) < groupIdentity(result.Groups[j].ID) })
	if result.Status == "complete" {
		result.Coverage = "complete for parsed attributes and bounded membership evidence"
	} else {
		result.Coverage = "partial; source or traversal limits apply"
	}
	if len(result.Users)+len(result.Groups) == 0 && result.AdminSDHolder == nil {
		return result, nil, nil
	}
	reportPath, jsonPath, err := WriteProtectedAccountsArtifacts(rustHoundResultsRoot(inputPath), result)
	if err != nil {
		return result, nil, err
	}
	evidence, _ := json.Marshal(map[string]any{"source_execution_id": executionID, "source_snapshot": result.SourceSnapshot, "structured_artifact": jsonPath, "human_report": "AD_PROTECTED_ACCOUNTS_EVIDENCE.txt", "admincount_users": countAdmin(result.Users), "admincount_groups": countAdmin(result.Groups), "admincount_user_examples": protectedObjectPreview(result.Users, 12), "admincount_group_examples": protectedObjectPreview(result.Groups, 12), "membership_paths": len(result.MembershipPaths), "membership_examples": protectedPathPreview(result.MembershipPaths, 16), "attribute_membership_differences": protectedDifferences(result, 16), "omitted_membership_paths": result.OmittedPaths, "admin_sdholder": result.AdminSDHolder, "coverage": result.Coverage, "limitations": result.Limitations, "effective_protection": "NOT VERIFIED"})
	h := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%d\x00%s", assessmentID, executionID, inputPath)))
	input := &storage.FindingInput{FindingKey: "adprotected:" + hex.EncodeToString(h[:]), AssessmentID: assessmentID, SourceTool: "RustHound-CE", SourceExecution: executionID, FindingType: "ad_protected_accounts_admincount_evidence", Title: "AD Protected Accounts & adminCount Evidence Overview", Description: fmt.Sprintf("RustHound execution %d contains observed adminCount attributes, protected-group membership context and AdminSDHolder evidence. Effective protection and SDProp application were not verified.", executionID), Severity: "informational", Confidence: "observed-partial-protected-account-evidence", AffectedObjectID: result.Domain, AffectedObject: "Protected accounts and AdminSDHolder evidence", EvidenceJSON: string(evidence), ArtifactPath: reportPath, ArtifactRef: "/", ObservedAt: now.UTC(), Status: "open", ParserVersion: protectedAccountsParserVersion}
	return result, input, nil
}

func protectedAdminCount(fields, props map[string]json.RawMessage) string {
	for _, m := range []map[string]json.RawMessage{props, fields} {
		if v, ok := rawBoolValue(m, "admincount"); ok {
			if v {
				return "true"
			}
			return "false"
		}
		if v, ok := rawBoolValue(m, "adminCount"); ok {
			if v {
				return "true"
			}
			return "false"
		}
	}
	return "unknown"
}
func findProtectedPaths(memberID string, groups []protectedObject, reverse map[string][]protectedEdge, objects map[string]protectedObject, limit int) []ProtectedMembershipPath {
	if limit <= 0 {
		return nil
	}
	out := []ProtectedMembershipPath{}
	var walk func(string, []string, []string, map[string]bool)
	walk = func(id string, path []string, refs []string, seen map[string]bool) {
		if len(out) >= limit {
			return
		}
		for _, e := range reverse[groupIdentity(id)] {
			k := groupIdentity(e.Parent)
			if seen[k] {
				continue
			}
			next := append(append([]string{}, path...), e.Parent)
			nextRefs := append(append([]string{}, refs...), e.Artifact+e.Ref)
			for _, g := range groups {
				if groupIdentity(g.ID) == k {
					p := objects[groupIdentity(memberID)]
					names := make([]string, 0, len(next))
					for _, n := range next {
						if o, ok := objects[groupIdentity(n)]; ok {
							names = append(names, principalName(o.groupObject))
						} else {
							names = append(names, n)
						}
					}
					c := "nested"
					if len(next) == 1 {
						c = "direct"
					}
					out = append(out, ProtectedMembershipPath{MemberID: p.ID, MemberName: principalName(p.groupObject), MemberType: p.Type, GroupID: g.ID, GroupName: principalName(g.groupObject), Classification: c, Path: append([]string{principalName(p.groupObject)}, names...), SourceRefs: nextRefs})
					break
				}
			}
			walk(e.Parent, next, nextRefs, seenWith(seen, k))
		}
	}
	walk(memberID, nil, nil, map[string]bool{})
	return dedupeProtectedPaths(out)
}
func pathsForAll(objects map[string]protectedObject, groups []protectedObject, reverse map[string][]protectedEdge) []ProtectedMembershipPath {
	var all []ProtectedMembershipPath
	for _, o := range objects {
		if o.Type == "user" || o.Type == "group" {
			all = append(all, findProtectedPaths(o.ID, groups, reverse, objects, protectedAccountsMaxPaths)...)
		}
	}
	return all
}
func seenWith(in map[string]bool, k string) map[string]bool {
	o := map[string]bool{}
	for x, v := range in {
		o[x] = v
	}
	o[k] = true
	return o
}
func dedupeProtectedPaths(in []ProtectedMembershipPath) []ProtectedMembershipPath {
	seen := map[string]bool{}
	out := in[:0]
	for _, p := range in {
		k := p.MemberID + "\x00" + p.GroupID + "\x00" + p.Classification + "\x00" + strings.Join(p.Path, "\x00")
		if !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	return out
}
func findAdminSDHolder(objects map[string]protectedObject) *AdminSDHolderEvidence {
	for _, o := range objects {
		if o.Type != "container" {
			continue
		}
		n := strings.ToLower(principalName(o.groupObject) + " " + o.DN)
		if !strings.Contains(n, "adminsdholder") {
			continue
		}
		e := &AdminSDHolderEvidence{ID: o.ID, Name: principalName(o.groupObject), DN: o.DN, Type: o.Type, SourceArtifact: o.Artifact, SourceRef: o.Ref, ACLProtected: "unknown", Descriptor: "not_verified", Limitations: []string{"Source export contains object identity and bounded ACE data, not a complete security descriptor."}}
		if data, err := os.ReadFile(o.Artifact); err == nil {
			var ex struct {
				Data []json.RawMessage `json:"data"`
			}
			index := -1
			if parsed, parseErr := strconv.Atoi(strings.TrimPrefix(o.Ref, "/data/")); parseErr == nil {
				index = parsed
			}
			if json.Unmarshal(data, &ex) == nil && index >= 0 && index < len(ex.Data) && strings.HasPrefix(strings.TrimSpace(string(ex.Data[index])), "{") {
				var f map[string]json.RawMessage
				_ = json.Unmarshal(ex.Data[index], &f)
				if v, ok := rawBoolValue(f, "IsACLProtected"); ok {
					if v {
						e.ACLProtected = "true"
					} else {
						e.ACLProtected = "false"
					}
				}
				var aces []json.RawMessage
				_ = json.Unmarshal(f["Aces"], &aces)
				for i, a := range aces {
					if i >= protectedAccountsMaxACEs {
						break
					}
					var af map[string]json.RawMessage
					_ = json.Unmarshal(a, &af)
					e.ACEs = append(e.ACEs, ProtectedACE{PrincipalID: firstString(af, "PrincipalSID", "PrincipalSecurityIdentifier", "PrincipalObjectIdentifier"), Principal: firstString(af, "PrincipalName", "Principal"), Rights: firstString(af, "RightName", "Rights", "Right"), Decision: aclDecision(af), Inheritance: func() string {
						if v, k := rawBoolValue(af, "IsInherited"); k {
							if v {
								return "inherited"
							}
							return "explicit"
						}
						return "unknown"
					}(), SourceRef: fmt.Sprintf("%s/Aces/%d", o.Ref, i)})
				}
			}
		}
		return e
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}
func countAdmin(v []ProtectedAccountObject) int {
	n := 0
	for _, x := range v {
		if x.AdminCount == "true" {
			n++
		}
	}
	return n
}

func protectedObjectPreview(values []ProtectedAccountObject, limit int) []ProtectedAccountObject {
	preview := make([]ProtectedAccountObject, 0, limit)
	for _, value := range values {
		if value.AdminCount != "true" {
			continue
		}
		preview = append(preview, value)
		if len(preview) >= limit {
			break
		}
	}
	return preview
}

func protectedPathPreview(values []ProtectedMembershipPath, limit int) []ProtectedMembershipPath {
	if len(values) > limit {
		return append([]ProtectedMembershipPath(nil), values[:limit]...)
	}
	return append([]ProtectedMembershipPath(nil), values...)
}

func protectedDifferences(report ProtectedAccountsReport, limit int) []ProtectedAccountObject {
	differences := make([]ProtectedAccountObject, 0, limit)
	for _, value := range append(append([]ProtectedAccountObject{}, report.Users...), report.Groups...) {
		if value.AdminCount == "true" && value.Membership == "not_observed" || value.AdminCount == "false" && value.Membership == "observed" || value.AdminCount == "unknown" {
			differences = append(differences, value)
			if len(differences) >= limit {
				break
			}
		}
	}
	return differences
}
func uniqueProtectedStrings(v []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range v {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
func WriteProtectedAccountsArtifacts(resultsRoot string, report ProtectedAccountsReport) (string, string, error) {
	if resultsRoot == "" {
		return "", "", fmt.Errorf("protected-account results root unavailable")
	}
	dir := filepath.Join(resultsRoot, "Enumeration", "ActiveDirectory", "ProtectedAccounts", fmt.Sprintf("execution-%d", report.SourceExecutionID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	jsonPath := filepath.Join(dir, "AD_protected_accounts_evidence.json")
	data, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(jsonPath, append(data, '\n'), 0o600); err != nil {
		return "", "", err
	}
	reportPath := filepath.Join(dir, "AD_PROTECTED_ACCOUNTS_EVIDENCE.txt")
	var b strings.Builder
	fmt.Fprintf(&b, "AD PROTECTED ACCOUNTS & ADMINCOUNT EVIDENCE\n\nSource execution: %d\nSource snapshot: %s\nStatus: %s\nCoverage: %s\n\n", report.SourceExecutionID, report.SourceSnapshot, report.Status, report.Coverage)
	fmt.Fprintf(&b, "Users: %d (adminCount=true: %d)\nGroups: %d (adminCount=true: %d)\nMembership paths retained: %d\nMembership paths omitted: %d\n\n", len(report.Users), countAdmin(report.Users), len(report.Groups), countAdmin(report.Groups), len(report.MembershipPaths), report.OmittedPaths)
	b.WriteString("ADMINCOUNT=TRUE USERS\n")
	for _, o := range report.Users {
		if o.AdminCount == "true" {
			fmt.Fprintf(&b, "%s [%s]\n", o.Name, o.ID)
		}
	}
	b.WriteString("\nADMINCOUNT=TRUE GROUPS\n")
	for _, o := range report.Groups {
		if o.AdminCount == "true" {
			fmt.Fprintf(&b, "%s [%s]\n", o.Name, o.ID)
		}
	}
	b.WriteString("\nOBSERVED PROTECTED-GROUP MEMBERSHIP PATHS\n")
	for _, p := range report.MembershipPaths {
		fmt.Fprintf(&b, "%s (%s)\n", strings.Join(p.Path, " -> "), p.Classification)
	}
	b.WriteString("\nATTRIBUTE / MEMBERSHIP DIFFERENCES\n")
	for _, o := range protectedDifferences(report, len(report.Users)+len(report.Groups)) {
		fmt.Fprintf(&b, "%s [%s] adminCount=%s membership=%s (not a protection conclusion)\n", o.Name, o.ID, o.AdminCount, o.Membership)
	}
	b.WriteString("\nREMAINING USER/GROUP INVENTORY\n")
	for _, o := range append(append([]ProtectedAccountObject{}, report.Users...), report.Groups...) {
		if o.AdminCount != "true" {
			fmt.Fprintf(&b, "%s [%s] type=%s adminCount=%s membership=%s\n", o.Name, o.ID, o.Type, o.AdminCount, o.Membership)
		}
	}
	b.WriteString("\nADMINSDHOLDER\n")
	if report.AdminSDHolder != nil {
		fmt.Fprintf(&b, "Object: %s [%s]\nDN: %s\nACL protected: %s\nDescriptor: %s\nObserved ACEs: %d\n", report.AdminSDHolder.Name, report.AdminSDHolder.ID, report.AdminSDHolder.DN, report.AdminSDHolder.ACLProtected, report.AdminSDHolder.Descriptor, len(report.AdminSDHolder.ACEs))
		for _, a := range report.AdminSDHolder.ACEs {
			fmt.Fprintf(&b, "  %s %s %s (%s; %s)\n", a.Principal, a.Rights, a.PrincipalID, a.Decision, a.Inheritance)
		}
	} else {
		b.WriteString("AdminSDHolder object: NOT OBSERVED\n")
	}
	b.WriteString("\nSOURCE REFERENCES\n")
	for _, source := range report.SourceArtifacts {
		fmt.Fprintf(&b, "%s\n", source)
	}
	b.WriteString("\nLIMITATIONS\n")
	for _, l := range report.Limitations {
		fmt.Fprintf(&b, "- %s\n", l)
	}
	b.WriteString("\nEffective protection: NOT VERIFIED\n")
	tmp := reportPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return "", "", err
	}
	if err := os.Rename(tmp, reportPath); err != nil {
		return "", "", err
	}
	return reportPath, jsonPath, nil
}
