package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const informationalDerivedParserVersion = "informational-derived-v1"

type derivedDomainUser struct {
	ID      string
	Enabled *bool
}

type derivedDomainController struct {
	ID        string
	FQDN      string
	Domain    string
	Addresses []string
}

// DeriveInformationalFindings builds presentation-only summaries from findings and
// finalized RustHound artifacts already associated with the assessment. It never
// writes to the database or changes the source artifacts.
func DeriveInformationalFindings(ctx context.Context, rows []storage.Finding) []storage.Finding {
	if len(rows) == 0 {
		return nil
	}
	roots := rustHoundRoots(rows)
	derived := make([]storage.Finding, 0)
	seen := map[string]bool{}
	hasUsers, hasControllers := false, false
	for _, row := range rows {
		if row.FindingType == "domain_information_privileged_group_membership" {
			seen[row.AffectedObjectID] = true
		}
		hasUsers = hasUsers || row.FindingType == "domain_information_user_inventory"
		hasControllers = hasControllers || row.FindingType == "domain_information_domain_controllers"
	}
	derivedUsers, derivedControllers := false, false
	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return derived
		}
		groups, _, err := AnalyzeRustHoundGroups(ctx, root.path, rowAssessmentID(rows), rowExecutionID(rows, root.path), root.observedAt)
		if err == nil {
			for _, group := range groups.PrivilegedGroups {
				if seen[group.ID] {
					continue
				}
				seen[group.ID] = true
				derived = append(derived, derivedPrivilegedGroupFinding(group, root.observedAt, rowExecutionID(rows, root.path)))
			}
		}
		users, controllers, artifact, ok := readDomainInventory(root.path)
		if !ok {
			continue
		}
		observed := root.observedAt
		execution := rowExecutionID(rows, root.path)
		if len(users) > 0 && !hasUsers && !derivedUsers {
			derived = append(derived, derivedUserFinding(users, artifact, execution, observed))
			derivedUsers = true
		}
		if len(controllers) > 0 && !hasControllers && !derivedControllers {
			derived = append(derived, derivedControllerFinding(controllers, artifact, execution, observed))
			derivedControllers = true
		}
	}
	assessmentID := rowAssessmentID(rows)
	for index := range derived {
		derived[index].AssessmentID = assessmentID
		derived[index].FindingInput.AssessmentID = assessmentID
	}
	return deduplicateDerivedFindings(derived)
}

type rustHoundRoot struct {
	path       string
	observedAt time.Time
}

func rustHoundRoots(rows []storage.Finding) []rustHoundRoot {
	seen := map[string]bool{}
	result := make([]rustHoundRoot, 0)
	for _, row := range rows {
		if !strings.EqualFold(row.SourceTool, "RustHound-CE") && !strings.EqualFold(row.SourceTool, "RustHound") {
			continue
		}
		if row.ArtifactPath == "" {
			continue
		}
		path := row.ArtifactPath
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			path = filepath.Dir(path)
		}
		path = filepath.Clean(path)
		if seen[path] {
			continue
		}
		seen[path] = true
		observed := row.LastSeen
		if observed.IsZero() {
			observed = row.FirstSeen
		}
		result = append(result, rustHoundRoot{path: path, observedAt: observed})
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].observedAt.Equal(result[j].observedAt) {
			return result[i].observedAt.After(result[j].observedAt)
		}
		return result[i].path < result[j].path
	})
	return result
}

func rowAssessmentID(rows []storage.Finding) int64 {
	if len(rows) > 0 {
		return rows[0].AssessmentID
	}
	return 0
}

func rowExecutionID(rows []storage.Finding, artifact string) int64 {
	for _, row := range rows {
		path := row.ArtifactPath
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			path = filepath.Dir(path)
		}
		if filepath.Clean(path) == filepath.Clean(artifact) {
			return row.SourceExecution
		}
	}
	return 0
}

func derivedPrivilegedGroupFinding(group PrivilegedGroup, observed time.Time, execution int64) storage.Finding {
	effective := uniqueResolvedMembers(group.DirectMembers, group.NestedMembers)
	evidence, _ := json.Marshal(map[string]any{
		"domain": group.Domain, "domain_sid": group.DomainSID, "group_id": group.ID, "group_name": group.Name,
		"direct_member_count": len(group.DirectMembers), "effective_member_count": len(effective),
		"unresolved_count": len(group.Unresolved), "coverage": "historical RustHound artifact reanalyzed in memory",
		"collection_timestamp": observed.UTC(),
	})
	return derivedFinding("domain_information_privileged_group_membership", "Domain Privileged Group Membership Summary: "+group.Name, group.Name, group.ID, evidence, group.Artifact, group.ArtifactRef, execution, observed,
		"Historical RustHound evidence was reanalyzed in memory. Counts include distinct resolved members; unresolved and incomplete coverage remain explicit.")
}

func readDomainInventory(root string) ([]derivedDomainUser, []derivedDomainController, string, bool) {
	files := make([]string, 0)
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	sort.Strings(files)
	users := map[string]derivedDomainUser{}
	controllers := map[string]derivedDomainController{}
	firstArtifact := ""
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil || len(data) > MaxJSONBytes {
			continue
		}
		var export struct {
			Meta struct {
				Type string `json:"type"`
			} `json:"meta"`
			Data []json.RawMessage `json:"data"`
		}
		if json.Unmarshal(data, &export) != nil {
			continue
		}
		kind := strings.ToLower(export.Meta.Type)
		if kind != "users" && kind != "computers" {
			continue
		}
		if firstArtifact == "" {
			firstArtifact = path
		}
		for index, raw := range export.Data {
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil {
				continue
			}
			props := rawObject(fields, "Properties")
			id := rawString(fields, "ObjectIdentifier")
			if id == "" {
				id = rawString(props, "distinguishedname")
			}
			if id == "" {
				continue
			}
			if kind == "users" {
				key := strings.ToLower(id)
				if _, exists := users[key]; exists {
					continue
				}
				enabled, known := rawBoolValue(props, "enabled")
				var enabledPtr *bool
				if known {
					enabledPtr = &enabled
				}
				users[key] = derivedDomainUser{ID: id, Enabled: enabledPtr}
				continue
			}
			if !isDerivedDomainController(fields, props) {
				continue
			}
			name := rawString(props, "name")
			fqdn := name
			if !strings.Contains(fqdn, ".") {
				fqdn = "unknown"
			}
			controller := derivedDomainController{ID: id, FQDN: fqdn, Domain: rawString(props, "domain"), Addresses: derivedAddresses(props)}
			controllers[strings.ToLower(id)] = controller
			_ = index
		}
	}
	if firstArtifact == "" {
		return nil, nil, "", false
	}
	userList := make([]derivedDomainUser, 0, len(users))
	for _, user := range users {
		userList = append(userList, user)
	}
	controllerList := make([]derivedDomainController, 0, len(controllers))
	for _, controller := range controllers {
		controllerList = append(controllerList, controller)
	}
	sort.Slice(userList, func(i, j int) bool { return strings.ToLower(userList[i].ID) < strings.ToLower(userList[j].ID) })
	sort.Slice(controllerList, func(i, j int) bool {
		return strings.ToLower(controllerList[i].FQDN+controllerList[i].ID) < strings.ToLower(controllerList[j].FQDN+controllerList[j].ID)
	})
	return userList, controllerList, firstArtifact, true
}

func isDerivedDomainController(fields, props map[string]json.RawMessage) bool {
	if strings.EqualFold(rawString(props, "isdc"), "true") || strings.EqualFold(rawString(fields, "IsDC"), "true") || informationalRawBool(props, "isdc") || informationalRawBool(fields, "IsDC") {
		return true
	}
	return strings.Contains(strings.ToLower(rawString(props, "distinguishedname")), "ou=domain controllers")
}

func informationalRawBool(values map[string]json.RawMessage, key string) bool {
	value, ok := values[key]
	if !ok {
		return false
	}
	var result bool
	return json.Unmarshal(value, &result) == nil && result
}

func derivedAddresses(props map[string]json.RawMessage) []string {
	result := make([]string, 0)
	for _, key := range []string{"ipaddress", "ip", "ipv4"} {
		if value := rawString(props, key); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func derivedUserFinding(users []derivedDomainUser, artifact string, execution int64, observed time.Time) storage.Finding {
	enabled, disabled, unknown := 0, 0, 0
	for _, user := range users {
		if user.Enabled == nil {
			unknown++
		} else if *user.Enabled {
			enabled++
		} else {
			disabled++
		}
	}
	evidence, _ := json.Marshal(map[string]any{"distinct_user_count": len(users), "enabled_count": enabled, "disabled_count": disabled, "status_unknown_count": unknown, "coverage": "source-backed RustHound user inventory; completeness follows the retained export", "collection_timestamp": observed.UTC()})
	return derivedFinding("domain_information_user_inventory", "Domain User Inventory Summary", "Domain users", "domain-users", evidence, artifact, "/data", execution, observed, "Distinct domain users were counted from retained RustHound user objects. Enabled/disabled status is counted only where the source recorded it.")
}

func derivedControllerFinding(controllers []derivedDomainController, artifact string, execution int64, observed time.Time) storage.Finding {
	values := make([]map[string]any, 0, len(controllers))
	for _, controller := range controllers {
		values = append(values, map[string]any{"id": controller.ID, "fqdn": controller.FQDN, "domain": controller.Domain, "addresses": controller.Addresses})
	}
	evidence, _ := json.Marshal(map[string]any{"verified_domain_controller_count": len(controllers), "controllers": values, "coverage": "source-backed RustHound computer inventory; addresses are shown only when explicitly present", "collection_timestamp": observed.UTC()})
	return derivedFinding("domain_information_domain_controllers", "Domain Controller Inventory", "Domain Controllers", "domain-controllers", evidence, artifact, "/data", execution, observed, "Domain Controllers were selected from explicit RustHound DC indicators; short names and absent addresses are not converted into guesses.")
}

func derivedFinding(typ, title, object, objectID string, evidence []byte, artifact, ref string, execution int64, observed time.Time, description string) storage.Finding {
	hash := sha256.Sum256([]byte(strings.Join([]string{typ, objectID, artifact, ref}, "\x00")))
	return storage.Finding{FindingInput: storage.FindingInput{
		FindingKey: "derived-informational:" + hex.EncodeToString(hash[:]), AssessmentID: 0, SourceTool: "RustHound-CE", SourceExecution: execution,
		FindingType: typ, Title: title, Description: description, Severity: "informational", Confidence: "derived-from-retained-evidence",
		AffectedObjectID: objectID, AffectedObject: object, EvidenceJSON: string(evidence), ArtifactPath: artifact, ArtifactRef: ref,
		ObservedAt: observed, Status: "open", ParserVersion: informationalDerivedParserVersion,
	}, FirstSeen: observed, LastSeen: observed}
}

func deduplicateDerivedFindings(rows []storage.Finding) []storage.Finding {
	seen := map[string]bool{}
	result := make([]storage.Finding, 0, len(rows))
	for _, row := range rows {
		if seen[row.FindingKey] {
			continue
		}
		seen[row.FindingKey] = true
		result = append(result, row)
	}
	return result
}
