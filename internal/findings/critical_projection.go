package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/pwnflow/pwnflow/internal/storage"
)

// CriticalState is the in-memory classification state of a projected path.
type CriticalState string

const (
	CriticalConfirmed   CriticalState = "confirmed_critical"
	CriticalPotential   CriticalState = "potential_critical_not_verified"
	CriticalNotCritical CriticalState = "not_critical"
)

// CriticalEvidenceReference keeps the immutable source provenance for a path.
type CriticalEvidenceReference struct {
	FindingID       int64  `json:"finding_id,omitempty"`
	SourceExecution int64  `json:"source_execution,omitempty"`
	ArtifactPath    string `json:"artifact_path"`
	ArtifactRef     string `json:"artifact_ref"`
}

// CriticalPath is a read-only, in-memory attack-path projection. Finding is a
// presentation record only; it is never persisted back to the Findings store.
type CriticalPath struct {
	AssessmentID         int64
	ID                   string
	State                CriticalState
	Family               string
	StartingPrincipal    string
	Target               string
	TargetType           string
	Capability           string
	ConfirmedPrereqs     []string
	UnverifiedPrereqs    []string
	Evidence             []CriticalEvidenceReference
	SupportingFindingIDs []int64
	Reason               string
	Title                string
	Finding              storage.Finding
}

type CriticalProjection struct {
	Confirmed []CriticalPath
	Potential []CriticalPath
}

// CriticalStateOf returns the state carried by a projected presentation row.
// Ordinary persisted Findings remain not critical unless classified separately.
func CriticalStateOf(row storage.Finding) CriticalState {
	metadata := findingEvidence(row)
	if state := cpFirstString(metadata, "critical_state"); state != "" {
		return CriticalState(state)
	}
	return CriticalNotCritical
}

const criticalProjectionVersion = "critical-projection-v1"
const maxPotentialACLPaths = 128

// ProjectCritical builds a bounded projection from retained Finding rows. It
// never reads or writes the database and deliberately does not load raw
// artifacts. Artifact paths and references remain source-backed provenance.
func ProjectCritical(rows []storage.Finding) CriticalProjection {
	ordered := append([]storage.Finding(nil), rows...)
	sort.SliceStable(ordered, func(i, j int) bool { return cpProjectionFindingKey(ordered[i]) < cpProjectionFindingKey(ordered[j]) })
	confirmed := make(map[string]*CriticalPath)
	potential := make(map[string]*CriticalPath)
	for _, row := range ordered {
		if qualification, ok := ClassifyCritical(row); ok {
			path := confirmedPath(row, qualification)
			mergeProjectedPath(confirmed, path)
			continue
		}
		for _, path := range potentialPaths(row) {
			mergeProjectedPath(potential, path)
		}
	}
	for key := range potential {
		if _, exists := confirmed[key]; exists {
			delete(potential, key)
		}
	}
	return CriticalProjection{Confirmed: sortedProjectedPaths(confirmed), Potential: boundedPotentialPaths(potential)}
}

func confirmedPath(row storage.Finding, qualification CriticalQualification) CriticalPath {
	metadata := findingEvidence(row)
	family := cpCriticalFamily(row)
	principal := cpFirstString(metadata, "principal", "account_identity", "principal_name", "account")
	if principal == "" {
		principal = row.RelatedObject
	}
	target := cpFirstString(metadata, "target", "target_name", "destination")
	if target == "" {
		target = row.AffectedObject
	}
	targetType := cpFirstString(metadata, "target_type", "target_class", "object_type")
	capability := cpFirstString(metadata, "permission", "material_type", "protocol", "esc")
	confirmed := []string{qualification.Reason}
	if family == "privileged_access" {
		protocol := cpFirstString(metadata, "protocol")
		capability = "target-level administrative access"
		confirmed = []string{"successful administrative access was reported by NetExec"}
		if protocol != "" {
			confirmed = append(confirmed, "validated protocol: "+protocol)
		}
	}
	return newProjectedPath(row, CriticalConfirmed, family, principal, target, targetType, capability, confirmed, nil, qualification.Reason)
}

func potentialPaths(row storage.Finding) []CriticalPath {
	metadata := findingEvidence(row)
	typ := strings.ToLower(strings.TrimSpace(row.FindingType))
	if strings.HasPrefix(typ, "adcs_esc_") {
		return potentialCertipyPaths(row, metadata)
	}
	if typ == "ad_replication_rights_evidence_overview" {
		return potentialReplicationPaths(row, metadata)
	}
	if typ == "ad_acl_evidence_inventory" || typ == "ad_privileged_acl_evidence_inventory" || typ == "ad_writable_object_assessment" {
		return potentialACLPaths(row, metadata)
	}
	if typ == "relay_exposure_observed" {
		return []CriticalPath{newProjectedPath(row, CriticalPotential, "ntlm_relay", cpFirstString(metadata, "principal", "source_identity"), cpFirstString(metadata, "destination", "target"), cpFirstString(metadata, "target_type", "protocol"), "relay exposure", []string{"an explicit relay-related path was observed"}, []string{"relayable privileged authentication and successful relay are not verified"}, "Relay exposure is potentially relevant to a high-impact path, but no privileged relay chain is established.")}
	}
	if typ == "smb_signing_not_required" && cpBoolValue(metadata, "signing_required", false) {
		return []CriticalPath{newProjectedPath(row, CriticalPotential, "ntlm_relay", "", cpFirstString(metadata, "target"), "SMB endpoint", "signing not required", []string{"SMB signing is explicitly reported as not required"}, []string{"coercion, relayability, privileged authentication, and successful relay are not verified"}, "SMB signing absence is a relay prerequisite observation, not proof of a critical relay path.")}
	}
	if paths := potentialHygienePaths(row, metadata, typ); paths != nil {
		return paths
	}
	if (typ == "unconstrained_delegation_configured" && !strings.EqualFold(row.Severity, "informational")) || typ == "constrained_delegation_configured" || typ == "constrained_delegation_to_dc" || typ == "rbcd_observed" {
		return []CriticalPath{newProjectedPath(row, CriticalPotential, "delegation", cpFirstString(metadata, "principal", "object_name"), cpFirstString(metadata, "target", "object_name"), cpFirstString(metadata, "target_type", "object_type"), cpFirstString(metadata, "delegation_type", "delegation"), []string{"delegation configuration was observed"}, []string{"effective controlled principal and privileged target/service abuse are not verified"}, "Delegation can support an attack path, but the retained evidence does not establish effective abuse.")}
	}
	return nil
}

func potentialCertipyPaths(row storage.Finding, metadata map[string]any) []CriticalPath {
	typ := strings.ToLower(strings.TrimSpace(row.FindingType))
	esc := strings.ToUpper(strings.TrimPrefix(typ, "adcs_esc_"))
	if esc == "" || esc == "ESC1" && cpCriticalPathVerified(metadata) {
		return nil
	}
	if !cpSupportedPotentialESC(esc) {
		return nil
	}
	confirmed := []string{"Certipy reported " + esc + " in retained source evidence"}
	unknown := []string{"effective authorization and complete exploitation prerequisites are not verified"}
	if esc == "ESC8" {
		confirmed = []string{"HTTP AD CS Web Enrollment is enabled"}
		unknown = []string{"relayable authentication, usable enrollment rights, privileged source identity, and successful relay are not verified"}
	}
	principal := cpFirstString(metadata, "principal", "principal_name")
	target := cpFirstString(metadata, "object_name")
	if target == "" {
		target = row.AffectedObject
	}
	return []CriticalPath{newProjectedPath(row, CriticalPotential, "adcs_"+strings.ToLower(esc), principal, target, cpFirstString(metadata, "object_type"), esc, confirmed, unknown, "This AD CS condition is potentially high impact, but the retained evidence does not establish a complete effective attack path.")}
}

func potentialReplicationPaths(row storage.Finding, metadata map[string]any) []CriticalPath {
	roots, _ := metadata["domain_roots"].([]any)
	paths := make([]CriticalPath, 0)
	for _, rawRoot := range roots {
		root, ok := rawRoot.(map[string]any)
		if !ok {
			continue
		}
		principals, _ := root["principals"].([]any)
		for _, rawPrincipal := range principals {
			principal, ok := rawPrincipal.(map[string]any)
			if !ok || !cpHasReplicationRight(principal) {
				continue
			}
			paths = append(paths, newProjectedPath(row, CriticalPotential, "dcsync", cpFirstString(principal, "name"), cpFirstString(root, "name"), cpFirstString(root, "object_type"), "replication rights", []string{"one or more replication rights were observed"}, []string{"effective paired authorization and controlled-principal context are not verified"}, "Replication-right observations may support DCSync, but effective authorization is explicitly unverified."))
		}
	}
	return paths
}

func potentialACLPaths(row storage.Finding, metadata map[string]any) []CriticalPath {
	var rawRelations []any
	for _, key := range []string{"relationships", "acl_relationships", "relationship_overview", "normalized_relationships"} {
		if values, ok := metadata[key].([]any); ok {
			rawRelations = append(rawRelations, values...)
		}
	}
	paths := make([]CriticalPath, 0)
	for _, raw := range rawRelations {
		relation, ok := raw.(map[string]any)
		if !ok || !cpDangerousACLRight(cpFirstString(relation, "permission", "right")) || !cpCriticalTargetClass(cpFirstString(relation, "target_class", "object_type")) {
			continue
		}
		decision := strings.ToLower(cpFirstString(relation, "decision", "status"))
		if decision == "deny" || decision == "denied" || decision == "inapplicable" {
			continue
		}
		if decision == "allow" && cpExplicitlyNonPrivileged(relation) {
			continue
		}
		paths = append(paths, newProjectedPath(row, CriticalPotential, "acl_control", cpFirstString(relation, "principal_name", "name"), cpFirstString(relation, "target_name"), cpFirstString(relation, "target_class", "object_type"), cpFirstString(relation, "permission", "right"), []string{"a dangerous ACL relationship was retained"}, []string{"effective allow semantics, applicable membership, deny precedence, and exploitable impact are not fully verified"}, "A dangerous right over a high-value target is a candidate path, but raw ACL evidence is not sufficient to confirm effective control."))
	}
	return paths
}

func newProjectedPath(row storage.Finding, state CriticalState, family, principal, target, targetType, capability string, confirmed, unknown []string, reason string) CriticalPath {
	ref := CriticalEvidenceReference{FindingID: row.ID, SourceExecution: row.SourceExecution, ArtifactPath: row.ArtifactPath, ArtifactRef: row.ArtifactRef}
	id := cpStableProjectionID(row.AssessmentID, family, principal, target, capability)
	path := CriticalPath{AssessmentID: row.AssessmentID, ID: id, State: state, Family: family, StartingPrincipal: principal, Target: target, TargetType: targetType, Capability: capability, ConfirmedPrereqs: append([]string(nil), confirmed...), UnverifiedPrereqs: append([]string(nil), unknown...), Evidence: []CriticalEvidenceReference{ref}, SupportingFindingIDs: []int64{row.ID}, Reason: reason, Title: row.Title}
	path.Finding = projectedFinding(path)
	if state == CriticalConfirmed && family != "privileged_access" {
		path.Finding.Title = row.Title
	}
	return path
}

func mergeProjectedPath(paths map[string]*CriticalPath, candidate CriticalPath) {
	current := paths[candidate.ID]
	if current == nil {
		copy := candidate
		paths[candidate.ID] = &copy
		return
	}
	current.ConfirmedPrereqs = cpUniqueStrings(append(current.ConfirmedPrereqs, candidate.ConfirmedPrereqs...))
	current.UnverifiedPrereqs = cpUniqueStrings(append(current.UnverifiedPrereqs, candidate.UnverifiedPrereqs...))
	current.Evidence = cpUniqueEvidence(append(current.Evidence, candidate.Evidence...))
	current.SupportingFindingIDs = cpUniqueInt64(append(current.SupportingFindingIDs, candidate.SupportingFindingIDs...))
	current.Finding = projectedFinding(*current)
}

func projectedFinding(path CriticalPath) storage.Finding {
	evidence := map[string]any{"projection_version": criticalProjectionVersion, "critical_state": string(path.State), "path_id": path.ID, "family": path.Family, "starting_principal": path.StartingPrincipal, "target": path.Target, "target_type": path.TargetType, "capability": path.Capability, "confirmed_prerequisites": path.ConfirmedPrereqs, "unverified_prerequisites": path.UnverifiedPrereqs, "evidence_chain": path.Evidence, "supporting_finding_ids": path.SupportingFindingIDs, "reason": path.Reason}
	encoded, _ := json.Marshal(evidence)
	severity := "critical"
	if path.State == CriticalPotential {
		severity = "high"
	}
	sourceExecution, artifactPath, artifactRef := int64(0), "", ""
	if len(path.Evidence) > 0 {
		sourceExecution, artifactPath, artifactRef = path.Evidence[0].SourceExecution, path.Evidence[0].ArtifactPath, path.Evidence[0].ArtifactRef
	}
	title := path.Title
	if path.Family == "privileged_access" {
		title = "Privileged administrative access"
	}
	if title == "" {
		title = "Critical attack path: " + path.Family
	}
	if path.Target != "" {
		title += " — " + path.Target
	}
	return storage.Finding{FindingInput: storage.FindingInput{FindingKey: path.ID, AssessmentID: path.AssessmentID, SourceTool: "PwnFlow Critical Projection", SourceExecution: sourceExecution, FindingType: "critical_projection_" + path.Family, Title: title, Description: path.Reason, Severity: severity, Confidence: string(path.State), AffectedObject: path.Target, RelatedObject: path.StartingPrincipal, EvidenceJSON: string(encoded), ArtifactPath: artifactPath, ArtifactRef: artifactRef, Status: "open", ParserVersion: criticalProjectionVersion}}
}

func sortedProjectedPaths(paths map[string]*CriticalPath) []CriticalPath {
	result := make([]CriticalPath, 0, len(paths))
	for _, path := range paths {
		path.Finding = projectedFinding(*path)
		result = append(result, *path)
	}
	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i].Finding.Title) < strings.ToLower(result[j].Finding.Title)
	})
	return result
}

func boundedPotentialPaths(paths map[string]*CriticalPath) []CriticalPath {
	result := sortedProjectedPaths(paths)
	if len(result) > maxPotentialACLPaths {
		result = result[:maxPotentialACLPaths]
	}
	return result
}

func findingEvidence(row storage.Finding) map[string]any {
	var evidence map[string]any
	_ = json.Unmarshal([]byte(row.EvidenceJSON), &evidence)
	return evidence
}
func cpFirstString(value map[string]any, keys ...string) string {
	for _, key := range keys {
		if text, ok := value[key].(string); ok && strings.TrimSpace(text) != "" {
			return strings.TrimSpace(text)
		}
	}
	return ""
}
func cpBoolValue(value map[string]any, key string, want bool) bool {
	actual, ok := value[key].(bool)
	return ok && actual == want
}
func cpCriticalPathVerified(metadata map[string]any) bool {
	path, ok := metadata["critical_path"].(map[string]any)
	return ok && cpBoolValue(path, "verified", true)
}
func cpSupportedPotentialESC(esc string) bool {
	switch esc {
	case "ESC1", "ESC2", "ESC3", "ESC4", "ESC7", "ESC8", "ESC15", "ESC17":
		return true
	}
	return false
}
func cpCriticalFamily(row storage.Finding) string {
	typ := strings.ToLower(strings.TrimSpace(row.FindingType))
	switch {
	case typ == "netexec_privileged_access":
		return "privileged_access"
	case typ == "sccm_task_sequence_credentials_exposed":
		return "credential_disclosure"
	case typ == "ad_account_password_attribute_readable":
		return "credential_exposure"
	case strings.HasPrefix(typ, "adcs_esc_"):
		return typ
	case typ == "ad_replication_rights_evidence_overview":
		return "dcsync"
	case typ == "ad_privileged_acl_evidence_inventory", typ == "ad_acl_evidence_inventory":
		return "acl_control"
	default:
		return typ
	}
}
func cpProjectionFindingKey(row storage.Finding) string {
	return fmt.Sprintf("%020d:%s:%s:%s", row.ID, strings.ToLower(row.FindingType), strings.ToLower(row.AffectedObjectID), strings.ToLower(row.AffectedObject))
}
func cpStableProjectionID(assessmentID int64, family, principal, target, capability string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s", assessmentID, strings.ToLower(strings.TrimSpace(family)), strings.ToLower(strings.TrimSpace(principal)), strings.ToLower(strings.TrimSpace(target)), strings.ToLower(strings.TrimSpace(capability)))))
	return "critical:" + hex.EncodeToString(sum[:12])
}
func cpDangerousACLRight(value string) bool {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), " ", "")) {
	case "genericall", "genericwrite", "writedacl", "writeowner", "allextendedrights", "forcechangepassword", "addmember", "writemember", "addkeycredentiallink", "getchanges", "getchangesall":
		return true
	}
	return false
}
func cpCriticalTargetClass(value string) bool {
	value = strings.ToLower(value)
	return value == "domain_root" || value == "domains" || value == "tier0_group" || strings.HasPrefix(value, "privileged_group") || strings.Contains(value, "domain_controller") || strings.Contains(value, "high_value") || strings.Contains(value, "privileged")
}
func cpExplicitlyNonPrivileged(value map[string]any) bool {
	flag, ok := value["principal_is_privileged"].(bool)
	return ok && !flag
}
func cpHasReplicationRight(principal map[string]any) bool {
	rights, _ := principal["rights"].([]any)
	for _, raw := range rights {
		right, ok := raw.(map[string]any)
		if ok && (strings.EqualFold(cpFirstString(right, "right"), "GetChanges") || strings.EqualFold(cpFirstString(right, "right"), "GetChangesAll")) {
			return true
		}
	}
	return false
}
func cpUniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
func cpUniqueInt64(values []int64) []int64 {
	seen := map[int64]bool{}
	result := make([]int64, 0, len(values))
	for _, value := range values {
		if value > 0 && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
func cpUniqueEvidence(values []CriticalEvidenceReference) []CriticalEvidenceReference {
	seen := map[string]bool{}
	result := make([]CriticalEvidenceReference, 0, len(values))
	for _, value := range values {
		key := fmt.Sprintf("%d:%s:%s", value.SourceExecution, value.ArtifactPath, value.ArtifactRef)
		if !seen[key] {
			seen[key] = true
			result = append(result, value)
		}
	}
	return result
}

// potentialHygienePaths projects the directory-configuration Findings that can
// lead to privileged access when combined with steps the evidence does not
// show. Each stays a potential path: the retained evidence proves the
// configuration, not its abuse.
func potentialHygienePaths(row storage.Finding, metadata map[string]any, typ string) []CriticalPath {
	path := func(family, principal, target, targetType, capability, confirmed, unverified, reason string) []CriticalPath {
		return []CriticalPath{newProjectedPath(row, CriticalPotential, family, principal, target, targetType, capability, []string{confirmed}, []string{unverified}, reason)}
	}
	classes, _ := metadata["reader_classes"].(map[string]any)
	broadReaders := false
	if count, ok := classes["broad"].(float64); ok && count > 0 {
		broadReaders = true
	}
	switch typ {
	case "ad_account_laps_password_readers":
		if !broadReaders {
			return nil
		}
		return path("credential_exposure", "broad principal", cpFirstString(metadata, "domain"), "LAPS-managed computers", "read LAPS passwords",
			"a broad principal holds ReadLAPSPassword on LAPS-managed computers",
			"no LAPS password was read; which computers matter for privileged access is not evaluated",
			"Any account in a broad group can read local administrator passwords of the listed computers.")
	case "ad_account_gmsa_password_readers":
		if !broadReaders && !strings.EqualFold(row.Severity, "medium") {
			return nil
		}
		return path("credential_exposure", strings.Join(cpStringSlice(metadata["affected_objects"]), ", "), row.AffectedObject, "gMSA", "read the gMSA password",
			"the listed principals hold ReadGMSAPassword on the gMSA",
			"no password was read; the gMSA's own privileges beyond adminCount are not evaluated",
			"Reading the gMSA password yields its credential; the account is privileged or the reader is a broad group.")
	case "ad_account_sid_history_present":
		if !strings.EqualFold(row.Severity, "high") {
			return nil
		}
		return path("sid_history", row.AffectedObject, cpFirstString(metadata, "domain"), "domain", "privileged SID in sIDHistory",
			"sIDHistory holds a well-known privileged SID of the object's own domain",
			"token construction and use of the account are not verified",
			"An account whose sIDHistory carries a privileged SID of its own domain is treated as a member of that group at logon.")
	case "ad_trust_sid_filtering_relaxed":
		return path("trust", cpFirstString(metadata, "target_domain", "trust_partner"), cpFirstString(metadata, "domain"), "trust", "SID filtering relaxed",
			"trust attributes show SID filtering relaxed on an outbound or bidirectional trust",
			"control of the trusted domain and an actual SID-history attack are not verified",
			"With SID filtering relaxed, a compromise of the trusted domain can extend into this one.")
	case "ad_domain_config_dns_zone_broad_write":
		return path("ntlm_relay", strings.Join(cpStringSlice(metadata["principals"]), ", "), cpFirstString(metadata, "zone"), "DNS zone", "modify DNS zone",
			"a broad principal holds write rights on the DNS zone object",
			"record changes, name resolution by victims and any follow-on relay are not verified",
			"Any domain account can change existing records in this zone and redirect clients.")
	case "smb_spooler_service_running", "smb_webclient_service_running":
		capability := "authentication coercion (Print Spooler)"
		if typ == "smb_webclient_service_running" {
			capability = "authentication coercion over HTTP (WebClient)"
		}
		return path("ntlm_relay", "any authenticated user", row.AffectedObject, "domain controller", capability,
			"the coercion-capable service answered on the configured domain controller",
			"a relay target that accepts the coerced authentication, or a host with unconstrained delegation, and a successful coercion are not verified",
			"Coercing the domain controller's machine account is the first step of NTLM relay and unconstrained-delegation paths to domain compromise.")
	case "ldap_signing_policy_not_required", "ldap_channel_binding_policy_not_required":
		capability := "LDAP signing not required by policy"
		if typ == "ldap_channel_binding_policy_not_required" {
			capability = "LDAPS channel binding not required by policy"
		}
		return path("ntlm_relay", "", cpFirstString(metadata, "scope_dn", "scope"), "domain controllers (Group Policy)", capability,
			"Group Policy linked to the Domain Controllers OU configures "+strings.ToLower(capability),
			"WMI and security filtering, the hosts' registry, coercion, relayable privileged authentication and a successful relay are not verified",
			"Relaying NTLM to LDAP on a domain controller is a known route to privileged directory changes when the policy does not require signing or channel binding.")
	case "ldap_signing_not_enforced", "ldap_channel_binding_not_enforced":
		capability := "LDAP signing not enforced"
		if typ == "ldap_channel_binding_not_enforced" {
			capability = "LDAPS channel binding not required"
		}
		return path("ntlm_relay", "", cpFirstString(metadata, "target", "host"), "domain controller LDAP", capability,
			"NetExec reported "+strings.ToLower(capability)+" on the domain controller",
			"NetExec's probe is not policy proof; coercion, relayable privileged authentication and a successful relay are not verified",
			"Relaying NTLM to LDAP on a domain controller is a known route to privileged directory changes when signing and channel binding are not enforced.")
	}
	return nil
}

func cpStringSlice(value any) []string {
	items, _ := value.([]any)
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
			result = append(result, text)
		}
	}
	return result
}
