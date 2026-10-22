package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const (
	CriticalRuleESC1     = "CRIT-ADCS-ESC1"
	CriticalRuleESC8     = "CRIT-ADCS-ESC8"
	CriticalRuleDCSync   = "CRIT-AD-DCSYNC"
	CriticalRuleTierZero = "CRIT-AD-TIER0-CONTROL"
	CriticalRulePwn3d    = "CRIT-NETEXEC-PWN3D"
	CriticalRulePXE      = "CRIT-PXETHIEF-CREDENTIAL-DISCLOSURE"
)

type CriticalQualification struct {
	RuleID string
	Reason string
}

type criticalEvidence map[string]any

func ClassifyCritical(finding storage.Finding) (CriticalQualification, bool) {
	var evidence criticalEvidence
	if err := json.Unmarshal([]byte(finding.EvidenceJSON), &evidence); err != nil || evidence == nil {
		return CriticalQualification{}, false
	}
	// Older persisted Certipy findings contain only the vulnerability summary.
	// Recover the structured prerequisites from their immutable artifact when
	// available, without changing the database or trusting the finding title.
	enrichCertipyCriticalEvidence(finding, evidence)
	if source, ok := evidenceInt64(evidence, "source_execution_id"); ok && source != finding.SourceExecution {
		return CriticalQualification{}, false
	}
	typ := strings.ToLower(strings.TrimSpace(finding.FindingType))
	switch typ {
	case "netexec_privileged_access":
		return classifyNetExecPwn3d(finding, evidence)
	case "sccm_task_sequence_credentials_exposed":
		return classifyPXECredentialDisclosure(finding, evidence)
	case "adcs_esc_esc1":
		return classifyESC1(evidence)
	case "adcs_esc_esc8":
		return classifyESC8(evidence)
	case "ad_replication_rights_evidence_overview":
		return classifyDCSync(evidence)
	case "ad_privileged_acl_evidence_inventory", "ad_acl_evidence_inventory":
		return classifyTierZeroControl(evidence)
	default:
		return CriticalQualification{}, false
	}
}

func enrichCertipyCriticalEvidence(finding storage.Finding, evidence criticalEvidence) {
	typ := strings.ToLower(strings.TrimSpace(finding.FindingType))
	if typ != "adcs_esc_esc1" && typ != "adcs_esc_esc8" || finding.ArtifactPath == "" || finding.ArtifactRef == "" {
		return
	}
	if _, ok := evidence["critical_path"]; ok {
		return
	}
	var document map[string]any
	if err := readBoundedJSON(finding.ArtifactPath, &document); err != nil {
		return
	}
	object, kind, ok := certipyArtifactObject(document, finding.ArtifactRef)
	if !ok {
		return
	}
	esc := "ESC1"
	if typ == "adcs_esc_esc8" {
		esc = "ESC8"
	}
	addCertipyCriticalPath(evidence, object, kind, esc)
}

func certipyArtifactObject(document map[string]any, reference string) (map[string]any, string, bool) {
	parts := strings.Split(strings.TrimPrefix(reference, "/"), "/")
	if len(parts) < 2 {
		return nil, "", false
	}
	section := strings.ReplaceAll(strings.ReplaceAll(parts[0], "~1", "/"), "~0", "~")
	key := strings.ReplaceAll(strings.ReplaceAll(parts[1], "~1", "/"), "~0", "~")
	objects, ok := document[section].(map[string]any)
	if !ok {
		return nil, "", false
	}
	object, ok := objects[key].(map[string]any)
	if !ok {
		return nil, "", false
	}
	if section == "Certificate Templates" {
		return object, "template", true
	}
	if section == "Certificate Authorities" {
		return object, "ca", true
	}
	return nil, "", false
}

func classifyNetExecPwn3d(finding storage.Finding, evidence criticalEvidence) (CriticalQualification, bool) {
	if !strings.EqualFold(strings.TrimSpace(finding.SourceTool), "NetExec (nxc)") || !boolValue(evidence, "privileged") || !strings.EqualFold(stringValue(evidence, "outcome"), "success") {
		return CriticalQualification{}, false
	}
	protocol := strings.TrimSpace(stringValue(evidence, "protocol"))
	target := strings.TrimSpace(stringValue(evidence, "target"))
	if protocol == "" || target == "" {
		return CriticalQualification{}, false
	}
	return CriticalQualification{
		RuleID: CriticalRulePwn3d,
		Reason: fmt.Sprintf("NetExec reported successful administrative access on the tested %s target %s; this confirms target-level administrative access, not Domain Admin membership", protocol, target),
	}, true
}

func classifyPXECredentialDisclosure(finding storage.Finding, evidence criticalEvidence) (CriticalQualification, bool) {
	if !strings.EqualFold(strings.TrimSpace(finding.SourceTool), "PXEThief") || !boolValue(evidence, "value_present") {
		return CriticalQualification{}, false
	}
	variables, ok := evidence["credential_variables"].([]any)
	if !ok || len(variables) == 0 {
		return CriticalQualification{}, false
	}
	identity := strings.TrimSpace(stringValue(evidence, "account_identity"))
	if identity == "" {
		identity = "an affected task-sequence account"
	}
	return CriticalQualification{
		RuleID: CriticalRulePXE,
		Reason: fmt.Sprintf("PXEThief evidence confirms recovered credential material for %s; secret values remain protected in the evidence view", identity),
	}, true
}

func CriticalFindings(rows []storage.Finding) []storage.Finding {
	result := make([]storage.Finding, 0)
	seen := make(map[string]struct{})
	for _, row := range rows {
		if _, ok := ClassifyCritical(row); !ok {
			continue
		}
		key := criticalFindingIdentity(row)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, row)
	}
	return result
}

func criticalFindingIdentity(finding storage.Finding) string {
	if strings.TrimSpace(finding.FindingKey) != "" {
		return "key:" + strings.Join([]string{finding.FindingKey, finding.AffectedObjectID, finding.AffectedObject, finding.RelatedObjectID, finding.RelatedObject}, "\x00")
	}
	if finding.ID > 0 {
		return fmt.Sprintf("id:%d", finding.ID)
	}
	hash := sha256.Sum256([]byte(strings.Join([]string{finding.FindingType, finding.AffectedObjectID, finding.AffectedObject, finding.Title, finding.EvidenceJSON}, "\x00")))
	return "hash:" + hex.EncodeToString(hash[:])
}

func classifyESC1(evidence criticalEvidence) (CriticalQualification, bool) {
	path, ok := nestedObject(evidence, "critical_path")
	if !ok || !boolValue(path, "verified") || !boolValue(path, "enrollee_supplies_subject") || !boolValue(path, "client_authentication_eku") || !boolValue(path, "low_privilege_enrollment") {
		return CriticalQualification{}, false
	}
	return CriticalQualification{RuleID: CriticalRuleESC1, Reason: "verified ESC1 prerequisites: enrollee-supplied subject, client-authentication EKU, and low-privilege enrollment are all evidenced"}, true
}

func classifyESC8(evidence criticalEvidence) (CriticalQualification, bool) {
	path, ok := nestedObject(evidence, "critical_path")
	if !ok || !boolValue(path, "verified") || !boolValue(path, "web_enrollment_http") || !boolValue(path, "relay_exposure_verified") || !boolValue(path, "enrollment_exposure_verified") {
		return CriticalQualification{}, false
	}
	return CriticalQualification{RuleID: CriticalRuleESC8, Reason: "verified ESC8 prerequisites: HTTP Web Enrollment, applicable relay exposure, and enrollment exposure are all evidenced"}, true
}

func classifyDCSync(evidence criticalEvidence) (CriticalQualification, bool) {
	if strings.ToLower(stringValue(evidence, "coverage")) != "complete" || numberValue(evidence, "omitted_relationships") != 0 || strings.ToLower(stringValue(evidence, "effective_replication_authorization")) != "verified" {
		return CriticalQualification{}, false
	}
	roots, ok := evidence["domain_roots"].([]any)
	if !ok {
		return CriticalQualification{}, false
	}
	for _, rootValue := range roots {
		root, ok := rootValue.(map[string]any)
		if !ok || !isDomainRoot(root) {
			continue
		}
		principals, ok := root["principals"].([]any)
		if !ok {
			continue
		}
		for _, principalValue := range principals {
			principal, ok := principalValue.(map[string]any)
			if !ok || !inappropriatePrincipal(principal) {
				continue
			}
			if observedRight(principal, "GetChanges") && observedRight(principal, "GetChangesAll") {
				return CriticalQualification{RuleID: CriticalRuleDCSync, Reason: fmt.Sprintf("complete evidence verifies GetChanges and GetChangesAll on the domain root for inappropriate principal %s", stringValue(principal, "name"))}, true
			}
		}
	}
	return CriticalQualification{}, false
}

func classifyTierZeroControl(evidence criticalEvidence) (CriticalQualification, bool) {
	if !boolValue(evidence, "complete") && strings.ToLower(stringValue(evidence, "status")) != "complete" {
		return CriticalQualification{}, false
	}
	relations, ok := evidence["relationships"].([]any)
	if !ok {
		relations, ok = evidence["acl_relationships"].([]any)
	}
	if !ok {
		relations, ok = evidence["relationship_overview"].([]any)
	}
	if !ok {
		return CriticalQualification{}, false
	}
	for _, relationValue := range relations {
		relation, ok := relationValue.(map[string]any)
		if !ok || strings.ToLower(stringValue(relation, "decision")) != "allow" || !inappropriatePrincipal(relation) {
			continue
		}
		permission := strings.ToLower(stringValue(relation, "permission"))
		if permission != "genericall" && permission != "writedacl" && permission != "writeowner" {
			continue
		}
		targetClass := strings.ToLower(stringValue(relation, "target_class"))
		if targetClass != "domain_root" && targetClass != "tier0_group" && !strings.HasPrefix(targetClass, "privileged_group") {
			continue
		}
		return CriticalQualification{RuleID: CriticalRuleTierZero, Reason: fmt.Sprintf("complete evidence verifies allowed %s control by %s over Tier Zero target %s", stringValue(relation, "permission"), stringValue(relation, "principal_name"), stringValue(relation, "target_name"))}, true
	}
	return CriticalQualification{}, false
}

func inappropriatePrincipal(value map[string]any) bool {
	if boolValue(value, "principal_is_privileged") {
		return false
	}
	kind := strings.ToLower(stringValue(value, "principal_type"))
	if kind == "" {
		kind = strings.ToLower(stringValue(value, "type"))
	}
	return kind == "user" || kind == "computer" || kind == "service" || kind == "service_account"
}

func isDomainRoot(value map[string]any) bool {
	objectType := strings.ToLower(stringValue(value, "object_type"))
	return objectType == "domain_root" || objectType == "domains" || strings.ToLower(stringValue(value, "target_class")) == "domain_root"
}

func observedRight(principal map[string]any, required string) bool {
	rights, ok := principal["rights"].([]any)
	if !ok {
		return false
	}
	for _, rightValue := range rights {
		right, ok := rightValue.(map[string]any)
		if ok && strings.EqualFold(stringValue(right, "right"), required) && strings.EqualFold(stringValue(right, "status"), "observed") {
			return true
		}
	}
	return false
}

func nestedObject(value map[string]any, key string) (map[string]any, bool) {
	child, ok := value[key].(map[string]any)
	return child, ok
}

func boolValue(value map[string]any, key string) bool {
	result, ok := value[key].(bool)
	return ok && result
}

func stringValue(value map[string]any, key string) string {
	result, _ := value[key].(string)
	return result
}

func numberValue(value map[string]any, key string) int64 {
	result, ok := value[key].(float64)
	if !ok {
		return -1
	}
	return int64(result)
}

func evidenceInt64(value map[string]any, key string) (int64, bool) {
	result, ok := value[key].(float64)
	return int64(result), ok
}
