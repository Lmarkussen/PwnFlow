package findings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/storage"
)

func criticalFixture(typ, evidence string) storage.Finding {
	return storage.Finding{ID: 1, FindingInput: storage.FindingInput{
		FindingKey: "fixture", SourceExecution: 7, FindingType: typ, EvidenceJSON: evidence,
	}}
}

func TestClassifyCriticalESC1RequiresEveryPrerequisite(t *testing.T) {
	finding := criticalFixture("adcs_esc_esc1", `{"source_execution_id":7,"critical_path":{"verified":true,"enrollee_supplies_subject":true,"client_authentication_eku":true,"low_privilege_enrollment":true}}`)
	qualification, ok := ClassifyCritical(finding)
	if !ok || qualification.RuleID != CriticalRuleESC1 || qualification.Reason == "" {
		t.Fatalf("ESC1 was not qualified with complete evidence: %#v, %v", qualification, ok)
	}
	finding.EvidenceJSON = `{"source_execution_id":7,"critical_path":{"verified":true,"enrollee_supplies_subject":true,"client_authentication_eku":true}}`
	if _, ok := ClassifyCritical(finding); ok {
		t.Fatal("ESC1 missing enrollment evidence was qualified")
	}
}

func TestClassifyCriticalESC1RecoversStructuredCertipyArtifactEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certipy.json")
	data := `{"Certificate Templates":{"10":{"Display Name":"ADEnum-ESC1-Positive","Enabled":true,"Client Authentication":true,"Enrollee Supplies Subject":true,"Requires Manager Approval":false,"Authorized Signatures Required":0,"Permissions":{"Enrollment Permissions":{"Enrollment Rights":["SCCM.LAB\\Domain Users"]}},"[!] Vulnerabilities":{"ESC1":"Enrollee supplies subject and template allows client authentication."}}}}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	finding := criticalFixture("adcs_esc_esc1", `{"enabled":true,"esc":"ESC1","vulnerability":{"ESC1":"Enrollee supplies subject and template allows client authentication."}}`)
	finding.ArtifactPath = path
	finding.ArtifactRef = "/Certificate Templates/10/[!] Vulnerabilities"
	qualification, ok := ClassifyCritical(finding)
	if !ok || qualification.RuleID != CriticalRuleESC1 {
		t.Fatalf("structured Certipy evidence was not recovered: %#v, %v", qualification, ok)
	}
}

func TestClassifyCriticalESC1DoesNotRecoverDisabledOrPrivilegedEnrollment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certipy.json")
	data := `{"Certificate Templates":{"10":{"Display Name":"Not-Critical","Enabled":false,"Client Authentication":true,"Enrollee Supplies Subject":true,"Requires Manager Approval":false,"Authorized Signatures Required":0,"Permissions":{"Enrollment Permissions":{"Enrollment Rights":["SCCM.LAB\\Enterprise Admins"]}},"[!] Vulnerabilities":{"ESC1":"reported"}}}}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	finding := criticalFixture("adcs_esc_esc1", `{}`)
	finding.ArtifactPath = path
	finding.ArtifactRef = "/Certificate Templates/10/[!] Vulnerabilities"
	if _, ok := ClassifyCritical(finding); ok {
		t.Fatal("disabled template with privileged-only enrollment was qualified")
	}
}

func TestClassifyCriticalNetExecPwn3dRequiresTrustedPositiveEvidence(t *testing.T) {
	finding := criticalFixture("netexec_privileged_access", `{"protocol":"SMB","target":"10.1.10.40","outcome":"success","privileged":true}`)
	finding.SourceTool = "NetExec (nxc)"
	qualification, ok := ClassifyCritical(finding)
	if !ok || qualification.RuleID != CriticalRulePwn3d || !strings.Contains(qualification.Reason, "not Domain Admin") {
		t.Fatalf("Pwn3d evidence was not qualified safely: %#v, %v", qualification, ok)
	}
	finding.EvidenceJSON = `{"protocol":"SMB","target":"10.1.10.40","outcome":"success","privileged":false}`
	if _, ok := ClassifyCritical(finding); ok {
		t.Fatal("negative NetExec administrative evidence was qualified")
	}
	finding.EvidenceJSON = `{"protocol":"SMB","target":"10.1.10.40","outcome":"success","privileged":true}`
	finding.SourceTool = "documentation"
	if _, ok := ClassifyCritical(finding); ok {
		t.Fatal("untrusted source was qualified as NetExec Pwn3d")
	}
}

func TestClassifyCriticalPXERequiresRecoveredCredentialMaterial(t *testing.T) {
	finding := criticalFixture("sccm_task_sequence_credentials_exposed", `{"account_identity":"sccm.lab\\sccm-naa","credential_variables":["OSDJoinPassword"],"task_sequence_context":"line:110","value_present":true}`)
	finding.SourceTool = "PXEThief"
	qualification, ok := ClassifyCritical(finding)
	if !ok || qualification.RuleID != CriticalRulePXE || strings.Contains(qualification.Reason, "OSD") {
		t.Fatalf("PXE credential disclosure was not qualified without leaking secret detail: %#v, %v", qualification, ok)
	}
	finding.EvidenceJSON = `{"account_identity":"sccm.lab\\sccm-naa","credential_variables":["OSDJoinPassword"],"value_present":false}`
	if _, ok := ClassifyCritical(finding); ok {
		t.Fatal("PXE availability without recovered material was qualified")
	}
}

func TestClassifyCriticalESC8RequiresRelayAndEnrollmentEvidence(t *testing.T) {
	finding := criticalFixture("adcs_esc_esc8", `{"source_execution_id":7,"critical_path":{"verified":true,"web_enrollment_http":true,"relay_exposure_verified":true,"enrollment_exposure_verified":true}}`)
	qualification, ok := ClassifyCritical(finding)
	if !ok || qualification.RuleID != CriticalRuleESC8 {
		t.Fatalf("ESC8 was not qualified with complete evidence: %#v, %v", qualification, ok)
	}
	finding.EvidenceJSON = `{"source_execution_id":7,"critical_path":{"verified":true,"web_enrollment_http":true,"relay_exposure_verified":true,"enrollment_exposure_verified":false}}`
	if _, ok := ClassifyCritical(finding); ok {
		t.Fatal("ESC8 with incomplete enrollment evidence was qualified")
	}
}

func TestClassifyCriticalTierZeroControlDistinguishesTargetAndPrincipal(t *testing.T) {
	finding := criticalFixture("ad_privileged_acl_evidence_inventory", `{"source_execution_id":7,"complete":true,"relationships":[{"principal_name":"alice","principal_type":"user","principal_is_privileged":false,"target_name":"Domain Admins","target_class":"privileged_group","permission":"GenericAll","decision":"allow"}]}`)
	qualification, ok := ClassifyCritical(finding)
	if !ok || qualification.RuleID != CriticalRuleTierZero {
		t.Fatalf("Tier Zero control was not qualified: %#v, %v", qualification, ok)
	}
	finding.EvidenceJSON = `{"source_execution_id":7,"complete":true,"relationships":[{"principal_name":"alice","principal_type":"user","principal_is_privileged":false,"target_name":"WORKSTATION01$","target_class":"workstation","permission":"GenericAll","decision":"allow"}]}`
	if _, ok := ClassifyCritical(finding); ok {
		t.Fatal("workstation GenericAll was qualified as Critical")
	}
	finding.EvidenceJSON = `{"source_execution_id":7,"complete":true,"relationships":[{"principal_name":"Domain Admins","principal_type":"group","principal_is_privileged":true,"target_name":"Domain Admins","target_class":"privileged_group","permission":"GenericAll","decision":"allow"}]}`
	if _, ok := ClassifyCritical(finding); ok {
		t.Fatal("privileged principal control was qualified as Critical")
	}
}

func TestClassifyCriticalDCSyncRequiresCompletePairedRights(t *testing.T) {
	finding := criticalFixture("ad_replication_rights_evidence_overview", `{"source_execution_id":7,"coverage":"complete","omitted_relationships":0,"effective_replication_authorization":"verified","domain_roots":[{"object_type":"domain_root","principals":[{"name":"alice","principal_type":"user","principal_is_privileged":false,"rights":[{"right":"GetChanges","status":"observed"},{"right":"GetChangesAll","status":"observed"}]}]}]}`)
	qualification, ok := ClassifyCritical(finding)
	if !ok || qualification.RuleID != CriticalRuleDCSync {
		t.Fatalf("DCSync was not qualified: %#v, %v", qualification, ok)
	}
	finding.EvidenceJSON = `{"source_execution_id":7,"coverage":"partial","omitted_relationships":0,"effective_replication_authorization":"verified","domain_roots":[{"object_type":"domain_root","principals":[{"name":"alice","principal_type":"user","principal_is_privileged":false,"rights":[{"right":"GetChanges","status":"observed"},{"right":"GetChangesAll","status":"not_observed"}]}]}]}`
	if _, ok := ClassifyCritical(finding); ok {
		t.Fatal("incomplete replication evidence was qualified as Critical")
	}
}

func TestClassifyCriticalUnderstandsCollectorEvidenceShapes(t *testing.T) {
	finding := criticalFixture("ad_privileged_acl_evidence_inventory", `{"source_execution_id":7,"status":"complete","relationship_overview":[{"principal_name":"alice","principal_type":"User","principal_is_privileged":false,"target_name":"Domain Admins","target_class":"privileged_group:Domain Admins","permission":"GenericAll","decision":"allow"}]}`)
	qualification, ok := ClassifyCritical(finding)
	if !ok || qualification.RuleID != CriticalRuleTierZero {
		t.Fatalf("collector-native ACL evidence was not recognized: %#v, %v", qualification, ok)
	}
	finding = criticalFixture("ad_replication_rights_evidence_overview", `{"source_execution_id":7,"coverage":"complete","omitted_relationships":0,"effective_replication_authorization":"NOT VERIFIED","domain_roots":[{"object_type":"domains","principals":[{"name":"alice","type":"User","rights":[{"right":"GetChanges","status":"observed"},{"right":"GetChangesAll","status":"observed"}]}]}]}`)
	if _, ok := ClassifyCritical(finding); ok {
		t.Fatal("unverified collector-native DCSync evidence was qualified")
	}
}

func TestCriticalFindingsDeduplicatesByFindingIdentity(t *testing.T) {
	first := criticalFixture("adcs_esc_esc1", `{"source_execution_id":7,"critical_path":{"verified":true,"enrollee_supplies_subject":true,"client_authentication_eku":true,"low_privilege_enrollment":true}}`)
	second := first
	second.ID = 2
	rows := CriticalFindings([]storage.Finding{first, second})
	if len(rows) != 1 {
		t.Fatalf("duplicate finding was not collapsed: %d rows", len(rows))
	}
	second.AffectedObject = "Different Tier Zero target"
	rows = CriticalFindings([]storage.Finding{first, second})
	if len(rows) != 2 {
		t.Fatalf("separate affected objects were merged: %d rows", len(rows))
	}
}
