package findings

import (
	"encoding/json"
	"testing"

	"github.com/pwnflow/pwnflow/internal/storage"
)

func projectionFinding(id int64, assessment int64, typ, title, evidence string) storage.Finding {
	return storage.Finding{ID: id, FindingInput: storage.FindingInput{AssessmentID: assessment, SourceTool: "NetExec (nxc)", FindingType: typ, Title: title, EvidenceJSON: evidence, SourceExecution: id, ArtifactPath: "artifact.log", ArtifactRef: "line 1"}}
}

func TestProjectCriticalConsolidatesPrivilegedProtocolsAndEvidence(t *testing.T) {
	rows := []storage.Finding{}
	for id, protocol := range []string{"SMB", "RDP", "WMI", "WINRM"} {
		rows = append(rows, projectionFinding(int64(id+1), 9, "netexec_privileged_access", "Privileged access reported — "+protocol, `{"protocol":"`+protocol+`","target":"10.1.10.40","account_identity":"sccm.lab\\snablr-lab-admin","outcome":"success","privileged":true}`))
	}
	projection := ProjectCritical(rows)
	if len(projection.Confirmed) != 1 || len(projection.Confirmed[0].Evidence) != 4 {
		t.Fatalf("privileged protocols were not consolidated: %#v", projection.Confirmed)
	}
	if len(projection.Confirmed[0].ConfirmedPrereqs) != 5 {
		t.Fatalf("protocol evidence was not retained: %#v", projection.Confirmed[0].ConfirmedPrereqs)
	}
}

func TestProjectCriticalKeepsUnverifiedACLAndDCSyncOutOfConfirmed(t *testing.T) {
	acl := projectionFinding(1, 3, "ad_acl_evidence_inventory", "ACL", `{"relationships":[{"principal_name":"LOCALUSER","target_name":"Domain Admins","target_class":"tier0_group","permission":"GenericAll","decision":"unknown"}]}`)
	dcsync := projectionFinding(2, 3, "ad_replication_rights_evidence_overview", "DCSync", `{"domain_roots":[{"name":"DC=sccm,DC=lab","object_type":"domain_root","principals":[{"name":"LOCALUSER","rights":[{"right":"GetChanges"},{"right":"GetChangesAll"}]}]}]}`)
	projection := ProjectCritical([]storage.Finding{acl, dcsync})
	if len(projection.Confirmed) != 0 {
		t.Fatalf("unverified access was promoted: %#v", projection.Confirmed)
	}
	if len(projection.Potential) != 2 {
		t.Fatalf("expected two potential paths, got %#v", projection.Potential)
	}
}

func TestProjectCriticalExcludesNonCriticalAndDeniedACLs(t *testing.T) {
	rows := []storage.Finding{
		projectionFinding(1, 1, "ad_acl_evidence_inventory", "ACL", `{"relationships":[{"principal_name":"UserA","target_name":"UserB","target_class":"user","permission":"GenericWrite","decision":"allow"},{"principal_name":"UserC","target_name":"Domain Admins","target_class":"tier0_group","permission":"GenericAll","decision":"deny"}]}`),
	}
	projection := ProjectCritical(rows)
	if len(projection.Confirmed) != 0 || len(projection.Potential) != 0 {
		t.Fatalf("noncritical or denied ACLs became critical candidates: %#v", projection)
	}
}

func TestProjectCriticalESC8EndpointOnlyIsPotential(t *testing.T) {
	row := projectionFinding(1, 1, "adcs_esc_esc8", "ESC8", `{"esc":"ESC8","critical_path":{"verified":false,"web_enrollment_http":true}}`)
	projection := ProjectCritical([]storage.Finding{row})
	if len(projection.Confirmed) != 0 || len(projection.Potential) != 1 {
		t.Fatalf("endpoint-only ESC8 classification incorrect: %#v", projection)
	}
	if len(projection.Potential[0].UnverifiedPrereqs) == 0 {
		t.Fatal("ESC8 uncertainty was not retained")
	}
}

func TestProjectCriticalAssessmentIsolationAndMalformedEvidence(t *testing.T) {
	rows := []storage.Finding{
		projectionFinding(1, 1, "netexec_privileged_access", "Access A", `{"protocol":"SMB","target":"host","account_identity":"DOMAIN\\User","outcome":"success","privileged":true}`),
		projectionFinding(2, 2, "netexec_privileged_access", "Access B", `{"protocol":"SMB","target":"host","account_identity":"DOMAIN\\User","outcome":"success","privileged":true}`),
		projectionFinding(3, 1, "adcs_esc_esc8", "Malformed", "{"),
	}
	projection := ProjectCritical(rows)
	if len(projection.Confirmed) != 2 {
		t.Fatalf("cross-assessment paths were merged: %#v", projection.Confirmed)
	}
	for _, path := range projection.Confirmed {
		if path.AssessmentID == 0 || path.ID == "" {
			t.Fatalf("projection lost stable identity: %#v", path)
		}
	}
	if _, err := json.Marshal(projection); err != nil {
		t.Fatal(err)
	}
}

func TestProjectCriticalDirectoryHygiene(t *testing.T) {
	row := func(id int64, source, typ, severity, evidence string) storage.Finding {
		finding := projectionFinding(id, 4, typ, typ, evidence)
		finding.SourceTool, finding.Severity, finding.AffectedObject = source, severity, "OBJECT"
		return finding
	}
	rows := []storage.Finding{
		row(1, "NetExec (nxc)", "ad_account_password_attribute_readable", "high", `{"account":"svc-legacy","attribute":"userPassword","read_by":"corp.example\\auditor","value_recorded":false}`),
		row(2, "RustHound-CE", "ad_account_laps_password_readers", "high", `{"domain":"CORP.EXAMPLE","reader_classes":{"broad":1}}`),
		row(3, "RustHound-CE", "ad_account_laps_password_readers", "medium", `{"domain":"OTHER.EXAMPLE","reader_classes":{"delegated":1}}`),
		row(4, "RustHound-CE", "ad_account_gmsa_password_readers", "low", `{"affected_objects":["APP01$"],"reader_classes":{"delegated":1}}`),
		row(5, "RustHound-CE", "ad_account_sid_history_present", "high", `{"domain":"CORP.EXAMPLE"}`),
		row(6, "RustHound-CE", "ad_account_sid_history_present", "medium", `{"domain":"CORP.EXAMPLE"}`),
		row(7, "RustHound-CE", "ad_trust_sid_filtering_relaxed", "medium", `{"domain":"CORP.EXAMPLE","target_domain":"PARTNER.EXAMPLE"}`),
		row(8, "AD Directory Settings", "ad_domain_config_dns_zone_broad_write", "high", `{"zone":"corp.example","principals":["Authenticated Users (GenericWrite)"]}`),
		row(9, "NetExec (nxc)", "ldap_signing_not_enforced", "medium", `{"target":"192.0.2.10","host":"DC01"}`),
		row(10, "AD Directory Settings", "ad_domain_config_dns_record_creation", "medium", `{"zones":[]}`),
		row(11, "NetExec (nxc)", "smb_null_session_enumeration", "high", `{"users_enumerated":5}`),
	}
	projection := ProjectCritical(rows)
	if len(projection.Confirmed) != 1 || projection.Confirmed[0].Family != "credential_exposure" {
		t.Fatalf("want the password-attribute read confirmed, got %#v", projection.Confirmed)
	}
	families := map[string]int{}
	for _, path := range projection.Potential {
		families[path.Family]++
		if len(path.UnverifiedPrereqs) == 0 {
			t.Fatalf("%s lost its unverified prerequisites", path.Family)
		}
	}
	want := map[string]int{"credential_exposure": 1, "sid_history": 1, "trust": 1, "ntlm_relay": 2}
	for family, count := range want {
		if families[family] != count {
			t.Fatalf("family %s has %d potential paths, want %d (all %v)", family, families[family], count, families)
		}
	}
	if len(projection.Potential) != 5 {
		t.Fatalf("delegated LAPS/gMSA readers, ordinary sIDHistory, default DNS record creation or anonymous enumeration entered the projection: %v", families)
	}

	// A password-attribute Finding without a recorded reader is not confirmed.
	missing := row(12, "NetExec (nxc)", "ad_account_password_attribute_readable", "high", `{"account":"svc","attribute":"userPassword"}`)
	if projection := ProjectCritical([]storage.Finding{missing}); len(projection.Confirmed) != 0 {
		t.Fatal("password attribute without reader was confirmed")
	}
}
