package findings

import (
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestAttackChainTemplates(t *testing.T) {
	id := int64(0)
	row := func(typ, object, severity, evidence string) storage.Finding {
		id++
		return storage.Finding{ID: id, FindingInput: storage.FindingInput{AssessmentID: 5, FindingType: typ, Title: typ + ": " + object, AffectedObject: object, Severity: severity, EvidenceJSON: evidence, ArtifactPath: "a", ArtifactRef: "r"}}
	}
	stale := row("smb_webclient_service_running", "OLD01", "medium", "{}")
	stale.NotReobserved = true
	rows := []storage.Finding{
		row("smb_spooler_service_running", "DC01", "medium", "{}"),
		row("adcs_esc_esc8", "CORP-CA", "high", `{"esc":"ESC8"}`),
		row("unconstrained_delegation_configured", "SRV01$", "medium", "{}"),
		row("unconstrained_delegation_configured", "DC01$", "informational", "{}"),
		row("netexec_gpp_password_exposure", "corp\\svc-admin", "high", `{"account":"CORP\\svc-admin"}`),
		row("ad_account_privileged_not_protected", "CORP.EXAMPLE", "low", `{"affected_objects":["SVC-ADMIN@CORP.EXAMPLE","ADMINISTRATOR@CORP.EXAMPLE"]}`),
		stale,
	}
	paths := attackChainPaths(rows)
	byCapability := map[string]CriticalPath{}
	for _, path := range paths {
		byCapability[path.Capability] = path
		if path.State != CriticalPotential || path.Family != attackChainFamily || len(path.UnverifiedPrereqs) == 0 {
			t.Fatalf("chain %s is not a qualified potential path: %+v", path.Capability, path)
		}
	}
	if len(paths) != 3 {
		t.Fatalf("want three chains (ESC8 relay, unconstrained, privileged credential), got %v", byCapability)
	}
	esc8 := byCapability["coerce-relay-esc8"]
	if esc8.Target != "CORP-CA" || len(esc8.ConfirmedPrereqs) != 3 || !strings.Contains(esc8.ConfirmedPrereqs[0], "Coerce DC01") || !strings.Contains(esc8.Finding.Title, "Attack path: Coerce the domain controller and relay to AD CS web enrollment (ESC8)") {
		t.Fatalf("ESC8 chain %+v", esc8)
	}
	if byCapability["coerce-unconstrained"].Target != "SRV01$" {
		t.Fatalf("unconstrained chain targets %q (the DC's own default must not start one)", byCapability["coerce-unconstrained"].Target)
	}
	if byCapability["credential-privileged"].Target != "CORP\\svc-admin" || len(byCapability["credential-privileged"].SupportingFindingIDs) != 2 {
		t.Fatalf("credential chain %+v", byCapability["credential-privileged"])
	}

	// WebClient plus LDAP signing (and MAQ) gives the HTTP relay to LDAP chain.
	relay := attackChainPaths([]storage.Finding{
		row("smb_webclient_service_running", "WS01", "medium", "{}"),
		row("ldap_signing_policy_not_required", "OU=DOMAIN CONTROLLERS", "medium", "{}"),
		row("ad_domain_policy_machine_account_creation_quota", "CORP.EXAMPLE", "informational", "{}"),
	})
	if len(relay) != 1 || relay[0].Capability != "webclient-relay-ldap" || len(relay[0].ConfirmedPrereqs) != 4 || !strings.Contains(relay[0].ConfirmedPrereqs[2], "MachineAccountQuota") {
		t.Fatalf("relay chain %+v", relay)
	}

	// ADIDNS record creation plus a relay target gives the spoof-and-relay
	// chain, which prefers AD CS web enrollment, then LDAP, then SMB.
	dns := row("ad_domain_config_dns_record_creation", "CORP.EXAMPLE", "medium", "{}")
	smbOnly := attackChainPaths([]storage.Finding{dns,
		row("smb_signing_not_required", "SRV01", "medium", "{}"),
		row("smb_signing_not_required", "SRV02", "medium", "{}"),
	})
	if len(smbOnly) != 1 || smbOnly[0].Capability != "adidns-spoof-relay" || smbOnly[0].Target != "CORP.EXAMPLE" || len(smbOnly[0].ConfirmedPrereqs) != 3 || !strings.Contains(smbOnly[0].ConfirmedPrereqs[2], "SMB on SRV01 (and 1 other host(s))") {
		t.Fatalf("ADIDNS SMB chain %+v", smbOnly)
	}
	withCA := attackChainPaths([]storage.Finding{dns,
		row("smb_signing_not_required", "SRV01", "medium", "{}"),
		row("adcs_esc_esc8", "CORP-CA", "high", "{}"),
	})
	if len(withCA) != 1 || !strings.Contains(withCA[0].ConfirmedPrereqs[2], "web enrollment endpoint of CORP-CA") {
		t.Fatalf("ADIDNS chain should prefer ESC8: %+v", withCA)
	}
	if got := attackChainPaths([]storage.Finding{dns}); len(got) != 0 {
		t.Fatalf("ADIDNS without a relay target is not a path: %+v", got)
	}

	// Local admin on a host where a privileged account is signed in; an
	// unprivileged session or a host without admin access adds nothing.
	admin := row("netexec_privileged_access", "192.0.2.12", "high", `{"protocol":"SMB","target":"192.0.2.12","privileged":true}`)
	privilegedAccount := row("ad_account_privileged_not_protected", "CORP.EXAMPLE", "low", `{"affected_objects":["OPSADMIN@CORP.EXAMPLE"]}`)
	session := row("smb_signed_in_accounts", "WS01", "informational", `{"target":"192.0.2.12","accounts":["CORP\\jdoe","CORP\\opsadmin"]}`)
	elsewhere := row("smb_signed_in_accounts", "WS02", "informational", `{"target":"192.0.2.13","accounts":["CORP\\opsadmin"]}`)
	theft := attackChainPaths([]storage.Finding{admin, privilegedAccount, session, elsewhere})
	if len(theft) != 1 || theft[0].Capability != "admin-session-credentials" || theft[0].Target != "WS01" || len(theft[0].ConfirmedPrereqs) != 4 || !strings.Contains(theft[0].ConfirmedPrereqs[1], `CORP\opsadmin signed in on WS01`) || strings.Contains(theft[0].ConfirmedPrereqs[1], "jdoe") {
		t.Fatalf("session chain %+v", theft)
	}

	projection := ProjectCritical(rows)
	found := false
	for _, path := range projection.Potential {
		found = found || path.Family == attackChainFamily
	}
	if !found {
		t.Fatal("chains are not part of the Critical projection")
	}
}
