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

	projection := ProjectCritical(rows)
	found := false
	for _, path := range projection.Potential {
		found = found || path.Family == attackChainFamily
	}
	if !found {
		t.Fatal("chains are not part of the Critical projection")
	}
}
