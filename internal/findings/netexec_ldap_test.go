package findings

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const (
	ldapFixtureBanner = "LDAPS                    192.0.2.10      636    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:corp.example) (signing:None) (channel binding:Never) \n"
	ldapFixtureLogin  = "LDAPS                    192.0.2.10      636    DC01             [+] corp.example\\auditor:Fixture-Secret-1 \n"
)

func writeLDAPFixture(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func analyzeLDAPFixture(t *testing.T, name, body string) []storage.FindingInput {
	t.Helper()
	inputs, err := AnalyzeNetExecLDAP(context.Background(), writeLDAPFixture(t, name, body), 1, 2, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range inputs {
		for name, value := range map[string]string{"key": input.FindingKey, "source": input.SourceTool, "type": input.FindingType, "title": input.Title, "artifact": input.ArtifactPath, "ref": input.ArtifactRef, "parser": input.ParserVersion} {
			if strings.TrimSpace(value) == "" {
				t.Fatalf("%s has an empty %s", input.FindingType, name)
			}
		}
	}
	return inputs
}

func ldapFindingsByType(inputs []storage.FindingInput) map[string][]storage.FindingInput {
	result := make(map[string][]storage.FindingInput)
	for _, input := range inputs {
		result[input.FindingType] = append(result[input.FindingType], input)
	}
	return result
}

func TestNetExecLDAPBannerReportsSigningAndChannelBinding(t *testing.T) {
	byType := ldapFindingsByType(analyzeLDAPFixture(t, "LDAP_obsolete.txt", ldapFixtureBanner+ldapFixtureLogin+ldapFixtureBanner))
	signing := byType["ldap_signing_not_enforced"]
	binding := byType["ldap_channel_binding_not_enforced"]
	if len(signing) != 1 || len(binding) != 1 {
		t.Fatalf("want one signing and one channel-binding Finding, got %d and %d", len(signing), len(binding))
	}
	if signing[0].Severity != "medium" || binding[0].Severity != "medium" {
		t.Fatalf("severities %q/%q, want medium", signing[0].Severity, binding[0].Severity)
	}
	if signing[0].Confidence != "tool-reported-not-verified" || !strings.Contains(signing[0].Description, "probe fails") {
		t.Fatalf("signing Finding must carry the probe caveat: %+v", signing[0])
	}
	if signing[0].AffectedObject != "DC01" {
		t.Fatalf("affected object %q", signing[0].AffectedObject)
	}
}

func TestNetExecLDAPBannerQuietWhenEnforcedOrUnknown(t *testing.T) {
	for _, tc := range []struct {
		banner, wantType, wantSeverity string
	}{
		{"(signing:Enforced) (channel binding:Always)", "", ""},
		{"(signing:Enforced) (channel binding:When Supported)", "ldap_channel_binding_not_enforced", "low"},
		{"(signing:Enforced) (channel binding:No TLS cert)", "", ""},
		{"(signing:Enforced) (channel binding:Unknown)", "", ""},
	} {
		line := "LDAP                     192.0.2.10      389    DC01             [*] Windows Server 2022 (name:DC01) (domain:corp.example) " + tc.banner + "\n"
		inputs := analyzeLDAPFixture(t, "LDAP_obsolete.txt", line)
		if tc.wantType == "" {
			if len(inputs) != 0 {
				t.Fatalf("%s: unexpected Findings %+v", tc.banner, inputs)
			}
			continue
		}
		if len(inputs) != 1 || inputs[0].FindingType != tc.wantType || inputs[0].Severity != tc.wantSeverity {
			t.Fatalf("%s: got %+v", tc.banner, inputs)
		}
	}
}

func TestNetExecLDAPDNSNonsecureZones(t *testing.T) {
	body := ldapFixtureBanner + ldapFixtureLogin +
		"DNS-NONS...              192.0.2.10      636    DC01             [+] Domain DNS zone(s) allowing nonsecure dynamic updates\n" +
		"DNS-NONS...              192.0.2.10      636    DC01             legacy.corp.example\n" +
		"DNS-NONS...              192.0.2.10      636    DC01             [-] No forest DNS zones allowing nonsecure dynamic updates\n"
	zones := ldapFindingsByType(analyzeLDAPFixture(t, "LDAP_dns_nonsecure.txt", body))["ad_domain_config_dns_nonsecure_updates"]
	if len(zones) != 1 || zones[0].AffectedObject != "legacy.corp.example" || zones[0].Severity != "medium" {
		t.Fatalf("got %+v", zones)
	}
	var evidence map[string]any
	if err := json.Unmarshal([]byte(zones[0].EvidenceJSON), &evidence); err != nil || evidence["zone_scope"] != "domain" {
		t.Fatalf("evidence %s (%v)", zones[0].EvidenceJSON, err)
	}

	quiet := ldapFixtureBanner +
		"DNS-NONS...              192.0.2.10      636    DC01             [-] No domain DNS zones allowing nonsecure dynamic updates\n" +
		"DNS-NONS...              192.0.2.10      636    DC01             [-] No forest DNS zones allowing nonsecure dynamic updates\n"
	if got := ldapFindingsByType(analyzeLDAPFixture(t, "LDAP_dns_nonsecure.txt", quiet))["ad_domain_config_dns_nonsecure_updates"]; len(got) != 0 {
		t.Fatalf("negative output produced %+v", got)
	}
}

func TestNetExecLDAPObsoleteHostsAreGrouped(t *testing.T) {
	body := ldapFixtureBanner + ldapFixtureLogin +
		"OBSOLETE                 192.0.2.10      636    DC01             [*] 2 Obsolete hosts will be saved to /tmp/corp.example.obsoletehosts.txt\n" +
		"OBSOLETE                 192.0.2.10      636    DC01             ws07.corp.example (N/A) : Windows 7 Professional [pwd-last-set: 2019-03-01 10:00:00]\n" +
		"OBSOLETE                 192.0.2.10      636    DC01             app08.corp.example (192.0.2.20) : Windows Server 2008 R2 Enterprise [pwd-last-set: Never]\n"
	group := ldapFindingsByType(analyzeLDAPFixture(t, "LDAP_obsolete.txt", body))["ad_account_obsolete_operating_system"]
	if len(group) != 1 {
		t.Fatalf("want one grouped Finding, got %+v", group)
	}
	var evidence struct {
		Affected []string            `json:"affected_objects"`
		Objects  []map[string]string `json:"objects"`
		Count    int                 `json:"object_count"`
	}
	if err := json.Unmarshal([]byte(group[0].EvidenceJSON), &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Count != 2 || strings.Join(evidence.Affected, ",") != "app08.corp.example,ws07.corp.example" || evidence.Objects[0]["operating_system"] != "Windows Server 2008 R2 Enterprise" {
		t.Fatalf("evidence %s", group[0].EvidenceJSON)
	}

	none := ldapFixtureBanner + "OBSOLETE                 192.0.2.10      636    DC01             [*] No Obsolete Hosts Identified\n"
	if got := ldapFindingsByType(analyzeLDAPFixture(t, "LDAP_obsolete.txt", none))["ad_account_obsolete_operating_system"]; len(got) != 0 {
		t.Fatalf("negative output produced %+v", got)
	}
}

func TestNetExecLDAPPasswordAttributesRecordReaderNotValue(t *testing.T) {
	body := ldapFixtureBanner + ldapFixtureLogin +
		"GET-USER...              192.0.2.10      636    DC01             [+] Found following users: \n" +
		"GET-USER...              192.0.2.10      636    DC01             User: svc-legacy userPassword: Fixture-Value-9\n"
	inputs := analyzeLDAPFixture(t, "LDAP_get_userPassword.txt", body)
	readable := ldapFindingsByType(inputs)["ad_account_password_attribute_readable"]
	if len(readable) != 1 || readable[0].AffectedObject != "svc-legacy" || readable[0].Severity != "high" {
		t.Fatalf("got %+v", readable)
	}
	if !strings.Contains(readable[0].EvidenceJSON, `"read_by":"corp.example\\auditor"`) {
		t.Fatalf("reader not recorded: %s", readable[0].EvidenceJSON)
	}
	encoded, _ := json.Marshal(inputs)
	for _, secret := range []string{"Fixture-Value-9", "Fixture-Secret-1"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("Finding output contains secret %q", secret)
		}
	}
}

func TestNetExecLDAPPasswordAttributeHeaderAloneIsNotEvidence(t *testing.T) {
	// The module prints the header when the search returned only referrals.
	body := ldapFixtureBanner + ldapFixtureLogin +
		"GET-UNIX...              192.0.2.10      636    DC01             [+] Found following users: \n"
	if got := ldapFindingsByType(analyzeLDAPFixture(t, "LDAP_get_unixUserPassword.txt", body))["ad_account_password_attribute_readable"]; len(got) != 0 {
		t.Fatalf("header without account lines produced %+v", got)
	}
}

func TestNetExecLDAPHandlesANSIAndStableKeys(t *testing.T) {
	colored := "\x1b[1m\x1b[34mLDAPS\x1b[0m                    192.0.2.10      636    DC01             [*] Windows Server 2019 (name:DC01) (domain:corp.example) (\x1b[1m\x1b[33msigning:None\x1b[0m) (\x1b[1m\x1b[33mchannel binding:Never\x1b[0m) \n"
	first := analyzeLDAPFixture(t, "LDAP_obsolete.txt", colored)
	second := analyzeLDAPFixture(t, "LDAP_dns_nonsecure.txt", ldapFixtureBanner)
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("got %d and %d Findings", len(first), len(second))
	}
	keys := map[string]bool{first[0].FindingKey: true, first[1].FindingKey: true}
	for _, input := range second {
		if !keys[input.FindingKey] {
			t.Fatalf("banner Finding key changed between artifacts: %s", input.FindingType)
		}
	}
}

func TestNetExecLDAPObservationArtifactsAreRouted(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ module, file string }{
		{"Find Nonsecure DNS Zones", "LDAP_dns_nonsecure.txt"},
		{"Find Obsolete Operating Systems", "LDAP_obsolete.txt"},
		{"Get userPassword Attribute", "LDAP_get_userPassword.txt"},
		{"Get unixUserPassword Attribute", "LDAP_get_unixUserPassword.txt"},
	} {
		path := filepath.Join(dir, tc.file)
		if err := os.WriteFile(path, []byte(ldapFixtureBanner), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := netExecArtifactForExecution(tc.module, path); got != path {
			t.Fatalf("%s: routed to %q, want %q", tc.module, got, path)
		}
	}
}
