package findings

import (
	"strings"
	"testing"
	"time"
)

func gpoFixture(guid, name, flags string, registry map[string]string) map[string]any {
	entries := []any{}
	for path, value := range registry {
		entries = append(entries, map[string]any{"path": `MACHINE\` + path, "value": value})
	}
	return map[string]any{"guid": guid, "name": name, "flags": flags, "content": map[string]any{"computer": map[string]any{"registry": entries}}}
}

func link(guids ...string) []any {
	list := []any{}
	for _, guid := range guids {
		list = append(list, []any{guid, float64(0)})
	}
	return list
}

func gpoTypes(t *testing.T, document map[string]any) map[string]string {
	t.Helper()
	got := map[string]string{}
	for _, input := range gpoSecurityOptionFindings(document, "gpoparser.json", 1, 2, time.Now()) {
		got[input.FindingType+"@"+strings.SplitN(input.AffectedObject, ",", 2)[0]] = input.Severity
		if input.Confidence != "policy-configured" || !strings.Contains(input.Description, "not evaluated") {
			t.Fatalf("%s lacks its policy caveat: %+v", input.FindingType, input)
		}
	}
	return got
}

const (
	gpoDefaultDomain = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
	gpoDefaultDC     = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"
	gpoHardening     = "{11111111-2222-3333-4444-555555555555}"
	gpoLegacy        = "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
)

func TestGPOSecurityOptionsByScope(t *testing.T) {
	document := map[string]any{
		"gpos": []any{
			gpoFixture(gpoDefaultDomain, "Default Domain Policy", "0", map[string]string{
				`System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel`:                     "4,2",
				`System\CurrentControlSet\Control\Lsa\NoLMHash`:                                 "4,1",
				`System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential`: "1",
			}),
			gpoFixture(gpoDefaultDC, "Default Domain Controllers Policy", "0", map[string]string{
				`System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity`:              "4,1",
				`System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding`:        "4,1",
				`System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature`: "4,1",
			}),
		},
		"ous": []any{
			map[string]any{"dn": "DC=CORP,DC=EXAMPLE", "gpos_guids": link(gpoDefaultDomain), "enforced_gpos_guids": []any{}, "effective_gpos_guids": link(gpoDefaultDomain)},
			// The Domain Controllers OU lists a GUID in different case.
			map[string]any{"dn": "OU=DOMAIN CONTROLLERS,DC=CORP,DC=EXAMPLE", "gpos_guids": link(strings.ToLower(gpoDefaultDC)), "enforced_gpos_guids": []any{}, "effective_gpos_guids": link(gpoDefaultDomain, strings.ToLower(gpoDefaultDC))},
			map[string]any{"dn": "OU=WORKSTATIONS,DC=CORP,DC=EXAMPLE", "gpos_guids": link(), "effective_gpos_guids": link(gpoDefaultDomain)},
		},
	}
	got := gpoTypes(t, document)
	want := map[string]string{
		"ldap_signing_policy_not_required@OU=DOMAIN CONTROLLERS":         "medium",
		"ldap_channel_binding_policy_not_required@OU=DOMAIN CONTROLLERS": "low",
		"ntlm_policy_lm_compatibility_weak@DC=CORP":                      "medium",
		"ntlm_policy_wdigest_enabled@DC=CORP":                            "high",
		// The DC OU inherits the domain policy.
		"ntlm_policy_lm_compatibility_weak@OU=DOMAIN CONTROLLERS": "medium",
		"ntlm_policy_wdigest_enabled@OU=DOMAIN CONTROLLERS":       "high",
	}
	for key, severity := range want {
		if got[key] != severity {
			t.Fatalf("%s = %q, want %q (all %v)", key, got[key], severity, got)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("unexpected findings: %v", got)
	}
}

func TestGPOSecurityOptionPrecedence(t *testing.T) {
	ldap := `System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity`
	dcOU := func(linked, enforced, effective []any) map[string]any {
		return map[string]any{"dn": "OU=DOMAIN CONTROLLERS,DC=CORP,DC=EXAMPLE", "gpos_guids": linked, "enforced_gpos_guids": enforced, "effective_gpos_guids": effective}
	}
	for _, tc := range []struct {
		name   string
		gpos   []any
		ou     map[string]any
		report bool
	}{
		{"linked beats inherited", []any{gpoFixture(gpoDefaultDomain, "Domain", "0", map[string]string{ldap: "4,1"}), gpoFixture(gpoHardening, "Hardening", "0", map[string]string{ldap: "4,2"})},
			dcOU(link(gpoHardening), link(), link(gpoDefaultDomain, gpoHardening)), false},
		{"enforced beats linked", []any{gpoFixture(gpoLegacy, "Legacy", "0", map[string]string{ldap: "4,0"}), gpoFixture(gpoHardening, "Hardening", "0", map[string]string{ldap: "4,2"})},
			dcOU(link(gpoHardening), link(gpoLegacy), link(gpoLegacy, gpoHardening)), true},
		{"same-level conflict is undetermined", []any{gpoFixture(gpoLegacy, "Legacy", "0", map[string]string{ldap: "4,0"}), gpoFixture(gpoHardening, "Hardening", "0", map[string]string{ldap: "4,2"})},
			dcOU(link(gpoLegacy, gpoHardening), link(), link(gpoLegacy, gpoHardening)), false},
		{"computer settings disabled", []any{gpoFixture(gpoLegacy, "Legacy", "2", map[string]string{ldap: "4,0"})},
			dcOU(link(gpoLegacy), link(), link(gpoLegacy)), false},
		{"required signing is quiet", []any{gpoFixture(gpoHardening, "Hardening", "0", map[string]string{ldap: "4,2"})},
			dcOU(link(gpoHardening), link(), link(gpoHardening)), false},
	} {
		got := gpoTypes(t, map[string]any{"gpos": tc.gpos, "ous": []any{tc.ou}})
		_, reported := got["ldap_signing_policy_not_required@OU=DOMAIN CONTROLLERS"]
		if reported != tc.report {
			t.Fatalf("%s: reported=%v, want %v (%v)", tc.name, reported, tc.report, got)
		}
	}
}
