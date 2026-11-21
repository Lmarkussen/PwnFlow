package findings

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPreWindows2000MembershipSeverity(t *testing.T) {
	group := func(members ...string) map[string]any {
		list := make([]any, 0, len(members))
		for _, member := range members {
			list = append(list, map[string]any{"ObjectIdentifier": member, "ObjectType": "Group"})
		}
		return map[string]any{"ObjectIdentifier": "CORP.EXAMPLE-S-1-5-32-554", "Properties": map[string]any{"name": "PRE-WINDOWS 2000 COMPATIBLE ACCESS@CORP.EXAMPLE", "domain": "CORP.EXAMPLE"}, "Members": list}
	}
	for _, tc := range []struct {
		name     string
		groups   []map[string]any
		severity string
	}{
		{"default", []map[string]any{group("CORP.EXAMPLE-S-1-5-11")}, "informational"},
		{"anonymous", []map[string]any{group("CORP.EXAMPLE-S-1-5-11", "CORP.EXAMPLE-S-1-5-7")}, "high"},
		{"unusual member", []map[string]any{group("CORP.EXAMPLE-S-1-5-11", hygieneDomainSID+"-1105")}, "low"},
		// RustHound-CE can list the group twice, once without members.
		{"duplicate empty copy", []map[string]any{group("CORP.EXAMPLE-S-1-5-7"), group()}, "high"},
	} {
		inputs := findingsOfType(analyzeHygiene(t, writeHygieneCollection(t, nil, nil, tc.groups, nil)), "ad_domain_config_pre2000_compatible_access")
		if len(inputs) != 1 || inputs[0].Severity != tc.severity {
			t.Fatalf("%s: got %+v, want one %s Finding", tc.name, inputs, tc.severity)
		}
	}
}

func TestKerberosEncryptionTypeConditions(t *testing.T) {
	users := []map[string]any{
		hygieneUser("1701", "svc-rc4", map[string]any{"supportedencryptiontypes": []string{"RC4-HMAC-MD5"}}),
		hygieneUser("1702", "svc-des", map[string]any{"supportedencryptiontypes": []string{"DES-CBC-MD5", "AES256-CTS-HMAC-SHA1-96"}}),
		hygieneUser("1703", "svc-modern", map[string]any{"supportedencryptiontypes": []string{"AES256-CTS-HMAC-SHA1-96"}}),
		hygieneUser("1704", "svc-spn", map[string]any{"supportedencryptiontypes": []string{}, "hasspn": true}),
		hygieneUser("1705", "plain", map[string]any{"supportedencryptiontypes": []string{"Not defined"}, "hasspn": false}),
		hygieneUser("1706", "old-collector", map[string]any{"hasspn": true}), // property absent: unknown
	}
	inputs := analyzeHygiene(t, writeHygieneCollection(t, users, nil, nil, nil))
	expect := map[string]string{
		"ad_account_kerberos_rc4_only":        "SVC-RC4@CORP.EXAMPLE",
		"ad_account_kerberos_des_enabled":     "SVC-DES@CORP.EXAMPLE",
		"ad_account_kerberos_spn_without_aes": "SVC-SPN@CORP.EXAMPLE",
	}
	for typ, account := range expect {
		found := findingsOfType(inputs, typ)
		if len(found) != 1 {
			t.Fatalf("%s: got %d Findings", typ, len(found))
		}
		affected, _ := json.Marshal(evidenceOf(t, found[0])["affected_objects"])
		if string(affected) != `["`+account+`"]` {
			t.Fatalf("%s affects %s, want only %s", typ, affected, account)
		}
	}
}

func TestSMBBannerSessionAndProtocolState(t *testing.T) {
	body := "SMB                      192.0.2.10      445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:corp.example) (signing:True) (SMBv1:True) (Null Auth:True)\n" +
		"SMB                      192.0.2.11      445    WS01             [*] Windows 10 Build 19041 x64 (name:WS01) (domain:corp.example) (signing:False) (SMBv1:False) (Guest Auth:True)\n" +
		"SMB                      192.0.2.12      445    WS02             [*] Windows 10 Build 19041 x64 (name:WS02) (domain:corp.example) (signing:True) (SMBv1:None)\n"
	path := filepath.Join(t.TempDir(), "SMB_server_info.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	inputs, err := AnalyzeNetExecSecurity(context.Background(), path, 1, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, input := range inputs {
		got[input.FindingType+"|"+input.AffectedObject] = input.Severity
	}
	for key, severity := range map[string]string{
		"smb_null_session_accepted|DC01": "low", "smb_v1_enabled|DC01": "medium",
		"smb_guest_session_mapped|WS01": "medium", "smb_signing_not_required|192.0.2.11": "",
	} {
		value, ok := got[key]
		if !ok && severity != "" {
			t.Fatalf("missing %s in %v", key, got)
		}
		if severity != "" && value != severity {
			t.Fatalf("%s severity %q, want %q", key, value, severity)
		}
	}
	for key := range got {
		if strings.Contains(key, "WS02") {
			t.Fatalf("clean host produced %s", key)
		}
	}
}

func TestNullSessionEnumerationAndAuthenticationParser(t *testing.T) {
	prefix := "SMB                      192.0.2.10      445    DC01             "
	body := prefix + "[*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:corp.example) (signing:True) (SMBv1:None) (Null Auth:True)\n" +
		prefix + "[+] corp.example\\: \n" +
		prefix + "[-] Error enumerating shares: STATUS_ACCESS_DENIED\n" +
		prefix + "-Username-                    -Last PW Set-       -BadPW- -Description-\n" +
		prefix + "svc-backup                    2026-01-01 10:00:00 0       Fixture-Description-Secret\n" +
		prefix + "[*] Enumerated 2 local users: CORP\n" +
		prefix + "[+] Dumping password info for domain: CORP\n" +
		prefix + "Minimum password length: 7\n"
	path := filepath.Join(t.TempDir(), "SMB_null_session.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	inputs, err := AnalyzeNetExecNullSession(context.Background(), path, 1, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 1 || inputs[0].Severity != "high" || inputs[0].FindingType != "smb_null_session_enumeration" {
		t.Fatalf("got %+v", inputs)
	}
	if strings.Contains(inputs[0].EvidenceJSON+inputs[0].Description, "Fixture-Description-Secret") {
		t.Fatal("user description copied into the Finding")
	}
	auth, err := AnalyzeNetExecAuthentication(context.Background(), path, 1, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(auth) != 0 {
		t.Fatalf("null session or status line reported as a login: %+v", auth)
	}

	refused := prefix + "[-] corp.example\\: STATUS_ACCESS_DENIED\n"
	if err := os.WriteFile(path, []byte(refused), 0o600); err != nil {
		t.Fatal(err)
	}
	if inputs, _ := AnalyzeNetExecNullSession(context.Background(), path, 1, 2, time.Now()); len(inputs) != 0 {
		t.Fatalf("refused session produced %+v", inputs)
	}
}

func TestDirectorySettingsFindings(t *testing.T) {
	dir := t.TempDir()
	report := map[string]any{
		"schema_version": 1, "domain": "corp.example",
		"ds_heuristics":  map[string]any{"status": "read", "dn": "CN=Directory Service", "value": "0000002"},
		"anonymous_ldap": map[string]any{"status": "objects_readable", "endpoint": "192.0.2.10:389", "user_objects": 5},
		"dns_zones": []any{
			map[string]any{"name": "corp.example", "dn": "DC=corp.example", "partition": "DomainDnsZones", "acl_status": "read", "wildcard_status": "read", "wildcard_record": false, "aces": []any{
				map[string]any{"sid": "S-1-5-11", "allow": true, "rights": []string{"CreateChild"}},
				map[string]any{"sid": "S-1-5-21-1-2-3-512", "name": "Domain Admins", "allow": true, "rights": []string{"GenericAll"}},
				map[string]any{"sid": "S-1-5-21-1-2-3-1201", "name": "DnsAdmins", "allow": true, "rights": []string{"WriteDacl"}},
				map[string]any{"sid": "S-1-5-21-1-2-3-1301", "name": "Helpdesk", "allow": true, "rights": []string{"CreateChild", "WriteProperty"}},
			}},
			map[string]any{"name": "legacy.example", "dn": "DC=legacy.example", "partition": "DomainDnsZones", "acl_status": "read", "wildcard_status": "read", "wildcard_record": true, "aces": []any{
				map[string]any{"sid": "CORP.EXAMPLE-S-1-5-11", "allow": true, "rights": []string{"GenericWrite"}},
			}},
			map[string]any{"name": "locked.example", "dn": "DC=locked.example", "partition": "DomainDnsZones", "acl_status": "read", "wildcard_status": "read", "aces": []any{
				map[string]any{"sid": "S-1-5-11", "allow": true, "rights": []string{"CreateChild"}},
				map[string]any{"sid": "S-1-5-11", "allow": false, "rights": []string{"CreateChild"}},
			}},
		},
	}
	encoded, _ := json.Marshal(report)
	jsonPath := filepath.Join(dir, directorySettingsJSON)
	if err := os.WriteFile(jsonPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := directorySettingsArtifact(filepath.Join(dir, "AD_directory_settings.txt")); got != jsonPath {
		t.Fatalf("artifact discovery %q", got)
	}
	inputs, err := AnalyzeDirectorySettings(context.Background(), jsonPath, 1, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, input := range inputs {
		got[input.FindingType] = input.Severity
		if input.FindingType == "ad_domain_config_dns_record_creation" && strings.Contains(input.EvidenceJSON, "locked.example") {
			t.Fatal("zone with a matching deny ACE reported as open")
		}
		if input.FindingType == "ad_domain_config_dns_zone_delegated_write" && (strings.Contains(input.EvidenceJSON, "DnsAdmins") || !strings.Contains(input.EvidenceJSON, "Helpdesk")) {
			t.Fatalf("delegated writers %s", input.EvidenceJSON)
		}
	}
	want := map[string]string{
		"ad_domain_config_anonymous_ldap_operations": "medium", "ad_domain_config_anonymous_ldap_read": "high",
		"ad_domain_config_dns_record_creation": "medium", "ad_domain_config_dns_zone_broad_write": "high",
		"ad_domain_config_dns_zone_delegated_write": "low",
	}
	for typ, severity := range want {
		if got[typ] != severity {
			t.Fatalf("%s severity %q, want %q (all %v)", typ, got[typ], severity, got)
		}
	}
}

func TestNoTrustsObservedOnlyWhenTrustsWereExported(t *testing.T) {
	domain := func(trusts any) map[string]any {
		object := map[string]any{"ObjectIdentifier": hygieneDomainSID, "Properties": map[string]any{"name": "CORP.EXAMPLE", "domain": "CORP.EXAMPLE", "functionallevel": "2016"}}
		if trusts != nil {
			object["Trusts"] = trusts
		}
		return object
	}
	empty := findingsOfType(analyzeHygiene(t, writeHygieneCollection(t, nil, nil, nil, []map[string]any{domain([]any{})})), "ad_trust_none_observed")
	if len(empty) != 1 || empty[0].Severity != "informational" {
		t.Fatalf("empty trust list: %+v", empty)
	}
	if missing := findingsOfType(analyzeHygiene(t, writeHygieneCollection(t, nil, nil, nil, []map[string]any{domain(nil)})), "ad_trust_none_observed"); len(missing) != 0 {
		t.Fatalf("missing trust list reported as no trusts: %+v", missing)
	}
}
