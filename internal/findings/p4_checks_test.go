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

func TestDefaultDomainPasswordPolicyFindings(t *testing.T) {
	domain := func(props map[string]any) map[string]any {
		properties := map[string]any{"name": "CORP.EXAMPLE", "domain": "CORP.EXAMPLE"}
		for key, value := range props {
			properties[key] = value
		}
		return map[string]any{"ObjectIdentifier": hygieneDomainSID, "Properties": properties, "Trusts": []any{}}
	}
	for _, tc := range []struct {
		name  string
		props map[string]any
		want  map[string]string
	}{
		{"weak", map[string]any{"lockoutthreshold": 0, "pwdproperties": 0, "minpwdlength": 5}, map[string]string{"ad_domain_policy_no_account_lockout": "medium", "ad_domain_policy_complexity_disabled": "low"}},
		{"lenient", map[string]any{"lockoutthreshold": 50, "pwdproperties": 1}, map[string]string{"ad_domain_policy_lenient_account_lockout": "low"}},
		{"sound", map[string]any{"lockoutthreshold": 5, "pwdproperties": 1}, map[string]string{}},
		{"unknown", map[string]any{}, map[string]string{}},
	} {
		inputs := analyzeHygiene(t, writeHygieneCollection(t, nil, nil, nil, []map[string]any{domain(tc.props)}))
		got := map[string]string{}
		for _, input := range inputs {
			if strings.HasPrefix(input.FindingType, "ad_domain_policy_") {
				got[input.FindingType] = input.Severity
			}
		}
		if len(got) != len(tc.want) {
			t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
		}
		for typ, severity := range tc.want {
			if got[typ] != severity {
				t.Fatalf("%s: %s = %q, want %q", tc.name, typ, got[typ], severity)
			}
		}
	}
}

func TestPrivilegedAccountWeaknesses(t *testing.T) {
	member := func(ids ...string) []any {
		list := []any{}
		for _, id := range ids {
			list = append(list, map[string]any{"ObjectIdentifier": id})
		}
		return list
	}
	groups := []map[string]any{
		{"ObjectIdentifier": hygieneDomainSID + "-512", "Properties": map[string]any{"name": "DOMAIN ADMINS@CORP.EXAMPLE", "domain": "CORP.EXAMPLE"}, "Members": member(hygieneDomainSID + "-1900")},
		{"ObjectIdentifier": hygieneDomainSID + "-1900", "Properties": map[string]any{"name": "TIER0-OPS@CORP.EXAMPLE", "domain": "CORP.EXAMPLE"}, "Members": member(hygieneDomainSID + "-1901")},
		{"ObjectIdentifier": "CORP.EXAMPLE-S-1-5-32-544", "Properties": map[string]any{"name": "ADMINISTRATORS@CORP.EXAMPLE", "domain": "CORP.EXAMPLE"}, "Members": member(hygieneDomainSID + "-1902")},
	}
	users := []map[string]any{
		hygieneUser("1901", "svc-sql-admin", map[string]any{"hasspn": true, "pwdneverexpires": true}),
		hygieneUser("1902", "old-admin", map[string]any{"lastlogontimestamp": daysBefore(200), "pwdlastset": daysBefore(800)}),
		hygieneUser("1903", "svc-web", map[string]any{"hasspn": true}),
	}
	inputs := analyzeHygiene(t, writeHygieneCollection(t, users, nil, groups, nil))
	expect := map[string]string{
		"ad_account_privileged_kerberoastable":    "SVC-SQL-ADMIN@CORP.EXAMPLE",
		"ad_account_privileged_pwd_never_expires": "SVC-SQL-ADMIN@CORP.EXAMPLE",
		"ad_account_privileged_stale":             "OLD-ADMIN@CORP.EXAMPLE",
		"ad_account_privileged_old_password":      "OLD-ADMIN@CORP.EXAMPLE",
	}
	for typ, account := range expect {
		found := findingsOfType(inputs, typ)
		if len(found) != 1 {
			t.Fatalf("%s: %d Findings", typ, len(found))
		}
		affected, _ := json.Marshal(evidenceOf(t, found[0])["affected_objects"])
		if string(affected) != `["`+account+`"]` {
			t.Fatalf("%s affects %s, want only %s", typ, affected, account)
		}
	}
	if found := findingsOfType(inputs, "ad_account_privileged_kerberoastable"); found[0].Severity != "high" {
		t.Fatalf("kerberoastable privileged severity %q", found[0].Severity)
	}
}

func TestShadowAdminRights(t *testing.T) {
	ace := func(principal, right string, extra ...string) map[string]any {
		entry := map[string]any{"PrincipalSID": principal, "RightName": right, "IsInherited": false}
		if len(extra) > 0 {
			entry["Decision"] = extra[0]
		}
		return entry
	}
	helpdesk := hygieneDomainSID + "-2001"
	daMember := hygieneDomainSID + "-2002"
	replicator := hygieneDomainSID + "-2003"
	groups := []map[string]any{
		withACEs(map[string]any{"ObjectIdentifier": hygieneDomainSID + "-512", "Properties": map[string]any{"name": "DOMAIN ADMINS@CORP.EXAMPLE", "domain": "CORP.EXAMPLE"}, "Members": []any{map[string]any{"ObjectIdentifier": daMember}}},
			ace(helpdesk, "AddMember"), ace(daMember, "GenericAll"), ace(helpdesk, "WriteDacl", "Deny"), ace(hygieneDomainSID+"-9999", "GenericAll")),
		{"ObjectIdentifier": helpdesk, "Properties": map[string]any{"name": "HELPDESK@CORP.EXAMPLE", "domain": "CORP.EXAMPLE"}},
		// A group nested in Administrators, whose membership a low-privileged
		// user controls.
		{"ObjectIdentifier": "CORP.EXAMPLE-S-1-5-32-544", "Properties": map[string]any{"name": "ADMINISTRATORS@CORP.EXAMPLE", "domain": "CORP.EXAMPLE"}, "Members": []any{map[string]any{"ObjectIdentifier": hygieneDomainSID + "-2010"}}},
		withACEs(map[string]any{"ObjectIdentifier": hygieneDomainSID + "-2010", "Properties": map[string]any{"name": "SERVER-ADMINS@CORP.EXAMPLE", "domain": "CORP.EXAMPLE"}}, ace(hygieneDomainSID+"-2004", "AddMember")),
	}
	users := []map[string]any{
		hygieneUser("2002", "da-user", nil),
		withACEs(hygieneUser("2003", "svc-sync", nil)),
		withACEs(hygieneUser("2004", "plain", nil), ace(replicator, "GetChangesAll")),
	}
	domains := []map[string]any{withACEs(map[string]any{"ObjectIdentifier": hygieneDomainSID, "Properties": map[string]any{"name": "CORP.EXAMPLE", "domain": "CORP.EXAMPLE"}, "Trusts": []any{}}, ace(replicator, "GetChangesAll"))}
	dir := writeHygieneCollection(t, users, nil, groups, domains)
	writeExport(t, filepath.Join(dir, "20260601_containers.json"), "containers", []map[string]any{
		withACEs(map[string]any{"ObjectIdentifier": "ADMINSDHOLDER-GUID", "Properties": map[string]any{"name": "ADMINSDHOLDER@CORP.EXAMPLE", "domain": "CORP.EXAMPLE"}}, ace("CORP.EXAMPLE-S-1-5-11", "WriteDacl")),
	})
	found := findingsOfType(analyzeHygiene(t, dir), "ad_shadow_admin_rights")
	if len(found) != 1 || found[0].Severity != "high" {
		t.Fatalf("got %+v", found)
	}
	evidence := evidenceOf(t, found[0])
	affected, _ := json.Marshal(evidence["affected_objects"])
	text := string(affected)
	for _, want := range []string{"HELPDESK@CORP.EXAMPLE → AddMember on DOMAIN ADMINS@CORP.EXAMPLE (privileged group)", "SVC-SYNC@CORP.EXAMPLE → GetChangesAll on CORP.EXAMPLE (domain object)", "WriteDacl on ADMINSDHOLDER@CORP.EXAMPLE (AdminSDHolder)", "PLAIN@CORP.EXAMPLE → AddMember on SERVER-ADMINS@CORP.EXAMPLE (group nested in a privileged group)"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing grant %q in %s", want, text)
		}
	}
	for _, unwanted := range []string{"DA-USER", "9999", "PLAIN → GETCHANGESALL"} {
		if strings.Contains(strings.ToUpper(text), unwanted) {
			t.Fatalf("excluded principal or target %s reported: %s", unwanted, text)
		}
	}
	if !strings.Contains(found[0].Description, "broad principal") {
		t.Fatalf("broad principal not called out: %s", found[0].Description)
	}
}
