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

const hygieneDomainSID = "S-1-5-21-1000-2000-3000"

var hygieneReference = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func daysBefore(days int) int64 {
	return hygieneReference.Add(-time.Duration(days) * 24 * time.Hour).Unix()
}

func writeHygieneCollection(t *testing.T, users, computers, groups, domains []map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	write := func(kind string, data []map[string]any) {
		if data == nil {
			return
		}
		encoded, err := json.Marshal(map[string]any{"meta": map[string]any{"type": kind, "version": 6, "collectorversion": "test"}, "data": data})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "20260601_"+kind+".json")
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, hygieneReference, hygieneReference); err != nil {
			t.Fatal(err)
		}
	}
	write("users", users)
	write("computers", computers)
	write("groups", groups)
	write("domains", domains)
	return dir
}

func hygieneUser(rid, name string, props map[string]any) map[string]any {
	properties := map[string]any{
		"name": strings.ToUpper(name) + "@CORP.EXAMPLE", "domain": "CORP.EXAMPLE", "domainsid": hygieneDomainSID,
		"samaccountname": name, "enabled": true, "pwdneverexpires": false, "sensitive": false, "admincount": false,
		"encryptedtextpwdallowed": false, "usedeskeyonly": false, "lastlogontimestamp": daysBefore(1),
		"whencreated": daysBefore(1000), "pwdlastset": daysBefore(10), "sidhistory": []string{},
		"userpassword": "", "unixpassword": "", "unicodepassword": "", "sfupassword": "",
	}
	for key, value := range props {
		properties[key] = value
	}
	return map[string]any{"ObjectIdentifier": hygieneDomainSID + "-" + rid, "Properties": properties, "Aces": []any{}}
}

func hygieneComputer(rid, name string, props map[string]any) map[string]any {
	properties := map[string]any{
		"name": strings.ToUpper(name) + ".CORP.EXAMPLE", "domain": "CORP.EXAMPLE", "domainsid": hygieneDomainSID,
		"enabled": true, "isdc": false, "haslaps": true, "operatingsystem": "Windows Server 2022 Standard",
		"lastlogontimestamp": daysBefore(2), "whencreated": daysBefore(1000), "sidhistory": []string{},
	}
	for key, value := range props {
		properties[key] = value
	}
	return map[string]any{"ObjectIdentifier": hygieneDomainSID + "-" + rid, "Properties": properties, "Aces": []any{}}
}

func analyzeHygiene(t *testing.T, dir string) []storage.FindingInput {
	t.Helper()
	inputs, _, err := AnalyzeRustHound(context.Background(), dir, 1, 2, hygieneReference.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return inputs
}

func findingsOfType(inputs []storage.FindingInput, typ string) []storage.FindingInput {
	var result []storage.FindingInput
	for _, input := range inputs {
		if input.FindingType == typ {
			result = append(result, input)
		}
	}
	return result
}

func evidenceOf(t *testing.T, input storage.FindingInput) map[string]any {
	t.Helper()
	var evidence map[string]any
	if err := json.Unmarshal([]byte(input.EvidenceJSON), &evidence); err != nil {
		t.Fatal(err)
	}
	return evidence
}

func TestHygieneCleanCollectionProducesNoConditions(t *testing.T) {
	dir := writeHygieneCollection(t,
		[]map[string]any{hygieneUser("1105", "wanda", nil), hygieneUser("502", "krbtgt", map[string]any{"enabled": false, "pwdlastset": daysBefore(30)})},
		[]map[string]any{hygieneComputer("1106", "srv01", nil)},
		nil,
		[]map[string]any{{"ObjectIdentifier": hygieneDomainSID, "Properties": map[string]any{"name": "CORP.EXAMPLE", "domain": "CORP.EXAMPLE", "functionallevel": "2016", "dsheuristics": ""}, "Trusts": []any{}, "Aces": []any{}}},
	)
	for _, input := range analyzeHygiene(t, dir) {
		if input.ParserVersion == hygieneParserVersion && input.Severity != "informational" {
			t.Fatalf("clean collection produced %s (%s)", input.FindingType, input.Title)
		}
	}
}

func TestHygieneAccountConditions(t *testing.T) {
	dir := writeHygieneCollection(t,
		[]map[string]any{
			hygieneUser("1105", "svc_never", map[string]any{"pwdneverexpires": true}),
			hygieneUser("1106", "admin_never", map[string]any{"pwdneverexpires": true, "admincount": true}),
			hygieneUser("1107", "disabled_never", map[string]any{"pwdneverexpires": true, "enabled": false}),
			hygieneUser("1108", "rev", map[string]any{"encryptedtextpwdallowed": true, "useraccountcontrol": 128 + 512}),
			hygieneUser("1109", "des", map[string]any{"usedeskeyonly": true}),
			hygieneUser("1110", "migrated", map[string]any{"sidhistory": []string{hygieneDomainSID + "-512"}}),
			hygieneUser("1111", "foreign", map[string]any{"sidhistory": []string{"S-1-5-21-9-9-9-1234"}}),
			hygieneUser("1112", "legacy", map[string]any{"userpassword": "SYNTHETIC_SECRET_VALUE"}),
			hygieneUser("502", "krbtgt", map[string]any{"enabled": false, "pwdlastset": daysBefore(400)}),
		},
		nil, nil, nil,
	)
	inputs := analyzeHygiene(t, dir)

	never := findingsOfType(inputs, "ad_account_pwd_never_expires")
	if len(never) != 1 {
		t.Fatalf("want one grouped non-expiring finding, got %d", len(never))
	}
	evidence := evidenceOf(t, never[0])
	if evidence["object_count"].(float64) != 2 || evidence["privileged_count"].(float64) != 1 || never[0].Severity != "medium" {
		t.Fatalf("non-expiring grouping wrong: %v severity=%s", evidence, never[0].Severity)
	}
	if strings.Contains(never[0].EvidenceJSON, "DISABLED_NEVER") {
		t.Fatal("disabled account included in non-expiring finding")
	}

	if got := findingsOfType(inputs, "ad_account_reversible_encryption"); len(got) != 1 || got[0].Severity != "medium" {
		t.Fatalf("reversible encryption: %+v", got)
	}
	if got := findingsOfType(inputs, "ad_account_des_only"); len(got) != 1 || got[0].Severity != "low" {
		t.Fatalf("DES only: %+v", got)
	}

	history := findingsOfType(inputs, "ad_account_sid_history_present")
	if len(history) != 2 {
		t.Fatalf("want two sIDHistory findings, got %d", len(history))
	}
	for _, input := range history {
		switch input.AffectedObjectID {
		case hygieneDomainSID + "-1110":
			if input.Severity != "high" || !strings.Contains(input.Description, "Domain Admins") {
				t.Fatalf("privileged sIDHistory not raised: %s %s", input.Severity, input.Description)
			}
		case hygieneDomainSID + "-1111":
			if input.Severity != "medium" {
				t.Fatalf("foreign sIDHistory severity %s", input.Severity)
			}
		}
	}

	password := findingsOfType(inputs, "ad_account_password_attribute_populated")
	if len(password) != 1 {
		t.Fatalf("want one password attribute finding, got %d", len(password))
	}
	if strings.Contains(password[0].EvidenceJSON+password[0].Description+password[0].Title, "SYNTHETIC_SECRET_VALUE") {
		t.Fatal("password attribute value leaked into the Finding")
	}

	krbtgt := findingsOfType(inputs, "ad_account_krbtgt_password_age")
	if len(krbtgt) != 1 || krbtgt[0].Severity != "medium" || evidenceOf(t, krbtgt[0])["age_days"].(float64) != 400 {
		t.Fatalf("krbtgt age: %+v", krbtgt)
	}
	if evidenceOf(t, krbtgt[0])["reference_source"] != "collection file modification time" {
		t.Fatal("krbtgt age must be measured against the collection time, not the analysis time")
	}
}

func TestHygieneKRBTGTRecentRotationIsQuiet(t *testing.T) {
	dir := writeHygieneCollection(t, []map[string]any{hygieneUser("502", "krbtgt", map[string]any{"enabled": false, "pwdlastset": daysBefore(179)})}, nil, nil, nil)
	if got := findingsOfType(analyzeHygiene(t, dir), "ad_account_krbtgt_password_age"); len(got) != 0 {
		t.Fatalf("krbtgt rotated 179 days ago reported: %+v", got)
	}
}

func TestHygienePrivilegedProtection(t *testing.T) {
	protectedUsers := map[string]any{
		"ObjectIdentifier": hygieneDomainSID + "-525",
		"Properties":       map[string]any{"name": "PROTECTED USERS@CORP.EXAMPLE", "domain": "CORP.EXAMPLE"},
		"Members":          []any{map[string]any{"ObjectIdentifier": hygieneDomainSID + "-1201", "ObjectType": "User"}},
		"Aces":             []any{},
	}
	dir := writeHygieneCollection(t,
		[]map[string]any{
			hygieneUser("1201", "da_protected", map[string]any{"admincount": true}),
			hygieneUser("1202", "da_sensitive", map[string]any{"admincount": true, "sensitive": true}),
			hygieneUser("1203", "da_exposed", map[string]any{"admincount": true}),
		},
		nil, []map[string]any{protectedUsers}, nil,
	)
	got := findingsOfType(analyzeHygiene(t, dir), "ad_account_privileged_not_protected")
	if len(got) != 1 {
		t.Fatalf("want one grouped finding, got %d", len(got))
	}
	names := evidenceOf(t, got[0])["affected_objects"].([]any)
	if len(names) != 1 || names[0] != "DA_EXPOSED@CORP.EXAMPLE" {
		t.Fatalf("unexpected affected objects %v", names)
	}
}

func TestHygieneStaleAndLAPS(t *testing.T) {
	dir := writeHygieneCollection(t,
		[]map[string]any{
			hygieneUser("1301", "old", map[string]any{"lastlogontimestamp": daysBefore(200)}),
			hygieneUser("1302", "never_old", map[string]any{"lastlogontimestamp": 0, "whencreated": daysBefore(300)}),
			hygieneUser("1303", "never_new", map[string]any{"lastlogontimestamp": 0, "whencreated": daysBefore(5)}),
			hygieneUser("1304", "recent", map[string]any{"lastlogontimestamp": daysBefore(89)}),
		},
		[]map[string]any{
			hygieneComputer("1401", "ws-nolaps", map[string]any{"haslaps": false, "operatingsystem": "Windows 11 Enterprise"}),
			hygieneComputer("1402", "dc01", map[string]any{"haslaps": false, "isdc": true}),
			hygieneComputer("1403", "linux01", map[string]any{"haslaps": false, "operatingsystem": "Ubuntu 22.04"}),
			hygieneComputer("1404", "ws-off", map[string]any{"enabled": false, "haslaps": false}),
			hygieneComputer("1405", "ws-stale", map[string]any{"lastlogontimestamp": daysBefore(120)}),
		},
		nil, nil,
	)
	inputs := analyzeHygiene(t, dir)
	users := findingsOfType(inputs, "ad_account_stale_enabled_users")
	if len(users) != 1 || evidenceOf(t, users[0])["object_count"].(float64) != 2 {
		t.Fatalf("stale users: %+v", users)
	}
	computers := findingsOfType(inputs, "ad_account_stale_enabled_computers")
	if len(computers) != 1 || evidenceOf(t, computers[0])["object_count"].(float64) != 1 {
		t.Fatalf("stale computers: %+v", computers)
	}
	laps := findingsOfType(inputs, "ad_account_laps_not_observed")
	if len(laps) != 1 {
		t.Fatalf("want one LAPS finding, got %d", len(laps))
	}
	names := evidenceOf(t, laps[0])["affected_objects"].([]any)
	if len(names) != 1 || names[0] != "WS-NOLAPS.CORP.EXAMPLE" {
		t.Fatalf("LAPS must exclude DCs, non-Windows and disabled hosts: %v", names)
	}
}

func TestHygieneAbsentPropertiesAreUnknown(t *testing.T) {
	// An older collector that does not export a property must not produce a
	// Finding claiming the property is false.
	user := map[string]any{"ObjectIdentifier": hygieneDomainSID + "-1500", "Properties": map[string]any{"name": "OLD@CORP.EXAMPLE", "domain": "CORP.EXAMPLE", "enabled": true, "admincount": true}, "Aces": []any{}}
	computer := map[string]any{"ObjectIdentifier": hygieneDomainSID + "-1501", "Properties": map[string]any{"name": "OLD.CORP.EXAMPLE", "domain": "CORP.EXAMPLE", "enabled": true}, "Aces": []any{}}
	dir := writeHygieneCollection(t, []map[string]any{user}, []map[string]any{computer}, nil, nil)
	for _, input := range analyzeHygiene(t, dir) {
		if input.ParserVersion == hygieneParserVersion {
			t.Fatalf("absent properties produced %s", input.FindingType)
		}
	}
}

func TestHygieneDomainConfigurationAndTrusts(t *testing.T) {
	domain := map[string]any{
		"ObjectIdentifier": hygieneDomainSID,
		"Properties":       map[string]any{"name": "CORP.EXAMPLE", "domain": "CORP.EXAMPLE", "functionallevel": "2012", "dsheuristics": "0000002"},
		"Trusts": []any{
			map[string]any{"TargetDomainName": "PARTNER.EXAMPLE", "TargetDomainSid": "S-1-5-21-7-7-7", "TrustDirection": "Bidirectional", "TrustType": "External", "IsTransitive": false, "TrustAttributes": 0},
			map[string]any{"TargetDomainName": "QUARANTINED.EXAMPLE", "TrustDirection": "Outbound", "TrustType": "External", "TrustAttributes": trustQuarantinedDomain},
			map[string]any{"TargetDomainName": "FOREST.EXAMPLE", "TrustDirection": "Outbound", "TrustType": "Forest", "TrustAttributes": trustForestTransitive | trustTreatAsExternal | trustEnableTGTDelegation},
			map[string]any{"TargetDomainName": "INBOUND.EXAMPLE", "TrustDirection": "Inbound", "TrustType": "External", "TrustAttributes": 0},
			map[string]any{"TargetDomainName": "CHILD.CORP.EXAMPLE", "TrustDirection": "Bidirectional", "TrustType": "ParentChild", "TrustAttributes": trustWithinForest},
		},
		"Aces": []any{},
	}
	inputs := analyzeHygiene(t, writeHygieneCollection(t, nil, nil, nil, []map[string]any{domain}))

	if got := findingsOfType(inputs, "ad_domain_config_functional_level"); len(got) != 1 || got[0].Severity != "low" {
		t.Fatalf("functional level: %+v", got)
	}
	if got := findingsOfType(inputs, "ad_domain_config_anonymous_ldap_operations"); len(got) != 1 {
		t.Fatalf("dSHeuristics: %+v", got)
	}
	if got := findingsOfType(inputs, "ad_trust_observed"); len(got) != 5 {
		t.Fatalf("want 5 trust inventory findings, got %d", len(got))
	}
	relaxed := findingsOfType(inputs, "ad_trust_sid_filtering_relaxed")
	targets := map[string]bool{}
	for _, input := range relaxed {
		targets[input.RelatedObject] = true
	}
	if len(relaxed) != 2 || !targets["PARTNER.EXAMPLE"] || !targets["FOREST.EXAMPLE"] {
		t.Fatalf("SID filtering must flag only the unquarantined external and the TREAT_AS_EXTERNAL forest trust: %v", targets)
	}
	if got := findingsOfType(inputs, "ad_trust_tgt_delegation_enabled"); len(got) != 1 || got[0].RelatedObject != "FOREST.EXAMPLE" {
		t.Fatalf("TGT delegation: %+v", got)
	}
}

func TestHygieneFindingKeysAreStableAcrossRuns(t *testing.T) {
	users := []map[string]any{hygieneUser("1105", "svc", map[string]any{"pwdneverexpires": true})}
	first := findingsOfType(analyzeHygiene(t, writeHygieneCollection(t, users, nil, nil, nil)), "ad_account_pwd_never_expires")
	users = append(users, hygieneUser("1106", "svc2", map[string]any{"pwdneverexpires": true}))
	second := findingsOfType(analyzeHygiene(t, writeHygieneCollection(t, users, nil, nil, nil)), "ad_account_pwd_never_expires")
	if len(first) != 1 || len(second) != 1 || first[0].FindingKey != second[0].FindingKey {
		t.Fatal("grouped Finding key must not change when membership changes, so reruns update the same row")
	}
}
