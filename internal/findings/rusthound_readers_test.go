package findings

import (
	"encoding/json"
	"strings"
	"testing"
)

func readerACE(principal, principalType, right string) map[string]any {
	return map[string]any{"PrincipalSID": principal, "PrincipalType": principalType, "RightName": right, "IsInherited": false}
}

func withACEs(object map[string]any, aces ...map[string]any) map[string]any {
	list := make([]any, 0, len(aces))
	for _, ace := range aces {
		list = append(list, ace)
	}
	object["Aces"] = list
	return object
}

func hygieneGroup(rid, name string) map[string]any {
	return map[string]any{"ObjectIdentifier": hygieneDomainSID + "-" + rid, "Properties": map[string]any{"name": name + "@CORP.EXAMPLE", "domain": "CORP.EXAMPLE"}, "Members": []any{}}
}

func TestClassifyReader(t *testing.T) {
	for sid, want := range map[string]string{
		"CORP.EXAMPLE-S-1-5-32-544":    readerPrivileged,
		hygieneDomainSID + "-512":      readerPrivileged,
		"S-1-5-18":                     readerPrivileged,
		hygieneDomainSID + "-513":      readerBroad,
		"CORP.EXAMPLE-S-1-5-11":        readerBroad,
		"S-1-1-0":                      readerBroad,
		hygieneDomainSID + "-515":      readerBroad,
		hygieneDomainSID + "-1201":     readerDelegated,
		"CORP.EXAMPLE-S-1-5-32-548":    readerPrivileged,
		"S-1-5-21-9-9-9-1105":          readerDelegated,
		"CORP.EXAMPLE-S-1-5-32-545":    readerBroad,
		"S-1-5-21-1000-2000-3000-1000": readerDelegated,
	} {
		if got := classifyReader(sid); got != want {
			t.Errorf("classifyReader(%q)=%q, want %q", sid, got, want)
		}
	}
}

func TestLAPSReadersAreGroupedPerDomain(t *testing.T) {
	helpdesk := hygieneDomainSID + "-1201"
	computers := []map[string]any{
		withACEs(hygieneComputer("1301", "WS01", map[string]any{"haslaps": true}),
			readerACE("CORP.EXAMPLE-S-1-5-32-544", "Group", "ReadLAPSPassword"),
			readerACE(helpdesk, "Group", "ReadLAPSPassword")),
		withACEs(hygieneComputer("1302", "WS02", map[string]any{"haslaps": true}),
			readerACE(helpdesk, "Group", "ReadLAPSPassword"),
			readerACE(helpdesk, "Group", "GenericWrite")),
	}
	groups := []map[string]any{hygieneGroup("1201", "HELPDESK")}
	inputs := findingsOfType(analyzeHygiene(t, writeHygieneCollection(t, nil, computers, groups, nil)), "ad_account_laps_password_readers")
	if len(inputs) != 1 {
		t.Fatalf("want one grouped LAPS reader Finding, got %d", len(inputs))
	}
	if inputs[0].Severity != "medium" {
		t.Fatalf("delegated reader severity %q, want medium", inputs[0].Severity)
	}
	evidence := evidenceOf(t, inputs[0])
	affected, _ := json.Marshal(evidence["affected_objects"])
	if !strings.Contains(string(affected), "HELPDESK@CORP.EXAMPLE → 2 computer(s)") || !strings.Contains(string(affected), "→ 1 computer(s)") {
		t.Fatalf("affected readers %s", affected)
	}
	if evidence["value_recorded"] != false {
		t.Fatalf("value_recorded must be false: %v", evidence["value_recorded"])
	}
}

func TestLAPSReaderSeverityFollowsReaderClass(t *testing.T) {
	for _, tc := range []struct {
		reader, severity string
	}{
		{hygieneDomainSID + "-513", "high"},
		{"CORP.EXAMPLE-S-1-5-32-544", "informational"},
	} {
		computers := []map[string]any{withACEs(hygieneComputer("1301", "WS01", map[string]any{"haslaps": true}), readerACE(tc.reader, "Group", "ReadLAPSPassword"))}
		inputs := findingsOfType(analyzeHygiene(t, writeHygieneCollection(t, nil, computers, nil, nil)), "ad_account_laps_password_readers")
		if len(inputs) != 1 || inputs[0].Severity != tc.severity {
			t.Fatalf("reader %s: got %+v, want severity %s", tc.reader, inputs, tc.severity)
		}
	}
	// A deny ACE grants nothing.
	deny := readerACE(hygieneDomainSID+"-513", "Group", "ReadLAPSPassword")
	deny["Decision"] = "Deny"
	computers := []map[string]any{withACEs(hygieneComputer("1301", "WS01", map[string]any{"haslaps": true}), deny)}
	if inputs := findingsOfType(analyzeHygiene(t, writeHygieneCollection(t, nil, computers, nil, nil)), "ad_account_laps_password_readers"); len(inputs) != 0 {
		t.Fatalf("deny ACE produced a broad reader: %+v", inputs)
	}
}

func TestGMSAReadersPerAccount(t *testing.T) {
	appServer := hygieneDomainSID + "-1401"
	users := []map[string]any{
		withACEs(hygieneUser("1501", "svc-app$", nil),
			readerACE(appServer, "Computer", "ReadGMSAPassword"),
			readerACE("CORP.EXAMPLE-S-1-5-32-544", "Group", "ReadGMSAPassword")),
		withACEs(hygieneUser("1502", "svc-wide$", map[string]any{"admincount": true}),
			readerACE(hygieneDomainSID+"-515", "Group", "ReadGMSAPassword")),
		withACEs(hygieneUser("1503", "svc-tier0$", map[string]any{"admincount": true}),
			readerACE(appServer, "Computer", "ReadGMSAPassword")),
	}
	computers := []map[string]any{hygieneComputer("1401", "APP01", nil)}
	inputs := findingsOfType(analyzeHygiene(t, writeHygieneCollection(t, users, computers, nil, nil)), "ad_account_gmsa_password_readers")
	if len(inputs) != 3 {
		t.Fatalf("want one Finding per gMSA, got %d", len(inputs))
	}
	severity := map[string]string{}
	for _, input := range inputs {
		severity[input.AffectedObject] = input.Severity
	}
	want := map[string]string{"SVC-APP$@CORP.EXAMPLE": "low", "SVC-WIDE$@CORP.EXAMPLE": "high", "SVC-TIER0$@CORP.EXAMPLE": "medium"}
	for account, expected := range want {
		if severity[account] != expected {
			t.Errorf("%s severity %q, want %q (all: %v)", account, severity[account], expected, severity)
		}
	}
	for _, input := range inputs {
		if input.AffectedObject == "SVC-WIDE$@CORP.EXAMPLE" && !strings.Contains(input.Title, "Domain Computers") {
			t.Fatalf("well-known reader not named in title: %q", input.Title)
		}
	}
}

func TestPasswordNotRequiredFromRustHound(t *testing.T) {
	users := []map[string]any{
		hygieneUser("1601", "svc-blank", map[string]any{"passwordnotreqd": true, "useraccountcontrol": 544}),
		hygieneUser("1602", "old-guest", map[string]any{"passwordnotreqd": true, "enabled": false}),
		hygieneUser("1603", "normal", map[string]any{"passwordnotreqd": false}),
	}
	inputs := findingsOfType(analyzeHygiene(t, writeHygieneCollection(t, users, nil, nil, nil)), "ad_account_passwd_notreqd")
	if len(inputs) != 2 {
		t.Fatalf("want two PASSWD_NOTREQD Findings, got %+v", inputs)
	}
	for _, input := range inputs {
		want := "medium"
		if strings.Contains(input.AffectedObject, "OLD-GUEST") {
			want = "informational"
		}
		if input.Severity != want {
			t.Fatalf("%s severity %q, want %q", input.AffectedObject, input.Severity, want)
		}
	}
}
