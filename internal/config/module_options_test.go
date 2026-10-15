package config

import (
	"strings"
	"testing"
)

func TestParseModuleOptionsAcceptsRepeatedAssignments(t *testing.T) {
	options, err := ParseModuleOptions([]string{
		`smb-reg-query.PATH=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		"smb-reg-query.KEY=ProductName",
		"find-computer.TEXT=SQL Server",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := options["smb-reg-query"]["PATH"]; got != `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` {
		t.Fatalf("PATH = %q", got)
	}
	if got := options["smb-reg-query"]["KEY"]; got != "ProductName" {
		t.Fatalf("KEY = %q", got)
	}
	// A value may contain spaces, '=', and ',' because the operator's shell, not
	// a separator inside the value, decides where it ends.
	if got := options["find-computer"]["TEXT"]; got != "SQL Server" {
		t.Fatalf("TEXT = %q", got)
	}
	withPunctuation, err := ParseModuleOptions([]string{"m.K=v=1,2;3"})
	if err != nil {
		t.Fatal(err)
	}
	if got := withPunctuation["m"]["K"]; got != "v=1,2;3" {
		t.Fatalf("value with punctuation = %q", got)
	}
}

func TestParseModuleOptionsRejectsMalformedAssignments(t *testing.T) {
	cases := map[string]string{
		"missing separator":  "smb-reg-query.PATH",
		"missing key":        "smb-reg-query=PATH",
		"bad module id":      "smb reg query.PATH=x",
		"bad option key":     "smb-reg-query.path-value=x",
		"empty value":        "smb-reg-query.PATH=",
		"control character":  "smb-reg-query.PATH=x\ny",
		"option-like module": "-smb-reg-query.PATH=x",
	}
	for name, raw := range cases {
		if _, err := ParseModuleOptions([]string{raw}); err == nil {
			t.Fatalf("%s: %q was accepted", name, raw)
		}
	}
	options, err := ParseModuleOptions(nil)
	if err != nil || options != nil {
		t.Fatalf("no options = %v, %v", options, err)
	}
}

// Error text names the module and the key without echoing the value: it is
// printed to a terminal and may be quoted in a report.
func TestParseModuleOptionsErrorsDoNotEchoTheValue(t *testing.T) {
	secret := "operator-supplied-value"
	for _, raw := range []string{
		"smb-reg-query.PATH=" + secret + "\nnext",
		"bad id.PATH=" + secret,
		"smb-reg-query.PATH WITH SPACE=" + secret,
	} {
		_, err := ParseModuleOptions([]string{raw})
		if err == nil {
			t.Fatalf("%q was accepted", raw)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("the error echoed the value: %v", err)
		}
	}
}
