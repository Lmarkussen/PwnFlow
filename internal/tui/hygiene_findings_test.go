package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestHygieneFindingRouting(t *testing.T) {
	for _, tc := range []struct {
		typ, title, category, subcategory string
	}{
		// Titles carry names that would trip the substring rules.
		{"ad_account_des_only", "DES-only Kerberos encryption: SVC_LDAP@CORP.EXAMPLE", "active_directory", "account_security"},
		{"ad_account_sid_history_present", "sIDHistory present: SMB_SVC@CORP.EXAMPLE", "active_directory", "account_security"},
		{"ad_account_laps_not_observed", "Computers without observed LAPS (CORP.EXAMPLE)", "active_directory", "account_security"},
		{"ad_domain_config_anonymous_ldap_operations", "Anonymous LDAP operations enabled (CORP.EXAMPLE)", "active_directory", "domain_configuration"},
		{"ad_trust_sid_filtering_relaxed", "SID filtering relaxed on trust CORP.EXAMPLE → SPN.EXAMPLE", "active_directory", "trusts"},
		// Existing routing is unchanged.
		{"ad_account_passwd_notreqd", "Password Not Required Account", "active_directory", "account_security"},
		{"ad_domain_policy_password_policy_snapshot", "Domain Password Policy Snapshot", "active_directory", "domain_security_policy"},
	} {
		finding := storage.Finding{FindingInput: storage.FindingInput{FindingType: tc.typ, Title: tc.title, SourceTool: "RustHound-CE"}}
		if got := findingCategoryKey(finding); got != tc.category {
			t.Errorf("%s: category %q, want %q", tc.typ, got, tc.category)
		}
		if got := findingSubcategoryKey(finding); got != tc.subcategory {
			t.Errorf("%s: subcategory %q, want %q", tc.typ, got, tc.subcategory)
		}
		if !findingBelongsToSubcategory(tc.category, tc.subcategory, finding) {
			t.Errorf("%s: not listed under %s/%s", tc.typ, tc.category, tc.subcategory)
		}
	}
	for _, key := range []string{"domain_configuration", "trusts"} {
		found := false
		for _, definition := range findingSubcategoryOrder["active_directory"] {
			found = found || definition.Key == key
		}
		if !found {
			t.Errorf("subcategory %q is not offered under Active Directory", key)
		}
	}
}

func TestGroupedAccountFindingListsAffectedObjects(t *testing.T) {
	finding := storage.Finding{FindingInput: storage.FindingInput{
		FindingType: "ad_account_laps_not_observed", Title: "Computers without observed LAPS (CORP.EXAMPLE)",
		EvidenceJSON: `{"account":"2 enabled non-DC computer(s)","flag":"no LAPS expiration attribute observed","enabled":true,"user_account_control":"2 enabled non-DC computer(s)","affected_objects":["WS01.CORP.EXAMPLE","WS02.CORP.EXAMPLE"],"objects_omitted":3}`,
	}}
	rendered := ansi.Strip(findingAttributes(finding, 120))
	for _, want := range []string{"Affected", "WS01.CORP.EXAMPLE", "WS02.CORP.EXAMPLE", "and 3 more"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered attributes missing %q:\n%s", want, rendered)
		}
	}
}
