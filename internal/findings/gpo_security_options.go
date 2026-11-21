package findings

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const gpoSecurityOptionsParserVersion = "gpo-security-options-v1"

// gpoSecurityOption is one registry-backed security option a GPO can set.
type gpoSecurityOption struct {
	key   string // registry path below MACHINE\, compared case-insensitively
	label string
}

var (
	gpoLDAPServerIntegrity  = gpoSecurityOption{`System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity`, "Domain controller: LDAP server signing requirements"}
	gpoLDAPChannelBinding   = gpoSecurityOption{`System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding`, "Domain controller: LDAP server channel binding token requirements"}
	gpoSMBServerSigning     = gpoSecurityOption{`System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature`, "Microsoft network server: Digitally sign communications (always)"}
	gpoSMBClientSigning     = gpoSecurityOption{`System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature`, "Microsoft network client: Digitally sign communications (always)"}
	gpoLMCompatibilityLevel = gpoSecurityOption{`System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel`, "Network security: LAN Manager authentication level"}
	gpoNoLMHash             = gpoSecurityOption{`System\CurrentControlSet\Control\Lsa\NoLMHash`, "Network security: Do not store LAN Manager hash value on next password change"}
	gpoWDigest              = gpoSecurityOption{`System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential`, "WDigest authentication (UseLogonCredential)"}
)

var gpoTrailingInteger = regexp.MustCompile(`(-?\d+)\s*"?\s*$`)

// gpoSetting is the value a scope receives for one option.
type gpoSetting struct {
	value      int
	gpo        string
	guid       string
	precedence string // enforced, linked, inherited
	conflict   []string
}

// gpoSecurityOptionFindings evaluates the security options that Group Policy
// configures for the Domain Controllers OU and for the domain root. The
// result is what the linked GPOs configure, not the registry state of a
// host: WMI and security filtering, local policy and later changes are not
// evaluated.
func gpoSecurityOptionFindings(document map[string]any, path string, assessmentID, executionID int64, now time.Time) []storage.FindingInput {
	gpos := map[string]map[string]any{}
	for _, raw := range anySlice(document["gpos"]) {
		gpo, _ := raw.(map[string]any)
		if guid := strings.ToUpper(stringOf(gpo["guid"])); guid != "" {
			gpos[guid] = gpo
		}
	}
	var result []storage.FindingInput
	for _, raw := range anySlice(document["ous"]) {
		ou, _ := raw.(map[string]any)
		dn := strings.ToUpper(stringOf(ou["dn"]))
		var scope string
		switch {
		case strings.HasPrefix(dn, "OU=DOMAIN CONTROLLERS,"):
			scope = "dc"
		case strings.HasPrefix(dn, "DC="):
			scope = "domain"
		default:
			continue
		}
		settings := effectiveGPOSettings(ou, gpos)
		result = append(result, gpoScopeFindings(scope, stringOf(ou["dn"]), settings, path, assessmentID, executionID, now)...)
	}
	return result
}

// effectiveGPOSettings resolves each option across the GPOs that apply to an
// OU. An enforced link beats a link on the OU itself, which beats an
// inherited link; GPOs at the same level that disagree are recorded as a
// conflict instead of being ordered.
func effectiveGPOSettings(ou map[string]any, gpos map[string]map[string]any) map[string]gpoSetting {
	linked := gpoGUIDSet(ou["gpos_guids"])
	enforced := gpoGUIDSet(ou["enforced_gpos_guids"])
	rank := map[string]int{"enforced": 3, "linked": 2, "inherited": 1}
	settings := map[string]gpoSetting{}
	for _, guid := range gpoGUIDList(ou["effective_gpos_guids"]) {
		gpo := gpos[guid]
		if gpo == nil || gpoComputerSettingsDisabled(gpo) {
			continue
		}
		precedence := "inherited"
		if linked[guid] {
			precedence = "linked"
		}
		if enforced[guid] {
			precedence = "enforced"
		}
		name := fallbackString(stringOf(gpo["name"]), guid)
		content, _ := gpo["content"].(map[string]any)
		computer, _ := content["computer"].(map[string]any)
		for _, entry := range anySlice(computer["registry"]) {
			item, _ := entry.(map[string]any)
			key := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(stringOf(item["path"]), "MACHINE\\"), "machine\\"))
			match := gpoTrailingInteger.FindStringSubmatch(stringOf(item["value"]))
			if key == "" || len(match) != 2 {
				continue
			}
			value, err := strconv.Atoi(match[1])
			if err != nil {
				continue
			}
			candidate := gpoSetting{value: value, gpo: name, guid: guid, precedence: precedence}
			current, exists := settings[key]
			switch {
			case !exists || rank[precedence] > rank[current.precedence]:
				settings[key] = candidate
			case rank[precedence] == rank[current.precedence] && current.value != value:
				current.conflict = append(current.conflict, fmt.Sprintf("%s sets %d", name, value))
				settings[key] = current
			}
		}
	}
	return settings
}

func gpoScopeFindings(scope, dn string, settings map[string]gpoSetting, path string, assessmentID, executionID int64, now time.Time) []storage.FindingInput {
	scopeLabel := "the domain root"
	if scope == "dc" {
		scopeLabel = "the Domain Controllers OU"
	}
	caveat := " The value is what Group Policy linked to " + scopeLabel + " configures; WMI and security filtering, local policy and the hosts' registry were not evaluated."
	var result []storage.FindingInput
	add := func(option gpoSecurityOption, typ, title, description, severity string) {
		setting := settings[strings.ToLower(option.key)]
		evidence := map[string]any{
			"scope": scopeLabel, "scope_dn": dn, "setting": option.label, "registry_value": "MACHINE\\" + option.key,
			"configured_value": setting.value, "gpo": setting.gpo, "gpo_guid": setting.guid, "precedence": setting.precedence,
			"account": scopeLabel, "flag": option.label, "user_account_control": fmt.Sprintf("%d (set by %s)", setting.value, setting.gpo),
		}
		if len(setting.conflict) > 0 {
			evidence["conflicting_gpos"] = setting.conflict
		}
		encoded, _ := json.Marshal(evidence)
		result = append(result, storage.FindingInput{
			FindingKey: stableSourceKey(assessmentID, "gpo-security-option-"+typ, strings.ToLower(dn), option.key), AssessmentID: assessmentID,
			SourceTool: "gpoParser", SourceExecution: executionID, FindingType: typ, Title: title,
			Description: description + caveat, Severity: severity, Confidence: "policy-configured",
			AffectedObjectID: strings.ToLower(dn), AffectedObject: dn, EvidenceJSON: string(encoded),
			ArtifactPath: path, ArtifactRef: "/gpos/" + setting.guid, ObservedAt: now, Status: "open", ParserVersion: gpoSecurityOptionsParserVersion,
		})
	}
	get := func(option gpoSecurityOption) (gpoSetting, bool) {
		setting, ok := settings[strings.ToLower(option.key)]
		// A conflict at the same precedence level leaves the outcome
		// undetermined, so it is not reported as either value.
		return setting, ok && len(setting.conflict) == 0
	}
	if scope == "dc" {
		if setting, ok := get(gpoLDAPServerIntegrity); ok && setting.value < 2 {
			add(gpoLDAPServerIntegrity, "ldap_signing_policy_not_required", "LDAP signing not required by policy (Domain Controllers)",
				fmt.Sprintf("Group Policy sets LDAPServerIntegrity to %d on domain controllers, so they accept unsigned LDAP binds; 2 (require signing) is needed to refuse them. This confirms at policy level what the NetExec LDAP banner reports.", setting.value), "medium")
		}
		if setting, ok := get(gpoLDAPChannelBinding); ok && setting.value < 2 {
			severity := "medium"
			if setting.value == 1 {
				severity = "low"
			}
			add(gpoLDAPChannelBinding, "ldap_channel_binding_policy_not_required", "LDAPS channel binding not required by policy (Domain Controllers)",
				fmt.Sprintf("Group Policy sets LdapEnforceChannelBinding to %d on domain controllers (0 never, 1 when supported, 2 always). Without 2, NTLM relayed to LDAPS is not reliably rejected.", setting.value), severity)
		}
	}
	if setting, ok := get(gpoSMBServerSigning); ok && setting.value == 0 {
		add(gpoSMBServerSigning, "smb_signing_policy_not_required", "SMB server signing explicitly not required by policy ("+strings.TrimPrefix(scopeLabel, "the ")+")",
			"Group Policy explicitly sets the SMB server signing requirement to disabled, so the affected hosts accept unsigned SMB sessions and NTLM can be relayed to them.", "medium")
	}
	if setting, ok := get(gpoSMBClientSigning); ok && setting.value == 0 && scope == "dc" {
		add(gpoSMBClientSigning, "smb_client_signing_policy_not_required", "SMB client signing explicitly not required by policy (Domain Controllers)",
			"Group Policy explicitly sets the SMB client signing requirement to disabled on domain controllers.", "low")
	}
	if setting, ok := get(gpoLMCompatibilityLevel); ok && setting.value <= 2 {
		add(gpoLMCompatibilityLevel, "ntlm_policy_lm_compatibility_weak", "LM/NTLMv1 permitted by policy ("+strings.TrimPrefix(scopeLabel, "the ")+")",
			fmt.Sprintf("Group Policy sets LmCompatibilityLevel to %d, which lets hosts send LM or NTLMv1 responses. NTLMv1 responses can be cracked or converted to the account's NT hash; level 5 refuses LM and NTLMv1.", setting.value), "medium")
	}
	if setting, ok := get(gpoNoLMHash); ok && setting.value == 0 {
		add(gpoNoLMHash, "ntlm_policy_lm_hash_stored", "LM hash storage permitted by policy ("+strings.TrimPrefix(scopeLabel, "the ")+")",
			"Group Policy disables 'Do not store LAN Manager hash value', so new passwords also get a weak LM hash.", "medium")
	}
	if setting, ok := get(gpoWDigest); ok && setting.value == 1 {
		add(gpoWDigest, "ntlm_policy_wdigest_enabled", "WDigest credential caching enabled by policy ("+strings.TrimPrefix(scopeLabel, "the ")+")",
			"Group Policy sets WDigest UseLogonCredential to 1, so LSASS keeps signed-in users' passwords in a recoverable form.", "high")
	}
	return result
}

func gpoComputerSettingsDisabled(gpo map[string]any) bool {
	flags, err := strconv.Atoi(strings.TrimSpace(stringOf(gpo["flags"])))
	return err == nil && flags&2 != 0
}

// gpoGUIDList reads gpoParser's [[guid, link options], ...] lists.
func gpoGUIDList(value any) []string {
	var result []string
	for _, raw := range anySlice(value) {
		switch typed := raw.(type) {
		case []any:
			if len(typed) > 0 {
				result = append(result, strings.ToUpper(stringOf(typed[0])))
			}
		case string:
			result = append(result, strings.ToUpper(typed))
		}
	}
	return result
}

func gpoGUIDSet(value any) map[string]bool {
	set := map[string]bool{}
	for _, guid := range gpoGUIDList(value) {
		set[guid] = true
	}
	return set
}

func anySlice(value any) []any {
	items, _ := value.([]any)
	return items
}

func stringOf(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}
