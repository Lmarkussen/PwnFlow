package findings

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/pwnflow/pwnflow/internal/storage"
)

// attackChainFamily is the Critical projection family of stitched paths.
const attackChainFamily = "attack_chain"

// attackChainStep is one link of a stitched path: what it does and the
// Finding that shows the condition it relies on.
type attackChainStep struct {
	Action  string
	Finding storage.Finding
}

// attackChainPaths joins current Findings into concrete multi-step paths. A
// chain only uses conditions that were each observed; it never infers one.
// Chains are potential Critical paths: the observed conditions are listed
// step by step and what was not verified is listed as such.
func attackChainPaths(rows []storage.Finding) []CriticalPath {
	byType := map[string][]storage.Finding{}
	for _, row := range rows {
		if row.NotReobserved {
			continue
		}
		typ := strings.ToLower(strings.TrimSpace(row.FindingType))
		byType[typ] = append(byType[typ], row)
	}
	for _, list := range byType {
		sort.SliceStable(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	}
	first := func(types ...string) (storage.Finding, bool) {
		for _, typ := range types {
			if list := byType[typ]; len(list) > 0 {
				return list[0], true
			}
		}
		return storage.Finding{}, false
	}
	var paths []CriticalPath

	coercion, coercionOK := first("smb_webclient_service_running", "smb_spooler_service_running")
	coercionMethod := "the Print Spooler (MS-RPRN)"
	if coercionOK && strings.EqualFold(coercion.FindingType, "smb_webclient_service_running") {
		coercionMethod = "WebClient (HTTP)"
	}

	// Coerce the domain controller and relay to AD CS web enrollment (ESC8).
	if coercionOK {
		for _, esc8 := range byType["adcs_esc_esc8"] {
			paths = append(paths, attackChain("coerce-relay-esc8", "Coerce the domain controller and relay to AD CS web enrollment (ESC8)", esc8.AffectedObject,
				[]attackChainStep{
					{"Coerce " + coercion.AffectedObject + " to authenticate through " + coercionMethod, coercion},
					{"Relay the authentication to the HTTP web enrollment endpoint of " + esc8.AffectedObject, esc8},
					{"Enroll a certificate as the domain controller's machine account and use it (PKINIT) to replicate secrets (DCSync)", esc8},
				},
				[]string{"the web enrollment endpoint accepts NTLM without Extended Protection for Authentication", "the coerced machine account may enroll in a template that allows client authentication", "coercion and relay succeed from the operator's position"},
				"Every condition for a coerce-and-relay path to AD CS was observed: a coercion-capable service on the domain controller and HTTP web enrollment on the CA. Together they are a common route to domain compromise."))
		}
	}

	// Coerce the domain controller to a host with unconstrained delegation.
	if coercionOK {
		for _, unconstrained := range byType["unconstrained_delegation_configured"] {
			if strings.EqualFold(unconstrained.Severity, "informational") {
				continue // a domain controller's own default
			}
			paths = append(paths, attackChain("coerce-unconstrained", "Coerce the domain controller to an unconstrained-delegation principal", unconstrained.AffectedObject,
				[]attackChainStep{
					{"Take control of " + unconstrained.AffectedObject + ", which has unconstrained delegation", unconstrained},
					{"Coerce " + coercion.AffectedObject + " to authenticate to it through " + coercionMethod, coercion},
					{"Extract the domain controller's forwarded TGT and use it to replicate secrets (DCSync)", unconstrained},
				},
				[]string{"control of the unconstrained-delegation principal (its credentials or host)", "a name and SPN that route the coerced authentication to that principal", "coercion succeeds from the operator's position"},
				"An unconstrained-delegation principal and a coercion-capable domain controller were both observed; together they let the principal's controller capture the domain controller's TGT."))
		}
	}

	// Coerce over HTTP and relay to LDAP.
	if webclient, ok := first("smb_webclient_service_running"); ok {
		if ldap, ldapOK := first("ldap_signing_policy_not_required", "ldap_signing_not_enforced", "ldap_channel_binding_policy_not_required", "ldap_channel_binding_not_enforced"); ldapOK {
			steps := []attackChainStep{
				{"Coerce " + webclient.AffectedObject + " to authenticate over HTTP through WebClient", webclient},
				{"Relay the authentication to LDAP on a domain controller that does not require signing or channel binding", ldap},
			}
			if maq, maqOK := first("ad_domain_policy_machine_account_creation_quota"); maqOK {
				steps = append(steps, attackChainStep{"Create a computer account (MachineAccountQuota) and write resource-based delegation or shadow credentials on " + webclient.AffectedObject, maq})
			} else {
				steps = append(steps, attackChainStep{"Write resource-based delegation or shadow credentials on " + webclient.AffectedObject + "'s computer object", ldap})
			}
			steps = append(steps, attackChainStep{"Obtain a ticket as an administrator to " + webclient.AffectedObject, webclient})
			paths = append(paths, attackChain("webclient-relay-ldap", "Coerce over HTTP and relay to LDAP", webclient.AffectedObject, steps,
				[]string{"the relay target is a domain controller other than the coerced host (NTLM reflection is blocked)", "the coerced host resolves an attacker-controlled name in the intranet zone", "relay succeeds from the operator's position"},
				"WebClient on a host and LDAP that does not require signing or channel binding were both observed; HTTP authentication relayed to LDAP can rewrite the host's own computer object."))
		}
	}

	// Register a name through ADIDNS and relay the authentication it attracts.
	if dns, ok := first("ad_domain_config_dns_record_creation", "ad_domain_config_dns_zone_broad_write", "ad_domain_config_dns_nonsecure_updates"); ok {
		if relayStep, relayOK := adidnsRelayStep(byType); relayOK {
			paths = append(paths, attackChain("adidns-spoof-relay", "Spoof a name through ADIDNS and relay the authentication it attracts", dns.AffectedObject,
				[]attackChainStep{
					{"Register a DNS record in " + dns.AffectedObject + " (a wildcard, or a stale host name clients still look up) that points to the operator's host", dns},
					{"Receive the NTLM authentication of clients that resolve the name and connect over SMB or HTTP", dns},
					relayStep,
				},
				[]string{"clients actually look up the registered name (WPAD and ISATAP are on the DNS server's global query block list by default)", "the relayed account has rights worth using on the relay target", "relay succeeds from the operator's position"},
				"Any domain account could add DNS records and a relay target that accepts NTLM was observed; spoofed names make clients authenticate to the operator, whose relay reaches that target."))
		}
	}

	// Poison name resolution or DHCPv6 and relay the captured authentication.
	for _, poisoning := range []struct{ typ, template, title, action, reason string }{
		{"network_poisoning_name_resolution", "llmnr-relay", "Poison LLMNR/NBT-NS and relay the captured authentication",
			"Answer the LLMNR, NBT-NS or mDNS queries of clients on the segment (including WPAD lookups) so they authenticate to the operator",
			"Multicast name resolution is not disabled by Group Policy and a relay target that accepts NTLM was observed."},
		{"network_poisoning_ipv6_dhcpv6", "mitm6-relay", "Take over DNS through DHCPv6 and relay the captured authentication",
			"Answer DHCPv6 requests to become the clients' IPv6 DNS server and point WPAD at the operator, so their HTTP clients authenticate to it",
			"IPv6 is not disabled by Group Policy and a relay target that accepts NTLM was observed; mitm6 with a relay is a common route from the network to the directory."},
	} {
		finding, ok := first(poisoning.typ)
		if !ok {
			continue
		}
		relayStep, relayOK := adidnsRelayStep(byType)
		if !relayOK {
			continue
		}
		paths = append(paths, attackChain(poisoning.template, poisoning.title, finding.AffectedObject,
			[]attackChainStep{{poisoning.action, finding}, relayStep},
			[]string{"the operator's host is on a segment with clients that send the queries or DHCPv6 requests", "no switch or host control (RA Guard, DHCPv6 Guard, firewall) blocks the spoofed answers", "the relayed account has rights worth using on the relay target"},
			poisoning.reason))
	}

	// Take over DNS through DHCPv6 and serve a malicious update from HTTP WSUS.
	if wsus, ok := first("network_poisoning_wsus_http"); ok {
		if ipv6, ipv6OK := first("network_poisoning_ipv6_dhcpv6"); ipv6OK {
			paths = append(paths, attackChain("mitm6-wsus", "Serve a malicious update from WSUS over HTTP", wsus.AffectedObject,
				[]attackChainStep{
					{"Become the clients' IPv6 DNS server through DHCPv6 spoofing", ipv6},
					{"Resolve the WSUS host name to the operator and answer the clients' update scan over HTTP", wsus},
					{"Offer a Microsoft-signed binary (for example PsExec) as an update that runs a command as SYSTEM on each client", wsus},
				},
				[]string{"clients resolve the WSUS name through the spoofed DNS server", "the operator's host is on the clients' segment", "endpoint protection allows the offered binary and command"},
				"Clients fetch updates from WSUS over plain HTTP and IPv6 is not disabled, so a DHCPv6 spoofer controls where they look up the WSUS server."))
		}
	}

	// Recovered or readable credentials of a privileged account.
	privileged := privilegedAccountNames(byType)
	// Local administrator on a host where a privileged account is signed in.
	adminOn := map[string]storage.Finding{}
	for _, access := range byType["netexec_privileged_access"] {
		var evidence map[string]any
		_ = json.Unmarshal([]byte(access.EvidenceJSON), &evidence)
		if strings.EqualFold(cpFirstString(evidence, "protocol"), "SMB") || cpFirstString(evidence, "protocol") == "" {
			if _, exists := adminOn[strings.ToLower(access.AffectedObject)]; !exists {
				adminOn[strings.ToLower(access.AffectedObject)] = access
			}
		}
	}
	sessionPaths := map[string]bool{}
	for _, session := range byType["smb_signed_in_accounts"] {
		var evidence map[string]any
		_ = json.Unmarshal([]byte(session.EvidenceJSON), &evidence)
		target := strings.ToLower(cpFirstString(evidence, "target"))
		access, ok := adminOn[target]
		if !ok || sessionPaths[target] {
			continue
		}
		var exposed []string
		var source storage.Finding
		for _, account := range cpStringSlice(evidence["accounts"]) {
			if row, isPrivileged := privileged[normalizeAccountName(account)]; isPrivileged {
				exposed = append(exposed, account)
				source = row
			}
		}
		if len(exposed) == 0 {
			continue
		}
		sessionPaths[target] = true
		accounts := strings.Join(exposed, ", ")
		paths = append(paths, attackChain("admin-session-credentials", "Take a privileged account's credentials from a host you administer", session.AffectedObject,
			[]attackChainStep{
				{"Use the local administrator access PwnFlow's credentials have on " + session.AffectedObject, access},
				{accounts + " signed in on " + session.AffectedObject, session},
				{accounts + " is privileged", source},
				{"Extract the signed-in account's credentials or Kerberos tickets from LSASS on " + session.AffectedObject + " and use them", session},
			},
			[]string{"the session is interactive and still leaves reusable material in memory (network logons do not)", "Credential Guard or LSA protection does not block the extraction", "endpoint protection allows it"},
			"PwnFlow's credentials are local administrator on a host where a privileged account was signed in; its credentials can usually be taken from memory there."))
	}

	for _, typ := range []string{"netexec_gpp_password_exposure", "ad_account_password_attribute_readable", "sccm_task_sequence_credentials_exposed"} {
		for _, exposure := range byType[typ] {
			account := exposedAccount(exposure)
			source, ok := privileged[normalizeAccountName(account)]
			if account == "" || !ok {
				continue
			}
			paths = append(paths, attackChain("credential-privileged", "Exposed credential of a privileged account", account,
				[]attackChainStep{
					{"Recover the credential of " + account, exposure},
					{account + " is privileged", source},
				},
				[]string{"the recovered value is the account's current password"},
				"A credential PwnFlow recovered or could read belongs to a privileged account."))
		}
	}
	return paths
}

// adidnsRelayStep picks the strongest observed relay target for captured
// authentication: AD CS web enrollment, then LDAP without signing or channel
// binding, then SMB without signing.
func adidnsRelayStep(byType map[string][]storage.Finding) (attackChainStep, bool) {
	if list := byType["adcs_esc_esc8"]; len(list) > 0 {
		return attackChainStep{"Relay it to the HTTP web enrollment endpoint of " + list[0].AffectedObject + " and enroll a certificate as the relayed account", list[0]}, true
	}
	for _, typ := range []string{"ldap_signing_policy_not_required", "ldap_signing_not_enforced", "ldap_channel_binding_policy_not_required", "ldap_channel_binding_not_enforced"} {
		if list := byType[typ]; len(list) > 0 {
			return attackChainStep{"Relay HTTP authentication to LDAP on a domain controller that does not require signing or channel binding and act on the directory as the relayed account", list[0]}, true
		}
	}
	for _, typ := range []string{"smb_signing_not_required", "smb_signing_policy_not_required"} {
		if list := byType[typ]; len(list) > 0 {
			target := list[0].AffectedObject
			if others := len(list) - 1; others > 0 {
				target += fmt.Sprintf(" (and %d other host(s))", others)
			}
			return attackChainStep{"Relay it to SMB on " + target + ", which does not require signing", list[0]}, true
		}
	}
	return attackChainStep{}, false
}

// attackChain builds one stitched path from its steps.
func attackChain(template, title, target string, steps []attackChainStep, unverified []string, reason string) CriticalPath {
	assessment := int64(0)
	var confirmed []string
	var evidence []CriticalEvidenceReference
	var ids []int64
	for index, step := range steps {
		if assessment == 0 {
			assessment = step.Finding.AssessmentID
		}
		confirmed = append(confirmed, fmt.Sprintf("Step %d: %s (%s)", index+1, step.Action, step.Finding.Title))
		evidence = append(evidence, CriticalEvidenceReference{FindingID: step.Finding.ID, SourceExecution: step.Finding.SourceExecution, ArtifactPath: step.Finding.ArtifactPath, ArtifactRef: step.Finding.ArtifactRef})
		ids = append(ids, step.Finding.ID)
	}
	path := CriticalPath{
		AssessmentID: assessment, ID: cpStableProjectionID(assessment, attackChainFamily, template, target, ""), State: CriticalPotential,
		Family: attackChainFamily, Target: target, Capability: template, ConfirmedPrereqs: confirmed, UnverifiedPrereqs: unverified,
		Evidence: cpUniqueEvidence(evidence), SupportingFindingIDs: cpUniqueInt64(ids), Reason: reason, Title: "Attack path: " + title,
	}
	path.Finding = projectedFinding(path)
	return path
}

// privilegedAccountNames maps normalized account names that Findings show to
// be privileged to the Finding that shows it.
func privilegedAccountNames(byType map[string][]storage.Finding) map[string]storage.Finding {
	names := map[string]storage.Finding{}
	for _, typ := range []string{"ad_account_privileged_not_protected", "ad_account_privileged_kerberoastable", "ad_account_privileged_pwd_never_expires", "ad_account_privileged_stale", "ad_account_privileged_old_password"} {
		for _, row := range byType[typ] {
			var evidence map[string]any
			if json.Unmarshal([]byte(row.EvidenceJSON), &evidence) != nil {
				continue
			}
			for _, name := range cpStringSlice(evidence["affected_objects"]) {
				if key := normalizeAccountName(name); key != "" {
					if _, exists := names[key]; !exists {
						names[key] = row
					}
				}
			}
		}
	}
	return names
}

func exposedAccount(finding storage.Finding) string {
	var evidence map[string]any
	_ = json.Unmarshal([]byte(finding.EvidenceJSON), &evidence)
	return strings.TrimSpace(fallbackString(cpFirstString(evidence, "account", "account_identity"), finding.AffectedObject))
}

// normalizeAccountName reduces DOMAIN\user, user@domain and USER to "user".
func normalizeAccountName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if index := strings.LastIndexByte(name, '\\'); index >= 0 {
		name = name[index+1:]
	}
	if index := strings.IndexByte(name, '@'); index >= 0 {
		name = name[:index]
	}
	return name
}
