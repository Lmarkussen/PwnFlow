package tui

import "strings"

// techniqueLink is one public reference for how a Finding is abused: a
// technique write-up, the tool or proof of concept that performs it, or the
// MITRE ATT&CK entry. Every URL was checked to resolve when it was added.
type techniqueLink struct {
	Label string
	URL   string
}

var (
	thrNTLMRelay       = techniqueLink{"The Hacker Recipes — NTLM relay", "https://www.thehacker.recipes/ad/movement/ntlm/relay"}
	thrNTLMCapture     = techniqueLink{"The Hacker Recipes — NTLM capture", "https://www.thehacker.recipes/ad/movement/ntlm/capture"}
	thrCoerced         = techniqueLink{"The Hacker Recipes — MITM and coerced authentications", "https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications"}
	thrWebClient       = techniqueLink{"The Hacker Recipes — WebClient abuse", "https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/webclient"}
	thrADIDNS          = techniqueLink{"The Hacker Recipes — ADIDNS spoofing", "https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/adidns-spoofing"}
	thrMSRPC           = techniqueLink{"The Hacker Recipes — MS-RPC recon (null sessions)", "https://www.thehacker.recipes/ad/recon/ms-rpc"}
	thrLDAPRecon       = techniqueLink{"The Hacker Recipes — LDAP recon", "https://www.thehacker.recipes/ad/recon/ldap"}
	thrSpraying        = techniqueLink{"The Hacker Recipes — Password spraying", "https://www.thehacker.recipes/ad/movement/credentials/bruteforcing/spraying"}
	thrLSASS           = techniqueLink{"The Hacker Recipes — LSASS secrets", "https://www.thehacker.recipes/ad/movement/credentials/dumping/lsass"}
	thrReadLAPS        = techniqueLink{"The Hacker Recipes — ReadLAPSPassword", "https://www.thehacker.recipes/ad/movement/dacl/readlapspassword"}
	thrReadGMSA        = techniqueLink{"The Hacker Recipes — ReadGMSAPassword", "https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword"}
	thrSIDHistory      = techniqueLink{"The Hacker Recipes — SID history", "https://www.thehacker.recipes/ad/persistence/sid-history"}
	thrTrusts          = techniqueLink{"The Hacker Recipes — Trusts", "https://www.thehacker.recipes/ad/movement/trusts"}
	thrMAQ             = techniqueLink{"The Hacker Recipes — MachineAccountQuota", "https://www.thehacker.recipes/ad/movement/builtins/machineaccountquota"}
	thrDelegations     = techniqueLink{"The Hacker Recipes — Kerberos delegations", "https://www.thehacker.recipes/ad/movement/kerberos/delegations"}
	thrKerberoast      = techniqueLink{"The Hacker Recipes — Kerberoasting", "https://www.thehacker.recipes/ad/movement/kerberos/roasting/kerberoast"}
	thrDCSync          = techniqueLink{"The Hacker Recipes — DCSync", "https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync"}
	mmRoot             = techniqueLink{"Misconfiguration Manager — SCCM attack techniques", "https://github.com/subat0mik/Misconfiguration-Manager"}
	mmRecon1           = techniqueLink{"Misconfiguration Manager — RECON-1: Enumerate SCCM site information via LDAP", "https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/RECON/RECON-1/recon-1_description.md"}
	mmCred1            = techniqueLink{"Misconfiguration Manager — CRED-1: Retrieve secrets from PXE boot media", "https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-1/cred-1_description.md"}
	mmCred2            = techniqueLink{"Misconfiguration Manager — CRED-2: Request computer policy and deobfuscate secrets", "https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-2/cred-2_description.md"}
	mmTakeover1        = techniqueLink{"Misconfiguration Manager — TAKEOVER-1: Relay to the site database (MSSQL)", "https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-1/takeover-1_description.md"}
	mmTakeover2        = techniqueLink{"Misconfiguration Manager — TAKEOVER-2: Relay to the site database (SMB)", "https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-2/takeover-2_description.md"}
	toolImpacket       = techniqueLink{"impacket (ntlmrelayx.py, addcomputer.py)", "https://github.com/fortra/impacket"}
	toolKrbrelayx      = techniqueLink{"krbrelayx (printerbug.py, dnstool.py)", "https://github.com/dirkjanm/krbrelayx"}
	toolCoercer        = techniqueLink{"Coercer", "https://github.com/p0dalirius/Coercer"}
	toolPetitPotam     = techniqueLink{"PetitPotam", "https://github.com/topotam/PetitPotam"}
	toolResponder      = techniqueLink{"Responder", "https://github.com/lgandx/Responder"}
	toolMitm6          = techniqueLink{"mitm6", "https://github.com/dirkjanm/mitm6"}
	toolNTLMv1Multi    = techniqueLink{"ntlmv1-multi", "https://github.com/evilmog/ntlmv1-multi"}
	toolAdidnsdump     = techniqueLink{"adidnsdump", "https://github.com/dirkjanm/adidnsdump"}
	toolEnum4linuxNG   = techniqueLink{"enum4linux-ng", "https://github.com/cddmp/enum4linux-ng"}
	toolLdapdomaindump = techniqueLink{"ldapdomaindump", "https://github.com/dirkjanm/ldapdomaindump"}
	toolKerbrute       = techniqueLink{"kerbrute", "https://github.com/ropnop/kerbrute"}
	toolPyLAPS         = techniqueLink{"pyLAPS", "https://github.com/p0dalirius/pyLAPS"}
	toolGMSADumper     = techniqueLink{"gMSADumper", "https://github.com/micahvandeusen/gMSADumper"}
	toolMimikatz       = techniqueLink{"mimikatz", "https://github.com/gentilkiwi/mimikatz"}
	toolRubeus         = techniqueLink{"Rubeus", "https://github.com/GhostPack/Rubeus"}
	toolTargetedRoast  = techniqueLink{"targetedKerberoast", "https://github.com/ShutdownRepo/targetedKerberoast"}
	toolSCCMHunter     = techniqueLink{"sccmhunter", "https://github.com/garrettfoster13/sccmhunter"}
	toolPXEThief       = techniqueLink{"PXEThief", "https://github.com/MWR-CyberSec/PXEThief"}
	thrLLMNR           = techniqueLink{"The Hacker Recipes — LLMNR, NBT-NS, mDNS spoofing", "https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/llmnr-nbtns-mdns-spoofing"}
	thrDHCPv6          = techniqueLink{"The Hacker Recipes — DHCPv6 spoofing", "https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/dhcpv6-spoofing"}
	thrWPAD            = techniqueLink{"The Hacker Recipes — WPAD spoofing", "https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/wpad-spoofing"}
	thrWSUS            = techniqueLink{"The Hacker Recipes — WSUS spoofing", "https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/wsus-spoofing"}
	toolWsuks          = techniqueLink{"wsuks", "https://github.com/NeffIsBack/wsuks"}
	toolPyWSUS         = techniqueLink{"pywsus", "https://github.com/GoSecure/pywsus"}
	mitreAiTM          = techniqueLink{"MITRE ATT&CK T1557 — Adversary-in-the-Middle", "https://attack.mitre.org/techniques/T1557/"}
	thrGPO             = techniqueLink{"The Hacker Recipes — Group Policies", "https://www.thehacker.recipes/ad/movement/group-policies"}
	toolPyGPOAbuse     = techniqueLink{"pyGPOAbuse", "https://github.com/Hackndo/pyGPOAbuse"}
	toolGPOBackdoor    = techniqueLink{"GroupPolicyBackdoor", "https://github.com/synacktiv/GroupPolicyBackdoor"}
	toolSharpGPOAbuse  = techniqueLink{"SharpGPOAbuse", "https://github.com/FSecureLABS/SharpGPOAbuse"}
	mitreGPOModify     = techniqueLink{"MITRE ATT&CK T1484.001 — Group Policy Modification", "https://attack.mitre.org/techniques/T1484/001/"}
	mitreRelay         = techniqueLink{"MITRE ATT&CK T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay", "https://attack.mitre.org/techniques/T1557/001/"}
	mitreForcedAuth    = techniqueLink{"MITRE ATT&CK T1187 — Forced Authentication", "https://attack.mitre.org/techniques/T1187/"}
	mitreSIDHistory    = techniqueLink{"MITRE ATT&CK T1134.005 — SID-History Injection", "https://attack.mitre.org/techniques/T1134/005/"}
	mitreKerberoast    = techniqueLink{"MITRE ATT&CK T1558.003 — Kerberoasting", "https://attack.mitre.org/techniques/T1558/003/"}
	mitreSpraying      = techniqueLink{"MITRE ATT&CK T1110.003 — Password Spraying", "https://attack.mitre.org/techniques/T1110/003/"}
	mitreAccountDisc   = techniqueLink{"MITRE ATT&CK T1087.002 — Domain Account Discovery", "https://attack.mitre.org/techniques/T1087/002/"}
	mitreDCSync        = techniqueLink{"MITRE ATT&CK T1003.006 — DCSync", "https://attack.mitre.org/techniques/T1003/006/"}
	mitreLSASS         = techniqueLink{"MITRE ATT&CK T1003.001 — LSASS Memory", "https://attack.mitre.org/techniques/T1003/001/"}
)

// additionalTechniqueLinks covers Finding types the original technique
// references did not. findingTechniqueReference consults it last.
var additionalTechniqueLinks = map[string][]techniqueLink{
	// Anonymous access and enumeration.
	"ad_domain_policy_pso_weak":                  {thrSpraying, toolKerbrute, mitreSpraying},
	"ad_gpo_control_by_non_admin":                {thrGPO, toolPyGPOAbuse, toolGPOBackdoor, toolSharpGPOAbuse, mitreGPOModify},
	"network_poisoning_name_resolution":          {thrLLMNR, thrWPAD, toolResponder, thrNTLMRelay, toolImpacket, mitreRelay},
	"network_poisoning_ipv6_dhcpv6":              {thrDHCPv6, thrWPAD, toolMitm6, thrNTLMRelay, toolImpacket, mitreAiTM},
	"network_poisoning_wsus_http":                {thrWSUS, toolWsuks, toolPyWSUS, mitreAiTM},
	"smb_signed_in_accounts":                     {thrLSASS, toolMimikatz, mitreLSASS},
	"netexec_admin_reach":                        {thrLSASS, toolMimikatz, mitreLSASS},
	"smb_null_session_accepted":                  {thrMSRPC, toolEnum4linuxNG, mitreAccountDisc},
	"smb_null_session_enumeration":               {thrMSRPC, toolEnum4linuxNG, thrSpraying, toolKerbrute, mitreSpraying},
	"smb_guest_session_mapped":                   {thrMSRPC, toolEnum4linuxNG},
	"ad_domain_config_anonymous_ldap_operations": {thrLDAPRecon, toolLdapdomaindump, mitreAccountDisc},
	"ad_domain_config_anonymous_ldap_read":       {thrLDAPRecon, toolLdapdomaindump, mitreAccountDisc},
	"ad_domain_config_pre2000_compatible_access": {thrMSRPC, thrLDAPRecon, toolEnum4linuxNG},
	// ADIDNS.
	"ad_domain_config_dns_record_creation":      {thrADIDNS, toolKrbrelayx, toolAdidnsdump, mitreRelay},
	"ad_domain_config_dns_zone_broad_write":     {thrADIDNS, toolKrbrelayx, toolAdidnsdump},
	"ad_domain_config_dns_zone_delegated_write": {thrADIDNS, toolKrbrelayx},
	"ad_domain_config_dns_nonsecure_updates":    {thrADIDNS, toolAdidnsdump},
	// Coercion and relay.
	"smb_spooler_service_running":               {thrCoerced, toolKrbrelayx, toolCoercer, toolPetitPotam, mitreForcedAuth},
	"smb_webclient_service_running":             {thrWebClient, toolCoercer, toolImpacket, mitreForcedAuth},
	"ldap_signing_not_enforced":                 {thrNTLMRelay, toolImpacket, toolMitm6, mitreRelay},
	"ldap_channel_binding_not_enforced":         {thrNTLMRelay, toolImpacket, mitreRelay},
	"ldap_signing_policy_not_required":          {thrNTLMRelay, toolImpacket, toolMitm6, mitreRelay},
	"ldap_channel_binding_policy_not_required":  {thrNTLMRelay, toolImpacket, mitreRelay},
	"smb_signing_policy_not_required":           {thrNTLMRelay, toolImpacket, mitreRelay},
	"smb_client_signing_policy_not_required":    {thrNTLMRelay, toolImpacket, mitreRelay},
	"sccm_site_system_smb_signing_not_required": {mmTakeover1, mmTakeover2, toolImpacket, toolSCCMHunter},
	"smb_v1_enabled":                            {thrNTLMCapture, toolResponder},
	"ntlm_policy_lm_compatibility_weak":         {thrNTLMCapture, toolResponder, toolNTLMv1Multi, mitreRelay},
	"ntlm_policy_lm_hash_stored":                {thrNTLMCapture, toolResponder},
	"ntlm_policy_wdigest_enabled":               {thrLSASS, toolMimikatz, mitreLSASS},
	// Credentials and secrets.
	"ad_account_laps_password_readers":        {thrReadLAPS, toolPyLAPS},
	"ad_account_gmsa_password_readers":        {thrReadGMSA, toolGMSADumper},
	"ad_account_password_attribute_readable":  {thrLDAPRecon, toolLdapdomaindump},
	"ad_account_password_attribute_populated": {thrLDAPRecon, toolLdapdomaindump},
	"ad_user_description_credential_exposed":  {thrLDAPRecon, toolLdapdomaindump},
	"ad_user_description_keyword_observed":    {thrLDAPRecon, toolLdapdomaindump},
	"ad_account_reversible_encryption":        {thrDCSync, mitreDCSync},
	"sccm_site_inventory":                     {mmRoot, mmRecon1, toolSCCMHunter},
	"sccm_pxe_distribution_point":             {mmCred1, mmCred2, toolPXEThief},
	// Accounts and Kerberos.
	"ad_account_sid_history_present":          {thrSIDHistory, toolMimikatz, mitreSIDHistory},
	"ad_account_kerberos_rc4_only":            {thrKerberoast, toolTargetedRoast, toolRubeus, mitreKerberoast},
	"ad_account_kerberos_spn_without_aes":     {thrKerberoast, toolTargetedRoast, toolRubeus, mitreKerberoast},
	"ad_account_kerberos_des_enabled":         {thrKerberoast, toolRubeus},
	"ad_account_des_only":                     {thrKerberoast, toolRubeus},
	"ad_account_pwd_never_expires":            {thrSpraying, toolKerbrute, mitreSpraying},
	"ad_account_passwd_notreqd":               {thrSpraying, toolKerbrute, mitreSpraying},
	"ad_account_stale_enabled_users":          {thrSpraying, toolKerbrute, mitreSpraying},
	"ad_account_privileged_not_protected":     {thrDelegations, toolRubeus},
	"constrained_delegation_to_dc":            {thrDelegations, toolImpacket, toolRubeus},
	"ad_account_privileged_kerberoastable":    {thrKerberoast, toolTargetedRoast, toolRubeus, mitreKerberoast},
	"ad_account_privileged_pwd_never_expires": {thrSpraying, toolKerbrute, mitreSpraying},
	"ad_account_privileged_stale":             {thrSpraying, toolKerbrute, mitreSpraying},
	"ad_account_privileged_old_password":      {thrSpraying, toolKerbrute, mitreSpraying},
	// Domain configuration and trusts.
	"ad_domain_policy_machine_account_creation_quota": {thrMAQ, toolImpacket, toolKrbrelayx},
	"ad_domain_policy_no_account_lockout":             {thrSpraying, toolKerbrute, mitreSpraying},
	"ad_domain_policy_lenient_account_lockout":        {thrSpraying, toolKerbrute, mitreSpraying},
	"ad_domain_policy_complexity_disabled":            {thrSpraying, toolKerbrute, mitreSpraying},
	"ad_domain_policy_weak_minimum_password_length":   {thrSpraying, toolKerbrute, mitreSpraying},
	"ad_trust_sid_filtering_relaxed":                  {thrTrusts, mitreSIDHistory},
	"ad_trust_tgt_delegation_enabled":                 {thrTrusts, thrDelegations},
	"ad_trust_observed":                               {thrTrusts},
}

// additionalTechniqueReference renders the extra links for a Finding type in
// the same "label\nurl" form the original references use.
func additionalTechniqueReference(findingType string) string {
	links := additionalTechniqueLinks[strings.ToLower(strings.TrimSpace(findingType))]
	parts := make([]string, 0, len(links))
	for _, link := range links {
		parts = append(parts, link.Label+"\n"+link.URL)
	}
	return strings.Join(parts, "\n")
}
