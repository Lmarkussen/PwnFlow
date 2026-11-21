package findings

import "strings"

// Remediation is the fix for a Finding type. Action is short and shared by
// every Finding type the same change resolves, so a report can group them;
// Detail says how in one or two sentences.
type Remediation struct {
	Action string
	Detail string
}

var remediations = map[string]Remediation{
	// Accounts.
	"ad_account_pwd_never_expires":            {"Review non-expiring passwords", "Remove DONT_EXPIRE_PASSWORD from user accounts, rotate their passwords, and move service accounts to group managed service accounts."},
	"ad_account_dont_expire_password":         {"Review non-expiring passwords", "Remove DONT_EXPIRE_PASSWORD from user accounts, rotate their passwords, and move service accounts to group managed service accounts."},
	"ad_account_passwd_notreqd":               {"Clear PASSWD_NOTREQD", "Remove the PASSWD_NOTREQD flag and set a compliant password on each listed account; disable accounts that are not needed."},
	"ad_account_reversible_encryption":        {"Disable reversible password encryption", "Clear 'Store password using reversible encryption' on the accounts and in any password policy, then reset their passwords."},
	"ad_account_des_only":                     {"Remove DES from Kerberos", "Clear 'Use only Kerberos DES encryption types' and make sure the accounts have AES keys (reset their passwords)."},
	"ad_account_kerberos_des_enabled":         {"Remove DES from Kerberos", "Remove DES from msDS-SupportedEncryptionTypes on the listed accounts."},
	"ad_account_kerberos_rc4_only":            {"Enable AES for Kerberos", "Add AES128/AES256 to msDS-SupportedEncryptionTypes and reset the account passwords so AES keys exist."},
	"ad_account_kerberos_spn_without_aes":     {"Enable AES for Kerberos", "Set msDS-SupportedEncryptionTypes to AES on service accounts with SPNs, or move them to group managed service accounts with long random passwords."},
	"ad_account_sid_history_present":          {"Remove sIDHistory", "Clear sIDHistory once migrations are complete; investigate any privileged SID in it as possible persistence."},
	"ad_account_password_attribute_populated": {"Clear password attributes", "Empty userPassword, unixUserPassword, unicodePwd-like and msSFU30Password attributes and reset the affected accounts' passwords."},
	"ad_account_password_attribute_readable":  {"Clear password attributes", "Empty the readable password attribute, reset the account password, and restrict read access to the attribute."},
	"ad_account_krbtgt_password_age":          {"Rotate the krbtgt password", "Reset the krbtgt password twice, allowing replication between the resets, and repeat on a regular schedule."},
	"ad_account_privileged_not_protected":     {"Protect privileged accounts", "Add administrative accounts to Protected Users or mark them 'sensitive and cannot be delegated'; clear stale adminCount values."},
	"ad_account_stale_enabled_users":          {"Disable stale accounts", "Disable, then remove, enabled accounts that have not logged on within the retention period."},
	"ad_account_stale_enabled_computers":      {"Disable stale accounts", "Disable, then remove, computer accounts of retired hosts."},
	"ad_account_laps_not_observed":            {"Deploy Windows LAPS", "Deploy Windows LAPS to every non-DC Windows computer so each local administrator password is unique and rotated."},
	"ad_account_laps_password_readers":        {"Restrict LAPS password readers", "Limit read access to LAPS passwords to the administrators who need it; remove broad groups from the computer objects' ACLs."},
	"ad_account_gmsa_password_readers":        {"Restrict gMSA password readers", "Limit msDS-GroupMSAMembership to the hosts that run the service."},
	"ad_account_obsolete_operating_system":    {"Retire unsupported operating systems", "Upgrade or decommission hosts running unsupported Windows releases and remove their stale computer accounts."},
	"ad_user_description_credential_exposed":  {"Remove credentials from user attributes", "Delete passwords from description and info attributes and reset the affected accounts' passwords."},
	"ad_user_description_keyword_observed":    {"Remove credentials from user attributes", "Review the attribute text and remove any credential; reset the account password if one was stored."},
	// Domain configuration and policy.
	"ad_domain_policy_machine_account_creation_quota":   {"Set MachineAccountQuota to 0", "Set ms-DS-MachineAccountQuota to 0 and delegate computer joins to a dedicated group."},
	"ad_domain_policy_weak_minimum_password_length":     {"Strengthen the password policy", "Raise the minimum password length (14 or more), or use fine-grained policies for privileged accounts."},
	"ad_domain_policy_password_expiration_not_enforced": {"Strengthen the password policy", "Review the maximum password age together with length and breached-password checks."},
	"ad_domain_config_functional_level":                 {"Raise the functional level", "Raise the domain and forest functional level once no older domain controllers remain."},
	"ad_domain_config_anonymous_ldap_operations":        {"Block anonymous LDAP", "Reset character 7 of dSHeuristics so anonymous LDAP operations are refused."},
	"ad_domain_config_anonymous_ldap_read":              {"Block anonymous LDAP", "Refuse anonymous LDAP operations (dSHeuristics) and remove Anonymous Logon from Pre-Windows 2000 Compatible Access."},
	"ad_domain_config_pre2000_compatible_access":        {"Clean up Pre-Windows 2000 Compatible Access", "Remove Anonymous Logon and Everyone from the group; review any non-default member."},
	"ad_domain_config_dns_nonsecure_updates":            {"Require secure DNS updates", "Set the zones to 'Secure only' dynamic updates."},
	"ad_domain_config_dns_record_creation":              {"Harden ADIDNS", "Add a wildcard record to each AD-integrated zone, keep WPAD on the global query block list, and consider removing CreateChild from Authenticated Users."},
	"ad_domain_config_dns_zone_broad_write":             {"Harden ADIDNS", "Remove write rights for broad principals from the DNS zone object."},
	"ad_domain_config_dns_zone_delegated_write":         {"Harden ADIDNS", "Confirm each delegated DNS write right is intended and remove the others."},
	"ad_trust_sid_filtering_relaxed":                    {"Enforce SID filtering on trusts", "Enable SID filtering (quarantine) on external trusts and clear TREAT_AS_EXTERNAL on forest trusts unless required."},
	"ad_trust_tgt_delegation_enabled":                   {"Disable TGT delegation across trusts", "Disable TGT delegation on the trust (netdom trust /EnableTGTDelegation:No)."},
	// Protocols and policy.
	"smb_signing_not_required":                  {"Require SMB signing", "Enable 'Microsoft network server: Digitally sign communications (always)' on all hosts through Group Policy."},
	"smb_signing_policy_not_required":           {"Require SMB signing", "Enable 'Microsoft network server: Digitally sign communications (always)' in the affected GPO."},
	"smb_client_signing_policy_not_required":    {"Require SMB signing", "Enable 'Microsoft network client: Digitally sign communications (always)' on domain controllers."},
	"sccm_site_system_smb_signing_not_required": {"Require SMB signing", "Require SMB signing on SCCM site servers and site databases."},
	"smb_v1_enabled":                            {"Disable SMBv1", "Remove the SMB 1.0 feature from the affected hosts."},
	"smb_null_session_accepted":                 {"Restrict anonymous SMB access", "Set 'Network access: Restrict anonymous access to Named Pipes and Shares' and RestrictAnonymous/RestrictAnonymousSAM."},
	"smb_null_session_enumeration":              {"Restrict anonymous SMB access", "Remove Anonymous Logon and Everyone from Pre-Windows 2000 Compatible Access and restrict anonymous SAM and share enumeration."},
	"smb_guest_session_mapped":                  {"Disable guest fallback", "Disable the Guest account and 'insecure guest logons' so unknown users are refused."},
	"smb_spooler_service_running":               {"Disable the Print Spooler on domain controllers", "Stop and disable the Print Spooler service on domain controllers and servers that do not print."},
	"smb_webclient_service_running":             {"Disable the WebClient service", "Stop and disable the WebClient service on servers, and on clients where WebDAV is not needed."},
	"ldap_signing_not_enforced":                 {"Require LDAP signing and channel binding", "Set 'Domain controller: LDAP server signing requirements' to require signing (LDAPServerIntegrity=2)."},
	"ldap_signing_policy_not_required":          {"Require LDAP signing and channel binding", "Set LDAPServerIntegrity=2 in the GPO linked to the Domain Controllers OU."},
	"ldap_channel_binding_not_enforced":         {"Require LDAP signing and channel binding", "Set 'Domain controller: LDAP server channel binding token requirements' to Always (LdapEnforceChannelBinding=2)."},
	"ldap_channel_binding_policy_not_required":  {"Require LDAP signing and channel binding", "Set LdapEnforceChannelBinding=2 in the GPO linked to the Domain Controllers OU."},
	"ntlm_policy_lm_compatibility_weak":         {"Disable LM and NTLMv1", "Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM & NTLM' (5)."},
	"ntlm_policy_lm_hash_stored":                {"Disable LM and NTLMv1", "Enable 'Do not store LAN Manager hash value on next password change' and reset passwords."},
	"ntlm_policy_wdigest_enabled":               {"Disable WDigest caching", "Set WDigest UseLogonCredential to 0 in the GPO."},
	// Kerberos and delegation.
	"kerberoastable_account":              {"Harden service accounts", "Use group managed service accounts or 25+ character random passwords with AES for accounts with SPNs; remove unused SPNs."},
	"kerberos_ticket_material_collected":  {"Harden service accounts", "Use group managed service accounts or long random passwords with AES for the affected service accounts."},
	"asrep_roastable_account":             {"Require Kerberos pre-authentication", "Clear 'Do not require Kerberos preauthentication' on the listed accounts."},
	"asrep_material_collected":            {"Require Kerberos pre-authentication", "Clear 'Do not require Kerberos preauthentication' and reset the affected passwords."},
	"unconstrained_delegation_configured": {"Remove unconstrained delegation", "Replace unconstrained delegation on non-DC hosts with constrained or resource-based delegation."},
	"constrained_delegation_configured":   {"Review constrained delegation", "Confirm each delegated service is required; avoid protocol transition to sensitive services on domain controllers."},
	"rbcd_observed":                       {"Review resource-based delegation", "Remove msDS-AllowedToActOnBehalfOfOtherIdentity entries that are not required."},
	// Credentials and secrets.
	"netexec_gpp_password_exposure":          {"Remove GPP passwords", "Delete Group Policy Preferences items that contain cpassword and change every exposed password."},
	"gpo_preference_credential_exposed":      {"Remove GPP passwords", "Delete Group Policy Preferences items that contain cpassword and change every exposed password."},
	"sccm_task_sequence_credentials_exposed": {"Protect SCCM credentials", "Rotate the exposed accounts, protect PXE media with a password, and replace the network access account with Enhanced HTTP."},
	"sccm_pxe_distribution_point":            {"Protect SCCM credentials", "Require a password on PXE boot media and limit which task sequences are available to PXE."},
	// Access control and AD CS.
	"ad_acl_genericall":             {"Remove excessive ACL rights", "Remove GenericAll and similar rights that principals hold over objects they do not administer."},
	"bloodyad_writable_permissions": {"Remove excessive ACL rights", "Review the write rights the assessment account holds and remove those not required."},
	"adcs_esc_esc1":                 {"Fix vulnerable certificate templates", "Remove 'Supply in the request' or the client-authentication EKU, require manager approval, or restrict enrollment to the intended principals."},
	"adcs_esc_esc4":                 {"Fix vulnerable certificate templates", "Remove write rights on the template object from low-privileged principals."},
	"adcs_esc_esc8":                 {"Harden AD CS web enrollment", "Disable HTTP web enrollment, or require HTTPS with Extended Protection for Authentication on the CA's web endpoints."},
	"relay_exposure_observed":       {"Require SMB signing", "Require signing and channel binding on the relay destinations RelayKing reported."},
	"mssql_encryption_not_enforced": {"Enforce MSSQL encryption", "Force encryption on the SQL Server instance."},
	"pwntools_ftp_anonymous_access": {"Disable anonymous FTP", "Disable anonymous FTP access or restrict it to a dedicated public directory."},
	"ghostspn_orphaned_spn":         {"Remove orphaned SPNs", "Remove SPNs that point to hosts that no longer resolve, or re-register the host."},
}

// RemediationFor returns the remediation for a Finding type. Inventory and
// context Findings have none.
func RemediationFor(findingType string) (Remediation, bool) {
	typ := strings.ToLower(strings.TrimSpace(findingType))
	if remediation, ok := remediations[typ]; ok {
		return remediation, true
	}
	if strings.HasPrefix(typ, "adcs_esc_") {
		return Remediation{"Fix vulnerable certificate templates", "Remove the template or CA setting Certipy reports for this ESC condition and restrict enrollment to the intended principals."}, true
	}
	return Remediation{}, false
}
