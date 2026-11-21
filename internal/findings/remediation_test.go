package findings

import "testing"

func TestRemediationCoversSecurityFindingTypes(t *testing.T) {
	security := []string{
		"ad_account_pwd_never_expires", "ad_account_passwd_notreqd", "ad_account_reversible_encryption", "ad_account_des_only",
		"ad_account_kerberos_des_enabled", "ad_account_kerberos_rc4_only", "ad_account_kerberos_spn_without_aes", "ad_account_sid_history_present",
		"ad_account_password_attribute_populated", "ad_account_password_attribute_readable", "ad_account_krbtgt_password_age",
		"ad_account_privileged_not_protected", "ad_account_stale_enabled_users", "ad_account_stale_enabled_computers", "ad_account_laps_not_observed",
		"ad_account_laps_password_readers", "ad_account_gmsa_password_readers", "ad_account_obsolete_operating_system",
		"ad_domain_policy_machine_account_creation_quota", "ad_domain_config_anonymous_ldap_operations", "ad_domain_config_anonymous_ldap_read",
		"ad_domain_config_pre2000_compatible_access", "ad_domain_config_dns_nonsecure_updates", "ad_domain_config_dns_record_creation",
		"ad_domain_config_dns_zone_broad_write", "ad_trust_sid_filtering_relaxed", "ad_trust_tgt_delegation_enabled",
		"smb_signing_not_required", "smb_signing_policy_not_required", "smb_v1_enabled", "smb_null_session_accepted", "smb_null_session_enumeration",
		"smb_guest_session_mapped", "smb_spooler_service_running", "smb_webclient_service_running", "ldap_signing_not_enforced",
		"ldap_signing_policy_not_required", "ldap_channel_binding_not_enforced", "ldap_channel_binding_policy_not_required",
		"ntlm_policy_lm_compatibility_weak", "ntlm_policy_lm_hash_stored", "ntlm_policy_wdigest_enabled", "kerberoastable_account",
		"asrep_roastable_account", "unconstrained_delegation_configured", "netexec_gpp_password_exposure", "sccm_task_sequence_credentials_exposed",
		"sccm_pxe_distribution_point", "sccm_site_system_smb_signing_not_required", "ad_acl_genericall", "adcs_esc_esc1", "adcs_esc_esc8",
	}
	for _, typ := range security {
		remediation, ok := RemediationFor(typ)
		if !ok || remediation.Action == "" || remediation.Detail == "" {
			t.Errorf("%s has no remediation", typ)
		}
	}
	if remediation, ok := RemediationFor("adcs_esc_esc13"); !ok || remediation.Action != "Fix vulnerable certificate templates" {
		t.Fatalf("ESC fallback missing: %+v", remediation)
	}
	for _, inventory := range []string{"ad_trust_observed", "ad_trust_none_observed", "sccm_site_inventory", "networkhound_open_ports", "netexec_auth_success"} {
		if _, ok := RemediationFor(inventory); ok {
			t.Errorf("inventory type %s has a remediation", inventory)
		}
	}
}
