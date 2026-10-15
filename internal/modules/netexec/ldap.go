package netexec

import "github.com/pwnflow/pwnflow/internal/modules"

func LDAPEnumerationModules() []modules.Module {
	definitions := []Definition{
		definition("get-info-users", "Get AD-User Info", modules.CategoryEnumeration, modules.ProtocolLDAP, []string{"-M", "get-info-users"}, "LDAP_get_users_info.txt"),
		definition("get-desc-users", "Get AD-User Description", modules.CategoryEnumeration, modules.ProtocolLDAP, []string{"-M", "get-desc-users"}, "LDAP_get_users_description.txt"),
		definition("domain-users", "Enumerate Domain Users", modules.CategoryEnumeration, modules.ProtocolLDAP, []string{"--users"}, "LDAP_domain_users.txt"),
		definition("active-users", "Enumerate Active Users", modules.CategoryEnumeration, modules.ProtocolLDAP, []string{"--active-users"}, "LDAP_active_users.txt"),
		definition("domain-groups", "Enumerate Domain Groups", modules.CategoryEnumeration, modules.ProtocolLDAP, []string{"--groups"}, "LDAP_domain_groups.txt"),
		definition("domain-computers", "Enumerate Domain Computers", modules.CategoryEnumeration, modules.ProtocolLDAP, []string{"--computers"}, "LDAP_domain_computers.txt"),
		definition("domain-sid", "Get Domain SID", modules.CategoryEnumeration, modules.ProtocolLDAP, []string{"--get-sid"}, "LDAP_domain_sid.txt"),
		definition("password-policy", "Enumerate Domain Password Policy", modules.CategoryEnumeration, modules.ProtocolLDAP, []string{"--pass-pol"}, "LDAP_password_policy.txt"),
		definition("fine-grained-password-policy", "Enumerate Fine-Grained Password Policy", modules.CategoryEnumeration, modules.ProtocolLDAP, []string{"--pso"}, "LDAP_fine_grained_password_policy.txt"),
		definition("admin-count", "Enumerate AdminCount Accounts", modules.CategoryEnumeration, modules.ProtocolLDAP, []string{"--admin-count"}, "LDAP_admin_count.txt"),
		definition("password-not-required", "Find Password-Not-Required Accounts", modules.CategoryEnumeration, modules.ProtocolLDAP, []string{"--password-not-required"}, "LDAP_password_not_required.txt"),
		definition("delegation", "Enumerate Delegation Relationships", modules.CategoryEnumeration, modules.ProtocolLDAP, []string{"--find-delegation"}, "LDAP_delegation.txt"),
		definition("trusted-for-delegation", "Enumerate Trusted for Delegation", modules.CategoryEnumeration, modules.ProtocolLDAP, []string{"--trusted-for-delegation"}, "LDAP_trusted_for_delegation.txt"),
		definition("domain-controllers", "Enumerate Domain Controllers", modules.CategoryEnumeration, modules.ProtocolLDAP, []string{"--dc-list"}, "LDAP_domain_controllers.txt"),
		definition("maq", "Check Machine Account Quota", modules.CategoryEnumeration, modules.ProtocolLDAP, []string{"-M", "maq"}, "LDAP_machine_account_quota.txt"),
		definition("ldap-checker", "Check LDAP Signing", modules.CategoryEnumeration, modules.ProtocolLDAP, []string{"-M", "ldap-checker"}, "LDAP_signing.txt"),
		{IDValue: "bloodhound", NameValue: "BloodHound Collection", ToolValue: "NetExec (nxc)", ToolFamilyValue: modules.ToolFamilyNetExec, CategoryValue: modules.CategoryEnumeration, ProtocolValue: modules.ProtocolLDAP, DescriptionValue: "Disabled BloodHound CE graph collection; collection methods are not confined to the authorized DC-only scope.", Arguments: []string{"--bloodhound", "--collection", "All"}, OutputValue: "BloodHound/LDAP_bloodhound.zip", PrerequisiteValues: []string{"nxc LDAP --bloodhound capability", "authorized single-host collection workflow"}, SensitivityValue: modules.SensitivitySensitive, ReadOnlyValue: true, SecondaryConnectionValues: []string{"may contact domain hosts and services beyond the supplied DC"}},
	}
	return buildModules(definitions)
}

func CredentialAuditingModules() []modules.Module {
	definitions := []Definition{
		{IDValue: "asreproast", NameValue: "AS-REP Roasting", ToolValue: "NetExec (nxc)", ToolFamilyValue: modules.ToolFamilyNetExec, CategoryValue: modules.CategoryCredentialAuditing, ProtocolValue: modules.ProtocolLDAP, DescriptionValue: "Disabled sensitive Kerberos artifact workflow; exported authentication material requires a dedicated protected artifact workflow.", Arguments: []string{"--asreproast"}, OutputValue: "LDAP_asreproast/artifacts", PrerequisiteValues: []string{"nxc LDAP capability", "approved sensitive artifact workflow"}, SensitivityValue: modules.SensitivitySensitive, ReadOnlyValue: true},
		{IDValue: "kerberoasting", NameValue: "Kerberoasting", ToolValue: "NetExec (nxc)", ToolFamilyValue: modules.ToolFamilyNetExec, CategoryValue: modules.CategoryCredentialAuditing, ProtocolValue: modules.ProtocolLDAP, DescriptionValue: "Disabled sensitive Kerberos artifact workflow; exported service-ticket material requires a dedicated protected artifact workflow.", Arguments: []string{"--kerberoasting"}, OutputValue: "LDAP_kerberoasting/artifacts", PrerequisiteValues: []string{"nxc LDAP capability", "approved sensitive artifact workflow"}, SensitivityValue: modules.SensitivitySensitive, ReadOnlyValue: true},
	}
	return buildModules(definitions)
}

func buildModules(definitions []Definition) []modules.Module {
	result := make([]modules.Module, 0, len(definitions))
	for _, definition := range definitions {
		result = append(result, Module{definition: definition})
	}
	return result
}
