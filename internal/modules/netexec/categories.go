package netexec

import "github.com/pwnflow/pwnflow/internal/modules"

// The navigator shows one category at a time, so the registry is assembled by
// category across protocols. Each protocol keeps its own table file, and the
// aggregators below only decide the order the modules appear in.

// EnumerationModules returns every read-only registration, LDAP and SMB first
// because they are the protocols an Active Directory assessment starts with.
func EnumerationModules() []modules.Module {
	result := make([]modules.Module, 0)
	for _, builder := range []func() []modules.Module{
		LDAPEnumerationModules,
		SMBEnumerationModules,
		WinRMEnumerationModules,
		WMIEnumerationModules,
		MSSQLEnumerationModules,
		SSHEnumerationModules,
		FTPEnumerationModules,
		RDPEnumerationModules,
		VNCEnumerationModules,
		NFSEnumerationModules,
	} {
		result = append(result, builder()...)
	}
	return result
}

// CredentialAuditingModules are the registrations that export authentication
// material for offline cracking. They stay registered so the requirement is
// visible, and they stay disabled until a protected artifact workflow exists:
// their output is not an assessment note but a crackable artifact.
func CredentialAuditingModules() []modules.Module {
	entries := []entry{
		{
			id: "asreproast", name: "AS-REP Roasting",
			description: "Requests AS-REP material for accounts without pre-authentication through --asreproast. " + gateKerberosTicket + ".",
			args:        []string{"--asreproast"}, gated: gateKerberosTicket, sensitive: true,
			output: "LDAP_asreproast/artifacts",
		},
		{
			id: "kerberoasting", name: "Kerberoasting",
			description: "Requests service tickets for accounts with SPNs through --kerberoasting. " + gateKerberosTicket + ".",
			args:        []string{"--kerberoasting"}, gated: gateKerberosTicket, sensitive: true,
			output: "LDAP_kerberoasting/artifacts",
		},
	}
	return level(modules.CategoryCredentialAuditing, modules.ProtocolLDAP, entries)
}

// CredentialDumpingModules group every registration whose output is credential
// material. Read-only discovery modules run; extraction and dumping modules are
// gated because they need an approved artifact workflow.
func CredentialDumpingModules() []modules.Module {
	result := make([]modules.Module, 0)
	for _, builder := range []func() []modules.Module{
		LDAPCredentialDumpingModules,
		SMBCredentialDumpingModules,
		WinRMCredentialDumpingModules,
		WMICredentialDumpingModules,
		SSHCredentialDumpingModules,
	} {
		result = append(result, builder()...)
	}
	return result
}

// PrivilegeEscalationModules change state on the target or run code there. Every
// entry in this list is gated except the read-only privilege checks, so a
// category-wide run can never execute one by accident.
func PrivilegeEscalationModules() []modules.Module {
	result := make([]modules.Module, 0)
	for _, builder := range []func() []modules.Module{
		LDAPPrivilegeEscalationModules,
		SSHPrivilegeEscalationModules,
		SMBPrivilegeEscalationModules,
		WMIPrivilegeEscalationModules,
		MSSQLPrivilegeEscalationModules,
	} {
		result = append(result, builder()...)
	}
	return result
}
