package netexec

import (
	"path/filepath"

	"github.com/pwnflow/pwnflow/internal/modules"
)

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

// CredentialAuditingModules export authentication material for offline password
// auditing. They are read-only against the target - they request a ticket or an
// AS-REP response and write what came back - so they are part of an assessment
// rather than an exploit, and they are enabled.
//
// The exported material goes into the assessment's own artifact tree, next to the
// module output and its history, with the permissions the runner already applies
// to findings. PwnFlow never cracks anything: it produces the artifact the
// operator audits offline.
func CredentialAuditingModules() []modules.Module {
	entries := []entry{
		{
			id: "asreproast", name: "AS-REP Roasting",
			description: "Finds accounts that do not require Kerberos pre-authentication and requests their AS-REP material with --asreproast, which NetExec returns on stdout and appends to the artifact file. The material is crackable offline; PwnFlow neither cracks it nor sends it anywhere.",
			args:        []string{"--asreproast"},
			dynamicArgs: kerberosArtifactPath("LDAP_asreproast", "asreproast.txt"),
			sensitive:   true, output: "LDAP_asreproast/transcript.txt",
		},
		{
			id: "kerberoasting", name: "Kerberoasting",
			description: "Requests service tickets for accounts with SPNs through --kerberoasting, which NetExec returns on stdout and appends to the artifact file. The tickets are crackable offline; PwnFlow neither cracks them nor sends them anywhere.",
			args:        []string{"--kerberoasting"},
			dynamicArgs: kerberosArtifactPath("LDAP_kerberoasting", "kerberoast.txt"),
			sensitive:   true, output: "LDAP_kerberoasting/transcript.txt",
		},
	}
	return level(modules.CategoryCredentialAuditing, modules.ProtocolLDAP, entries)
}

// kerberosArtifactPath supplies the file a native Kerberos export flag writes to.
// The flag takes the path as its value and NetExec rejects the command without
// one, so the path is part of the command rather than an option the operator has
// to remember. It lands inside the assessment tree, next to the transcript.
func kerberosArtifactPath(directory, filename string) func(*modules.Runtime) []string {
	return func(runtime *modules.Runtime) []string {
		root := runtime.ResultsRoot
		if root == "" {
			return nil
		}
		return []string{filepath.Join(root, categoryPath(modules.CategoryCredentialAuditing), "NetExec", directory, filename)}
	}
}

// CredentialDumpingModules group every registration whose output is credential
// material that a plain read exposes: Group Policy Preferences, directory
// attributes, and share metadata.
func CredentialDumpingModules() []modules.Module {
	result := make([]modules.Module, 0)
	for _, builder := range []func() []modules.Module{
		LDAPCredentialDumpingModules,
		SMBCredentialDumpingModules,
	} {
		result = append(result, builder()...)
	}
	return result
}
