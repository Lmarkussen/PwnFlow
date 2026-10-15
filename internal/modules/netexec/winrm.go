package netexec

import "github.com/pwnflow/pwnflow/internal/modules"

// WinRM is an execution and dumping protocol: the installed build advertises no
// enumeration flag beyond the authentication check, so the enumeration table
// holds the credential check and nothing is invented to fill the scope. The
// modules WinRM does advertise are registered under the categories they belong
// to.

// WinRMEnumerationModules establish whether the credentials work over WinRM.
func WinRMEnumerationModules() []modules.Module {
	return level(modules.CategoryEnumeration, modules.ProtocolWinRM, []entry{
		{
			id: "winrm-auth-check", name: "WinRM Authentication Check",
			description: "Authenticates over WinRM and prints the result without running anything. It establishes whether the channel a later WinRM module needs is available to the account.",
			output:      "WINRM_auth_check.txt",
		},
	})
}

// WinRMCredentialDumpingModules need elevated rights or an approved artifact
// workflow before they may run.
func WinRMCredentialDumpingModules() []modules.Module {
	return level(modules.CategoryCredentialDumping, modules.ProtocolWinRM, []entry{
		{
			id: "winrm-aws-credentials", name: "Search for AWS Credentials",
			description: "Searches the target's file system for AWS credential files through -M aws-credentials. Reads only; nothing is written to the target.",
			module:      "aws-credentials", sensitive: true,
		},
		{
			id: "winrm-ntds-dump-raw", name: "Dump NTDS, SAM and SYSTEM (raw)",
			description: "Reads ntds.dit, SAM, and SYSTEM through the raw drive with -M ntds-dump-raw. " + gateCredentialDump + "; needs " + adminDC + ".",
			module:      "ntds-dump-raw", gated: gateCredentialDump, admin: adminDC, sensitive: true,
		},
		{
			id: "winrm-sam", name: "Dump SAM",
			description: "Dumps local SAM hashes through the --sam native flag. " + gateCredentialDump + "; needs " + adminLocal + ".",
			args:        []string{"--sam"}, gated: gateCredentialDump, admin: adminLocal, sensitive: true,
			output: "WINRM_sam.txt",
		},
		{
			id: "winrm-lsa", name: "Dump LSA Secrets",
			description: "Dumps LSA secrets through the --lsa native flag. " + gateCredentialDump + "; needs " + adminLocal + ".",
			args:        []string{"--lsa"}, gated: gateCredentialDump, admin: adminLocal, sensitive: true,
			output: "WINRM_lsa.txt",
		},
		{
			id: "winrm-dpapi", name: "Dump DPAPI Secrets",
			description: "Dumps DPAPI-protected Credential Manager secrets through the --dpapi native flag. " + gateCredentialDump + "; needs " + adminLocal + ".",
			args:        []string{"--dpapi"}, gated: gateCredentialDump, admin: adminLocal, sensitive: true,
			output: "WINRM_dpapi.txt",
		},
	})
}
