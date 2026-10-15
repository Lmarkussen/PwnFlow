package netexec

import "github.com/pwnflow/pwnflow/internal/modules"

// SSH has no domain: the transport spec passes only the assessment username and
// password. The native -x flag takes an operator-supplied command, so remote
// execution is documented rather than registered; the sudo check is registered
// because it answers a question an operator asks before choosing a path.

func SSHEnumerationModules() []modules.Module {
	return level(modules.CategoryEnumeration, modules.ProtocolSSH, []entry{
		{
			id: "ssh-auth-check", name: "SSH Authentication Check",
			description: "Authenticates over SSH and prints the result, including whether the host key and authentication method were accepted.",
			output:      "SSH_auth_check.txt",
		},
	})
}

// SSHPrivilegeEscalationModules hold the account's local privilege posture. The
// sudo check is read-only: it asks the target whether the account may elevate.
func SSHPrivilegeEscalationModules() []modules.Module {
	return level(modules.CategoryPrivilegeEscalation, modules.ProtocolSSH, []entry{
		{
			id: "ssh-sudo-check", name: "Check sudo Rights",
			description: "Checks through --sudo-check whether the authenticated account may run sudo on the target and with which method. It answers with the target's own response and changes nothing.",
			args:        []string{"--sudo-check"},
		},
	})
}

func SSHCredentialDumpingModules() []modules.Module {
	return level(modules.CategoryCredentialDumping, modules.ProtocolSSH, []entry{
		{
			id: "ssh-aws-credentials", name: "Search for AWS Credentials",
			description: "Searches the account's readable paths for AWS credential files through -M aws-credentials. Reads only.",
			module:      "aws-credentials", sensitive: true,
		},
	})
}
