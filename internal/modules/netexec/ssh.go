package netexec

import "github.com/pwnflow/pwnflow/internal/modules"

// SSH has no domain: the transport spec passes only the assessment username and
// password. It keeps the credential check - whether the account can reach the
// host over SSH at all - and the sudo check, which reports what that account may
// elevate to. The native -x flag runs commands, and --put-file/--get-file move
// files; both are documented rather than registered.
//
// The installed build's only SSH module searches for AWS credential files, which
// the SMB registration already covers on hosts where SMB is reachable, so it is
// registered once instead of once per transport.

func SSHEnumerationModules() []modules.Module {
	return level(modules.CategoryEnumeration, modules.ProtocolSSH, []entry{
		{
			id: "ssh-auth-check", name: "SSH Authentication Check",
			description: "Authenticates over SSH and prints the result, including whether the host key and authentication method were accepted.",
			output:      "SSH_auth_check.txt",
		},
		{
			id: "ssh-sudo-check", name: "Check sudo Rights",
			description: "Checks through --sudo-check whether the authenticated account may run sudo on the target and with which method. It answers with the target's own response and changes nothing.",
			args:        []string{"--sudo-check"}, output: "SSH_sudo_check.txt",
		},
	})
}
