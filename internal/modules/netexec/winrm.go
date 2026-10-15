package netexec

import "github.com/pwnflow/pwnflow/internal/modules"

// WinRM is an execution and dumping protocol: the installed build advertises no
// enumeration flag beyond the credential check, and every module it does
// advertise either dumps credentials or runs code on the target. PwnFlow keeps
// the credential check - an operator needs to know whether that channel is open
// to the account - and nothing else, rather than listing modules whose only
// usable form is remote execution.
//
// The native --sam/--lsa/--dpapi dumps and -x/-X execution flags this protocol
// offers are documented in docs/netexec-inventory.md as deliberately not
// registered.

func WinRMEnumerationModules() []modules.Module {
	return level(modules.CategoryEnumeration, modules.ProtocolWinRM, []entry{
		{
			id: "winrm-auth-check", name: "WinRM Authentication Check",
			description: "Authenticates over WinRM and prints the result without running anything. It establishes whether the channel a later WinRM module needs is available to the account.",
			output:      "WINRM_auth_check.txt",
		},
	})
}
