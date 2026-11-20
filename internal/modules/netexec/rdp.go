package netexec

import "github.com/pwnflow/pwnflow/internal/modules"

// RDP reports whether a login is accepted and whether NLA is required. It
// advertises no modules in the installed build. The native -x/-X flags take
// operator-supplied commands and the screenshot flags capture the screen, so
// neither is registered.

func RDPEnumerationModules() []modules.Module {
	return level(modules.CategoryEnumeration, modules.ProtocolRDP, []entry{
		{
			id: "rdp-auth-check", name: "RDP Authentication Check",
			description: "Tests whether the supplied credentials are accepted by the RDP service and reports the NLA requirement.",
			output:      "RDP_auth_check.txt",
		},
	})
}
