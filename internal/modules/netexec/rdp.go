package netexec

import "github.com/pwnflow/pwnflow/internal/modules"

// RDP reports whether a login is accepted and can capture the login screen when
// NLA is disabled. It advertises no modules in the installed build, and the
// native -x/-X flags take operator-supplied commands, so nothing is registered
// for execution here.

func RDPEnumerationModules() []modules.Module {
	return level(modules.CategoryEnumeration, modules.ProtocolRDP, []entry{
		{
			id: "rdp-auth-check", name: "RDP Authentication Check",
			description: "Tests whether the supplied credentials are accepted by the RDP service and reports the NLA requirement.",
			output:      "RDP_auth_check.txt",
		},
		{
			id: "rdp-screenshot", name: "Capture Login Screen",
			description: "Captures a screenshot of the RDP login prompt when NLA is disabled, through --nla-screenshot. The image is written to NetExec's own screenshot directory; nothing is changed on the target.",
			args:        []string{"--nla-screenshot"}, output: "RDP_screenshot.txt",
		},
	})
}
