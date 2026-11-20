package netexec

import "github.com/pwnflow/pwnflow/internal/modules"

// VNC authenticates with a password only: the transport spec deliberately does
// not pass the assessment username, because a domain account is not a VNC
// credential. The installed build advertises no modules for VNC, and the native
// --screenshot flag captures the remote screen, so it is not registered.

func VNCEnumerationModules() []modules.Module {
	return level(modules.CategoryEnumeration, modules.ProtocolVNC, []entry{
		{
			id: "vnc-auth-check", name: "VNC Authentication Check",
			description: "Attempts the supplied password against the VNC service and reports whether the session was accepted. Uses the password configured for this assessment.",
			output:      "VNC_auth_check.txt",
		},
	})
}
