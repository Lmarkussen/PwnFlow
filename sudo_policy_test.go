package pwnflow

import (
	"os"
	"strings"
	"testing"
)

// Sudo is the operator's privilege, not PwnFlow's.
//
// PwnFlow never receives a sudo password: it releases the terminal, sudo reads the
// password itself, and what is left behind is sudo's own cached authorization. The
// patterns below are the ways that rule could be broken - a password piped into
// sudo, an askpass helper, a passwordless rule, a capability handed to an
// interpreter - so the repository is checked for them rather than trusted.
//
// The patterns are assembled here so this file does not match itself.
func TestRepositoryNeverHandlesASudoPassword(t *testing.T) {
	passwordTransport := []string{
		"-" + "-stdin",                         // sudo --stdin
		"\"" + "-S" + "\"",                     // sudo -S
		" " + "-S ",                            // sudo -S in shell example text
		"SUDO_" + "ASKPASS",                    // askpass helper
		"\"" + "sudo" + "\", \"" + "-i" + "\"", // an interactive login shell, not a structured command
		"Defaults " + "NOPASSWD",               // a passwordless rule in a sudoers file
		"setcap cap_net_raw",                   // a capability on a system interpreter
		"chmod u+s",                            // a setuid binary
		"chmod 4755",
	}
	for _, path := range trackedFiles(t) {
		if !strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".sh") {
			continue
		}
		if strings.HasSuffix(path, "sudo_policy_test.go") {
			continue
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text := string(contents)
		for _, pattern := range passwordTransport {
			if strings.Contains(text, pattern) {
				t.Errorf("%s contains %q: PwnFlow must let sudo collect its own password", path, pattern)
			}
		}
	}
}
