package netexec

import (
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
)

func TestSMBPasswordPolicyUsesPassPol(t *testing.T) {
	var found Module
	foundModule := false
	for _, candidate := range SMBEnumerationModules() {
		if candidate.ID() == "smb-password-policy" {
			found = candidate.(Module)
			foundModule = true
			break
		}
	}
	if !foundModule {
		t.Fatal("SMB password policy module was not registered")
	}
	args := found.CommandArgs(&modules.Runtime{Target: "198.51.100.40", Domain: "example.test", Username: "operator", Password: "secret"})
	if len(args) == 0 || args[len(args)-1] != "--pass-pol" {
		t.Fatalf("SMB password policy arguments=%v, want --pass-pol", args)
	}
}
