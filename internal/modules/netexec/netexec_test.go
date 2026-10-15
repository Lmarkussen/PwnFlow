package netexec

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// Fixtures for arbitrary operator-supplied assessment configuration.
const (
	testTarget = "198.51.100.10"
	testDomain = "example.test"
)

func TestEnumerationDefinitionsAndArguments(t *testing.T) {
	all := EnumerationModules()
	if len(all) != 30 {
		t.Fatalf("got %d enumeration modules", len(all))
	}
	ldapCount := 0
	for _, raw := range LDAPEnumerationModules() {
		ldapCount++
		if raw.ID() == "organizational-units" {
			t.Fatal("obsolete organizational-units module is still registered")
		}
	}
	if ldapCount != 16 {
		t.Fatalf("got %d LDAP enumeration modules, want 16", ldapCount)
	}
	module := all[0].(Module)
	args := module.CommandArgs(&modules.Runtime{Target: testTarget, Username: "user", Password: "secret"})
	want := []string{"ldap", testTarget, "-u", "user", "-p", "secret", "-M", "get-info-users", "--port", "636"}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("arg %d: got %q want %q", i, args[i], want[i])
		}
	}
	if got := module.OutputFile(); got != "Enumeration/NetExec/LDAP_get_users_info.txt" {
		t.Fatal(got)
	}
}

func TestSMBDefinitionsUseSMBProtocolAndArguments(t *testing.T) {
	var shares Module
	for _, raw := range SMBEnumerationModules() {
		module := raw.(Module)
		if module.Protocol() != modules.ProtocolSMB {
			t.Fatalf("%s protocol = %s", module.ID(), module.Protocol())
		}
		if module.ID() == "smb-shares" {
			shares = module
		}
	}
	if shares.ID() == "" {
		t.Fatal("SMB shares module was not registered")
	}
	args := shares.CommandArgs(&modules.Runtime{Target: testTarget, Username: "user", Password: "secret"})
	want := []string{"smb", testTarget, "-u", "user", "-p", "secret", "--shares"}
	if len(args) != len(want) {
		t.Fatalf("got args %#v, want %#v", args, want)
	}
	for index := range want {
		if args[index] != want[index] {
			t.Fatalf("arg %d: got %q want %q", index, args[index], want[index])
		}
	}
	if got := shares.OutputFile(); got != "Enumeration/NetExec/SMB_shares.txt" {
		t.Fatalf("output path = %q", got)
	}
}

func TestCredentialAuditingModulesAreDisabledAndScoped(t *testing.T) {
	for _, raw := range CredentialAuditingModules() {
		module := raw.(Module)
		if module.Category() != modules.CategoryCredentialAuditing || module.Sensitivity() != modules.SensitivitySensitive {
			t.Fatalf("metadata missing for %s", module.ID())
		}
		wantPath := "CredentialAuditing/NetExec/LDAP_" + module.ID() + "/artifacts"
		if got := module.OutputFile(); got != wantPath {
			t.Fatalf("%s output path = %q, want %q", module.ID(), got, wantPath)
		}
		if err := module.Check(context.Background(), &modules.Runtime{Target: testTarget, Domain: testDomain}); err == nil {
			t.Fatalf("%s unexpectedly enabled", module.ID())
		}
		if err := module.Check(context.Background(), &modules.Runtime{Target: "198.51.100.10", Domain: testDomain}); err == nil {
			t.Fatal("scope guard bypassed")
		}
	}
}

func TestKerberosCapabilitiesAreDetectedBeforeSensitiveWorkflowGate(t *testing.T) {
	dir := t.TempDir()
	nxc := filepath.Join(dir, "nxc")
	script := `#!/bin/sh
case "$1 $2" in
  "--help ") echo global-help; exit 0 ;;
  "ldap --help") echo "--asreproast --kerberoasting --port PORT"; exit 0 ;;
esac
exit 0
`
	if err := os.WriteFile(nxc, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	runtime := &modules.Runtime{Target: testTarget, Domain: testDomain}
	for _, raw := range CredentialAuditingModules() {
		module := raw.(Module)
		err := module.Check(context.Background(), runtime)
		if err == nil || !strings.Contains(err.Error(), "sensitive-artifact workflow") {
			t.Fatalf("%s capability/workflow result = %v", module.ID(), err)
		}
	}
}

func TestKerberosCapabilityMissingIsNotHiddenByWorkflowGate(t *testing.T) {
	dir := t.TempDir()
	nxc := filepath.Join(dir, "nxc")
	script := `#!/bin/sh
case "$1 $2" in
  "--help ") echo global-help; exit 0 ;;
  "ldap --help") echo "--asreproast --port PORT"; exit 0 ;;
esac
exit 0
`
	if err := os.WriteFile(nxc, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	var kerberoasting Module
	for _, raw := range CredentialAuditingModules() {
		candidate := raw.(Module)
		if candidate.ID() == "kerberoasting" {
			kerberoasting = candidate
		}
	}
	err := kerberoasting.Check(context.Background(), &modules.Runtime{Target: testTarget, Domain: testDomain})
	if err == nil || !strings.Contains(err.Error(), "--kerberoasting") {
		t.Fatalf("missing capability result = %v", err)
	}
}

// The retired NetExec BloodHound collection module is gone from the registry: it
// is not registered, not selectable, and cannot be executed through NetExec. The
// remaining LDAP and SMB enumeration modules stay registered.
func TestBloodHoundCollectionIsNoLongerRegistered(t *testing.T) {
	for _, raw := range EnumerationModules() {
		module := raw.(Module)
		if module.ID() == "bloodhound" {
			t.Fatalf("the retired BloodHound collection module is still registered: %#v", module.ID())
		}
		for _, argument := range module.CommandArgs(&modules.Runtime{Target: testTarget, Domain: testDomain, Username: "user", Password: "secret"}) {
			if argument == "--bloodhound" || argument == "--collection" {
				t.Fatalf("%s still builds a BloodHound collection command", module.ID())
			}
		}
		if strings.Contains(module.OutputFile(), "BloodHound") {
			t.Fatalf("%s still writes into the retired BloodHound output path: %s", module.ID(), module.OutputFile())
		}
	}
	var ldapModules, smbModules int
	for _, raw := range EnumerationModules() {
		switch raw.Protocol() {
		case modules.ProtocolLDAP:
			ldapModules++
		case modules.ProtocolSMB:
			smbModules++
		}
	}
	if ldapModules != 16 || smbModules != 14 {
		t.Fatalf("got %d LDAP and %d SMB modules; the remaining enumeration modules must stay registered", ldapModules, smbModules)
	}
}

// LDAP modules are run over LDAPS: NetExec selects it from the port, so the
// builder has to pass 636 and never an invented flag.
func TestLDAPModulesPreferLDAPSAndSMBIsUnchanged(t *testing.T) {
	runtime := &modules.Runtime{Target: testTarget, Domain: testDomain, Username: "audituser", Password: "Sup3rSecret"}
	for _, raw := range LDAPEnumerationModules() {
		module := raw.(Module)
		args := module.CommandArgs(runtime)
		if len(args) < 2 || args[len(args)-2] != "--port" || args[len(args)-1] != "636" {
			t.Fatalf("%s does not select LDAPS with --port 636: %#v", module.ID(), args)
		}
		for _, argument := range args {
			if argument == "--ldaps" {
				t.Fatalf("%s invents an unsupported --ldaps option", module.ID())
			}
		}
		if !slices.Contains(args, runtime.Password) {
			t.Fatalf("%s no longer passes the operator credentials", module.ID())
		}
	}
	for _, raw := range SMBEnumerationModules() {
		module := raw.(Module)
		for _, argument := range module.CommandArgs(runtime) {
			if argument == "--port" || argument == "--ldaps" || argument == "636" {
				t.Fatalf("%s SMB command changed transport: %#v", module.ID(), module.CommandArgs(runtime))
			}
		}
	}
}

func TestProtocolCapabilityChecksAreIndependent(t *testing.T) {
	dir := t.TempDir()
	nxc := filepath.Join(dir, "nxc")
	script := `#!/bin/sh
case "$1 $2" in
  "--help ") echo global-help; exit 0 ;;
  "ldap --help") echo "--users --port PORT"; exit 0 ;;
  "ldap -L") echo "get-info-users"; exit 0 ;;
  "smb --help") echo "--shares"; exit 0 ;;
esac
exit 0
`
	if err := os.WriteFile(nxc, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	runtime := &modules.Runtime{Target: testTarget, Domain: testDomain}
	var users, active, shares Module
	for _, raw := range EnumerationModules() {
		module := raw.(Module)
		switch module.ID() {
		case "domain-users":
			users = module
		case "active-users":
			active = module
		case "smb-shares":
			shares = module
		}
	}
	if err := users.Check(context.Background(), runtime); err != nil {
		t.Fatalf("supported LDAP option unavailable: %v", err)
	}
	if err := shares.Check(context.Background(), runtime); err != nil {
		t.Fatalf("supported SMB option unavailable: %v", err)
	}
	if err := active.Check(context.Background(), runtime); err == nil {
		t.Fatal("unsupported LDAP option was reported available")
	}
}
