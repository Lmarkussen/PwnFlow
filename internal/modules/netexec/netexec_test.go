package netexec

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
)

func TestEnumerationDefinitionsAndArguments(t *testing.T) {
	all := EnumerationModules()
	if len(all) != 31 {
		t.Fatalf("got %d enumeration modules", len(all))
	}
	ldapCount := 0
	for _, raw := range LDAPEnumerationModules() {
		ldapCount++
		if raw.ID() == "organizational-units" {
			t.Fatal("obsolete organizational-units module is still registered")
		}
	}
	if ldapCount != 17 {
		t.Fatalf("got %d LDAP enumeration modules, want 17", ldapCount)
	}
	module := all[0].(Module)
	args := module.CommandArgs(&modules.Runtime{Target: config.AuthorizedTarget, Username: "user", Password: "secret"})
	want := []string{"ldap", config.AuthorizedTarget, "-u", "user", "-p", "secret", "-M", "get-info-users"}
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
	args := shares.CommandArgs(&modules.Runtime{Target: config.AuthorizedTarget, Username: "user", Password: "secret"})
	want := []string{"smb", config.AuthorizedTarget, "-u", "user", "-p", "secret", "--shares"}
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
		if err := module.Check(context.Background(), &modules.Runtime{Target: config.AuthorizedTarget, Domain: config.AuthorizedDomain}); err == nil {
			t.Fatalf("%s unexpectedly enabled", module.ID())
		}
		if err := module.Check(context.Background(), &modules.Runtime{Target: "198.51.100.10", Domain: config.AuthorizedDomain}); err == nil {
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
  "ldap --help") echo "--asreproast --kerberoasting"; exit 0 ;;
esac
exit 0
`
	if err := os.WriteFile(nxc, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	runtime := &modules.Runtime{Target: config.AuthorizedTarget, Domain: config.AuthorizedDomain}
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
  "ldap --help") echo "--asreproast"; exit 0 ;;
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
	err := kerberoasting.Check(context.Background(), &modules.Runtime{Target: config.AuthorizedTarget, Domain: config.AuthorizedDomain})
	if err == nil || !strings.Contains(err.Error(), "--kerberoasting") {
		t.Fatalf("missing capability result = %v", err)
	}
}

func TestBloodHoundIsLDAPAndScopeRestricted(t *testing.T) {
	var bloodhound Module
	for _, raw := range LDAPEnumerationModules() {
		candidate := raw.(Module)
		if candidate.ID() == "bloodhound" {
			bloodhound = candidate
		}
	}
	if bloodhound.ID() == "" || bloodhound.Protocol() != modules.ProtocolLDAP {
		t.Fatal("BloodHound was not registered under LDAP")
	}
	if bloodhound.ExecutionEnabled() {
		t.Fatal("BloodHound collection must remain disabled")
	}
	if got := bloodhound.OutputFile(); got != "Enumeration/NetExec/BloodHound/LDAP_bloodhound.zip" {
		t.Fatalf("unexpected BloodHound artifact path: %s", got)
	}

	dir := t.TempDir()
	nxc := filepath.Join(dir, "nxc")
	script := `#!/bin/sh
case "$1 $2" in
  "--help ") echo global-help; exit 0 ;;
  "ldap --help") echo "--bloodhound --collection"; exit 0 ;;
esac
exit 0
`
	if err := os.WriteFile(nxc, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	err := bloodhound.Check(context.Background(), &modules.Runtime{Target: config.AuthorizedTarget, Domain: config.AuthorizedDomain})
	if err == nil || !strings.Contains(err.Error(), "scope restricted") {
		t.Fatalf("unexpected BloodHound check result: %v", err)
	}
}

func TestProtocolCapabilityChecksAreIndependent(t *testing.T) {
	dir := t.TempDir()
	nxc := filepath.Join(dir, "nxc")
	script := `#!/bin/sh
case "$1 $2" in
  "--help ") echo global-help; exit 0 ;;
  "ldap --help") echo "--users"; exit 0 ;;
  "ldap -L") echo "get-info-users"; exit 0 ;;
  "smb --help") echo "--shares"; exit 0 ;;
esac
exit 0
`
	if err := os.WriteFile(nxc, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	runtime := &modules.Runtime{Target: config.AuthorizedTarget, Domain: config.AuthorizedDomain}
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
