package netexec

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/runner"
)

// The live lab validation is opt-in and offline by default. It runs PwnFlow's own
// registrations - the same command builder, capability check, and runner the TUI
// uses - against an authorized target named in the environment, and it prints one
// summary line per module. Module output is never echoed: recovered material
// stays in the artifact files.
//
//	PWNFLOW_LIVE_TARGET=198.51.100.10 \
//	PWNFLOW_LIVE_DOMAIN=example.test \
//	PWNFLOW_LIVE_USER=audituser \
//	PWNFLOW_LIVE_PASSWORD=... \
//	go test ./internal/modules/netexec -run TestLiveLabReadOnlyEnumeration -v
//
// Only read-only enumeration and credential checks are exercised here. Credential
// access, escalation, coercion, spraying, and execution modules are deliberately
// absent: they need an operator approval that this test cannot grant itself.
func TestLiveLabReadOnlyEnumeration(t *testing.T) {
	target := os.Getenv("PWNFLOW_LIVE_TARGET")
	if target == "" {
		t.Skip("set PWNFLOW_LIVE_TARGET (and PWNFLOW_LIVE_USER/PASSWORD/DOMAIN) to run the live lab validation")
	}
	domain := os.Getenv("PWNFLOW_LIVE_DOMAIN")
	user := os.Getenv("PWNFLOW_LIVE_USER")
	password := os.Getenv("PWNFLOW_LIVE_PASSWORD")
	if domain == "" || user == "" || password == "" {
		t.Fatal("PWNFLOW_LIVE_DOMAIN, PWNFLOW_LIVE_USER, and PWNFLOW_LIVE_PASSWORD are required")
	}
	// Artifacts go to a private temporary root. The live check must never write
	// into an operator's assessment tree, whose history it would then disturb.
	root := t.TempDir()
	runtime := &modules.Runtime{
		Target: target, Domain: domain, Username: user, Password: password, ResultsRoot: root,
		ModuleOptions: map[string]map[string]string{
			"find-computer":         {"TEXT": "DC"},
			"daclread":              {"ACTION": "read", "TARGET": "Domain Admins"},
			"groupmembership":       {"USER": user},
			"smb-reg-query":         {"PATH": `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "KEY": "ProductName"},
			"smb-test-connection":   {"HOST": "127.0.0.1"},
			"smb-wcc":               {"OUTPUT": root + "/wcc.json", "OUTPUT_FORMAT": "text"},
			"mssql-test-connection": {"HOST": "127.0.0.1"},
		},
	}
	byID := map[string]Module{}
	for _, module := range RegisteredModules() {
		byID[module.ID()] = module.(Module)
	}

	failures := 0
	started := time.Now()
	for _, id := range liveReadOnlyModules {
		entry, ok := byID[id]
		if !ok {
			t.Errorf("%s is not registered", id)
			failures++
			continue
		}
		shown := entry.CommandPreview(runtime)
		result := (runner.Runner{Secrets: []string{password}, BufferLimit: 512 * 1024}).
			Execute(context.Background(), entry, runtime, root)
		size := int64(0)
		if info, err := os.Stat(result.OutputPath); err == nil {
			size = info.Size()
		}
		t.Logf("%-28s %-10s exit=%-3d %6dB  nxc %s", id, result.Status, result.ExitCode, size, shown)
		if result.Err != nil {
			t.Errorf("%s: %v", id, result.Err)
			failures++
		}
	}
	t.Logf("live lab validation: %d modules in %s, %d failures", len(liveReadOnlyModules), time.Since(started).Round(time.Second), failures)
}

// liveReadOnlyModules is the approved live scope: every registration below reads
// target state or asks the service a question without changing anything and
// without collecting credential material.
var liveReadOnlyModules = []string{
	// LDAP enumeration, native queries and modules.
	"domain-users", "active-users", "domain-groups", "domain-computers", "domain-sid",
	"password-policy", "fine-grained-password-policy", "admin-count", "password-not-required",
	"delegation", "trusted-for-delegation", "domain-controllers", "maq", "adcs", "badsuccessor",
	"dns-nonsecure", "dump-computers", "entra-id", "get-network", "groupmembership",
	"obsolete", "sccm", "subnets", "whoami", "find-computer", "daclread",
	// SMB enumeration, native queries and modules.
	"smb-server-info", "smb-shares", "smb-disks", "smb-domain-users", "smb-domain-groups",
	"smb-domain-computers", "smb-password-policy", "smb-local-groups", "smb-sessions",
	"logged-on-users", "terminal-sessions", "running-processes", "network-interfaces",
	"smb-enum-av", "smb-enum-ca", "smb-gpp-privileges", "smb-ioxidresolver", "smb-spooler",
	"smb-webdav", "smb-nopac", "smb-ntlm-reflection", "smb-sccm-recon6", "smb-smbghost",
	"smb-remove-mic", "smb-printnightmare", "smb-zerologon", "smb-ms17-010", "smb-bitlocker",
	"smb-enum-interfaces", "smb-get-netconnections", "smb-hyperv-host", "smb-install-elevated",
	"smb-keepass-discover", "smb-lockscreendoors", "smb-ntlmv1", "smb-presence", "smb-reg-query",
	"smb-runasppl", "smb-test-connection", "smb-uac", "smb-wcc",
	// Every other protocol: the credential check, plus whatever read-only
	// enumeration that protocol advertises.
	"winrm-auth-check", "wmi-auth-check", "wmi-ioxidresolver", "wmi-spooler", "wmi-zerologon",
	"wmi-list-snapshots",
	"wmi-bitlocker", "wmi-enum-dns", "wmi-get-netconnections",
	"mssql-auth-check", "mssql-databases", "mssql-enum-logins", "mssql-enum-links", "mssql-rid-brute",
	"mssql-enum-impersonate", "mssql-test-connection",
	"ssh-auth-check", "ssh-sudo-check", "ftp-auth-check", "ftp-list", "rdp-auth-check",
	"vnc-auth-check", "nfs-auth-check", "nfs-shares",
}

// The live scope must stay inside read-only, non-credential registrations. This
// guard fails if a module is added to the list that belongs to a category the
// live check is not authorized to run.
func TestLiveScopeExcludesCredentialAndEscalationModules(t *testing.T) {
	byID := map[string]Module{}
	for _, module := range RegisteredModules() {
		byID[module.ID()] = module.(Module)
	}
	for _, id := range liveReadOnlyModules {
		entry, ok := byID[id]
		if !ok {
			t.Fatalf("%s is not registered", id)
		}
		if entry.Category() != modules.CategoryEnumeration && entry.Category() != modules.CategoryPrivilegeEscalation {
			t.Fatalf("%s is in %s and must not be part of the live read-only scope", id, entry.Category())
		}
		if entry.Category() == modules.CategoryPrivilegeEscalation && !entry.ReadOnly() {
			t.Fatalf("%s changes state and must not be part of the live read-only scope", id)
		}
		if entry.definition.SensitivityValue == modules.SensitivitySensitive {
			t.Fatalf("%s handles credential material and needs an explicit approval, not this test", id)
		}
		if !entry.ExecutionEnabled() {
			t.Fatalf("%s is gated and must not be part of the live read-only scope", id)
		}
	}
}
