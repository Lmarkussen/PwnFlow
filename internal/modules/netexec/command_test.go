package netexec

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// Fixtures for arbitrary operator-supplied assessment configuration.
const (
	testTarget = "198.51.100.10"
	testDomain = "example.test"
)

func testRuntime() *modules.Runtime {
	return &modules.Runtime{
		Target: testTarget, Domain: testDomain, Username: "audituser", Password: "Sup3rSecret",
		ResultsRoot: "/tmp/pwnflow-results",
		ModuleOptions: map[string]map[string]string{
			"find-computer": {"TEXT": "SQL"},
			"daclread":      {"TARGET": "Domain Admins"},
		},
	}
}

// Every registration has to build a real argument vector: the protocol command,
// the target, and structured arguments with no shell syntax in them.
func TestEveryRegistrationBuildsAStructuredCommand(t *testing.T) {
	for _, module := range RegisteredModules() {
		entry := module.(Module)
		args := entry.CommandArgs(testRuntime())
		if len(args) < 2 {
			t.Fatalf("%s built %#v", entry.ID(), args)
		}
		if args[0] != protocolCommand(entry.Protocol()) {
			t.Fatalf("%s starts with %q, want the %s command", entry.ID(), args[0], entry.Protocol())
		}
		if args[1] != testTarget {
			t.Fatalf("%s targets %q, want the configured target", entry.ID(), args[1])
		}
		for _, argument := range args {
			if argument == "" {
				t.Fatalf("%s built an empty argument: %#v", entry.ID(), args)
			}
			if strings.ContainsAny(argument, "$`;&|><\n") {
				t.Fatalf("%s built %q, which carries shell syntax", entry.ID(), argument)
			}
			if argument == "nxc" || strings.HasPrefix(argument, "nxc ") {
				t.Fatalf("%s built a command line instead of an argument vector: %#v", entry.ID(), args)
			}
		}
		if entry.ModuleName() != "" {
			if index := slices.Index(args, "-M"); index < 0 || args[index+1] != entry.ModuleName() {
				t.Fatalf("%s did not pass -M %s: %#v", entry.ID(), entry.ModuleName(), args)
			}
		}
	}
}

// Each protocol has its own authentication shape. The protocols that take a
// domain get one, VNC gets a password and no user, NFS gets no credentials at
// all, and only LDAP selects LDAPS.
func TestProtocolSpecificAuthenticationAndTransportFlags(t *testing.T) {
	cases := map[modules.Protocol]struct {
		username, password, domain bool
		trailing                   []string
	}{
		modules.ProtocolLDAP:  {username: true, password: true, domain: true, trailing: []string{"--port", "636"}},
		modules.ProtocolSMB:   {username: true, password: true, domain: true},
		modules.ProtocolWinRM: {username: true, password: true, domain: true},
		modules.ProtocolWMI:   {username: true, password: true, domain: true},
		modules.ProtocolMSSQL: {username: true, password: true, domain: true},
		modules.ProtocolSSH:   {username: true, password: true},
		modules.ProtocolFTP:   {username: true, password: true},
		modules.ProtocolRDP:   {username: true, password: true, domain: true},
		modules.ProtocolVNC:   {password: true},
		modules.ProtocolNFS:   {},
	}
	runtime := testRuntime()
	for _, module := range RegisteredModules() {
		entry := module.(Module)
		want, ok := cases[entry.Protocol()]
		if !ok {
			t.Fatalf("%s has no protocol expectation; add it to the table", entry.ID())
		}
		args := entry.CommandArgs(runtime)
		if got := slices.Contains(args, "-u"); got != want.username {
			t.Fatalf("%s: -u present=%t, want %t (%#v)", entry.ID(), got, want.username, args)
		}
		if got := slices.Contains(args, "-p"); got != want.password {
			t.Fatalf("%s: -p present=%t, want %t (%#v)", entry.ID(), got, want.password, args)
		}
		if got := slices.Contains(args, "-d"); got != want.domain {
			t.Fatalf("%s: -d present=%t, want %t (%#v)", entry.ID(), got, want.domain, args)
		}
		if entry.Protocol() == modules.ProtocolLDAP {
			if len(args) < 2 || args[len(args)-2] != "--port" || args[len(args)-1] != "636" {
				t.Fatalf("%s does not select LDAPS with --port 636: %#v", entry.ID(), args)
			}
			continue
		}
		for _, argument := range args {
			if argument == "--port" || argument == "636" || argument == "--ldaps" {
				t.Fatalf("%s inherited the LDAP transport: %#v", entry.ID(), args)
			}
		}
	}
}

// The transport table is only meaningful if it covers every protocol PwnFlow
// offers, so a new protocol cannot be added without an authentication shape.
func TestEveryProtocolHasATransportDefinition(t *testing.T) {
	covered := make(map[string]bool)
	for _, module := range RegisteredModules() {
		covered[string(module.Protocol())] = true
	}
	for _, protocol := range modules.Protocols() {
		if protocol == modules.ProtocolNA {
			continue
		}
		if !covered[string(protocol)] {
			t.Fatalf("protocol %s is offered by the taxonomy with no registration", protocol)
		}
		if spec(protocol).command == "" {
			t.Fatalf("protocol %s has no transport definition", protocol)
		}
	}
}

// Operator-supplied options are appended as `-o KEY=VALUE`, in the order the
// registration declares, and never as a default the module did not ask for.
func TestModuleOptionsBecomeStructuredDashOArguments(t *testing.T) {
	runtime := testRuntime()
	find := findModule(t, "find-computer")
	args := find.CommandArgs(runtime)
	index := slices.Index(args, "-o")
	if index < 0 || args[index+1] != "TEXT=SQL" {
		t.Fatalf("find-computer did not receive its configured option: %#v", args)
	}
	gpp := findModule(t, "sccm")
	if slices.Contains(gpp.CommandArgs(runtime), "-o") {
		t.Fatalf("a module without configured options received -o: %#v", gpp.CommandArgs(runtime))
	}
	// An option the registration does not declare is never passed: an unknown
	// key would silently do nothing on the target.
	undeclared := findModule(t, "maq")
	options := runtime.ModuleOptions
	options["maq"] = map[string]string{"NOT_A_REAL_OPTION": "x"}
	if slices.Contains(undeclared.CommandArgs(runtime), "-o") {
		t.Fatalf("an undeclared option was passed: %#v", undeclared.CommandArgs(runtime))
	}
}

func TestRequiredModuleOptionMakesTheModuleUnavailableUntilItIsConfigured(t *testing.T) {
	entry := findModule(t, "daclread")
	without := &modules.Runtime{Target: testTarget, Domain: testDomain, Username: "u", Password: "p"}
	if status := entry.Status(without); status != modules.StatusUnavailable {
		t.Fatalf("status without the option = %v, want unavailable", status)
	}
	reason := entry.StatusReason(without)
	if !strings.Contains(reason, "TARGET") || !strings.Contains(reason, "--module-options daclread=TARGET") {
		t.Fatalf("reason does not tell the operator how to configure it: %q", reason)
	}
	installFakeNXC(t, `#!/bin/sh
case "$1 $2" in
  "ldap --help") echo "--port --users"; exit 0 ;;
  "ldap -L") printf 'LOW PRIVILEGE MODULES\nENUMERATION\n[*] daclread   Read and backup the DACL of objects\n'; exit 0 ;;
esac
exit 0
`)
	if err := entry.Check(context.Background(), without); err == nil || !strings.Contains(err.Error(), "TARGET") {
		t.Fatalf("Check allowed a module whose required option is missing: %v", err)
	}
	if status := entry.Status(testRuntime()); status == modules.StatusUnavailable {
		t.Fatalf("status with the option configured = unavailable: %s", entry.StatusReason(testRuntime()))
	}
	if err := entry.Check(context.Background(), testRuntime()); err != nil {
		t.Fatalf("Check refused a module whose option is configured: %v", err)
	}
}

// ADMIN-REQ is informational: it describes the target-side right, and it never
// stops a module from being selected and run.
func TestAdminRequiredIsInformationalAndNeverBlocks(t *testing.T) {
	entry := findModule(t, "smb-bitlocker")
	if status := entry.Status(testRuntime()); status != modules.StatusAdminRequired {
		t.Fatalf("smb-bitlocker status = %v, want admin-required", status)
	}
	if reason := entry.StatusReason(testRuntime()); !strings.Contains(reason, "local administrator") {
		t.Fatalf("the requirement does not name the right: %q", reason)
	}
}

// ADMIN-REQ is a label, not a gate: nothing in the registry refuses to run, or is
// hidden, because it needs elevated rights on the target.
func TestAdminRequiredNeverBlocksExecution(t *testing.T) {
	admin := 0
	for _, module := range RegisteredModules() {
		entry := module.(Module)
		if !entry.definition.AdminRequiredValue {
			continue
		}
		admin++
		if status := entry.Status(testRuntime()); status != modules.StatusAdminRequired {
			t.Fatalf("%s needs admin but reports %v", entry.ID(), status)
		}
		if _, ok := any(entry).(modules.ExecutionPolicy); ok {
			t.Fatalf("%s carries an execution policy; ADMIN-REQ must not gate anything", entry.ID())
		}
	}
	if admin == 0 {
		t.Fatal("no registration declares an administrative requirement")
	}
}

// A module the installed build does not advertise is unavailable, and the
// reason names the listing that proved it.
func TestUnadvertisedModuleIsUnavailable(t *testing.T) {
	installFakeNXC(t, `#!/bin/sh
case "$1 $2" in
  "ldap --help") echo "--users --port PORT"; exit 0 ;;
  "ldap -L") printf 'LOW PRIVILEGE MODULES\nENUMERATION\n[*] maq   Retrieves the MachineAccountQuota domain-level attribute\n[*] ldap-checker  [REMOVED] Checks LDAP signing\n'; exit 0 ;;
esac
exit 0
`)
	registered := findModule(t, "badsuccessor")
	// The capability snapshot is filled off the render path; the test asks for
	// the same refresh the TUI performs in the background.
	registered.RefreshDetails(context.Background(), testRuntime())
	if status := registered.Status(testRuntime()); status != modules.StatusUnavailable {
		t.Fatalf("an unadvertised module is %v, want unavailable", status)
	}
	if reason := registered.StatusReason(testRuntime()); !strings.Contains(reason, "-L") {
		t.Fatalf("the reason does not name the evidence: %q", reason)
	}
	if err := registered.Check(context.Background(), testRuntime()); err == nil {
		t.Fatal("Check allowed a module the installed build does not advertise")
	}
	// A module that is advertised as [REMOVED] is unavailable too, even though
	// its name appears in the listing.
	retired := Module{definition: Definition{
		IDValue: "ldap-checker", NameValue: "Check LDAP Signing", ToolValue: "NetExec (nxc)",
		ToolFamilyValue: modules.ToolFamilyNetExec, CategoryValue: modules.CategoryEnumeration,
		ProtocolValue: modules.ProtocolLDAP, ModuleName: "ldap-checker", OutputValue: "LDAP_signing.txt",
	}}
	if status := retired.Status(testRuntime()); status != modules.StatusUnavailable {
		t.Fatalf("a module marked [REMOVED] is %v, want unavailable", status)
	}
}

// A protocol the installed build does not implement reports every registration
// under it as unavailable, without PwnFlow having to guess.
func TestUnsupportedProtocolIsUnavailable(t *testing.T) {
	installFakeNXC(t, `#!/bin/sh
case "$1 $2" in
  "nfs --help") exit 2 ;;
  "nfs -L") exit 2 ;;
esac
echo "--users --port PORT"
exit 0
`)
	entry := findModule(t, "nfs-shares")
	entry.RefreshDetails(context.Background(), testRuntime())
	if status := entry.Status(testRuntime()); status != modules.StatusUnavailable {
		t.Fatalf("NFS shares = %v, want unavailable when the build lacks NFS", status)
	}
	if reason := entry.StatusReason(testRuntime()); !strings.Contains(reason, "not supported") {
		t.Fatalf("reason = %q", reason)
	}
	// A different protocol is unaffected by the missing one.
	if status := findModule(t, "domain-users").Status(testRuntime()); status != modules.StatusAvailable {
		t.Fatalf("LDAP became unavailable because NFS is missing: %s", findModule(t, "domain-users").StatusReason(testRuntime()))
	}
}

// The capability probe runs off the render path: an unknown protocol must not
// make the status question wait for the executable.
func TestStatusNeverProbesSynchronously(t *testing.T) {
	ResetCapabilities()
	defer ResetCapabilities()
	installFakeNXC(t, `#!/bin/sh
sleep 30
exit 0
`)
	done := make(chan struct{})
	go func() {
		for _, module := range RegisteredModules() {
			_ = module.(Module).Status(testRuntime())
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("status asked the executable a question while answering")
	}
}

// The command preview has to show the protocol, target, and flags while never
// printing the operator's runtime password.
func TestCommandPreviewProtectsTheRuntimePassword(t *testing.T) {
	runtime := testRuntime()
	for _, module := range RegisteredModules() {
		preview := module.(Module).CommandPreview(runtime)
		if strings.Contains(preview, runtime.Password) {
			t.Fatalf("%s leaked the runtime password into its preview: %s", module.ID(), preview)
		}
		if !strings.Contains(preview, protocolCommand(module.Protocol())) || !strings.Contains(preview, testTarget) {
			t.Fatalf("%s preview does not show the protocol and target: %s", module.ID(), preview)
		}
	}
	entry := findModule(t, "domain-users")
	if preview := entry.CommandPreview(runtime); !strings.Contains(preview, "[REDACTED]") {
		t.Fatalf("preview does not mark the credential: %s", preview)
	}
	if preview := entry.CommandPreview(runtime); !strings.Contains(preview, "--port 636") {
		t.Fatalf("preview hides the transport: %s", preview)
	}
}

// Module Information must say what the module needs, in the operator's terms.
func TestDetailLinesDescribeTransportAndPrivilege(t *testing.T) {
	runtime := testRuntime()
	shares := strings.Join(findModule(t, "smb-shares").DetailLines(runtime), "\n")
	if !strings.Contains(shares, "SMB (port 445)") || !strings.Contains(shares, "none beyond valid credentials") {
		t.Fatalf("smb-shares details = %s", shares)
	}
	bitlocker := strings.Join(findModule(t, "smb-bitlocker").DetailLines(runtime), "\n")
	if !strings.Contains(bitlocker, "ADMIN-REQ") || !strings.Contains(bitlocker, "local administrator") {
		t.Fatalf("smb-bitlocker details = %s", bitlocker)
	}
	dacl := strings.Join(findModule(t, "daclread").DetailLines(runtime), "\n")
	if !strings.Contains(dacl, "Configured options: TARGET=Domain Admins") ||
		!strings.Contains(dacl, "Default options: ACTION=read") {
		t.Fatalf("configured options are not reported: %s", dacl)
	}
	vnc := strings.Join(findModule(t, "vnc-auth-check").DetailLines(runtime), "\n")
	if !strings.Contains(vnc, "VNC (port 5900)") {
		t.Fatalf("vnc details = %s", vnc)
	}
}

func findModule(t *testing.T, id string) Module {
	t.Helper()
	for _, module := range RegisteredModules() {
		if module.ID() == id {
			return module.(Module)
		}
	}
	t.Fatalf("module %q is not registered", id)
	return Module{}
}

// installFakeNXC puts a stand-in executable first on PATH and clears the
// capability snapshot so the probe actually runs against it.
func installFakeNXC(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	nxc := filepath.Join(dir, "nxc")
	if err := os.WriteFile(nxc, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	ResetCapabilities()
	t.Cleanup(ResetCapabilities)
}
