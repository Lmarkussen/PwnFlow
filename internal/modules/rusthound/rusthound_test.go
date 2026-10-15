package rusthound

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
)

// installedHelp mirrors the option surface of the installed RustHound-CE 2.5.25.
const installedHelp = `Active Directory data collector for BloodHound Community Edition.

Usage: rusthound-ce [OPTIONS] --domain <domain>

Options:
  -v...          Set the level of verbosity
  -h, --help     Print help
  -V, --version  Print version

REQUIRED VALUES:
  -d, --domain <domain>  Domain name like: DOMAIN.LOCAL

OPTIONAL VALUES:
  -u, --ldapusername <ldapusername>  LDAP username, like: user@domain.local
  -p, --ldappassword <ldappassword>  LDAP password
  -H, --hashes <hashes>              NT hash for pass-the-hash authentication (NTLM)
  -i, --ldapip <ldapip>              Domain Controller IP address like: 192.168.1.10
  -o, --output <output>              Output directory where you would like to save JSON files [default: ./]

OPTIONAL FLAGS:
  -c, --collectionmethod [<COLLECTIONMETHOD>]
          Which information to collect. (default: All) [possible values: All, DCOnly, Session, RegistryOnly, LdapOnly, GPOLocalGroup, LocalGroup, WebClient]
  -k, --kerberos
          Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME)
  -z, --zip
          Compress the JSON files into a zip archive`

// writeFakeRustHound installs a stand-in binary whose --help output satisfies
// the module's capability probe unless help is overridden.
func writeFakeRustHound(t *testing.T, directory, help, body string) string {
	t.Helper()
	var script strings.Builder
	script.WriteString("#!/bin/sh\ncase \"$1\" in\n--help)\n")
	for _, line := range strings.Split(help, "\n") {
		// echo is a shell builtin, so the stand-in needs no other binary on PATH.
		script.WriteString("echo '" + line + "'\n")
	}
	script.WriteString("exit 0\n;;\n--version)\necho 'rusthound-ce 2.5.25'\nexit 0\n;;\nesac\n")
	script.WriteString(body + "\n")
	path := filepath.Join(directory, "rusthound-ce")
	if err := os.WriteFile(path, []byte(script.String()), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func authorizedRuntime() *modules.Runtime {
	return &modules.Runtime{Target: config.AuthorizedTarget, Domain: config.AuthorizedDomain, Username: "audituser", Password: "Sup3rSecret", ResultsRoot: "/tmp/pwnflow-results"}
}

// confineFor supplies the verdict a confined process would report, for both the
// cached display check and the per-run probe, without needing a confined kernel.
func confineFor(t *testing.T) {
	t.Helper()
	originalEnforced, originalProbe := egressEnforced, egressProbe
	egressEnforced = func() error { return nil }
	egressProbe = func() error { return nil }
	t.Cleanup(func() { egressEnforced, egressProbe = originalEnforced, originalProbe })
}

// unconfineFor supplies the verdict of a process whose egress is not filtered, so
// the blocked paths are deterministic on any host.
func unconfineFor(t *testing.T) {
	t.Helper()
	blocked := func() error {
		return errors.New("egress is unfiltered: the probe connection was refused by the local stack")
	}
	originalEnforced, originalProbe := egressEnforced, egressProbe
	egressEnforced, egressProbe = blocked, blocked
	t.Cleanup(func() { egressEnforced, egressProbe = originalEnforced, originalProbe })
}

func TestRustHoundRegistrationAndControlledOutput(t *testing.T) {
	module := Module{}
	if module.ToolFamily() != modules.ToolFamilyActiveDirectory || module.Category() != modules.CategoryEnumeration || module.Protocol() != modules.ProtocolNA {
		t.Fatalf("unexpected taxonomy: %s/%s/%s", module.ToolFamily(), module.Category(), module.Protocol())
	}
	if module.ExecutionEnabled() || !strings.Contains(module.AvailabilityReason(), "scope restricted") {
		t.Fatal("RustHound-CE must remain scope restricted")
	}
	runtime := &modules.Runtime{ResultsRoot: "/tmp/pwnflow-results"}
	want := filepath.Join(runtime.ResultsRoot, "Enumeration", "RustHoundCE", "artifacts")
	if got := module.ArtifactDirectory(runtime); got != want {
		t.Fatalf("artifact directory=%q want %q", got, want)
	}
	if got := module.OutputFile(); got != "Enumeration/RustHoundCE/rusthound-ce.log" {
		t.Fatalf("log path=%q", got)
	}
}

// The collection method is always stated explicitly and is never the CLI's
// default All collection.
func TestRustHoundCommandPinsAuthorizedScopeAndLdapOnly(t *testing.T) {
	module := Module{}
	runtime := authorizedRuntime()
	args := module.CommandArgs(runtime)
	want := []string{"-d", "sccm.lab", "-i", "10.1.10.40", "-c", "LdapOnly", "-u", "audituser", "-p", runtime.Password, "-o", filepath.Join(runtime.ResultsRoot, "Enumeration", "RustHoundCE", "artifacts")}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("command args=%q want %q", strings.Join(args, " "), strings.Join(want, " "))
	}
	if count := strings.Count(strings.Join(args, " "), "-c"); count != 1 {
		t.Fatalf("collection method must be stated exactly once: %q", strings.Join(args, " "))
	}
	for _, forbidden := range []string{"All", "DCOnly", "Session", "RegistryOnly"} {
		if strings.Contains(strings.Join(args, " "), forbidden) {
			t.Fatalf("command args contain non-approved collection method %q: %q", forbidden, strings.Join(args, " "))
		}
	}
}

// A runtime that claims another target must not be able to redirect the
// collector: the pinned configuration constants win.
func TestRustHoundCommandIgnoresRuntimeTargetOverride(t *testing.T) {
	module := Module{}
	runtime := &modules.Runtime{Target: "192.0.2.10", Domain: "elsewhere.lab", Username: "audituser", ResultsRoot: t.TempDir()}
	args := strings.Join(module.CommandArgs(runtime), " ")
	if !strings.Contains(args, "-i "+config.AuthorizedTarget) || !strings.Contains(args, "-d "+config.AuthorizedDomain) {
		t.Fatalf("command did not pin the authorized scope: %q", args)
	}
	for _, unwanted := range []string{"192.0.2.10", "elsewhere.lab"} {
		if strings.Contains(args, unwanted) {
			t.Fatalf("command accepted the runtime override %q: %q", unwanted, args)
		}
	}
}

// The operator accepts RustHound's native -p argument, so the command carries
// the configured password - but nothing operator-visible may show it.
func TestRustHoundNativePasswordIsUsedButNeverExposed(t *testing.T) {
	module := Module{}
	runtime := authorizedRuntime()
	args := module.CommandArgs(runtime)
	if len(args) < 2 || !containsPair(args, "-p", runtime.Password) {
		t.Fatalf("command did not pass the native -p credentials: %q", strings.Join(args, " "))
	}
	if containsPair(args, "--ldappassword", runtime.Password) {
		t.Fatalf("command used the long password flag: %q", strings.Join(args, " "))
	}
	preview := module.CommandPreview(runtime)
	if strings.Contains(preview, runtime.Password) {
		t.Fatalf("preview leaked the password: %q", preview)
	}
	if !strings.Contains(preview, "-p "+redactedValue) || !strings.Contains(preview, "-c LdapOnly") {
		t.Fatalf("preview did not redact the password in place: %q", preview)
	}
	if details := strings.Join(module.DetailLines(runtime), "\n"); strings.Contains(details, runtime.Password) {
		t.Fatalf("Module Information leaked the password: %q", details)
	}
	if reason := module.AvailabilityReason(); strings.Contains(reason, runtime.Password) {
		t.Fatalf("availability reason leaked the password: %q", reason)
	}
	redacted := redactArguments([]string{"-d", "sccm.lab", "-p", "Sup3rSecret", "--ldappassword=inline", "--ldappassword", "long-form", "-H", "aad3b435b51404ee", "--pfx-pass", "pfx-secret"})
	joined := strings.Join(redacted, " ")
	for _, secret := range []string{"Sup3rSecret", "long-form", "aad3b435b51404ee", "pfx-secret"} {
		if strings.Contains(joined, secret) {
			t.Fatalf("credential %q survived redaction: %q", secret, joined)
		}
	}
	if strings.Count(joined, redactedValue) != 4 {
		t.Fatalf("expected four redacted values: %q", joined)
	}
}

func containsPair(args []string, flag, value string) bool {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == flag && args[index+1] == value {
			return true
		}
	}
	return false
}

// Without an enforced boundary the module is not executable, and the reason an
// operator reads names the missing mechanism and the permitted destination.
func TestRustHoundIsBlockedWithoutAnEnforcedBoundary(t *testing.T) {
	unconfineFor(t)
	dir := t.TempDir()
	writeFakeRustHound(t, dir, installedHelp, `exit 1`)
	t.Setenv("PATH", dir)
	module := Module{}
	err := module.Check(context.Background(), authorizedRuntime())
	if err == nil {
		t.Fatal("capability check passed although no egress boundary is enforced")
	}
	for _, want := range []string{"scope restricted", "egress boundary", config.AuthorizedTarget} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("blocking reason %q missing %q", err.Error(), want)
		}
	}
	if module.ExecutionEnabled() {
		t.Fatal("RustHound-CE must not be executable")
	}
	if reason := module.AvailabilityReason(); !strings.Contains(reason, "no enforced process-specific egress boundary") {
		t.Fatalf("unexpected availability reason: %q", reason)
	}
}

// With the boundary verified the module becomes executable and selectable, which
// is what lets Enter run it from the TUI.
func TestRustHoundIsExecutableWithAnEnforcedBoundary(t *testing.T) {
	confineFor(t)
	dir := t.TempDir()
	writeFakeRustHound(t, dir, installedHelp, `exit 0`)
	t.Setenv("PATH", dir)
	module := Module{}
	if !module.ExecutionEnabled() {
		t.Fatal("module stayed disabled although the boundary is enforced")
	}
	if reason := module.AvailabilityReason(); reason != "" {
		t.Fatalf("module reported a blocker although the boundary is enforced: %q", reason)
	}
	if err := module.Check(context.Background(), authorizedRuntime()); err != nil {
		t.Fatalf("capability check failed with the boundary enforced: %v", err)
	}
}

// A version whose help no longer documents the options this module pins must be
// reported instead of producing a different command.
func TestRustHoundCapabilityProbeRejectsChangedOptionSurface(t *testing.T) {
	dir := t.TempDir()
	writeFakeRustHound(t, dir, "Usage: rusthound-ce --domain <domain>\n  -d, --domain <domain>", `exit 1`)
	t.Setenv("PATH", dir)
	err := (Module{}).Check(context.Background(), authorizedRuntime())
	if err == nil || !strings.Contains(err.Error(), "unsupported by the installed version") {
		t.Fatalf("unexpected capability result: %v", err)
	}
}

func TestRustHoundMissingDependencyIsReported(t *testing.T) {
	empty := t.TempDir()
	t.Setenv("PATH", empty)
	t.Setenv("HOME", empty)
	t.Setenv("CARGO_HOME", filepath.Join(empty, "cargo"))
	t.Setenv("PIPX_BIN_DIR", filepath.Join(empty, "pipx"))
	err := (Module{}).Check(context.Background(), authorizedRuntime())
	if err == nil || !strings.Contains(err.Error(), "RustHound-CE") || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("unexpected missing-dependency result: %v", err)
	}
}

func TestRustHoundRejectsUnauthorizedTargetBeforeCapabilityCheck(t *testing.T) {
	err := (Module{}).Check(context.Background(), &modules.Runtime{Target: "192.0.2.10", Domain: config.AuthorizedDomain})
	if err == nil || !strings.Contains(err.Error(), "outside the authorized assessment scope") {
		t.Fatalf("unexpected scope result: %v", err)
	}
}

// Each collection gets its own artifact directory, so a later run cannot
// overwrite an earlier run's JSON output.
func TestRustHoundRunArtifactsAreScopedPerRun(t *testing.T) {
	module := Module{}
	runtime := &modules.Runtime{ResultsRoot: t.TempDir()}
	first := time.Date(2026, 10, 15, 9, 30, 0, 0, time.Local)
	second := time.Date(2026, 10, 15, 11, 5, 0, 0, time.Local)
	firstDirectory := module.RunArtifactDirectory(runtime, first)
	secondDirectory := module.RunArtifactDirectory(runtime, second)
	if firstDirectory == secondDirectory {
		t.Fatalf("runs share an artifact directory: %q", firstDirectory)
	}
	if want := filepath.Join(module.ArtifactDirectory(runtime), "20261015-093000"); firstDirectory != want {
		t.Fatalf("artifact directory=%q want %q", firstDirectory, want)
	}
	for _, directory := range []string{firstDirectory, secondDirectory} {
		if err := os.MkdirAll(directory, 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "20261015093000_users.json"), []byte("{\"data\":[]}"), 0640); err != nil {
			t.Fatal(err)
		}
	}
	preserved, err := os.ReadFile(filepath.Join(firstDirectory, "20261015093000_users.json"))
	if err != nil || string(preserved) != "{\"data\":[]}" {
		t.Fatalf("earlier artifact was not preserved: %v %q", err, string(preserved))
	}
}

// The log path stays separate from the raw artifacts, failures are reported, and
// no credential appears in streamed output.
func TestRustHoundRunStreamsSanitizedOutputAndReportsFailure(t *testing.T) {
	confineFor(t)
	dir := t.TempDir()
	writeFakeRustHound(t, dir, installedHelp, `echo "bind attempt for $*" >&2`+"\n"+`echo "error: anonymous bind failed" >&2`+"\n"+`exit 3`)
	t.Setenv("PATH", dir)
	module := Module{}
	runtime := authorizedRuntime()
	runtime.ResultsRoot = t.TempDir()
	var output bytes.Buffer
	err := module.Run(context.Background(), runtime, &output)
	if err == nil || !strings.Contains(err.Error(), "RustHound-CE failed") {
		t.Fatalf("unexpected run result: %v", err)
	}
	if !strings.Contains(output.String(), "error: anonymous bind failed") {
		t.Fatalf("command output was not streamed to the sink: %q", output.String())
	}
	// The module streams the collector's output verbatim; the runner's redacting
	// sink is what strips credentials from displays and persisted logs (covered
	// by the runner tests).
	if !strings.Contains(output.String(), "-p "+runtime.Password) {
		t.Fatalf("native password argument did not reach the collector: %q", output.String())
	}
	if strings.Contains(err.Error(), runtime.Password) {
		t.Fatalf("error text leaked the credential: %q", err.Error())
	}
	if !strings.Contains(output.String(), "-c LdapOnly") {
		t.Fatalf("run did not pass the pinned collection method: %q", output.String())
	}
	if !strings.Contains(output.String(), filepath.Join(module.ArtifactDirectory(runtime))) {
		t.Fatalf("run did not target the managed artifact directory: %q", output.String())
	}
}

func TestRustHoundRunHonoursCancellation(t *testing.T) {
	confineFor(t)
	dir := t.TempDir()
	// exec replaces the shell so the stand-in itself is the process that the
	// cancelled context has to terminate, as the real single-binary collector is.
	writeFakeRustHound(t, dir, installedHelp, `exec /bin/sleep 5`)
	t.Setenv("PATH", dir)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	runtime := authorizedRuntime()
	runtime.ResultsRoot = t.TempDir()
	started := time.Now()
	err := (Module{}).Run(ctx, runtime, &bytes.Buffer{})
	if err == nil {
		t.Fatal("cancelled collection reported success")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("cancellation took %s; the process was not stopped promptly", elapsed)
	}
}

// Fail closed: without a freshly verified boundary the collector must never be
// started, so no unconfined collection can happen even if the interface was
// rendered while a boundary existed.
func TestRustHoundRefusesToRunWithoutAnEnforcedBoundary(t *testing.T) {
	unconfineFor(t)
	dir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "collector-ran")
	t.Setenv("RUN_MARKER", marker)
	writeFakeRustHound(t, dir, installedHelp, `: > "$RUN_MARKER"`)
	t.Setenv("PATH", dir)
	runtime := authorizedRuntime()
	runtime.ResultsRoot = t.TempDir()
	err := (Module{}).Run(context.Background(), runtime, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "without an enforced egress boundary") {
		t.Fatalf("expected a fail-closed refusal, got %v", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("collector was launched without an enforced boundary")
	}
}

// With the boundary verified the collector runs through the existing runner
// contract: pinned arguments, per-run artifacts, streamed output.
func TestRustHoundRunsWithAnEnforcedBoundary(t *testing.T) {
	confineFor(t)
	dir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "collector-ran")
	t.Setenv("RUN_MARKER", marker)
	writeFakeRustHound(t, dir, installedHelp, `echo "collector stdout"`+"\n"+`: > "$RUN_MARKER"`+"\n"+`exit 0`)
	t.Setenv("PATH", dir)
	runtime := authorizedRuntime()
	runtime.ResultsRoot = t.TempDir()
	var output bytes.Buffer
	if err := (Module{}).Run(context.Background(), runtime, &output); err != nil {
		t.Fatalf("confined run failed: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("collector did not run: %v", err)
	}
	if !strings.Contains(output.String(), "collector stdout") {
		t.Fatalf("collector output was not streamed: %q", output.String())
	}
	runs, err := os.ReadDir((Module{}).ArtifactDirectory(runtime))
	if err != nil || len(runs) != 1 {
		t.Fatalf("expected one per-run artifact directory, got %v (err=%v)", runs, err)
	}
}

func TestRustHoundDetailLinesDescribeConfigurationWithoutSecrets(t *testing.T) {
	unconfineFor(t)
	runtime := &modules.Runtime{ResultsRoot: "/tmp/pwnflow-results", Password: "Sup3rSecret"}
	joined := strings.Join((Module{}).DetailLines(runtime), "\n")
	for _, want := range []string{
		"Execution: blocked - Scope Restricted",
		"Authentication: native LDAP password",
		"LdapOnly",
		filepath.Join(runtime.ResultsRoot, "Enumeration", "RustHoundCE"),
		"Blocked by: no enforced process-specific egress boundary",
		"Remedy: cgroup restricted to " + config.AuthorizedTarget,
		config.AuthorizedTarget,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("detail lines missing %q: %q", want, joined)
		}
	}
	if strings.Contains(joined, runtime.Password) {
		t.Fatalf("detail lines leaked the credential: %q", joined)
	}

	confineFor(t)
	enabled := strings.Join((Module{}).DetailLines(runtime), "\n")
	if !strings.Contains(enabled, "Execution: enabled - egress confined to "+config.AuthorizedTarget) {
		t.Fatalf("enabled state not reported: %q", enabled)
	}
	if strings.Contains(enabled, "Blocked by:") || strings.Contains(enabled, runtime.Password) {
		t.Fatalf("enabled detail lines are inaccurate: %q", enabled)
	}
}
