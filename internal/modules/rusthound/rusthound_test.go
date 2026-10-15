package rusthound

import (
	"bytes"
	"context"
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

// RustHound-CE is a normal, executable module: it starts with PwnFlow, needs no
// wrapper, and advertises no blocker.
func TestRustHoundIsRegisteredAndExecutable(t *testing.T) {
	module := Module{}
	if module.ToolFamily() != modules.ToolFamilyActiveDirectory || module.Category() != modules.CategoryEnumeration || module.Protocol() != modules.ProtocolNA {
		t.Fatalf("unexpected taxonomy: %s/%s/%s", module.ToolFamily(), module.Category(), module.Protocol())
	}
	if !module.ExecutionEnabled() {
		t.Fatal("RustHound-CE must be executable without a special launcher")
	}
	if reason := module.AvailabilityReason(); reason != "" {
		t.Fatalf("module reported a blocker: %q", reason)
	}
	if prereqs := module.Prerequisites(); len(prereqs) != 1 || prereqs[0] != "rusthound-ce executable" {
		t.Fatalf("unexpected prerequisites: %#v", prereqs)
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
	if !containsPair(args, "-p", runtime.Password) {
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
	for name, surface := range map[string]string{
		"detail lines":       strings.Join(module.DetailLines(runtime), "\n"),
		"availability":       module.AvailabilityReason(),
		"description":        module.Description(),
		"secondary contacts": strings.Join(module.SecondaryConnections(), "\n"),
	} {
		if strings.Contains(surface, runtime.Password) {
			t.Fatalf("%s leaked the password: %q", name, surface)
		}
	}
	redacted := redactArguments([]string{"-d", "sccm.lab", "-p", "Sup3rSecret", "--ldappassword", "long-form", "-H", "aad3b435b51404ee", "--pfx-pass", "pfx-secret"})
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

// Module Information must state the enabled state, authentication, collection
// method, output location, and that the pinned scope is not a network boundary.
func TestRustHoundDetailLinesDescribeConfigurationWithoutSecrets(t *testing.T) {
	runtime := &modules.Runtime{ResultsRoot: "/tmp/pwnflow-results", Password: "Sup3rSecret"}
	joined := strings.Join((Module{}).DetailLines(runtime), "\n")
	for _, want := range []string{
		"Execution: enabled",
		"Authentication: native LDAP password",
		"Collection method: LdapOnly",
		filepath.Join(runtime.ResultsRoot, "Enumeration", "RustHoundCE"),
		"Network scope: pinned to sccm.lab / 10.1.10.40",
		"not kernel-enforced",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("detail lines missing %q: %q", want, joined)
		}
	}
	if strings.Contains(joined, runtime.Password) {
		t.Fatalf("detail lines leaked the credential: %q", joined)
	}
}

// A valid, installed collector with the authorized scope passes the check, which
// is what makes the module selectable.
func TestRustHoundCheckPassesForInstalledCollector(t *testing.T) {
	dir := t.TempDir()
	writeFakeRustHound(t, dir, installedHelp, `exit 0`)
	t.Setenv("PATH", dir)
	if err := (Module{}).Check(context.Background(), authorizedRuntime()); err != nil {
		t.Fatalf("capability check failed: %v", err)
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

// A normal run inside the existing runner contract: pinned arguments reach the
// collector, artifacts land in a fresh per-run directory, failures are reported.
func TestRustHoundRunStreamsOutputAndReportsFailure(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "collector-ran")
	t.Setenv("RUN_MARKER", marker)
	writeFakeRustHound(t, dir, installedHelp, `echo "bind attempt for $*" >&2`+"\n"+`echo "error: anonymous bind failed" >&2`+"\n"+`: > "$RUN_MARKER"`+"\n"+`exit 3`)
	t.Setenv("PATH", dir)
	module := Module{}
	runtime := authorizedRuntime()
	runtime.ResultsRoot = t.TempDir()
	var output bytes.Buffer
	err := module.Run(context.Background(), runtime, &output)
	if err == nil || !strings.Contains(err.Error(), "RustHound-CE failed") {
		t.Fatalf("unexpected run result: %v", err)
	}
	if _, statErr := os.Stat(marker); statErr != nil {
		t.Fatalf("collector did not run: %v", statErr)
	}
	if !strings.Contains(output.String(), "error: anonymous bind failed") {
		t.Fatalf("command output was not streamed to the sink: %q", output.String())
	}
	// The module streams the collector's output verbatim; the runner's redacting
	// sink is what strips credentials from displays and persisted logs (covered by
	// the runner tests).
	if !strings.Contains(output.String(), "-c LdapOnly") || !strings.Contains(output.String(), "-i "+config.AuthorizedTarget) {
		t.Fatalf("pinned arguments did not reach the collector: %q", output.String())
	}
	if !strings.Contains(output.String(), filepath.Join(module.ArtifactDirectory(runtime))) {
		t.Fatalf("run did not target the managed artifact directory: %q", output.String())
	}
	if strings.Contains(err.Error(), runtime.Password) {
		t.Fatalf("error text leaked the credential: %q", err.Error())
	}
}

func TestRustHoundRunHonoursCancellation(t *testing.T) {
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
