package certipy

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/runner"
)

// These fixtures reproduce the shape of the installed Certipy's own help, which
// is what the capability probes match against. The find subcommand's help does
// not contain the "Enumerate AD CS" action-list phrase: that line only exists in
// the top-level help, so keying on it would reject the shipped version.
const (
	certipyTopLevelHelp = `usage: certipy-ad [-v] [-h]
                  {account,auth,ca,cert,find,parse,forge,relay,req,shadow,template} ...

Active Directory Certificate Services enumeration and abuse

    find                Enumerate AD CS`

	certipyFindHelp = `usage: certipy-ad find [-h] [-text] [-stdout] [-json] [-output prefix]
                       [-enabled] [-dc-only] [-vulnerable]
                       [-dc-ip ip address] [-u username@domain] [-p password]
                       [-ldap-scheme ldap scheme] [-ldap-port port]

Discover and analyze Active Directory Certificate Services components.

find options:
  -enabled              Show only enabled certificate templates
  -dc-only              Collects data only from the domain controller.
  -vulnerable           Show only vulnerable certificate templates
  -json -text -output -dc-ip -u -p -ldap-scheme -ldap-port`
)

// writeCertipy writes a stand-in for the installed tool. It records its working
// directory, its arguments, and creates the report files the real tool writes,
// so a test can prove what the module actually executed.
func writeCertipy(t *testing.T, directory, name, help string) string {
	t.Helper()
	body := `case "$1" in
--version) echo 'Certipy v5.1.0 - by Oliver Lyak (ly4k)' ;;
--help) printf '%s\n' "` + help + `" ;;
find)
  if [ "$2" = "--help" ]; then printf '%s\n' "` + certipyFindHelp + `"; exit 0; fi
  printf '%s\n' "$@" > certipy-args.txt; printf '%s\n' "$PWD" > certipy-cwd.txt; printf '%s\n' '{"ok":true}' > report_Certipy.json ;;
*) exit 1 ;;
esac
`
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func testRuntime(t *testing.T) *modules.Runtime {
	t.Helper()
	return &modules.Runtime{
		Target:      "198.51.100.10",
		Domain:      "corp.example",
		Username:    "audituser",
		Password:    "Sup3rSecret",
		ResultsRoot: filepath.Join(t.TempDir(), "results", "corp.example"),
	}
}

func installedExecutable(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	path := writeCertipy(t, bin, "certipy-ad", certipyTopLevelHelp)
	t.Setenv("PATH", bin)
	return path
}

func moduleFor(t *testing.T, id string) Module {
	t.Helper()
	for _, module := range EnumerationModules() {
		if module.ID() == id {
			return module
		}
	}
	t.Fatalf("module %s is not registered", id)
	return Module{}
}

// Every module is registered under AD CS -> Enumeration -> Certipy and reports
// itself as a read-only LDAP module.
func TestModulesAreRegisteredUnderADCSCertipy(t *testing.T) {
	modulesFound := EnumerationModules()
	if len(modulesFound) != 3 {
		t.Fatalf("expected three enumeration modules, got %d", len(modulesFound))
	}
	for _, module := range modulesFound {
		if module.ToolFamily() != modules.ToolFamilyADCS || module.Category() != modules.CategoryEnumeration || module.Tool() != "Certipy" {
			t.Errorf("%s is not registered as AD CS -> Enumeration -> Certipy: %s/%s/%s", module.ID(), module.ToolFamily(), module.Category(), module.Tool())
		}
		if module.Protocol() != modules.ProtocolLDAP {
			t.Errorf("%s does not report its LDAP protocol: %s", module.ID(), module.Protocol())
		}
		if !module.ReadOnly() {
			t.Errorf("%s is not read-only", module.ID())
		}
	}
}

// The argument vector follows the operator-supplied configuration, pins DC-only
// collection and LDAPS, and never selects a collection mode the module does not
// advertise.
func TestCommandArgumentsFollowTheRuntimeConfiguration(t *testing.T) {
	installedExecutable(t)
	runtime := testRuntime(t)
	discovery := moduleFor(t, "certipy-adcs-discovery")
	args := discovery.CommandArgs(runtime)

	joined := strings.Join(args, " ")
	for _, want := range []string{
		"find",
		"-dc-ip " + runtime.Target,
		"-u audituser@corp.example",
		"-p " + runtime.Password,
		"-dc-only",
		"-ldap-scheme ldaps",
		"-ldap-port 636",
		"-json",
		"-text",
		"-output ",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("arguments are missing %q: %s", want, joined)
		}
	}
	if args[0] != "find" || args[1] != "-dc-ip" {
		t.Errorf("unexpected argument order: %#v", args)
	}
	for _, forbidden := range []string{"All", "DCOnly", "-stdout", "-csv"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("arguments contain %q: %s", forbidden, joined)
		}
	}
	if strings.Contains(joined, "..") || strings.Contains(joined, "/") && !strings.Contains(joined, "corp.example") {
		t.Errorf("the output prefix is not a bare name: %s", joined)
	}
	prefix := args[len(args)-1]
	if strings.ContainsAny(prefix, `/\`) {
		t.Errorf("the output prefix must stay inside the run directory: %q", prefix)
	}

	// A different operator configuration must be honoured, never a fixed lab.
	other := &modules.Runtime{Target: "203.0.113.7", Domain: "example.test", Username: "someone", Password: "Placeholder"}
	otherArgs := strings.Join(discovery.CommandArgs(other), " ")
	if !strings.Contains(otherArgs, "-dc-ip 203.0.113.7") || !strings.Contains(otherArgs, "-u someone@example.test") {
		t.Errorf("the runtime configuration was not honoured: %s", otherArgs)
	}
	if strings.Contains(otherArgs, runtime.Domain) || strings.Contains(otherArgs, runtime.Target) {
		t.Errorf("a previous configuration leaked into the command: %s", otherArgs)
	}
}

// Each module advertises one filter, and that filter is the argument it passes.
func TestModuleFiltersAreExplicit(t *testing.T) {
	installedExecutable(t)
	runtime := testRuntime(t)
	cases := map[string]string{
		"certipy-adcs-enabled-templates":    "-enabled",
		"certipy-adcs-vulnerable-templates": "-vulnerable",
	}
	for id, option := range cases {
		module := moduleFor(t, id)
		joined := strings.Join(module.CommandArgs(runtime), " ")
		if !strings.Contains(joined, "-dc-only "+option) {
			t.Errorf("%s does not pass its documented filter %s: %s", id, option, joined)
		}
	}
	discovery := strings.Join(moduleFor(t, "certipy-adcs-discovery").CommandArgs(runtime), " ")
	for _, option := range []string{"-enabled", "-vulnerable"} {
		if strings.Contains(discovery, option) {
			t.Errorf("discovery passes a filter it does not advertise (%s): %s", option, discovery)
		}
	}
}

// A command preview is shown on every frame, so it can never carry the password.
func TestCommandPreviewRedactsCredentials(t *testing.T) {
	installedExecutable(t)
	runtime := testRuntime(t)
	for _, module := range EnumerationModules() {
		preview := module.CommandPreview(runtime)
		if strings.Contains(preview, runtime.Password) {
			t.Fatalf("%s preview leaked the password: %s", module.ID(), preview)
		}
		if !strings.Contains(preview, "-p "+redactedValue) {
			t.Errorf("%s preview does not mark the redacted password: %s", module.ID(), preview)
		}
		if !strings.Contains(preview, "-dc-ip "+runtime.Target) {
			t.Errorf("%s preview does not show the configured target: %s", module.ID(), preview)
		}
	}
}

// Missing, unrelated, and outdated executables are all reported with the reason
// instead of producing a command the tool cannot run.
func TestCheckRejectsUnusableExecutables(t *testing.T) {
	module := moduleFor(t, "certipy-adcs-discovery")
	runtime := testRuntime(t)

	t.Run("missing", func(t *testing.T) {
		// Detection also looks in the user's own bin directories, so the home
		// directory has to be empty for this to be a missing dependency.
		t.Setenv("HOME", t.TempDir())
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv("CARGO_HOME", "")
		t.Setenv("PIPX_BIN_DIR", t.TempDir())
		t.Setenv("PATH", t.TempDir())
		err := module.Check(context.Background(), runtime)
		if err == nil || !strings.Contains(err.Error(), "install") {
			t.Fatalf("a missing dependency was not reported with its remedy: %v", err)
		}
	})

	t.Run("unrelated executable", func(t *testing.T) {
		bin := t.TempDir()
		writeCertipy(t, bin, "certipy", "certificate helper: no AD CS support")
		t.Setenv("PATH", bin)
		err := module.Check(context.Background(), runtime)
		if err == nil {
			t.Fatal("an unrelated certipy was accepted")
		}
		if !strings.Contains(err.Error(), "AD CS") {
			t.Fatalf("the rejection does not explain the mismatch: %v", err)
		}
	})

	t.Run("version without the required options", func(t *testing.T) {
		bin := t.TempDir()
		body := `case "$1" in
--help) printf '%s\n' "Active Directory Certificate Services enumeration and abuse";;
find) printf '%s\n' "Discover and analyze Active Directory Certificate Services components."; printf '%s\n' "-dc-only -u -p -dc-ip";;
esac`
		if err := os.WriteFile(filepath.Join(bin, "certipy-ad"), []byte("#!/bin/sh\n"+body), 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", bin)
		err := module.Check(context.Background(), runtime)
		if err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("an unsupported option was not reported: %v", err)
		}
	})

	t.Run("missing runtime configuration", func(t *testing.T) {
		installedExecutable(t)
		if err := module.Check(context.Background(), &modules.Runtime{}); err == nil {
			t.Fatal("a runtime without a target or domain was accepted")
		}
	})
}

// The shipped find subcommand describes itself in terms of the AD CS components
// it discovers; the "Enumerate AD CS" action-list line exists only in the
// top-level help. Keying the capability probe on that line rejected the installed
// version, so this pins the shape the probe has to accept.
func TestFindActionIsRecognisedFromItsOwnDescription(t *testing.T) {
	path := installedExecutable(t)
	output, err := exec.Command(path, "find", "--help").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output, []byte("Enumerate AD CS")) {
		t.Fatal("the fixture no longer reproduces the installed help shape")
	}
	if err := moduleFor(t, "certipy-adcs-discovery").Check(context.Background(), testRuntime(t)); err != nil {
		t.Fatalf("a find action described without the action-list line was rejected: %v", err)
	}
}

func TestCheckAcceptsInstalledADCS(t *testing.T) {
	path := installedExecutable(t)
	if err := moduleFor(t, "certipy-adcs-discovery").Check(context.Background(), testRuntime(t)); err != nil {
		t.Fatalf("the installed AD CS Certipy was rejected: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("test fixture is not executable: %v", err)
	}
}

// A run writes its reports into a per-run directory and runs the tool inside it,
// so a later run can never overwrite an earlier run's output.
func TestRunKeepsPerRunArtifacts(t *testing.T) {
	installedExecutable(t)
	module := moduleFor(t, "certipy-adcs-enabled-templates")
	runtime := testRuntime(t)
	sink := &strings.Builder{}

	if err := module.Run(context.Background(), runtime, sink); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	artifacts := module.ArtifactDirectory(runtime)
	entries, err := os.ReadDir(artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one run directory, got %d", len(entries))
	}
	runDirectory := filepath.Join(artifacts, entries[0].Name())
	files, err := os.ReadDir(runDirectory)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(files))
	for _, file := range files {
		names = append(names, file.Name())
	}
	for _, want := range []string{"report_Certipy.json", "certipy-args.txt", "certipy-cwd.txt"} {
		if !contains(names, want) {
			t.Errorf("run directory is missing %q: %v", want, names)
		}
	}
	cwd, err := os.ReadFile(filepath.Join(runDirectory, "certipy-cwd.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(cwd)) != runDirectory {
		t.Errorf("the tool did not run inside the per-run directory: %q", strings.TrimSpace(string(cwd)))
	}
	recorded, err := os.ReadFile(filepath.Join(runDirectory, "certipy-args.txt"))
	if err != nil {
		t.Fatal(err)
	}
	prefix := strings.TrimSpace(strings.Split(string(recorded), "-output")[1])
	if strings.ContainsAny(prefix, `/\`) {
		t.Errorf("the report prefix escaped the run directory: %q", prefix)
	}
}

// A failing tool is reported with the module that failed, and the runner's
// redaction keeps the password out of everything that is shown or stored.
func TestRunFailureIsReportedWithoutSecrets(t *testing.T) {
	bin := t.TempDir()
	writeExecutableBody := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeExecutableBody("certipy-ad", `case "$1" in
--version) echo 'Certipy v5.1.0 - by Oliver Lyak (ly4k)' ;;
--help) printf '%s\n' "`+certipyTopLevelHelp+`" ;;
find)
  if [ "$2" = "--help" ]; then printf '%s\n' "`+certipyFindHelp+`"; exit 0; fi
  echo "authenticating with $4"
  exit 3
  ;;
esac`)
	t.Setenv("PATH", bin)

	module := moduleFor(t, "certipy-adcs-vulnerable-templates")
	runtime := testRuntime(t)
	root := runtime.ResultsRoot
	result := runner.Runner{Secrets: []string{runtime.Password}, BufferLimit: 4096}.Execute(context.Background(), module, runtime, root)
	if result.Status != "failed" || result.ExitCode != 3 {
		t.Fatalf("unexpected result: status=%s exit=%d err=%v", result.Status, result.ExitCode, result.Err)
	}
	if !strings.Contains(result.Err.Error(), "vulnerable-templates") {
		t.Errorf("the failure does not name the module operation: %v", result.Err)
	}
	if strings.Contains(result.Err.Error(), runtime.Password) {
		t.Fatalf("the recorded failure leaked the password: %v", result.Err)
	}
	logged, err := os.ReadFile(result.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logged), runtime.Password) {
		t.Fatalf("the persisted log leaked the password:\n%s", logged)
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
