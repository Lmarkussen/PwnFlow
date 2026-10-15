package networkhound

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// Synthetic assessment configuration: no real environment appears in the tests.
const (
	testTarget   = "198.51.100.10"
	testDomain   = "corp.example"
	testUsername = "audituser"
	testPassword = "Sup3rSecret"
)

// installCheckout writes the NetworkHound layout the installer creates: a
// checkout with its own interpreter whose help documents the upstream options.
func installCheckout(t *testing.T, help string) {
	t.Helper()
	toolsRoot := t.TempDir()
	root := filepath.Join(toolsRoot, "NetworkHound")
	bin := filepath.Join(root, ".venv", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf '%s\\n' '" + help + "'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(root, "NetworkHound.py"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "python3"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWNFLOW_TOOLS_DIR", toolsRoot)
}

func runtimeWith(t *testing.T, options map[string]map[string]string) *modules.Runtime {
	t.Helper()
	return &modules.Runtime{
		Target: testTarget, Domain: testDomain, Username: testUsername, Password: testPassword,
		ResultsRoot:   filepath.Join(t.TempDir(), "results", testDomain),
		ModuleOptions: options,
	}
}

func module(t *testing.T, id string) Module {
	t.Helper()
	for _, candidate := range EnumerationModules() {
		if candidate.ID() == id {
			return candidate
		}
	}
	t.Fatalf("%s is not registered", id)
	return Module{}
}

// The directory collection is LDAP and DNS against the configured domain
// controller, and nothing else: no port scan, no service validation, no sweep.
func TestTopologyCollectionStaysOnTheDomainController(t *testing.T) {
	entry := module(t, "networkhound-topology")
	if entry.ToolFamily() != modules.ToolFamilyNetwork || entry.Category() != modules.CategoryEnumeration {
		t.Fatalf("%s is not under Network → Enumeration", entry.ID())
	}
	runtime := runtimeWith(t, nil)
	args := entry.CommandArgs(runtime)
	want := []string{
		"--dc", testTarget,
		"--domain", testDomain,
		"--user", testUsername,
		"--password", testPassword,
	}
	if strings.Join(args[:len(want)], " ") != strings.Join(want, " ") {
		t.Fatalf("the collection does not name the configured domain controller: %v", args)
	}
	for _, argument := range args {
		switch argument {
		case "--port-scan", "--valid-http", "--valid-smb", "--ssl", "--shadow-it", "--networks", "-Pn":
			t.Fatalf("the default collection requests %s, which reaches beyond the domain controller", argument)
		}
	}
	// The JSON goes into a per-run directory inside the assessment tree.
	index := slices.Index(args, "--output")
	if index < 0 || index+1 >= len(args) {
		t.Fatalf("the collection names no output file: %v", args)
	}
	if !strings.HasPrefix(args[index+1], runtime.ResultsRoot) {
		t.Fatalf("the output leaves the assessment tree: %s", args[index+1])
	}
	if !strings.HasSuffix(args[index+1], topologyOutput) {
		t.Fatalf("the output is not the OpenGraph file: %s", args[index+1])
	}
}

// The credential never reaches a preview, and the scope always does.
func TestPreviewRedactsTheCredential(t *testing.T) {
	entry := module(t, "networkhound-topology")
	preview := entry.CommandPreview(runtimeWith(t, nil))
	if strings.Contains(preview, testPassword) {
		t.Fatalf("the preview leaks the credential: %s", preview)
	}
	if !strings.Contains(preview, redactedValue) || !strings.Contains(preview, testTarget) {
		t.Fatalf("the preview does not show the target and the redaction: %s", preview)
	}
}

// The scoped registration cannot run without a scope, and it refuses anything that
// is not a literal address, block or range.
func TestScopedValidationRequiresALiteralScope(t *testing.T) {
	installCheckout(t, "--dc --domain --user --password --networks --output --port-scan --ports --scan-timeout --scan-threads -Pn")
	entry := module(t, "networkhound-scope-validation")
	bare := runtimeWith(t, nil)
	if inputs := entry.MissingInputs(bare); len(inputs) != 1 || inputs[0].Key != "NETWORKS" {
		t.Fatalf("the operator-facing input is %#v", inputs)
	}
	if err := entry.Check(context.Background(), bare); err == nil {
		t.Fatal("the scoped validation ran without a scope")
	}
	required, reason := entry.PlanApproval(bare)
	if !required || reason == "" {
		t.Fatalf("a scope-dependent scan is not held for approval: %v %q", required, reason)
	}
	for _, bad := range []string{"example.com", "dc.corp.example", "198.51.100.0/33", "198.51.100.999", "10.0.0.0/8; rm -rf /"} {
		if err := entry.ValidateOptionValue("NETWORKS", bad); err == nil {
			t.Fatalf("%q was accepted as a network scope", bad)
		}
	}
	for _, good := range []string{"198.51.100.0/29", "198.51.100.10", "198.51.100.10-198.51.100.20", "198.51.100.0/29,198.51.100.40-198.51.100.50"} {
		if err := entry.ValidateOptionValue("NETWORKS", good); err != nil {
			t.Fatalf("%q was refused: %v", good, err)
		}
	}
}

// A configured scope produces exactly one bounded scan of exactly those addresses.
func TestScopedValidationScansOnlyTheSuppliedScope(t *testing.T) {
	installCheckout(t, "--dc --domain --user --password --networks --output --port-scan --ports --scan-timeout --scan-threads -Pn")
	entry := module(t, "networkhound-scope-validation")
	runtime := runtimeWith(t, map[string]map[string]string{
		entry.ID(): {"NETWORKS": "198.51.100.0/29", "SCAN_THREADS": "10", "SCAN_TIMEOUT": "10"},
	})
	if err := entry.Check(context.Background(), runtime); err != nil {
		t.Fatalf("a valid scope was refused: %v", err)
	}
	args := entry.CommandArgs(runtime)
	index := slices.Index(args, "--networks")
	if index < 0 || args[index+1] != "198.51.100.0/29" {
		t.Fatalf("the scan does not use the supplied scope: %v", args)
	}
	for _, argument := range args {
		switch argument {
		case "--shadow-it":
			t.Fatalf("the scoped scan requests the shadow-IT sweep: %v", args)
		}
	}
	// No credential is passed: manual mode ignores the LDAP options, so there is no
	// reason to hand one over.
	for _, argument := range args {
		if argument == "--password" || argument == "--user" || argument == "--dc" {
			t.Fatalf("the scoped scan carries LDAP credentials it does not use: %v", args)
		}
	}
	if !slices.Contains(args, "-Pn") {
		t.Fatalf("the scoped scan does not state its ping policy: %v", args)
	}
	if !slices.Contains(args, "--port-scan") {
		t.Fatalf("the scoped scan does not scan ports: %v", args)
	}
	// The service validations are opt-in, and the details say which ones are on.
	if slices.Contains(args, "--valid-http") || slices.Contains(args, "--valid-smb") {
		t.Fatalf("service validation ran without being requested: %v", args)
	}
	enabled := runtimeWith(t, map[string]map[string]string{
		entry.ID(): {"NETWORKS": "198.51.100.10", "VALIDATE_SMB": "yes"},
	})
	if !slices.Contains(entry.CommandArgs(enabled), "--valid-smb") {
		t.Fatal("a requested SMB validation was not built")
	}
	if strings.Join(entry.DetailLines(enabled), "\n") == "" || !strings.Contains(strings.Join(entry.DetailLines(enabled), "\n"), "198.51.100.10") {
		t.Fatal("Module Information does not state the scope")
	}
}

// A checkout that does not document the options the registrations build is
// reported as unsupported rather than driven anyway.
func TestCheckoutMustDocumentTheOptionsUsed(t *testing.T) {
	installCheckout(t, "usage: NetworkHound.py [-h] [--dc DC]")
	entry := module(t, "networkhound-topology")
	err := entry.Check(context.Background(), runtimeWith(t, nil))
	if err == nil || !strings.Contains(err.Error(), "does not document") {
		t.Fatalf("an incompatible checkout was accepted: %v", err)
	}
}

// The two registrations are distinct, and neither duplicates a NetExec service
// check: one reads the directory, the other scans an operator-named scope.
func TestRegistrationsAreDistinctAndScoped(t *testing.T) {
	modulesHere := EnumerationModules()
	if len(modulesHere) != 2 {
		t.Fatalf("%d registrations, want two", len(modulesHere))
	}
	seen := map[string]bool{}
	for _, entry := range modulesHere {
		if seen[entry.ID()] {
			t.Fatalf("%s is registered twice", entry.ID())
		}
		seen[entry.ID()] = true
		if entry.Protocol() != modules.ProtocolNA {
			t.Fatalf("%s claims protocol %s", entry.ID(), entry.Protocol())
		}
		if !strings.Contains(strings.Join(entry.DetailLines(runtimeWith(t, map[string]map[string]string{entry.ID(): {"NETWORKS": "198.51.100.10"}})), "\n"), "Not requested") {
			t.Fatalf("%s does not state what it does not do", entry.ID())
		}
	}
}
