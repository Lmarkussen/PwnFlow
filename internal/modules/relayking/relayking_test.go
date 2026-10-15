package relayking

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

// mustParse parses a fixed timestamp for the artifact-directory test.
func mustParse(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// Synthetic assessment configuration: no real environment appears in the tests.
const (
	testTarget   = "198.51.100.10"
	testDomain   = "corp.example"
	testUsername = "lowpriv"
	testPassword = "Sup3rSecret"
)

// installCheckout writes the RelayKing layout the installer creates: a checkout
// with its own interpreter whose usage text documents the options PwnFlow builds.
func installCheckout(t *testing.T) {
	t.Helper()
	// The banner is what identifies the tool, and the exit status is non-zero, as
	// the real entry point behaves.
	help := "RelayKing - NTLM & Kerberos Relay Detection Tool\n" +
		"--protocols --dc-ip --output-file --proto-portscan --ntlmv1 --gen-relay-list --threads -o --audit " +
		"--coerce --coerce-all --ntlmv1-all --hashes -k --no-pass --target-file"
	toolsRoot := t.TempDir()
	root := filepath.Join(toolsRoot, "RelayKing")
	bin := filepath.Join(root, ".venv", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "#!/bin/sh\nprintf '%s\\n' '" + help + "'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(root, script), []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "python3"), []byte(body), 0o700); err != nil {
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

// Both registrations are under Network → Enumeration, use the installed checkout,
// and require credentials the tool actually uses.
func TestRegistrationsAreNetworkScopedAndCredentialled(t *testing.T) {
	installCheckout(t)
	modulesHere := EnumerationModules()
	if len(modulesHere) != 2 {
		t.Fatalf("%d registrations, want two", len(modulesHere))
	}
	for _, entry := range modulesHere {
		if entry.ToolFamily() != modules.ToolFamilyNetwork || entry.Category() != modules.CategoryEnumeration {
			t.Fatalf("%s is not under Network → Enumeration", entry.ID())
		}
		if entry.DependencyKey() != "relayking" {
			t.Fatalf("%s is gated by %q", entry.ID(), entry.DependencyKey())
		}
		if entry.Protocol() != modules.ProtocolNA {
			t.Fatalf("%s claims protocol %s", entry.ID(), entry.Protocol())
		}
		bare := runtimeWith(t, nil)
		bare.Password = ""
		if err := entry.Check(context.Background(), bare); err == nil {
			t.Fatalf("%s ran without credentials", entry.ID())
		}
	}
}

// The targeted assessment applies the full detection profile to the one host the
// operator configured, in single-target mode.
func TestTargetedAssessmentBuildsTheFullProfile(t *testing.T) {
	installCheckout(t)
	entry := module(t, "relayking-target-assessment")
	runtime := runtimeWith(t, nil)
	if err := entry.Check(context.Background(), runtime); err != nil {
		t.Fatalf("the targeted assessment was refused: %v", err)
	}
	args := entry.CommandArgs(runtime)
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"-u " + testUsername,
		"--dc-ip " + testTarget,
		"--protocols " + defaultProtocols,
		"--threads 10",
		"-o plaintext,json",
		"--proto-portscan",
		"--ntlmv1",
		"--gen-relay-list",
		"-vv",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("the profile is missing %q: %s", want, joined)
		}
	}
	// Single-target mode names the configured host last, and does not enumerate
	// the domain.
	if args[len(args)-1] != testTarget {
		t.Fatalf("the single target is not named last: %v", args)
	}
	if slices.Contains(args, "--audit") {
		t.Fatalf("the targeted assessment audits the domain: %v", args)
	}
}

// The audit registration is the operator's full profile, and it is held for an
// explicit approval so a global run cannot start it by itself.
func TestDomainAuditIsTheFullProfileAndNeedsApproval(t *testing.T) {
	installCheckout(t)
	entry := module(t, "relayking-domain-audit")
	runtime := runtimeWith(t, nil)
	if err := entry.Check(context.Background(), runtime); err != nil {
		t.Fatalf("the audit was refused: %v", err)
	}
	args := entry.CommandArgs(runtime)
	if !slices.Contains(args, "--audit") {
		t.Fatalf("the audit does not audit: %v", args)
	}
	for _, argument := range args {
		switch argument {
		case "--coerce", "--coerce-all", "--ntlmv1-all", "--target-file", "-t":
			t.Fatalf("the audit requests %s, which is not part of the exposure assessment", argument)
		}
	}
	required, reason := entry.PlanApproval(runtime)
	if !required || !strings.Contains(reason, "domain") {
		t.Fatalf("the domain-wide audit is not held for approval: %v %q", required, reason)
	}
	targeted := module(t, "relayking-target-assessment")
	if required, _ := targeted.PlanApproval(runtime); required {
		t.Fatal("the single-target assessment asks for approval it does not need")
	}
}

// The relay target list and both reports are written inside this run's artifact
// directory, never into the working directory and never over an earlier run.
func TestArtifactsStayInsideTheRunDirectory(t *testing.T) {
	installCheckout(t)
	entry := module(t, "relayking-domain-audit")
	runtime := runtimeWith(t, nil)
	args := entry.CommandArgs(runtime)
	index := slices.Index(args, "--output-file")
	if index < 0 || index+1 >= len(args) {
		t.Fatalf("no output file is named: %v", args)
	}
	output := args[index+1]
	if !strings.HasPrefix(output, runtime.ResultsRoot) {
		t.Fatalf("the report leaves the assessment tree: %s", output)
	}
	list := slices.Index(args, "--gen-relay-list")
	if list < 0 || !strings.HasPrefix(args[list+1], runtime.ResultsRoot) {
		t.Fatalf("the relay target list leaves the assessment tree: %v", args)
	}
	// Two runs produce two directories.
	first := entry.RunArtifactDirectory(runtime, mustParse(t, "2026-01-02T15:04:05Z"))
	second := entry.RunArtifactDirectory(runtime, mustParse(t, "2026-01-02T16:04:05Z"))
	if first == second {
		t.Fatal("two runs share one artifact directory")
	}
}

// The credential never reaches a preview, and the target always does.
func TestPreviewRedactsTheCredential(t *testing.T) {
	installCheckout(t)
	entry := module(t, "relayking-target-assessment")
	preview := entry.CommandPreview(runtimeWith(t, nil))
	if strings.Contains(preview, testPassword) {
		t.Fatalf("the preview leaks the credential: %s", preview)
	}
	if !strings.Contains(preview, redactedValue) || !strings.Contains(preview, testTarget) {
		t.Fatalf("the preview does not show the target and the redaction: %s", preview)
	}
}

// Protocol selection is explicit, and the protocols upstream marks work in
// progress are refused rather than advertised.
func TestProtocolsAreExplicitAndVerified(t *testing.T) {
	installCheckout(t)
	entry := module(t, "relayking-target-assessment")
	selected := runtimeWith(t, map[string]map[string]string{entry.ID(): {"PROTOCOLS": "smb,ldaps,mssql"}})
	if err := entry.Check(context.Background(), selected); err != nil {
		t.Fatalf("an explicit protocol list was refused: %v", err)
	}
	if args := entry.CommandArgs(selected); !slices.Contains(args, "smb,ldaps,mssql") {
		t.Fatalf("the selected protocols were not used: %v", args)
	}
	for _, protocol := range []string{"winrm", "smtp", "imap", "gopher"} {
		bad := runtimeWith(t, map[string]map[string]string{entry.ID(): {"PROTOCOLS": protocol}})
		if err := entry.Check(context.Background(), bad); err == nil {
			t.Fatalf("%s was accepted as a protocol", protocol)
		}
	}
}

// A checkout that does not document the options the registration builds is
// reported as unsupported rather than driven anyway.
func TestCheckoutMustDocumentTheOptionsUsed(t *testing.T) {
	toolsRoot := t.TempDir()
	root := filepath.Join(toolsRoot, "RelayKing")
	bin := filepath.Join(root, ".venv", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "#!/bin/sh\nprintf '%s\\n' 'RelayKing - NTLM & Kerberos Relay Detection Tool'\nprintf '%s\\n' 'usage: relayking.py [-h] --audit'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(root, script), []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "python3"), []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWNFLOW_TOOLS_DIR", toolsRoot)

	entry := module(t, "relayking-target-assessment")
	err := entry.Check(context.Background(), runtimeWith(t, nil))
	if err == nil || !strings.Contains(err.Error(), "does not document") {
		t.Fatalf("an incompatible checkout was accepted: %v", err)
	}
}
