package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/ldaptransport"
	"github.com/pwnflow/pwnflow/internal/trust"
)

// trustOptionsWithoutTerminal builds the preflight options for a run whose input
// is not a keyboard: it can never accept a certificate by itself, which is what
// the fail-closed cases below assert.
func trustOptionsWithoutTerminal(cfg config.Config) ldaptransport.Options {
	return trustOptions(cfg, strings.NewReader(""), io.Discard)
}

// A certificate authority the host does not know is decided by the operator, so
// the decision has to be installed even when the approval store cannot be read.
// Removing the decision in that case is what turns an internal CA into a bare
// "certificate signed by unknown authority" failure with no prompt at all.
func TestTrustOptionsKeepTheDecisionWhenTheStoreCannotBeLoaded(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home-is-a-file")
	if err := os.WriteFile(home, []byte("not a directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")

	path, err := trust.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Load(path); err == nil {
		t.Skipf("this environment can read %s, so no load failure can be exercised", path)
	}

	options := trustOptionsWithoutTerminal(config.Config{Target: "198.51.100.10", Domain: "corp.example"})
	if options.CertificateTrust == nil {
		t.Fatal("an unreadable approval store removed the certificate decision entirely")
	}
}

// Startup must offer a certificate decision that consults the local approval
// store, so an already-approved internal CA does not prompt again, and an
// unapproved certificate cannot be accepted without the operator.
func TestTrustOptionsConsultTheApprovalStore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	options := trustOptionsWithoutTerminal(config.Config{Target: "198.51.100.10", Domain: "corp.example"})
	if options.CertificateTrust == nil {
		t.Fatal("no certificate decision is wired into the preflight")
	}
	info := ldaptransport.CertificateInfo{
		Target:      "198.51.100.10",
		Identity:    "dc01.corp.example",
		Fingerprint: "AA:BB:CC",
		Subject:     "CN=domain controller",
		Issuer:      "CN=Lab Issuing CA",
	}
	if decision, err := options.CertificateTrust(info); err == nil || decision != ldaptransport.TrustReject {
		t.Fatalf("an unapproved certificate was accepted: %v %v", decision, err)
	}

	path, err := trust.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	store, err := trust.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Approve(trust.Record{Target: info.Target, Identity: info.Identity, Fingerprint: info.Fingerprint}); err != nil {
		t.Fatal(err)
	}
	approved := trustOptionsWithoutTerminal(config.Config{Target: "198.51.100.10", Domain: "corp.example"})
	if decision, err := approved.CertificateTrust(info); err != nil || decision != ldaptransport.TrustSession {
		t.Fatalf("a stored approval was not honoured: %v %v", decision, err)
	}
}

func TestCLIHelpUsesEmbeddedBannerAndPlainFallback(t *testing.T) {
	var output strings.Builder
	printFullHelp(&output)
	plain := output.String()
	if !strings.Contains(plain, strings.TrimRight(embeddedBanner, "\n")) {
		t.Fatal("help does not contain the embedded operator banner")
	}
	if strings.Contains(plain, "\x1b[") {
		t.Fatal("non-terminal help contains ANSI escape sequences")
	}
	for _, required := range []string{"USAGE", "CONNECTION", "TRANSPORT", "MODULE OPTIONS", "EVIDENCE & MAINTENANCE", "-h, --help", "EXAMPLES"} {
		if !strings.Contains(plain, required) {
			t.Fatalf("help is missing %q", required)
		}
	}
}

func TestCLIHelpNarrowWrappingKeepsWordsReadable(t *testing.T) {
	for _, width := range []string{"60", "40"} {
		t.Setenv("COLUMNS", width)
		var output strings.Builder
		printFullHelp(&output)
		limit := 60
		if width == "40" {
			limit = 40
		}
		for _, line := range strings.Split(output.String(), "\n") {
			if strings.HasSuffix(line, "syste") || strings.HasSuffix(line, "targe") {
				t.Fatalf("description was split mid-word: %q", line)
			}
			if len([]rune(line)) > limit {
				t.Fatalf("help line exceeds narrow width %d: %q", limit, line)
			}
		}
		if width == "60" && !strings.Contains(output.String(), "--module-options MODULE.KEY=VALUE\n") {
			t.Fatal("long option was not moved to its own narrow-terminal line")
		}
	}
}

func TestCLIHelpColorPolicy(t *testing.T) {
	if got := (cliTheme{}).paint("value", "1;92"); got != "value" {
		t.Fatalf("plain theme emitted styling: %q", got)
	}
	colored := (cliTheme{enabled: true}).paint("value", "1;92")
	if !strings.Contains(colored, "\x1b[1;92m") {
		t.Fatalf("enabled theme did not style output: %q", colored)
	}
}
