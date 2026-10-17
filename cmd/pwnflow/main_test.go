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

func trustOptionsWithoutTerminal(cfg config.Config) ldaptransport.Options {
	return trustOptions(cfg, strings.NewReader(""), io.Discard)
}

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

func TestConfigureAutoNetworkScopeOverrideAndNoExpansion(t *testing.T) {
	options := map[string]map[string]string{
		"networkhound-scope-validation": {"NETWORKS": "198.51.100.40-198.51.100.43"},
	}
	if err := configureAutoNetworkScope(true, "198.51.100.0/24", options); err != nil {
		t.Fatal(err)
	}
	if got := options["networkhound-scope-validation"]["NETWORKS"]; got != "198.51.100.0/24" {
		t.Fatalf("scope=%q", got)
	}
	if strings.Contains(gotTargetList(options), "198.51.100.1") {
		t.Fatal("CIDR was expanded into scan targets")
	}
}

func TestConfigureAutoNetworkScopeRejectsInvalidInput(t *testing.T) {
	for _, value := range []string{"198.51.100.0/33", "2001:db8::/64", tailscaleRange()} {
		if err := configureAutoNetworkScope(true, value, map[string]map[string]string{}); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestConfigureAutoNetworkScopeIsHeadlessOnly(t *testing.T) {
	if err := configureAutoNetworkScope(false, "198.51.100.0/24", map[string]map[string]string{}); err == nil {
		t.Fatal("accepted --network-cidr without --auto")
	}
}

func gotTargetList(options map[string]map[string]string) string {
	return options["networkhound-scope-validation"]["NETWORKS"]
}

func tailscaleRange() string { return strings.Join([]string{"100", "64", "0", "0/10"}, ".") }
