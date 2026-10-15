package main

import (
	"path/filepath"
	"testing"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/ldaptransport"
	"github.com/pwnflow/pwnflow/internal/trust"
)

// Startup must offer a certificate decision that consults the local approval
// store, so an already-approved internal CA does not prompt again, and an
// unapproved certificate cannot be accepted without the operator.
func TestTrustOptionsConsultTheApprovalStore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	options := trustOptions(config.Config{Target: "198.51.100.10", Domain: "corp.example"})
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
	approved := trustOptions(config.Config{Target: "198.51.100.10", Domain: "corp.example"})
	if decision, err := approved.CertificateTrust(info); err != nil || decision != ldaptransport.TrustSession {
		t.Fatalf("a stored approval was not honoured: %v %v", decision, err)
	}
}
