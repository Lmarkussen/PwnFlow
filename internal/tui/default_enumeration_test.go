package tui

import (
	"context"
	"testing"

	"github.com/pwnflow/pwnflow/internal/config"
)

func TestDefaultEnumerationProfilePreservesBaseAndAddsAuthenticationChecks(t *testing.T) {
	if len(defaultEnumerationModuleIDs) != 39 {
		t.Fatalf("Default Enumeration has %d entries, want 39", len(defaultEnumerationModuleIDs))
	}
	base := defaultEnumerationModuleIDs[:32]
	if len(base) != 32 || base[0] != "password-not-required" || base[31] != "relayking-domain-audit" {
		t.Fatal("the original 32-entry profile was not preserved as the prefix")
	}
	wantAuth := []string{"ftp-auth-check", "rdp-auth-check", "ssh-auth-check", "vnc-auth-check", "wmi-auth-check", "winrm-auth-check", "mssql-auth-check"}
	for index, id := range wantAuth {
		if defaultEnumerationModuleIDs[32+index] != id {
			t.Fatalf("auth entry %d=%q, want %q", index, defaultEnumerationModuleIDs[32+index], id)
		}
	}
	for _, id := range defaultEnumerationModuleIDs {
		if id == "mssqlrelay-check" || id == "mssqlpwner-enumerate" || id == "masscan" || id == "nfs-auth-check" {
			t.Fatalf("excluded module %q entered Default Enumeration", id)
		}
	}
}

func TestDefaultEnumerationDoesNotOpenGroupedApprovalPrompt(t *testing.T) {
	log := &executionLog{}
	registered, ids := yoloRegistry(log)
	m := newModel(context.Background(), config.Config{Target: "198.51.100.10", Domain: "example.test", Username: "operator", Root: t.TempDir()}, nil, registered, ids, 1, "production-test")
	m.width, m.height = 140, 45
	m.resizeOutput()
	m.focus = focusModules
	m.pending = plan{
		name:      "Default Enumeration",
		requested: 2,
		indices:   []int{0, 1},
		approvals: []approval{{index: 0, reason: "credential material"}},
	}
	m.startPlan(m.pending)
	if m.approvalPrompt {
		t.Fatal("Default Enumeration opened the grouped approval prompt")
	}
	if !m.running {
		t.Fatalf("Default Enumeration did not start: %q", m.status)
	}
	if len(m.batchItems) != 2 {
		t.Fatalf("unexpected Default Enumeration queue: %v", batchIDs(m))
	}
	m.cancelBatch()
}
