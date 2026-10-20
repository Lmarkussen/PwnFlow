package tui

import (
	"context"
	"testing"

	"github.com/pwnflow/pwnflow/internal/config"
)

func TestDefaultEnumerationProfilePreservesBaseAndAddsAuthenticationChecks(t *testing.T) {
	if len(defaultEnumerationModuleIDs) != 42 {
		t.Fatalf("Default Enumeration has %d entries, want 42", len(defaultEnumerationModuleIDs))
	}
	base := defaultEnumerationModuleIDs[:32]
	if len(base) != 32 || base[0] != "password-not-required" || base[31] != "relayking-domain-audit" {
		t.Fatal("the original 32-entry profile was not preserved as the prefix")
	}
	wantPrefix := []string{
		"password-not-required", "delegation", "dns-nonsecure", "get-network", "obsolete", "sccm", "whoami", "asreproast", "kerberoasting",
		"smb-server-info", "smb-sessions", "logged-on-users", "smb-ntlm-reflection", "smb-gpp-autologin", "smb-gpp-password", "smb-aws-credentials", "get-info-users", "get-desc-users", "get-userPassword", "get-unixUserPassword", "laps", "gmsa",
		"certipy-adcs-discovery", "certipy-adcs-enabled-templates", "certipy-adcs-vulnerable-templates", "rusthound-ce", "sccmhunter", "pxethief", "networkhound-topology", "networkhound-scope-validation", "relayking-target-assessment", "relayking-domain-audit", "gpoparser-remote",
		"ftp-auth-check", "rdp-auth-check", "ssh-auth-check", "vnc-auth-check", "wmi-auth-check", "winrm-auth-check",
	}
	for index, id := range wantPrefix {
		if defaultEnumerationModuleIDs[index] != id {
			t.Fatalf("original profile entry %d=%q, want %q", index+1, defaultEnumerationModuleIDs[index], id)
		}
	}
	wantAuth := []string{"ftp-auth-check", "rdp-auth-check", "ssh-auth-check", "vnc-auth-check", "wmi-auth-check", "winrm-auth-check"}
	for index, id := range wantAuth {
		if defaultEnumerationModuleIDs[33+index] != id {
			t.Fatalf("auth entry %d=%q, want %q", index, defaultEnumerationModuleIDs[33+index], id)
		}
	}
	for _, id := range defaultEnumerationModuleIDs {
		if id == "mssql-auth-check" || id == "mssqlrelay-check" || id == "mssqlpwner-enumerate" || id == "masscan" || id == "nfs-auth-check" {
			t.Fatalf("excluded module %q entered Default Enumeration", id)
		}
	}
	for _, id := range defaultEnumerationModuleIDs {
		if id == "gpoparser-local" {
			t.Fatal("path-prompting offline gpoParser entered Default Enumeration")
		}
	}
	if defaultEnumerationModuleIDs[32] != "gpoparser-remote" {
		t.Fatalf("GPO remote analysis is not after the existing Default Enumeration prefix: %q", defaultEnumerationModuleIDs[32])
	}
	if defaultEnumerationModuleIDs[39] != "sphunter-tenant-discovery" {
		t.Fatalf("SPHunter is not the additive entry 40: %q", defaultEnumerationModuleIDs[39])
	}
	if defaultEnumerationModuleIDs[40] != "ad-writable-objects" {
		t.Fatalf("AD writable analysis is not additive entry 41: %q", defaultEnumerationModuleIDs[40])
	}
	if defaultEnumerationModuleIDs[41] != "ftp-anonymous-access" {
		t.Fatalf("FTP anonymous access is not additive entry 42: %q", defaultEnumerationModuleIDs[41])
	}
}

func TestDefaultEnumerationExcludesAllMSSQLModules(t *testing.T) {
	excluded := map[string]bool{
		"mssql-auth-check":     true,
		"mssqlrelay-check":     true,
		"mssqlpwner-enumerate": true,
	}
	for _, id := range defaultEnumerationModuleIDs {
		if excluded[id] {
			t.Fatalf("MSSQL module %q entered Default Enumeration", id)
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
