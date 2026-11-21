package tui

import (
	"context"
	"testing"

	"github.com/pwnflow/pwnflow/internal/config"
)

func TestDefaultEnumerationProfilePreservesBaseAndAddsAuthenticationChecks(t *testing.T) {
	// The profile is pinned in full: adding, removing or reordering an entry
	// must be a deliberate change to this list.
	want := []string{
		"dns-nonsecure", "get-network", "obsolete", "sccm", "whoami", "asreproast", "kerberoasting", "ghostspn-audit",
		"smb-server-info", "smb-sessions", "logged-on-users", "smb-gpp-autologin", "smb-gpp-password", "smb-aws-credentials", "get-info-users", "get-desc-users", "get-userPassword", "get-unixUserPassword",
		"certipy-adcs-discovery", "rusthound-ce", "sccmhunter", "pxethief", "networkhound-topology", "networkhound-scope-validation", "relayking-target-assessment", "relayking-domain-audit", "gpoparser-remote",
		"ftp-auth-check", "rdp-auth-check", "ssh-auth-check", "vnc-auth-check", "wmi-auth-check", "winrm-auth-check",
		"sphunter-tenant-discovery", "ad-writable-objects", "ftp-anonymous-access", "smb-spider-plus", "smb-password-policy", "bloodyad-writable", "maq",
		"ad-directory-settings", "smb-null-session",
	}
	if len(defaultEnumerationModuleIDs) != 42 || len(want) != 42 {
		t.Fatalf("Default Enumeration has %d entries, want 42", len(defaultEnumerationModuleIDs))
	}
	for index, id := range want {
		if defaultEnumerationModuleIDs[index] != id {
			t.Fatalf("profile entry %d=%q, want %q", index+1, defaultEnumerationModuleIDs[index], id)
		}
	}
	// GhostSPN immediately follows Kerberoasting.
	for index, id := range defaultEnumerationModuleIDs {
		if id == "kerberoasting" && defaultEnumerationModuleIDs[index+1] != "ghostspn-audit" {
			t.Fatalf("GhostSPN does not follow Kerberoasting: %q", defaultEnumerationModuleIDs[index+1])
		}
	}
	// Covered by RustHound-CE or by the unfiltered Certipy find, or a password
	// read where Findings report who can read instead.
	for _, id := range []string{"password-not-required", "delegation", "laps", "gmsa", "certipy-adcs-enabled-templates", "certipy-adcs-vulnerable-templates", "smb-enum-cve", "badsuccessor"} {
		for _, entry := range defaultEnumerationModuleIDs {
			if entry == id {
				t.Fatalf("%q is back in Default Enumeration", id)
			}
		}
	}
	for _, id := range defaultEnumerationModuleIDs {
		if id == "mssql-auth-check" || id == "mssqlrelay-check" || id == "mssqlpwner-enumerate" || id == "masscan" || id == "nfs-auth-check" || id == "gpoparser-local" {
			t.Fatalf("excluded module %q entered Default Enumeration", id)
		}
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

func TestDefaultEnumerationDoesNotPromptForSMBSpiderTargetOrApproval(t *testing.T) {
	registered := fullRegistry()
	spiderIndex := -1
	for index, module := range registered {
		if module.ID() == "smb-spider-plus" {
			spiderIndex = index
			break
		}
	}
	if spiderIndex < 0 {
		t.Fatal("smb-spider-plus is missing from the production registry")
	}
	m := newModel(context.Background(), config.Config{Target: "198.51.100.10", Domain: "example.test", Username: "operator", Root: t.TempDir()}, nil, registered, make([]int64, len(registered)), 1, "production-test")
	m.width, m.height = 140, 45
	m.resizeOutput()
	m.focus = focusModules
	m.startPlan(plan{
		name:      "Default Enumeration",
		requested: 1,
		indices:   []int{spiderIndex},
		approvals: []approval{{index: spiderIndex, reason: "metadata traversal approval"}},
	})
	if m.approvalPrompt {
		t.Fatal("Default Enumeration opened a separate SMB Spider Plus approval prompt")
	}
	if !m.running {
		t.Fatalf("Default Enumeration did not start after the single operator approval: %q", m.status)
	}
	if m.inputPrompt || len(m.inputQueue) != 0 {
		t.Fatalf("SMB spider opened a target-input prompt: prompt=%v queue=%v status=%q", m.inputPrompt, len(m.inputQueue), m.status)
	}
}

func TestEnumerationDetailProfileHasNoDuplicateChecks(t *testing.T) {
	seen := map[string]bool{}
	for _, id := range defaultEnumerationModuleIDs {
		if seen[id] {
			t.Fatalf("duplicate %s", id)
		}
		seen[id] = true
	}
	if seen["smb-enum-cve"] || !seen["bloodyad-writable"] || !seen["maq"] || seen["smb-ntlm-reflection"] {
		t.Fatal(seen)
	}
}
