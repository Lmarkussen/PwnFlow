package tui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/modules/rusthound"
)

type categoryTestModule struct {
	category modules.Category
	id       string
	protocol modules.Protocol
	family   modules.ToolFamily
	blocked  bool
}

func (m categoryTestModule) ID() string   { return m.id }
func (m categoryTestModule) Name() string { return m.id }
func (m categoryTestModule) ToolFamily() modules.ToolFamily {
	if m.family == "" {
		return modules.ToolFamilyNetExec
	}
	return m.family
}
func (m categoryTestModule) ExecutionEnabled() bool { return !m.blocked }
func (m categoryTestModule) AvailabilityReason() string {
	if m.blocked {
		return "scope restricted: policy blocks this module"
	}
	return ""
}
func (m categoryTestModule) Category() modules.Category { return m.category }
func (m categoryTestModule) Description() string        { return "test" }
func (m categoryTestModule) Tool() string               { return "test" }
func (m categoryTestModule) Protocol() modules.Protocol {
	if m.protocol == "" {
		return modules.ProtocolLDAP
	}
	return m.protocol
}
func (m categoryTestModule) Prerequisites() []string                       { return nil }
func (m categoryTestModule) RequiredPrivileges() []string                  { return nil }
func (m categoryTestModule) OutputFile() string                            { return m.id + ".txt" }
func (m categoryTestModule) Sensitivity() modules.Sensitivity              { return modules.SensitivityStandard }
func (m categoryTestModule) ReadOnly() bool                                { return true }
func (m categoryTestModule) SecondaryConnections() []string                { return nil }
func (m categoryTestModule) Check(context.Context, *modules.Runtime) error { return nil }
func (m categoryTestModule) Run(context.Context, *modules.Runtime, modules.OutputSink) error {
	return nil
}

func TestCategorySwitchingFiltersModulesAndPreservesSelection(t *testing.T) {
	registered := []modules.Module{
		categoryTestModule{category: modules.CategoryEnumeration, id: "enumeration"},
		categoryTestModule{category: modules.CategoryCredentialAuditing, id: "credentials"},
	}
	model := newModel(context.Background(), config.Config{}, nil, registered, []int64{1, 2}, 1, "test")
	model.selectedModules["enumeration"] = true
	model.setCategory(1)
	if len(model.modules) != 1 || model.modules[0].ID() != "credentials" {
		t.Fatalf("unexpected filtered modules: %#v", model.modules)
	}
	model.setCategory(0)
	if len(model.modules) != 1 || !model.selectedModules[model.modules[0].ID()] {
		t.Fatal("enumeration selection was not preserved")
	}
}

func TestInactiveCategoryCannotStartYolo(t *testing.T) {
	model := newModel(context.Background(), config.Config{}, nil, []modules.Module{
		categoryTestModule{category: modules.CategoryEnumeration, id: "enumeration"},
		categoryTestModule{category: modules.CategoryCredentialAuditing, id: "credentials"},
	}, []int64{1, 2}, 1, "test")
	model.setCategory(1)
	if command := model.executeAll(); command != nil {
		t.Fatal("inactive category returned an execution command")
	}
	if model.status != "category is inactive; no modules executed" {
		t.Fatalf("unexpected status: %q", model.status)
	}
}

func TestProtocolSwitchFiltersModulesWithoutChangingCategory(t *testing.T) {
	model := newModel(context.Background(), config.Config{}, nil, []modules.Module{
		categoryTestModule{category: modules.CategoryEnumeration, id: "ldap", protocol: modules.ProtocolLDAP},
		categoryTestModule{category: modules.CategoryEnumeration, id: "smb", protocol: modules.ProtocolSMB},
	}, []int64{1, 2}, 1, "test")
	if len(model.modules) != 1 || model.modules[0].ID() != "ldap" {
		t.Fatalf("unexpected LDAP scope: %#v", model.modules)
	}
	model.setProtocol(1)
	if len(model.modules) != 1 || model.modules[0].ID() != "smb" {
		t.Fatalf("unexpected SMB scope: %#v", model.modules)
	}
}

func TestNavigationChangesScopeWithoutExecuting(t *testing.T) {
	m := newModel(context.Background(), config.Config{}, nil, []modules.Module{
		categoryTestModule{category: modules.CategoryEnumeration, id: "ldap", protocol: modules.ProtocolLDAP},
		categoryTestModule{category: modules.CategoryEnumeration, id: "smb", protocol: modules.ProtocolSMB},
	}, []int64{1, 2}, 1, "test")
	if m.focus != focusNavigation || len(m.modules) != 1 {
		t.Fatal("model did not start in navigation with LDAP scope")
	}
	updated, command := m.handleKey(tea.KeyMsg{Type: tea.KeyDown})
	if command != nil || updated.(*model).navigationRow != 1 {
		t.Fatal("navigation row handling executed an action")
	}
	updated, command = updated.(*model).handleKey(tea.KeyMsg{Type: tea.KeyRight})
	if command != nil || len(updated.(*model).modules) != 0 {
		t.Fatal("navigation category change did not select an inactive scope")
	}
	updated, command = updated.(*model).handleKey(tea.KeyMsg{Type: tea.KeyTab})
	if command != nil || updated.(*model).focus != focusModules {
		t.Fatal("Tab did not move from navigation to modules")
	}
}

func TestRustHoundIsActiveDirectoryScopedAndNeverYOLOEnabled(t *testing.T) {
	model := newModel(context.Background(), config.Config{}, nil, []modules.Module{rusthound.Module{}}, []int64{1}, 1, "test")
	model.setToolFamily(2)
	if len(model.modules) != 1 || model.modules[0].ToolFamily() != modules.ToolFamilyActiveDirectory || model.modules[0].Protocol() != modules.ProtocolNA {
		t.Fatalf("RustHound was not registered in Active Directory N/A scope: %#v", model.modules)
	}
	if command := model.executeAll(); command != nil || model.status != "category is inactive; no modules executed" {
		t.Fatalf("RustHound unexpectedly entered YOLO execution: cmd=%v status=%q", command, model.status)
	}
}

// Module Information must state the pinned configuration, the expected output
// directory, and why the module stays blocked.
func TestRustHoundModuleInformationShowsPinnedConfigurationAndBlockedStatus(t *testing.T) {
	cfg := config.Config{Target: config.AuthorizedTarget, Domain: config.AuthorizedDomain, Username: "audituser", Root: t.TempDir()}
	model := newModel(context.Background(), cfg, nil, []modules.Module{rusthound.Module{}}, []int64{1}, 1, "test")
	model.setToolFamily(2)
	model.width, model.height = 150, 50
	model.resizeOutput()
	frame := ansi.Strip(model.View())
	for _, want := range []string{
		"Execution: blocked - Scope Restricted",
		"Authentication: native LDAP password",
		"Collection method: LdapOnly",
		"Output directory: ",
		"Blocked by: no enforced process-specific egress boundary",
		"Remedy: cgroup restricted to " + config.AuthorizedTarget,
		"UNAVAILABLE",
	} {
		if !strings.Contains(frame, want) {
			t.Fatalf("Module Information is missing %q:\n%s", want, frame)
		}
	}
	if strings.Contains(frame, config.AuthorizedTarget+" -c All") || strings.Contains(frame, "-c All ") {
		t.Fatalf("Module Information advertises the default collection:\n%s", frame)
	}
}

// An enabled module outside the NetExec enumeration family must be runnable from
// Enter and from an explicit R selection, while category-scoped YOLO stays
// limited to NetExec enumeration so it can never sweep it in.
func TestEnabledModuleOutsideNetExecRunsIndividuallyButNotInYolo(t *testing.T) {
	registered := []modules.Module{categoryTestModule{family: modules.ToolFamilyActiveDirectory, category: modules.CategoryEnumeration, id: "admod"}}
	// A real batch writes module output, so keep it in a temporary results root
	// instead of the package directory.
	cfg := config.Config{Target: config.AuthorizedTarget, Domain: config.AuthorizedDomain, Username: "audituser", Root: t.TempDir()}
	model := newModel(context.Background(), cfg, nil, registered, []int64{1}, 1, "test")
	model.setToolFamily(2) // Active Directory
	if len(model.modules) != 1 {
		t.Fatalf("module not reachable in the Active Directory scope: %#v", model.modules)
	}
	if command := model.executeAll(); command != nil || model.status != "category is inactive; no modules executed" {
		t.Fatalf("YOLO accepted a non-NetExec module: cmd=%v status=%q", command, model.status)
	}
	// startBatch returns no tea.Cmd even on success, so the batch state is the
	// signal: a refusal leaves running false and explains itself in status.
	model.execute(0)
	if !model.running || model.batch == nil {
		t.Fatalf("Enter refused an eligible module: status=%q", model.status)
	}
	if err := model.batch.Wait(context.Background()); err != nil {
		t.Fatalf("wait for the run: %v", err)
	}

	model.running = false
	model.selectedModules["admod"] = true
	model.executeSelected()
	if !model.running {
		t.Fatalf("R refused an explicitly selected eligible module: status=%q", model.status)
	}
	if err := model.batch.Wait(context.Background()); err != nil {
		t.Fatalf("wait for the selected run: %v", err)
	}
}

// A module that is policy-blocked or dependency-blocked refuses Enter and R.
func TestUnavailableModuleRefusesIndividualExecution(t *testing.T) {
	registered := []modules.Module{categoryTestModule{family: modules.ToolFamilyActiveDirectory, category: modules.CategoryEnumeration, id: "blocked", blocked: true}}
	model := newModel(context.Background(), config.Config{}, nil, registered, []int64{1}, 1, "test")
	model.setToolFamily(2)
	if command := model.execute(0); command != nil || model.running {
		t.Fatalf("Enter started a blocked module: cmd=%v running=%t", command, model.running)
	}
	if !strings.Contains(model.status, "unavailable") || !strings.Contains(model.status, "scope restricted") {
		t.Fatalf("refusal did not explain why: %q", model.status)
	}
	model.selectedModules["blocked"] = true
	if command := model.executeSelected(); command != nil || model.running {
		t.Fatalf("R started a blocked module: cmd=%v running=%t", command, model.running)
	}
	if model.status != "selected modules are unavailable in the current scope" {
		t.Fatalf("unexpected refusal status: %q", model.status)
	}
}
