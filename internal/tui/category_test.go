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

// Fixtures for arbitrary operator-supplied assessment configuration.
const (
	testTarget = "198.51.100.10"
	testDomain = "example.test"
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

// YOLO is global: a flat family view does not narrow the plan, because the plan
// comes from the registry rather than from what is on screen.
func TestYoloFromAFlatScopeStillPlansTheEntireRegistry(t *testing.T) {
	log := &executionLog{}
	registered := []modules.Module{
		selectionModule{id: "nxc-ldap-users", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log},
		selectionModule{id: "adcs-discovery", family: modules.ToolFamilyADCS, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log},
		selectionModule{id: "rusthound-collect", family: modules.ToolFamilyActiveDirectory, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log},
	}
	ids := []int64{1, 2, 3}
	m := newModel(context.Background(), testConfig(t), nil, registered, ids, 1, "test")
	m.width, m.height = 140, 45
	m.resizeOutput()
	m.focus = focusModules
	navigateTo(t, m, modules.ToolFamilyADCS, modules.CategoryEnumeration)
	if len(m.modules) != 1 || m.modules[0].ID() != "adcs-discovery" {
		t.Fatalf("the flat AD CS scope is wrong: %v", moduleIDs(m.modules))
	}
	press(t, m, "a")
	waitForBatch(t, m)
	if got := log.executed(); strings.Join(got, ",") != "nxc-ldap-users,adcs-discovery,rusthound-collect" {
		t.Fatalf("YOLO from an empty scope ran %v, want the whole registry", got)
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

func TestRustHoundIsActiveDirectoryScopedAndPlannedGlobally(t *testing.T) {
	model := newModel(context.Background(), config.Config{}, nil, []modules.Module{rusthound.Module{}}, []int64{1}, 1, "test")
	model.setToolFamily(2)
	if len(model.modules) != 1 || model.modules[0].ToolFamily() != modules.ToolFamilyActiveDirectory || model.modules[0].Protocol() != modules.ProtocolNA {
		t.Fatalf("RustHound was not registered in Active Directory N/A scope: %#v", model.modules)
	}
	// It is not reachable from another family's scope, and YOLO does not care:
	// the plan is global, so the module is included wherever the cursor happens to be.
	plan := model.globalPlan()
	if len(plan.indices) != 1 {
		t.Fatalf("RustHound is missing from the global plan: %v", plan.indices)
	}
}

// Module Information must state the enabled state, the pinned configuration, the
// expected output directory, and that the pinned scope is not a boundary.
func TestRustHoundModuleInformationShowsEnabledConfiguration(t *testing.T) {
	cfg := config.Config{Target: testTarget, Domain: testDomain, Username: "audituser", Root: t.TempDir()}
	model := newModel(context.Background(), cfg, nil, []modules.Module{rusthound.Module{}}, []int64{1}, 1, "test")
	model.setToolFamily(2)
	model.width, model.height = 150, 50
	model.resizeOutput()
	if state := model.moduleState(0); state != "" {
		t.Fatalf("RustHound row is %q; an available module carries no suffix", state)
	}
	frame := ansi.Strip(model.View())
	for _, want := range []string{
		"Execution: enabled",
		"Authentication: native LDAP password",
		"Collection method: LdapOnly",
		"Output directory: ",
		"Network scope: LdapOnly over LDAPS against the supplied target",
		"Availability: AVAILABLE",
	} {
		if !strings.Contains(frame, want) {
			t.Fatalf("Module Information is missing %q:\n%s", want, frame)
		}
	}
	if strings.Contains(frame, "REA"+"DY") {
		t.Fatalf("the interface still labels a ready module:\n%s", frame)
	}
	if strings.Contains(frame, testTarget+" -c All") || strings.Contains(frame, "-c All ") {
		t.Fatalf("Module Information advertises the default collection:\n%s", frame)
	}
}

// An enabled module outside NetExec is runnable from Enter, from an explicit R
// selection, and from the global YOLO plan - the same module, one plan, whichever
// key asked for it.
func TestEnabledModuleOutsideNetExecRunsFromEveryEntryPoint(t *testing.T) {
	registered := []modules.Module{categoryTestModule{family: modules.ToolFamilyActiveDirectory, category: modules.CategoryEnumeration, id: "admod"}}
	// A real batch writes module output, so keep it in a temporary results root
	// instead of the package directory.
	cfg := config.Config{Target: testTarget, Domain: testDomain, Username: "audituser", Root: t.TempDir()}
	model := newModel(context.Background(), cfg, nil, registered, []int64{1}, 1, "test")
	model.setToolFamily(2) // Active Directory
	if len(model.modules) != 1 {
		t.Fatalf("module not reachable in the Active Directory scope: %#v", model.modules)
	}
	if plan := model.globalPlan(); len(plan.indices) != 1 {
		t.Fatalf("YOLO left a non-NetExec module out of the global plan: %v", plan.indices)
	}
	model.executeAll()
	if err := model.batch.Wait(context.Background()); err != nil {
		t.Fatalf("wait for the YOLO run: %v", err)
	}
	model.running = false

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
	if !strings.Contains(model.status, "cannot run") || !strings.Contains(model.status, "blocked") {
		t.Fatalf("refusal did not name the unavailable selection: %q", model.status)
	}
	// The global plan leaves it out too, and says why.
	plan := model.globalPlan()
	if len(plan.indices) != 0 {
		t.Fatalf("the global plan includes a blocked module: %v", plan.indices)
	}
	if len(plan.skipped) != 1 || !strings.Contains(plan.skipped[0], "scope restricted") {
		t.Fatalf("the global plan did not report the blocked module: %v", plan.skipped)
	}
}
