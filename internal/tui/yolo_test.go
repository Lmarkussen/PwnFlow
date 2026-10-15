package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// failingModule records that it ran and then fails, so a plan can be checked for
// continuing past an independent failure.
type failingModule struct{ selectionModule }

func (m failingModule) Run(ctx context.Context, _ *modules.Runtime, sink modules.OutputSink) error {
	m.log.record(m.id)
	_, _ = sink.Write([]byte(m.id + " failed\n"))
	return errors.New("module failed on purpose")
}

// yoloRegistry registers one module per tool family, plus the two
// credential-access categories, so a plan can be checked for reach.
func yoloRegistry(log *executionLog) ([]modules.Module, []int64) {
	definitions := []selectionModule{
		{id: "nxc-ldap-users", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log},
		{id: "nxc-smb-shares", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolSMB, log: log},
		{id: "adcs-discovery", family: modules.ToolFamilyADCS, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log},
		{id: "rusthound-collect", family: modules.ToolFamilyActiveDirectory, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log},
		{id: "sccmhunter", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log},
		{id: "network-hosts", family: modules.ToolFamilyNetwork, category: modules.Category("Host Discovery"), protocol: modules.ProtocolNA, log: log},
		{id: "cred-audit", family: modules.ToolFamilyNetExec, category: modules.CategoryCredentialAuditing, protocol: modules.ProtocolLDAP, log: log},
		{id: "cred-dump", family: modules.ToolFamilyNetExec, category: modules.CategoryCredentialDumping, protocol: modules.ProtocolSMB, log: log},
	}
	registered := make([]modules.Module, 0, len(definitions))
	ids := make([]int64, 0, len(definitions))
	for index, module := range definitions {
		registered = append(registered, module)
		ids = append(ids, int64(index+1))
	}
	return registered, ids
}

func yoloModel(t *testing.T, log *executionLog) *model {
	t.Helper()
	registered, ids := yoloRegistry(log)
	m := newModel(context.Background(), testConfig(t), nil, registered, ids, 1, "test")
	m.width, m.height = 140, 45
	m.resizeOutput()
	m.focus = focusModules
	return m
}

// A builds its plan from the whole registry: every family, every category, every
// protocol, whatever scope happens to be on screen. The credential-access modules
// are part of the plan but need the operator's answer before they run.
func TestYoloPlanCoversEveryFamilyFromAnyScope(t *testing.T) {
	scopes := map[string]func(t *testing.T, m *model){
		"NetExec LDAP enumeration": func(t *testing.T, m *model) {
			navigateTo(t, m, modules.ToolFamilyNetExec, modules.CategoryEnumeration)
			m.setProtocol(0)
		},
		"SCCM enumeration": func(t *testing.T, m *model) {
			navigateTo(t, m, modules.ToolFamilySCCM, modules.CategoryEnumeration)
		},
		"flat AD CS family": func(t *testing.T, m *model) {
			navigateTo(t, m, modules.ToolFamilyADCS, modules.CategoryEnumeration)
			if len(m.modules) != 1 || m.modules[0].ID() != "adcs-discovery" {
				t.Fatalf("the flat AD CS scope is wrong: %v", moduleIDs(m.modules))
			}
		},
	}
	var reference []string
	for name, scope := range scopes {
		t.Run(name, func(t *testing.T) {
			log := &executionLog{}
			m := yoloModel(t, log)
			scope(t, m)
			plan := m.globalPlan()
			got := m.planNames(plan.indices)
			if len(got) != len(m.allModules) {
				t.Fatalf("the plan holds %d of %d modules: %v", len(got), len(m.allModules), plan.skipped)
			}
			if reference == nil {
				reference = got
			} else if strings.Join(got, ",") != strings.Join(reference, ",") {
				t.Fatalf("the plan depends on the visible scope: %v vs %v", got, reference)
			}
		})
	}
	// The plan is not just the visible slice: it crosses families and protocols.
	log := &executionLog{}
	m := yoloModel(t, log)
	plan := m.globalPlan()
	families := map[modules.ToolFamily]bool{}
	for _, index := range plan.indices {
		families[m.allModules[index].ToolFamily()] = true
	}
	if len(families) != len(modules.ToolFamilies()) {
		t.Fatalf("the plan covers %d of %d tool families", len(families), len(modules.ToolFamilies()))
	}
}

// The credential-access modules in a plan are named and held back until the
// operator approves them; declining runs the rest of the plan.
func TestYoloAsksBeforeCredentialAccess(t *testing.T) {
	log := &executionLog{}
	m := yoloModel(t, log)
	navigateTo(t, m, modules.ToolFamilyNetExec, modules.CategoryEnumeration)
	press(t, m, "a")
	if !m.approvalPrompt || m.running {
		t.Fatalf("A started without asking: prompt=%v running=%v status=%q", m.approvalPrompt, m.running, m.status)
	}
	if !strings.Contains(m.status, "cred-audit") || !strings.Contains(m.status, "cred-dump") {
		t.Fatalf("the approval prompt does not name the modules: %q", m.status)
	}
	press(t, m, "n")
	if !m.running {
		t.Fatalf("declining the credential modules left nothing to run: %q", m.status)
	}
	for _, id := range batchIDs(m) {
		if id == "cred-audit" || id == "cred-dump" {
			t.Fatalf("a declined module entered the batch: %v", batchIDs(m))
		}
	}
	if len(m.batchItems) != len(m.allModules)-2 {
		t.Fatalf("the batch holds %d modules, want the %d enumeration modules", len(m.batchItems), len(m.allModules)-2)
	}
	waitForBatch(t, m)
	if got := log.executed(); len(got) != len(m.allModules)-2 {
		t.Fatalf("execution does not match the approved plan: %v", got)
	}

	// Approving them runs the whole plan.
	approved := &executionLog{}
	second := yoloModel(t, approved)
	press(t, second, "a")
	press(t, second, "y")
	if !second.running || len(second.batchItems) != len(second.allModules) {
		t.Fatalf("approving started %d of %d modules", len(second.batchItems), len(second.allModules))
	}
	waitForBatch(t, second)
	if got := approved.executed(); len(got) != len(second.allModules) {
		t.Fatalf("an approved module did not run: %v", got)
	}
}

// A failed module does not stop the plan: the batch reports it and continues.
func TestYoloContinuesAfterAFailure(t *testing.T) {
	log := &executionLog{}
	registered, ids := yoloRegistry(log)
	registered[1] = failingModule{selectionModule: selectionModule{id: "nxc-smb-shares", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolSMB, log: log}}
	m := newModel(context.Background(), testConfig(t), nil, registered, ids, 1, "test")
	m.width, m.height = 140, 45
	m.resizeOutput()
	m.focus = focusModules
	press(t, m, "a")
	if m.approvalPrompt {
		press(t, m, "n")
	}
	waitForBatch(t, m)
	executed := log.executed()
	if len(executed) != len(registered)-2 {
		t.Fatalf("the plan stopped at the failure: %v", executed)
	}
	if !strings.Contains(executed[len(executed)-1], "network") {
		t.Fatalf("the modules after the failure did not run: %v", executed)
	}
}

// Cancelling during the plan keeps the rest of the plan from starting.
func TestCancellingThePlanStopsIt(t *testing.T) {
	log := &executionLog{}
	m := yoloModel(t, log)
	press(t, m, "a")
	press(t, m, "ctrl+c")
	if m.running || m.approvalPrompt || m.inputPrompt {
		t.Fatalf("cancelling left the plan active: running=%v status=%q", m.running, m.status)
	}
	if len(log.executed()) != 0 {
		t.Fatalf("cancelling a pending plan still ran modules: %v", log.executed())
	}
	// A batch that is already running cancels through the existing path.
	second := yoloModel(t, log)
	press(t, second, "a")
	if second.approvalPrompt {
		press(t, second, "n")
	}
	if !second.running {
		t.Fatal("the plan did not start")
	}
	press(t, second, "ctrl+c")
	if !strings.Contains(second.status, "cancelling") {
		t.Fatalf("cancellation was not reported: %q", second.status)
	}
	waitForBatch(t, second)
}

// Pressing A twice from different scopes produces the same plan, and the plan
// never lists a module twice.
func TestYoloPlanIsDeterministicAndUnique(t *testing.T) {
	log := &executionLog{}
	m := yoloModel(t, log)
	first := m.planNames(m.globalPlan().indices)
	navigateTo(t, m, modules.ToolFamilySCCM, modules.CategoryEnumeration)
	second := m.planNames(m.globalPlan().indices)
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatalf("the plan is not deterministic: %v vs %v", first, second)
	}
	seen := map[string]bool{}
	for _, name := range first {
		if seen[name] {
			t.Fatalf("%s appears twice in the plan", name)
		}
		seen[name] = true
	}
}

// A module registered twice in the same registry view runs once: the plan is
// keyed by module identifier, not by position.
func TestYoloRunsADuplicateRegistrationOnce(t *testing.T) {
	log := &executionLog{}
	module := selectionModule{id: "twice", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log}
	other := selectionModule{id: "once", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log}
	m := newModel(context.Background(), testConfig(t), nil, []modules.Module{module, module, other}, []int64{1, 2, 3}, 1, "test")
	m.width, m.height = 140, 45
	m.resizeOutput()
	m.focus = focusModules

	plan := m.globalPlan()
	if len(plan.indices) != 2 {
		t.Fatalf("the plan holds %d entries for two distinct modules: %v", len(plan.indices), plan.indices)
	}
	if len(plan.skipped) != 1 || !strings.Contains(plan.skipped[0], "duplicate") {
		t.Fatalf("the duplicate was not reported: %v", plan.skipped)
	}
	press(t, m, "a")
	waitForBatch(t, m)
	executed := log.executed()
	if len(executed) != 2 {
		t.Fatalf("execution = %v, want each module once", executed)
	}
	for _, id := range executed {
		if strings.Count(strings.Join(executed, ","), id) != 1 {
			t.Fatalf("%s ran more than once: %v", id, executed)
		}
	}
}

// orderedModule declares that it must run after another module, the way PXEThief
// declares SCCMhunter.
type orderedModule struct {
	selectionModule
	requires []string
}

func (m orderedModule) BatchPrerequisites() []string { return m.requires }

// The global plan keeps the declared prerequisites: a module that consumes another
// module's discovery runs after it, whatever order the registry holds them in.
func TestGlobalPlanHonoursDeclaredPrerequisites(t *testing.T) {
	log := &executionLog{}
	consumer := orderedModule{
		selectionModule: selectionModule{id: "pxethief-like", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log},
		requires:        []string{"sccmhunter-like"},
	}
	producer := selectionModule{id: "sccmhunter-like", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log}
	// The consumer is registered first, so only the prerequisite can put it second.
	m := newModel(context.Background(), testConfig(t), nil, []modules.Module{consumer, producer}, []int64{1, 2}, 1, "test")
	m.width, m.height = 140, 45
	m.resizeOutput()
	m.focus = focusModules

	press(t, m, "a")
	waitForBatch(t, m)
	executed := log.executed()
	if len(executed) != 2 || executed[0] != "sccmhunter-like" || executed[1] != "pxethief-like" {
		t.Fatalf("the plan ignored the declared prerequisite: %v", executed)
	}
}
