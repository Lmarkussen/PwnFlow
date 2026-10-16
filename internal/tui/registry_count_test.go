package tui

import (
	"context"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/modules/certipy"
	"github.com/pwnflow/pwnflow/internal/modules/netexec"
	"github.com/pwnflow/pwnflow/internal/modules/networkhound"
	"github.com/pwnflow/pwnflow/internal/modules/relayking"
	"github.com/pwnflow/pwnflow/internal/modules/rusthound"
	"github.com/pwnflow/pwnflow/internal/modules/sccm"
	"github.com/pwnflow/pwnflow/internal/modules/specialized"
)

// fullRegistry is the registry the interface builds, so a test can ask what a
// global plan actually covers.
func fullRegistry() []modules.Module {
	registry := &modules.Registry{}
	for _, builder := range []func() []modules.Module{netexec.EnumerationModules, netexec.CredentialAuditingModules, netexec.CredentialDumpingModules} {
		for _, module := range builder() {
			registry.Register(module)
		}
	}
	registry.Register(rusthound.Module{})
	for _, module := range certipy.EnumerationModules() {
		registry.Register(module)
	}
	registry.Register(sccm.SCCMHunter{Resolver: sccm.SystemResolver{}})
	registry.Register(sccm.PXEThief{})
	for _, module := range networkhound.EnumerationModules() {
		registry.Register(module)
	}
	for _, module := range relayking.EnumerationModules() {
		registry.Register(module)
	}
	for _, module := range specialized.Modules() {
		registry.Register(module)
	}
	return registry.All()
}

// A global plan is built from the registry, not from a count written down
// anywhere: it covers every family, including the network assessment tools, and
// holds the operations that need a decision.
func TestGlobalPlanCoversTheWholeRegistryWithTheNetworkTools(t *testing.T) {
	registered := fullRegistry()
	m := newModel(context.Background(), testConfig(t), nil, registered, make([]int64, len(registered)), 1, "test")
	m.width, m.height = 140, 45
	m.resizeOutput()
	plan := m.globalPlan()
	if len(plan.indices)+len(plan.skipped) != len(registered) {
		t.Fatalf("the global plan accounts for %d of %d registrations: %v", len(plan.indices)+len(plan.skipped), len(registered), plan.skipped)
	}
	families := map[modules.ToolFamily]bool{}
	approvals := map[string]bool{}
	for _, index := range plan.indices {
		families[registered[index].ToolFamily()] = true
	}
	for _, item := range plan.approvals {
		approvals[registered[item.index].ID()] = true
	}
	for _, family := range modules.ToolFamilies() {
		if !families[family] {
			t.Fatalf("the global plan covers no module of %s", family)
		}
	}
	// The two network tools are in the plan, and the domain-wide audit is held for
	// a decision rather than launched by it.
	for _, id := range []string{"networkhound-topology", "networkhound-scope-validation", "relayking-target-assessment", "relayking-domain-audit"} {
		if !approvals[id] && !containsID(registered, plan.indices, id) {
			t.Fatalf("%s is missing from the global plan", id)
		}
	}
	if !approvals["relayking-domain-audit"] {
		t.Fatal("the domain-wide relay audit is not held for approval in a global plan")
	}
	if approvals["networkhound-topology"] {
		t.Fatal("the directory collection needs no approval")
	}
	t.Logf("global plan: %s", m.planSummary(plan))
}

func containsID(registered []modules.Module, indices []int, id string) bool {
	for _, index := range indices {
		if index >= 0 && index < len(registered) && registered[index].ID() == id {
			return true
		}
	}
	return false
}
