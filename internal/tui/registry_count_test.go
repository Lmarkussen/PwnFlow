package tui

import (
	"context"
	"strings"
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
func TestGlobalPlanUsesTheCuratedProfileWithTheNetworkTools(t *testing.T) {
	registered := fullRegistry()
	m := newModel(context.Background(), testConfig(t), nil, registered, make([]int64, len(registered)), 1, "test")
	m.width, m.height = 140, 45
	m.resizeOutput()
	plan := m.globalPlan()
	selected := map[string]bool{}
	for _, index := range plan.indices {
		selected[registered[index].ID()] = true
	}
	for _, id := range defaultEnumerationModuleIDs {
		if !selected[id] && !containsID(registered, plan.indices, id) {
			found := false
			for _, skipped := range plan.skipped {
				if strings.HasPrefix(skipped, id+" ") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("profile entry %s was neither selected nor reported skipped", id)
			}
		}
	}
	if selected["masscan"] {
		t.Fatal("Masscan entered Default Enumeration")
	}
	if len(plan.indices) >= len(registered) {
		t.Fatalf("curated plan unexpectedly covers the whole registry: %d/%d", len(plan.indices), len(registered))
	}
}

func containsID(registered []modules.Module, indices []int, id string) bool {
	for _, index := range indices {
		if index >= 0 && index < len(registered) && registered[index].ID() == id {
			return true
		}
	}
	return false
}
