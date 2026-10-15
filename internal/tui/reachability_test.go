package tui

import (
	"context"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// reachableModules walks the navigation the way an operator does - tool family,
// then category, then protocol - and returns every module the interface can
// actually show.
//
// The registry is the source of truth, and the navigation is what the operator
// browses. A registration the navigation cannot reach is invisible in practice, no
// matter what a registry count says, so this exists as an invariant rather than as
// another count to compare.
func reachableModules(t *testing.T, m *model) map[string]string {
	t.Helper()
	reachable := make(map[string]string)
	for familyIndex, family := range m.toolFamilies {
		m.setToolFamily(familyIndex)
		categories := append([]modules.Category(nil), m.categories...)
		for categoryIndex, category := range categories {
			m.setCategory(categoryIndex)
			protocols := append([]modules.Protocol(nil), m.protocols...)
			for protocolIndex, protocol := range protocols {
				m.setProtocol(protocolIndex)
				for _, module := range m.modules {
					scope := string(family) + " → " + string(category) + " → " + string(protocol)
					if previous, ok := reachable[module.ID()]; ok && previous != scope {
						t.Errorf("%s is reachable from two scopes: %s and %s", module.ID(), previous, scope)
					}
					reachable[module.ID()] = scope
				}
			}
		}
	}
	m.setToolFamily(0)
	return reachable
}

// Every registration the interface builds has to be reachable through the normal
// family → category → protocol browser. This is the invariant that keeps the
// registry and the operator's view from drifting apart: a module filed under a
// category its own family does not offer is invisible, however the registry is
// counted.
func TestEveryRegisteredModuleIsReachableThroughTheBrowser(t *testing.T) {
	registered := fullRegistry()
	m := newModel(context.Background(), testConfig(t), nil, registered, make([]int64, len(registered)), 1, "test")
	m.width, m.height = 140, 45
	m.resizeOutput()

	reachable := reachableModules(t, m)
	for _, module := range registered {
		if _, ok := reachable[module.ID()]; !ok {
			t.Errorf("%s (%s → %s) is not reachable from the browser",
				module.ID(), module.ToolFamily(), module.Category())
		}
	}
}

// The Network family is a first-class family: its registrations are reachable
// there, they are not hidden by their availability state, and the ones that need a
// decision or a value are still listed.
func TestNetworkFamilyShowsItsRegistrations(t *testing.T) {
	registered := fullRegistry()
	m := newModel(context.Background(), testConfig(t), nil, registered, make([]int64, len(registered)), 1, "test")
	m.width, m.height = 140, 45
	m.resizeOutput()

	familyIndex := -1
	for index, family := range m.toolFamilies {
		if family == modules.ToolFamilyNetwork {
			familyIndex = index
		}
	}
	if familyIndex < 0 {
		t.Fatalf("the Network family is not offered: %v", m.toolFamilies)
	}
	m.setToolFamily(familyIndex)
	visible := make(map[string]bool)
	for _, category := range append([]modules.Category(nil), m.categories...) {
		m.setCategory(categoryIndex(t, m, category))
		for _, protocol := range append([]modules.Protocol(nil), m.protocols...) {
			m.setProtocol(protocolIndex(t, m, protocol))
			for _, module := range m.modules {
				visible[module.ID()] = true
			}
		}
	}

	want := []string{
		"networkhound-topology",
		"networkhound-scope-validation",
		"relayking-target-assessment",
		"relayking-domain-audit",
	}
	for _, id := range want {
		if !visible[id] {
			t.Errorf("%s is not visible under Network", id)
		}
	}
	// A module that needs a scope or a decision is still discoverable: it is a
	// browser entry, not a hidden one.
	for _, id := range []string{"networkhound-scope-validation", "relayking-domain-audit"} {
		if !visible[id] {
			t.Fatalf("%s disappeared because it needs input or approval", id)
		}
	}
	// The scope-dependent registration says what it is waiting for, in the same
	// vocabulary the NetExec registrations use.
	m.setCategory(categoryIndex(t, m, modules.CategoryServiceEnumeration))
	m.setProtocol(protocolIndex(t, m, modules.ProtocolNA))
	row := rowOf(t, m, "networkhound-scope-validation")
	if state := m.moduleState(row); state != "INPUT-REQ" {
		t.Fatalf("the scope registration shows %q, want INPUT-REQ", state)
	}
	m.cursor = row
	if frame := ansi.Strip(m.View()); !strings.Contains(frame, "CONFIGURABLE: needs NETWORKS") {
		t.Fatalf("Module Information does not say what it needs:\n%s", frame)
	}
	// And it is still in a global plan: needing input is not a reason to be left
	// out of one.
	plan := m.globalPlan()
	found := false
	for _, index := range plan.indices {
		if registered[index].ID() == "networkhound-scope-validation" {
			found = true
		}
	}
	if !found {
		t.Fatal("a scope-dependent registration is missing from the global plan")
	}
}

func protocolIndex(t *testing.T, m *model, protocol modules.Protocol) int {
	t.Helper()
	for index, value := range m.protocols {
		if value == protocol {
			return index
		}
	}
	t.Fatalf("protocol %s is not offered in this scope: %v", protocol, m.protocols)
	return 0
}
