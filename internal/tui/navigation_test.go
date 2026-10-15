package tui

import (
	"context"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// reportingModule is a module that still declares the retired Reporting taxonomy.
// Nothing in the navigation may expose it.
type reportingModule struct{ selectionModule }

func (m reportingModule) ID() string   { return "reporting-generate" }
func (m reportingModule) Name() string { return "Generate Report" }
func (m reportingModule) ToolFamily() modules.ToolFamily {
	return modules.ToolFamily("Reporting")
}
func (m reportingModule) Category() modules.Category { return modules.Category("Reporting") }
func (m reportingModule) Protocol() modules.Protocol { return modules.ProtocolNA }

// Reporting is gone from the taxonomy: no tool family, no category, and no
// protocol scope can present it.
func TestReportingIsAbsentFromTheTaxonomy(t *testing.T) {
	for _, family := range modules.ToolFamilies() {
		if family == "Reporting" {
			t.Fatal("Reporting is still a tool family")
		}
		for _, category := range modules.CategoriesForFamily(family) {
			if category == "Reporting" {
				t.Fatalf("Reporting is still a category of %q", family)
			}
		}
	}
	for _, category := range modules.Categories() {
		if category == "Reporting" {
			t.Fatal("Reporting is still a category")
		}
	}
	for _, protocol := range modules.Protocols() {
		if protocol == "Reporting" {
			t.Fatal("Reporting is still a protocol")
		}
	}
	if len(modules.ToolFamilies()) != 4 {
		t.Fatalf("unexpected tool families: %v", modules.ToolFamilies())
	}
	for _, want := range []modules.ToolFamily{modules.ToolFamilyNetExec, modules.ToolFamilyADCS, modules.ToolFamilyActiveDirectory, modules.ToolFamilyNetwork} {
		if !containsFamily(modules.ToolFamilies(), want) {
			t.Fatalf("tool family %q was removed along with Reporting", want)
		}
	}
}

func containsFamily(families []modules.ToolFamily, wanted modules.ToolFamily) bool {
	for _, family := range families {
		if family == wanted {
			return true
		}
	}
	return false
}

// Cycling every navigation value must never show Reporting, and no visible row may
// carry it either.
func TestNavigationNeverShowsReporting(t *testing.T) {
	log := &executionLog{}
	registered, ids := mixedRegistry(log)
	registered = append(registered, reportingModule{selectionModule{id: "reporting-generate", log: log}})
	ids = append(ids, int64(len(ids)+1))
	m := newModel(context.Background(), testConfig(t), nil, registered, ids, 1, "test")
	m.width, m.height = 150, 50
	m.resizeOutput()

	for familyIndex := range m.toolFamilies {
		m.setToolFamily(familyIndex)
		for categoryIndex := range m.categories {
			m.setCategory(categoryIndex)
			for protocolIndex := range m.protocols {
				m.setProtocol(protocolIndex)
				for _, module := range m.modules {
					if module.Category() == "Reporting" || module.ToolFamily() == "Reporting" {
						t.Fatalf("a Reporting module is reachable in %q/%q/%q: %s", m.toolFamilies[familyIndex], m.categories[categoryIndex], m.protocols[protocolIndex], module.ID())
					}
				}
				frame := renderFrame(m)
				if strings.Contains(frame, "Reporting") {
					t.Fatalf("the navigation still shows Reporting:\n%s", frame)
				}
			}
		}
	}
	if m.selectedCount() != 0 {
		t.Fatalf("a Reporting module appeared as selected: %d", m.selectedCount())
	}
}

// The retired module cannot be run through any execution path: it is not visible,
// so it cannot be highlighted, selected, or swept up by YOLO, and R has nothing to
// resolve it from.
func TestReportingModuleCannotBeExecuted(t *testing.T) {
	log := &executionLog{}
	registered, ids := mixedRegistry(log)
	registered = append(registered, reportingModule{selectionModule{id: "reporting-generate", log: log}})
	ids = append(ids, int64(len(ids)+1))
	m := newModel(context.Background(), testConfig(t), nil, registered, ids, 1, "test")
	m.width, m.height = 150, 50
	m.resizeOutput()
	m.focus = focusModules

	navigateTo(t, m, modules.ToolFamilyNetExec, modules.CategoryEnumeration)
	press(t, m, "a")
	waitForBatch(t, m)

	// Nothing is selected, so R has nothing to resolve: no batch may start.
	m.batch, m.batchItems, m.running = nil, nil, false
	press(t, m, "r")
	if m.batch != nil {
		t.Fatalf("R started a batch with nothing selected: %v", batchIDs(m))
	}
	if !strings.Contains(m.status, "no modules selected") {
		t.Fatalf("unexpected status: %q", m.status)
	}

	m.focus = focusModules
	m.cursor = 0
	press(t, m, "enter")
	waitForBatch(t, m)
	for _, id := range log.executed() {
		if id == "reporting-generate" {
			t.Fatal("the retired Reporting module was executed")
		}
	}
}
