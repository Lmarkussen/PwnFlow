package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/modules/certipy"
)

// certipyFamilyIndex is the AD CS row of the navigation pane.
const certipyFamilyIndex = 1

func certipyModel(t *testing.T, availability ...map[string]string) *model {
	t.Helper()
	registered := make([]modules.Module, 0, 3)
	ids := make([]int64, 0, 3)
	for index, module := range certipy.EnumerationModules() {
		registered = append(registered, module)
		ids = append(ids, int64(index+1))
	}
	cfg := config.Config{Target: testTarget, Domain: testDomain, Username: "audituser", Root: t.TempDir()}
	m := newModel(context.Background(), cfg, nil, registered, ids, 1, "test", availability...)
	m.setToolFamily(certipyFamilyIndex)
	m.width, m.height = 150, 50
	m.resizeOutput()
	return m
}

// The Certipy modules appear in the existing navigation taxonomy, in the LDAP
// scope of AD CS enumeration, and carry no status suffix without any special
// setup.
func TestCertipyModulesAppearUnderADCSEnumeration(t *testing.T) {
	m := certipyModel(t)
	if len(m.modules) != 3 {
		t.Fatalf("expected the Certipy modules in the AD CS enumeration scope: %#v", m.modules)
	}
	for _, module := range m.modules {
		if module.ToolFamily() != modules.ToolFamilyADCS || module.Category() != modules.CategoryEnumeration || module.Protocol() != modules.ProtocolLDAP {
			t.Errorf("module is not in AD CS -> Enumeration -> LDAP scope: %#v", module)
		}
	}
	for index := range m.modules {
		if state := m.moduleState(index); state != "" {
			t.Fatalf("row %d is %q; an available module carries no suffix", index, state)
		}
	}
}

// A missing dependency is reported from the same availability data the rest of
// the TUI uses, and the row is not presented as runnable.
func TestCertipyModulesReportAMissingDependency(t *testing.T) {
	m := certipyModel(t, map[string]string{"certipy": "Certipy (AD CS): binary is not installed; install with install.sh --with-certipy"})
	if state := m.moduleState(0); state != "UNAVAILABLE" {
		t.Fatalf("a missing dependency still showed %q", state)
	}
	if reason := m.moduleAvailability(m.modules[0]); !strings.Contains(reason, "install.sh --with-certipy") {
		t.Fatalf("the missing dependency remedy is not surfaced: %q", reason)
	}
	if frame := ansi.Strip(m.View()); !strings.Contains(frame, "UNAVAILABLE") {
		t.Fatalf("the unavailable row is not shown:\n%s", frame)
	}
	if command := m.execute(0); command != nil {
		t.Fatal("an unavailable module still produced an execution command")
	}
}

// Module Information must state the enabled state, the pinned transport and
// scope, the output directory, and a redacted command preview.
func TestCertipyModuleInformationShowsConfiguration(t *testing.T) {
	m := certipyModel(t)
	m.cursor = 0
	frame := ansi.Strip(m.View())
	for _, want := range []string{
		"Family: AD CS",
		"Category: Enumeration",
		"Tool: Certipy",
		"Protocol: LDAP",
		"Execution: enabled",
		"Collection scope: -dc-only",
		"Transport: LDAPS (explicit -ldap-scheme ldaps -ldap-port 636",
		"Output directory: ",
		"Availability: AVAILABLE",
	} {
		if !strings.Contains(frame, want) {
			t.Fatalf("Module Information is missing %q:\n%s", want, frame)
		}
	}
	if strings.Contains(frame, "Sup3rSecret") {
		t.Fatalf("Module Information leaked a credential:\n%s", frame)
	}
}

// Certipy is not a NetExec enumeration module, so category-scoped YOLO stays
// limited to NetExec and can never sweep it in.
func TestCertipyIsNeverSweptIntoYolo(t *testing.T) {
	m := certipyModel(t)
	if command := m.executeAll(); command != nil || m.status != "category is inactive; no modules executed" {
		t.Fatalf("Certipy entered YOLO execution: cmd=%v status=%q", command, m.status)
	}
}

// Enter runs the highlighted module and R runs the explicitly selected one, both
// through the existing runner, and both stop through the existing cancellation.
func TestCertipyRunsFromEnterAndFromSelection(t *testing.T) {
	m := certipyModel(t)
	updated, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyTab})
	focused := updated.(*model)
	focused.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if !focused.running || focused.batch == nil {
		t.Fatalf("Enter refused the highlighted Certipy module: status=%q", focused.status)
	}
	if focused.batchItems[0].Module.ID() != focused.modules[focused.cursor].ID() {
		t.Fatalf("Enter ran the wrong module: %#v", focused.batchItems[0].Module.ID())
	}
	focused.cancelBatch()
	waitContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := focused.batch.Wait(waitContext); err != nil {
		t.Fatalf("cancellation did not stop the run: %v", err)
	}

	selected := certipyModel(t)
	selected.selectedModules[selected.modules[1].ID()] = true
	selected.executeSelected()
	if !selected.running || len(selected.batchItems) != 1 {
		t.Fatalf("R refused the explicitly selected module: status=%q", selected.status)
	}
	if selected.batchItems[0].Module.ID() != selected.modules[1].ID() {
		t.Fatalf("selection ran the wrong modules: %#v", selected.batchItems)
	}
	selected.cancelBatch()
	selectedWait, selectedCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer selectedCancel()
	if err := selected.batch.Wait(selectedWait); err != nil {
		t.Fatalf("cancellation did not stop the selected run: %v", err)
	}
}
