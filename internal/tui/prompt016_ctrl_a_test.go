package tui

import (
	"context"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
)

func ctrlATestModel(t *testing.T) *model {
	t.Helper()
	module := selectionModule{id: "nxc-ldap-users", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: &executionLog{}}
	m := newModel(context.Background(), config.Config{Target: "198.51.100.10", Domain: "example.test", Root: t.TempDir()}, nil, []modules.Module{module}, []int64{1}, 1, "test")
	m.focus = focusModules
	return m
}

func TestCtrlAIsBlockedOutsideToolRunnerEntryStates(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*model)
	}{
		{name: "output pane", setup: func(m *model) { m.focus = focusOutput }},
		{name: "watcher", setup: func(m *model) { m.watcher = true }},
		{name: "findings landing", setup: func(m *model) { m.findingsView = true; m.findingCategoryView = true; m.findingSubcategoryView = true }},
		{name: "nested findings detail", setup: func(m *model) {
			m.findingsView = true
			m.findingCategoryView = false
			m.findingCategory = "critical"
			m.findingDetail = true
		}},
		{name: "findings only", setup: func(m *model) { m.mode = ModeFindingsOnly; m.findingsView = true; m.findingCategoryView = true }},
		{name: "input prompt", setup: func(m *model) { m.inputPrompt = true }},
		{name: "approval prompt", setup: func(m *model) { m.approvalPrompt = true }},
		{name: "elevation prompt", setup: func(m *model) { m.elevationPrompt = true }},
		{name: "quit confirmation", setup: func(m *model) { m.quitConfirm = true }},
		{name: "active enumeration", setup: func(m *model) { m.running = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := ctrlATestModel(t)
			test.setup(m)
			runningBefore := m.running
			m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlA})
			if m.batch != nil || m.running != runningBefore || m.pendingName != "" {
				t.Fatalf("Ctrl+A started automatic enumeration: batch=%v running=%v pending=%q", m.batch != nil, m.running, m.pendingName)
			}
		})
	}
}

func TestCtrlAStartsFromBothToolRunnerEntryStates(t *testing.T) {
	for _, focus := range []paneFocus{focusNavigation, focusModules} {
		t.Run(map[paneFocus]string{focusNavigation: "navigation", focusModules: "modules"}[focus], func(t *testing.T) {
			m := ctrlATestModel(t)
			m.focus = focus
			m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlA})
			if m.batch == nil || !m.running {
				t.Fatalf("Ctrl+A did not start from Tool Runner focus %d: batch=%v running=%v status=%q", focus, m.batch != nil, m.running, m.status)
			}
			m.cancelBatch()
			if err := m.batch.Wait(context.Background()); err != nil {
				t.Fatalf("cancelled test batch did not finish: %v", err)
			}
		})
	}
}

func TestCtrlAStartsOnceFromToolRunnerAndDoesNotDuplicateRunningBatch(t *testing.T) {
	m := ctrlATestModel(t)
	m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlA})
	if m.batch == nil || !m.running {
		t.Fatalf("authorized Ctrl+A did not start: batch=%v running=%v status=%q", m.batch != nil, m.running, m.status)
	}
	first := m.batch
	m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlA})
	if m.batch != first {
		t.Fatal("repeated Ctrl+A replaced the running batch")
	}
	m.cancelBatch()
	if err := first.Wait(context.Background()); err != nil {
		t.Fatalf("cancelled test batch did not finish: %v", err)
	}
}

func TestExecuteAllCommandGuardAllowsToolRunnerNavigationAndBlocksOutput(t *testing.T) {
	m := ctrlATestModel(t)
	command := m.executeAll()
	if m.batch == nil || !m.running {
		t.Fatalf("command-layer guard blocked navigation execution: command=%v batch=%v running=%v", command != nil, m.batch != nil, m.running)
	}
	m.cancelBatch()
	if err := m.batch.Wait(context.Background()); err != nil {
		t.Fatalf("cancelled navigation batch did not finish: %v", err)
	}

	m = ctrlATestModel(t)
	m.focus = focusOutput
	if command := m.executeAll(); command != nil || m.batch != nil || m.running {
		t.Fatalf("command-layer guard allowed output execution: command=%v batch=%v running=%v", command != nil, m.batch != nil, m.running)
	}
}

func TestCtrlACancellationInvalidatesDelayedElevationResult(t *testing.T) {
	log := &executionLog{}
	module := elevatingModule{selectionModule: selectionModule{id: "needs-privileges", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log}, required: true}
	m := newModel(context.Background(), config.Config{Target: "198.51.100.10", Domain: "example.test", Root: t.TempDir()}, nil, []modules.Module{module}, []int64{1}, 1, "test")
	m.focus = focusModules
	m.pending = plan{name: "Default Enumeration", requested: 1, indices: []int{0}}
	stubSudo(t, nil)
	m.startPlan(m.pending)
	if !m.elevationPrompt {
		t.Fatal("setup did not open elevation prompt")
	}
	generation := m.planGeneration
	m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlC})
	if m.elevationPrompt || len(m.pending.indices) != 0 || m.pending.name != "" || m.running || m.batch != nil {
		t.Fatalf("Ctrl+C left setup active: prompt=%v pending=%#v running=%v batch=%v", m.elevationPrompt, m.pending, m.running, m.batch != nil)
	}
	if m.planGeneration == generation {
		t.Fatal("Ctrl+C did not invalidate the setup generation")
	}
	if command := m.finishElevation(nil); command != nil || m.batch != nil || m.running {
		t.Fatalf("stale elevation result restarted cancelled setup: command=%v batch=%v running=%v", command != nil, m.batch != nil, m.running)
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyDown})
	if m.batch != nil || m.running {
		t.Fatal("unrelated key restarted cancelled setup")
	}
}
