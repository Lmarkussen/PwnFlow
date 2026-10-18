package tui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/runner"
)

func TestWrapWatcherOutputPreservesLongLines(t *testing.T) {
	input := "LDAP  198.51.100.10  389  DC  [+] corp.example\\svc-audit: [REDACTED] (Pwn3d!)"
	wrapped := wrapWatcherOutput(input, 24)
	if strings.ReplaceAll(wrapped, "\n", "") != input {
		t.Fatalf("wrapped output lost characters: %q", wrapped)
	}
	for _, line := range strings.Split(wrapped, "\n") {
		if ansi.StringWidthWc(line) > 24 {
			t.Fatalf("line exceeds width: %q", line)
		}
	}
}

func TestWatcherRetainsAndNavigatesFullBatchHistory(t *testing.T) {
	all := make([]modules.Module, 30)
	items := make([]runner.BatchItem, 30)
	for index := range all {
		all[index] = viewTestModule{}
		items[index] = runner.BatchItem{Index: index, Module: all[index], Buffer: runner.NewBuffer(128)}
	}
	m := newModel(context.Background(), config.Config{}, nil, all, make([]int64, 30), 1, "test")
	m.modules = all
	m.moduleKeys = make([]int, 30)
	for index := range m.moduleKeys {
		m.moduleKeys[index] = index
	}
	m.batch = runner.NewBatchRun(items)
	m.width, m.height = 120, 30
	m.watcherListViewport = newWatcherViewport()
	m.watcherViewport = newWatcherViewport()
	m.resizeWatcher()
	m.setWatcherSelection(0, true)
	if !strings.Contains(m.watcherListViewport.View(), "View Module") {
		t.Fatal("first batch module is not visible")
	}
	m.setWatcherSelection(15, true)
	if m.watcherSelected != 15 {
		t.Fatalf("middle selection = %d", m.watcherSelected)
	}
	m.setWatcherSelection(29, true)
	if m.watcherListCursor != 29 || m.watcherSelected != 29 {
		t.Fatal("last batch module is not selectable")
	}
}

func TestWatcherHeaderOmitsUnavailableAndCancelledCounters(t *testing.T) {
	module := viewTestModule{}
	item := runner.BatchItem{Index: 0, Module: module, Buffer: runner.NewBuffer(128)}
	m := newModel(context.Background(), config.Config{Domain: "example.test"}, nil, []modules.Module{module}, []int64{1}, 1, "test")
	m.batch = runner.NewBatchRun([]runner.BatchItem{item})
	m.batchName = "Default Enumeration"
	header := m.batchSummary()
	if strings.Contains(header, "Unavailable:") || strings.Contains(header, "Cancelled:") {
		t.Fatalf("watcher header still exposes removed counters: %q", header)
	}
}

func TestWrapWatcherOutputHandlesANSIUnicodeAndNarrowWidths(t *testing.T) {
	input := "\x1b[32m界界界界界界\x1b[0m café café\n第二行"
	wrapped := wrapWatcherOutput(input, 2)
	if ansi.Strip(strings.ReplaceAll(wrapped, "\n", "")) != ansi.Strip(strings.ReplaceAll(input, "\n", "")) {
		t.Fatalf("ANSI/Unicode content changed: %q", wrapped)
	}
	for _, line := range strings.Split(wrapped, "\n") {
		if ansi.StringWidthWc(line) > 2 {
			t.Fatalf("narrow line exceeds width: %q", line)
		}
	}
}

func TestWrapWatcherOutputPreservesMultipleLines(t *testing.T) {
	input := "first very long line with words\nsecond very long line with words\nthird"
	wrapped := wrapWatcherOutput(input, 10)
	if strings.ReplaceAll(wrapped, "\n", "") != strings.ReplaceAll(input, "\n", "") {
		t.Fatalf("multiple lines changed: %q", wrapped)
	}
}

func TestWatcherPendingPlanShowsOnlyPlannedModules(t *testing.T) {
	all := make([]modules.Module, 8)
	for index := range all {
		all[index] = viewTestModule{}
	}
	m := newModel(context.Background(), config.Config{}, nil, all, make([]int64, len(all)), 1, "test")
	m.modules = all
	m.moduleKeys = make([]int, len(all))
	for index := range m.moduleKeys {
		m.moduleKeys[index] = index
	}
	m.pendingIndices = []int{1, 5, 7}

	states := m.watcherStates()
	if len(states) != len(m.pendingIndices) {
		t.Fatalf("pending watcher has %d rows, want %d: %#v", len(states), len(m.pendingIndices), states)
	}
	for position, state := range states {
		if state.Index != m.pendingIndices[position] {
			t.Fatalf("pending row %d has index %d, want %d", position, state.Index, m.pendingIndices[position])
		}
		if state.Status != "queued" {
			t.Fatalf("pending row %d has status %q, want queued", position, state.Status)
		}
	}
}

func TestWatcherDoesNotTreatVisibleFamilyAsQueuedBatch(t *testing.T) {
	all := make([]modules.Module, 8)
	for index := range all {
		all[index] = viewTestModule{}
	}
	m := newModel(context.Background(), config.Config{}, nil, all, make([]int64, len(all)), 1, "test")
	m.modules = all
	m.moduleKeys = make([]int, len(all))
	for index := range m.moduleKeys {
		m.moduleKeys[index] = index
	}
	if states := m.watcherStates(); len(states) != 0 {
		t.Fatalf("idle watcher exposed visible family as queued work: %#v", states)
	}
}

func TestWatcherNonRunningMessageIsActionScoped(t *testing.T) {
	m := &model{status: "Module is not running", width: 100}
	message := ansi.Strip(m.watcherStatusLine())
	if !strings.Contains(message, "Selected action: Module is not running") {
		t.Fatalf("watcher status was not scoped to selected action: %q", message)
	}
}

func TestWatcherQUsesGlobalQuitPathWhenIdle(t *testing.T) {
	for _, focus := range []paneFocus{focusModules, focusOutput} {
		m := &model{watcher: true, watcherFocus: focus, width: 100, height: 30}
		_, command := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
		if command == nil {
			t.Fatalf("focus %d: q did not request quit", focus)
		}
		if m.running || m.quitConfirm {
			t.Fatalf("focus %d: q changed state incorrectly: running=%t confirm=%t", focus, m.running, m.quitConfirm)
		}
	}
}

func TestWatcherQUsesSafeConfirmationDuringActiveBatch(t *testing.T) {
	m := &model{watcher: true, watcherFocus: focusOutput, running: true, width: 100, height: 30}
	_, command := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'Q'}})
	if command != nil || !m.quitConfirm || !m.running {
		t.Fatalf("active watcher Q bypassed safe confirmation: command=%v confirm=%t running=%t", command, m.quitConfirm, m.running)
	}
	if !strings.Contains(m.status, "cancel and quit") {
		t.Fatalf("active watcher Q did not explain the safe action: %q", m.status)
	}
}
