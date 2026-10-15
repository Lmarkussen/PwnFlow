package tui

import (
	"context"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/runner"
)

func TestTabSwitchesBetweenModuleAndOutputFocus(t *testing.T) {
	m := &model{focus: focusNavigation, outputViewport: newOutputViewport()}
	updated, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyTab})
	if updated.(*model).focus != focusModules {
		t.Fatal("Tab did not focus modules")
	}
	updated, _ = updated.(*model).handleKey(tea.KeyMsg{Type: tea.KeyTab})
	if updated.(*model).focus != focusOutput {
		t.Fatal("Tab did not focus output")
	}
	updated, _ = updated.(*model).handleKey(tea.KeyMsg{Type: tea.KeyTab})
	if updated.(*model).focus != focusNavigation {
		t.Fatal("Tab did not return focus to navigation")
	}
}

func TestOutputBuffersAreIsolatedByModule(t *testing.T) {
	first := runner.NewBuffer(100)
	second := runner.NewBuffer(100)
	_, _ = first.Write([]byte("first"))
	_, _ = second.Write([]byte("second"))
	viewport := newOutputViewport()
	viewport.Width = 20
	m := &model{ctx: context.Background(), outputBuffers: map[int]*runner.Buffer{0: first, 1: second}, cursor: 1, outputViewport: viewport}
	m.refreshOutput()
	if m.outputContent != "second" {
		t.Fatalf("got output %q", m.outputContent)
	}
}

func TestWatcherCtrlWClosesWithoutStoppingBatch(t *testing.T) {
	m := &model{watcher: true, watcherFocus: focusModules, running: true}
	updated, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlW})
	if updated.(*model).watcher {
		t.Fatal("Ctrl+W did not close watcher")
	}
	if !updated.(*model).running {
		t.Fatal("closing watcher changed execution state")
	}
}

func TestRunSelectedRequiresAnExplicitSelection(t *testing.T) {
	m := newModel(context.Background(), config.Config{}, nil, []modules.Module{viewTestModule{}}, []int64{1}, 1, "test")
	m.focus = focusModules
	updated, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	if updated.(*model).status != "no modules selected; press Space to select a module" {
		t.Fatalf("unexpected status: %q", updated.(*model).status)
	}
}

func TestGlobalQuitKeysWorkFromEveryMainFocus(t *testing.T) {
	for _, focus := range []paneFocus{focusNavigation, focusModules, focusOutput} {
		m := &model{focus: focus}
		_, cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
		if cmd == nil {
			t.Fatalf("q from focus %d did not request quit", focus)
		}
	}
}

func TestGlobalQuitKeysWorkFromEveryWatcherFocus(t *testing.T) {
	for _, focus := range []paneFocus{focusModules, focusOutput} {
		m := &model{watcher: true, watcherFocus: focus, focusBeforeWatcher: focusNavigation}
		_, cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
		if cmd == nil {
			t.Fatalf("q from watcher focus %d did not request quit", focus)
		}
	}
}

func TestCtrlCExitsWhenIdleAndCancelsWhenRunning(t *testing.T) {
	idle := &model{}
	_, cmd := idle.handleKey(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Fatal("idle Ctrl+C did not request quit")
	}

	running := &model{running: true}
	_, cmd = running.handleKey(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd != nil || running.status != "cancelling" {
		t.Fatalf("running Ctrl+C result: cmd=%v status=%q", cmd, running.status)
	}
}

func TestQDuringBatchRequiresConfirmation(t *testing.T) {
	m := &model{running: true}
	_, cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd != nil || !m.quitConfirm {
		t.Fatal("q during a batch did not request confirmation")
	}
	_, cmd = m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if cmd != nil || m.quitConfirm || m.status != "running" {
		t.Fatal("negative quit confirmation was not handled")
	}
}

func TestEscClosesWatcherAndRestoresFocus(t *testing.T) {
	m := &model{watcher: true, watcherFocus: focusOutput, focusBeforeWatcher: focusOutput}
	_, cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd != nil || m.watcher || m.focus != focusOutput {
		t.Fatalf("Esc watcher close: watcher=%t focus=%d cmd=%v", m.watcher, m.focus, cmd)
	}
}
