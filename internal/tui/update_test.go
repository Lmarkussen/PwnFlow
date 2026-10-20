package tui

import (
	"context"
	"testing"
	"time"

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
	m := &model{ctx: context.Background(), outputBuffers: map[int]*runner.Buffer{0: first, 1: second}, moduleKeys: []int{0, 1}, cursor: 1, outputViewport: viewport}
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
	updated, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlR})
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

func TestQuitAfterCompletedBatchDoesNotEnterCancellation(t *testing.T) {
	batch := runner.NewBatchRun(nil)
	batch.Start(context.Background(), nil, &modules.Runtime{}, t.TempDir(), runner.Runner{})
	<-batch.Done()
	m := &model{running: true, batch: batch, status: "complete"}
	_, cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil || m.running || m.quitConfirm || m.status == "cancelling; waiting for the active batch to stop" {
		t.Fatalf("completed batch entered stale cancellation: cmd=%v running=%v confirm=%v status=%q", cmd, m.running, m.quitConfirm, m.status)
	}
}

func TestQuitCancellationHasBoundedFallback(t *testing.T) {
	m := &model{running: true, quitAfterCancel: true, quitCancelDeadline: time.Now().Add(-time.Second)}
	quit := m.syncBatch()
	if quit == nil || m.running || m.quitAfterCancel {
		t.Fatalf("bounded quit fallback did not fire: cmd=%v running=%v after=%v", quit, m.running, m.quitAfterCancel)
	}
}

func TestBatchCompletionDefersPersistenceFromUpdate(t *testing.T) {
	batch := runner.NewBatchRun(nil)
	batch.Start(context.Background(), nil, &modules.Runtime{}, t.TempDir(), runner.Runner{})
	if err := batch.Wait(context.Background()); err != nil {
		t.Fatalf("completed batch did not close: %v", err)
	}
	m := &model{ctx: context.Background(), batch: batch, running: true, batchName: "Default Enumeration", focus: focusNavigation}
	command := m.syncBatch()
	if command == nil {
		t.Fatal("completed batch did not schedule deferred recording")
	}
	if m.running || m.batchRecorded || !m.batchRecording {
		t.Fatalf("completion state was not released before recording: running=%v recorded=%v recording=%v", m.running, m.batchRecorded, m.batchRecording)
	}
	if updated, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlW}); !updated.(*model).watcher {
		t.Fatal("watcher navigation was blocked while completion recording was deferred")
	}
	msg := command()
	updated, followUp := m.Update(msg)
	if followUp != nil {
		t.Fatal("database-free completion unexpectedly scheduled a follow-up command")
	}
	if !updated.(*model).batchRecorded || updated.(*model).batchRecording {
		t.Fatalf("deferred completion was not applied: recorded=%v recording=%v", updated.(*model).batchRecorded, updated.(*model).batchRecording)
	}
}

func TestActiveBatchKeepsToolNavigationBrowsable(t *testing.T) {
	log := &executionLog{}
	m := selectionModel(t, log)
	m.running = true
	m.batch = runner.NewBatchRun(nil)
	m.focus = focusNavigation
	m.navigationRow = 0
	familyBefore := m.toolFamilyIndex
	m.handleKey(tea.KeyMsg{Type: tea.KeyRight})
	if len(m.toolFamilies) > 1 && m.toolFamilyIndex == familyBefore {
		t.Fatal("Right navigation was suppressed during an active batch")
	}
	familyAfter := m.toolFamilyIndex
	m.handleKey(tea.KeyMsg{Type: tea.KeyLeft})
	if len(m.toolFamilies) > 1 && m.toolFamilyIndex != familyBefore {
		t.Fatalf("Left navigation did not remain reversible: before=%d after-right=%d after-left=%d", familyBefore, familyAfter, m.toolFamilyIndex)
	}
	m.focus = focusModules
	m.cursor = 0
	queued := append([]runner.BatchItem(nil), m.batchItems...)
	m.handleKey(tea.KeyMsg{Type: tea.KeyDown})
	if len(m.modules) > 1 && m.cursor == 0 {
		t.Fatal("module browsing was not available during an active batch")
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if !m.running || len(m.batchItems) != len(queued) {
		t.Fatal("active-batch browsing changed execution state or queue")
	}
}
