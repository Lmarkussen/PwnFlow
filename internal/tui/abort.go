package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/pwnflow/pwnflow/internal/runner"
)

// Aborting one running module from the watcher.
//
// The watcher is a view over the batch's executions. This file owns the operator's
// request: which execution they pointed at, the confirmation that follows, and the
// single call into the batch that stops exactly that execution. PwnFlow never kills
// a process from here - the batch owns the cancellation handle of every execution
// it started, and the modules own their own tools.
//
// It is deliberately not a batch cancellation. Ctrl+C keeps its meaning: stop
// everything. x stops the module under the arrow and the plan continues.

// requestWatcherAbort asks for confirmation for the execution under the selection
// arrow. A module that is not running is reported and nothing else happens.
func (m *model) requestWatcherAbort() tea.Cmd {
	if m.batch == nil {
		m.status = "Module is not running"
		return nil
	}
	state, ok := m.selectedWatcherState()
	if !ok {
		m.status = "Module is not running"
		return nil
	}
	if state.Status != "running" || !m.batch.Running(state.Index) {
		// Queued, completed, failed, skipped, aborted, or already stopped: there is
		// nothing to abort, and nothing else may be affected.
		m.status = "Module is not running"
		return nil
	}
	if _, stopping := m.batch.Abandoned(state.Index); stopping {
		// Already stopping: a second request is the same request, not a new one.
		m.status = fmt.Sprintf("%s is already stopping", state.Module.Name())
		return nil
	}
	m.watcherAbortConfirm = true
	m.watcherAbortIndex = state.Index
	m.watcherAbortName = state.Module.Name()
	m.status = fmt.Sprintf("Abort %s? [y/N]", state.Module.Name())
	return nil
}

// confirmWatcherAbort stops the execution that was selected when the operator
// pressed x. The identity is the one captured then, so a selection change or a
// module that finished in the meantime cannot move the abort to another run.
func (m *model) confirmWatcherAbort() tea.Cmd {
	index, name := m.watcherAbortIndex, m.watcherAbortName
	m.watcherAbortConfirm = false
	m.watcherAbortIndex, m.watcherAbortName = 0, ""
	if m.batch == nil || !m.batch.Abort(index, runner.AbortReason) {
		// It finished, or it was stopped already, before the answer arrived.
		m.status = fmt.Sprintf("%s is no longer running; nothing was aborted", name)
		return nil
	}
	m.status = fmt.Sprintf("aborting %s; the rest of the plan continues", name)
	return nil
}

// declineWatcherAbort leaves the module running, which is what every answer other
// than an explicit yes means.
func (m *model) declineWatcherAbort() tea.Cmd {
	name := m.watcherAbortName
	m.watcherAbortConfirm = false
	m.watcherAbortIndex, m.watcherAbortName = 0, ""
	m.status = fmt.Sprintf("%s keeps running", name)
	return nil
}

// selectedWatcherState is the execution under the watcher's selection arrow.
func (m *model) selectedWatcherState() (runner.BatchState, bool) {
	states := m.watcherStates()
	if len(states) == 0 {
		return runner.BatchState{}, false
	}
	cursor := m.watcherListCursor
	if cursor < 0 || cursor >= len(states) {
		cursor = len(states) - 1
	}
	return states[cursor], true
}
