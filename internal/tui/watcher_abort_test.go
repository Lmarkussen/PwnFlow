package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
)

// watcherAbortModel runs a batch whose first module blocks until it is stopped and
// returns the model with the watcher open on that execution.
func watcherAbortModel(t *testing.T) (*model, string) {
	t.Helper()
	log := &executionLog{}
	blocking := &blockingTestModule{id: "blocking", log: log, started: make(chan struct{}, 1)}
	next := selectionModule{id: "next", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log}
	root := t.TempDir()
	cfg := config.Config{Target: testTarget, Domain: testDomain, Username: "audituser", Password: "Sup3rSecret", Root: root}
	m := newModel(context.Background(), cfg, nil, []modules.Module{blocking, next}, []int64{1, 2}, 1, "test")
	m.width, m.height = 140, 45
	m.resizeOutput()
	m.focus = focusModules
	m.cursor = 0
	// R runs the selection, so the batch holds both modules: the aborted one and the
	// one that has to run after it.
	m.selectedModules["blocking"] = true
	m.selectedModules["next"] = true
	m.executeSelected()
	if !m.running {
		t.Fatalf("the batch did not start: %q", m.status)
	}
	select {
	case <-blocking.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the blocking module never started")
	}
	m.watcher = true
	m.watcherFocus = focusModules
	m.watcherListCursor = 0
	m.resizeWatcher()
	m.refreshWatcherList()
	return m, root
}

// blockingTestModule runs until it is stopped and records that it ran.
type blockingTestModule struct {
	id      string
	log     *executionLog
	started chan struct{}
}

func (m *blockingTestModule) ID() string                                    { return m.id }
func (m *blockingTestModule) Name() string                                  { return "Blocking Module" }
func (m *blockingTestModule) ToolFamily() modules.ToolFamily                { return modules.ToolFamilyNetExec }
func (m *blockingTestModule) Category() modules.Category                    { return modules.CategoryEnumeration }
func (m *blockingTestModule) Tool() string                                  { return "test tool" }
func (m *blockingTestModule) Protocol() modules.Protocol                    { return modules.ProtocolLDAP }
func (m *blockingTestModule) Description() string                           { return "test module" }
func (m *blockingTestModule) Prerequisites() []string                       { return nil }
func (m *blockingTestModule) RequiredPrivileges() []string                  { return nil }
func (m *blockingTestModule) OutputFile() string                            { return "test/" + m.id + ".log" }
func (m *blockingTestModule) Sensitivity() modules.Sensitivity              { return modules.SensitivityStandard }
func (m *blockingTestModule) ReadOnly() bool                                { return true }
func (m *blockingTestModule) SecondaryConnections() []string                { return nil }
func (m *blockingTestModule) Check(context.Context, *modules.Runtime) error { return nil }

func (m *blockingTestModule) Run(ctx context.Context, _ *modules.Runtime, sink modules.OutputSink) error {
	_, _ = sink.Write([]byte("partial output before the abort\n"))
	m.log.record(m.id)
	select {
	case m.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

// watcherKey sends one key in the watcher and runs whatever command it returns.
func watcherKey(t *testing.T, m *model, key string) {
	t.Helper()
	switch key {
	case "esc":
		m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	default:
		if len([]rune(key)) != 1 {
			t.Fatalf("unsupported watcher key %q", key)
		}
		m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
	}
}

// Pressing x on the running module under the arrow asks before doing anything, and
// declining leaves it running.
func TestWatcherAbortAsksAndDecliningKeepsItRunning(t *testing.T) {
	m, _ := watcherAbortModel(t)
	defer m.cancelBatch()

	watcherKey(t, m, "x")
	if m.status != "Abort Blocking Module? [y/N]" {
		t.Fatalf("the confirmation is %q", m.status)
	}
	watcherKey(t, m, "n")
	if !m.running {
		t.Fatal("declining stopped the batch")
	}
	states, _, _, _ := m.batch.Snapshot()
	if states[0].Status != "running" {
		t.Fatalf("declining left the module in %q", states[0].Status)
	}
	if m.status != "Blocking Module keeps running" {
		t.Fatalf("declining reported %q", m.status)
	}
}

// Confirming stops exactly the selected execution, marks it ABORTED, keeps its
// partial artifact, and lets the batch continue with the next module.
func TestWatcherAbortStopsTheSelectedModuleAndTheBatchContinues(t *testing.T) {
	m, root := watcherAbortModel(t)
	watcherKey(t, m, "x")
	watcherKey(t, m, "y")
	waitContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.batch.Wait(waitContext); err != nil {
		t.Fatal(err)
	}
	m.syncBatch()

	states, _, _, _ := m.batch.Snapshot()
	if states[0].Status != "aborted" {
		t.Fatalf("the aborted module is %q", states[0].Status)
	}
	if states[1].Status != "completed" {
		t.Fatalf("the next module is %q; the batch did not continue", states[1].Status)
	}
	if states[0].Result.Err == nil || !strings.Contains(states[0].Result.Err.Error(), "stopped by operator") {
		t.Fatalf("the recorded reason is %v", states[0].Result.Err)
	}
	// The watcher shows the terminal state the operator asked for.
	if line := ansi.Strip(m.watcherView()); !strings.Contains(line, "ABORTED") {
		t.Fatalf("the watcher does not show ABORTED:\n%s", line)
	}
	// Partial artifacts are retained, with the permissions every artifact has.
	artifact := filepath.Join(root, "results", testDomain, "test", "blocking.log")
	contents, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatalf("the aborted module's artifact is gone: %v", err)
	}
	if !strings.Contains(string(contents), "partial output before the abort") {
		t.Fatalf("the partial output was lost: %q", contents)
	}
	if info, err := os.Stat(artifact); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("artifact permissions: %v %v", info, err)
	}
}

// Pressing x when the selected module is not running changes nothing.
func TestWatcherAbortOnANonRunningModuleIsHarmless(t *testing.T) {
	for name, prepare := range map[string]func(m *model){
		"completed": func(m *model) {
			m.cancelBatch()
			waitForBatch(t, m)
		},
		"queued": func(m *model) {
			m.watcherListCursor = 1
		},
		"aborted": func(m *model) {
			m.batch.Abort(0, "ABORTED: stopped by operator")
			waitForBatch(t, m)
		},
	} {
		t.Run(name, func(t *testing.T) {
			m, _ := watcherAbortModel(t)
			defer m.cancelBatch()
			prepare(m)
			if name == "aborted" {
				m.watcherListCursor = 0
			}
			before, _, _, _ := m.batch.Snapshot()
			watcherKey(t, m, "x")
			if m.watcherAbortConfirm {
				t.Fatalf("x asked for confirmation on a %s module", name)
			}
			if m.status != "Module is not running" {
				t.Fatalf("x on a %s module reported %q", name, m.status)
			}
			after, _, _, _ := m.batch.Snapshot()
			for index := range before {
				if before[index].Status != after[index].Status {
					t.Fatalf("x on a %s module changed the batch: %v → %v", name, before[index].Status, after[index].Status)
				}
			}
		})
	}
}

// A module that failed earlier in the batch is not running either, and x on it
// changes nothing.
func TestWatcherAbortOnAFailedModuleIsHarmless(t *testing.T) {
	log := &executionLog{}
	failing := failingModule{selectionModule: selectionModule{id: "failing", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log}}
	cfg := testConfig(t)
	m := newModel(context.Background(), cfg, nil, []modules.Module{failing}, []int64{1}, 1, "test")
	m.width, m.height = 140, 45
	m.resizeOutput()
	m.focus = focusModules
	m.cursor = 0
	m.execute(0)
	waitForBatch(t, m)
	states, _, _, _ := m.batch.Snapshot()
	if states[0].Status != "failed" {
		t.Fatalf("the fixture module is %q, want failed", states[0].Status)
	}
	m.watcher = true
	m.watcherFocus = focusModules
	m.watcherListCursor = 0
	m.refreshWatcherList()

	watcherKey(t, m, "x")
	if m.watcherAbortConfirm {
		t.Fatal("x asked to abort a failed module")
	}
	if m.status != "Module is not running" {
		t.Fatalf("x on a failed module reported %q", m.status)
	}
	after, _, _, _ := m.batch.Snapshot()
	if after[0].Status != "failed" {
		t.Fatalf("x changed the failed module to %q", after[0].Status)
	}
}

// A module that finishes between the request and the answer cannot move the abort to
// its neighbour, and the neighbour is not cancelled by it.
func TestWatcherAbortAfterTheModuleFinishedIsNotMovedToTheNextOne(t *testing.T) {
	log := &executionLog{}
	short := &shortModule{id: "short", log: log}
	next := selectionModule{id: "next", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log}
	cfg := testConfig(t)
	m := newModel(context.Background(), cfg, nil, []modules.Module{short, next}, []int64{1, 2}, 1, "test")
	m.width, m.height = 140, 45
	m.resizeOutput()
	m.focus = focusModules
	m.selectedModules["short"] = true
	m.selectedModules["next"] = true
	m.executeSelected()
	m.watcher = true
	m.watcherFocus = focusModules
	m.watcherListCursor = 0
	m.refreshWatcherList()

	// The request lands while the module is still running...
	waitUntilRunning(t, m)
	watcherKey(t, m, "x")
	if !m.watcherAbortConfirm {
		t.Fatalf("x did not ask: %q", m.status)
	}
	// ...and the module finishes before the operator answers.
	waitForBatch(t, m)
	states, _, _, _ := m.batch.Snapshot()
	if states[0].Status != "completed" {
		t.Fatalf("the fixture module is %q, want completed", states[0].Status)
	}
	watcherKey(t, m, "y")
	if !strings.Contains(m.status, "no longer running") {
		t.Fatalf("the answer reported %q", m.status)
	}
	after, _, _, _ := m.batch.Snapshot()
	if after[0].Status != "completed" || after[1].Status != "completed" {
		t.Fatalf("the abort moved to another execution: %v", []string{after[0].Status, after[1].Status})
	}
}

// shortModule finishes on its own, so a test can make it complete between a request
// and an answer.
type shortModule struct {
	id  string
	log *executionLog
}

func (m *shortModule) ID() string                     { return m.id }
func (m *shortModule) Name() string                   { return "Short Module" }
func (m *shortModule) ToolFamily() modules.ToolFamily { return modules.ToolFamilyNetExec }
func (m *shortModule) Category() modules.Category     { return modules.CategoryEnumeration }
func (m *shortModule) Tool() string                   { return "test tool" }
func (m *shortModule) Protocol() modules.Protocol     { return modules.ProtocolLDAP }
func (m *shortModule) Description() string            { return "test module" }
func (m *shortModule) Prerequisites() []string        { return nil }
func (m *shortModule) RequiredPrivileges() []string   { return nil }
func (m *shortModule) OutputFile() string             { return "test/" + m.id + ".log" }
func (m *shortModule) Sensitivity() modules.Sensitivity {
	return modules.SensitivityStandard
}
func (m *shortModule) ReadOnly() bool                                { return true }
func (m *shortModule) SecondaryConnections() []string                { return nil }
func (m *shortModule) Check(context.Context, *modules.Runtime) error { return nil }

func (m *shortModule) Run(ctx context.Context, _ *modules.Runtime, sink modules.OutputSink) error {
	m.log.record(m.id)
	_, _ = sink.Write([]byte(m.id + " working\n"))
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(400 * time.Millisecond):
		return nil
	}
}

// waitUntilRunning waits for the batch to report its first item as running.
func waitUntilRunning(t *testing.T, m *model) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m.batch != nil {
			states, _, _, _ := m.batch.Snapshot()
			if len(states) > 0 && states[0].Status == "running" {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the first module never started running")
}

// The confirmation keeps the execution that was selected when x was pressed, so a
// selection that moves afterwards cannot move the abort to another module.
func TestWatcherAbortKeepsTheSelectedIdentity(t *testing.T) {
	m, _ := watcherAbortModel(t)
	defer m.cancelBatch()
	watcherKey(t, m, "x")
	// The selection moves under the confirmation, which is what a redraw or a
	// finished neighbour could do.
	m.watcherListCursor = 1
	watcherKey(t, m, "y")
	waitContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.batch.Wait(waitContext); err != nil {
		t.Fatal(err)
	}
	states, _, _, _ := m.batch.Snapshot()
	if states[0].Status != "aborted" {
		t.Fatalf("the module selected when x was pressed is %q", states[0].Status)
	}
	if states[1].Status == "aborted" {
		t.Fatal("the abort moved to the module the selection moved to")
	}
}

// A second confirmation for an execution that is already stopping is the same
// request, not a second abort.
func TestWatcherAbortIsIdempotent(t *testing.T) {
	m, _ := watcherAbortModel(t)
	defer m.cancelBatch()
	watcherKey(t, m, "x")
	watcherKey(t, m, "y")
	watcherKey(t, m, "x")
	if m.watcherAbortConfirm {
		t.Fatal("a second x offered to abort an execution that is already stopping")
	}
	waitForBatch(t, m)
	states, _, _, _ := m.batch.Snapshot()
	if states[0].Status != "aborted" || states[1].Status != "completed" {
		t.Fatalf("the batch ended as %v", []string{states[0].Status, states[1].Status})
	}
}

// Esc means the same as n: the module keeps running.
func TestWatcherAbortEscapeDeclines(t *testing.T) {
	m, _ := watcherAbortModel(t)
	defer m.cancelBatch()
	watcherKey(t, m, "x")
	_, command := m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if command != nil {
		t.Fatal("Escape started something")
	}
	if m.watcherAbortConfirm {
		t.Fatal("Escape left the confirmation open")
	}
	if !m.running {
		t.Fatal("Escape stopped the batch")
	}
}

// The watcher advertises the binding, and drops the least important hints before it
// would wrap.
func TestWatcherAdvertisesTheAbortBinding(t *testing.T) {
	m, _ := watcherAbortModel(t)
	defer m.cancelBatch()
	if footer := m.watcherFooter(); !strings.Contains(footer, "x abort selected") {
		t.Fatalf("the footer does not advertise the binding: %q", footer)
	}
	m.width = 24
	if footer := m.watcherFooter(); !strings.Contains(footer, "x abort selected") {
		t.Fatalf("the footer drops the abort binding when narrow: %q", footer)
	}
	// The confirmation is rendered inside the watcher: a question the operator
	// cannot see is a question they cannot answer.
	watcherKey(t, m, "x")
	if frame := ansi.Strip(m.watcherView()); !strings.Contains(frame, "Abort Blocking Module? [y/N]") {
		t.Fatalf("the watcher does not show the confirmation:\n%s", frame)
	}
	// Ctrl+C keeps its separate, global meaning.
	m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlC})
	waitForBatch(t, m)
	if m.running {
		t.Fatal("Ctrl+C no longer stops the batch")
	}
	if m.watcherAbortConfirm {
		t.Fatal("Ctrl+C left the abort confirmation open")
	}
}

// The watcher's status line reports what happened, so an operator who aborts a
// module reads it where they asked.
func TestWatcherShowsWhatTheAbortDid(t *testing.T) {
	m, _ := watcherAbortModel(t)
	defer m.cancelBatch()
	watcherKey(t, m, "x")
	if frame := ansi.Strip(m.watcherView()); !strings.Contains(frame, "Abort Blocking Module? [y/N]") {
		t.Fatalf("the watcher does not show the question:\n%s", frame)
	}
	watcherKey(t, m, "y")
	if frame := ansi.Strip(m.watcherView()); !strings.Contains(frame, "aborting Blocking Module") {
		t.Fatalf("the watcher does not show the outcome:\n%s", frame)
	}
	waitForBatch(t, m)
	if frame := ansi.Strip(m.watcherView()); !strings.Contains(frame, "ABORTED") {
		t.Fatalf("the watcher does not show the aborted state:\n%s", frame)
	}
}

// The watcher still renders the status line its other keys set, which is how the
// binding changes remain visible.
func TestWatcherStatusLineStaysQuietWhenThereIsNothingToSay(t *testing.T) {
	m, _ := watcherAbortModel(t)
	defer m.cancelBatch()
	m.status = ""
	if line := m.watcherStatusLine(); strings.TrimSpace(line) != "" {
		t.Fatalf("an idle watcher renders a status line: %q", line)
	}
	m.status = "Module is not running"
	if line := ansi.Strip(m.watcherStatusLine()); !strings.Contains(line, "Module is not running") {
		t.Fatalf("the status line hides the status: %q", line)
	}
}
