package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// blockingModule runs until its context ends, and records that it did.
type blockingModule struct {
	id      string
	started chan struct{}
	runs    *int32
}

func (m blockingModule) ID() string                                    { return m.id }
func (m blockingModule) Name() string                                  { return m.id }
func (m blockingModule) ToolFamily() modules.ToolFamily                { return modules.ToolFamilyNetExec }
func (m blockingModule) Category() modules.Category                    { return modules.CategoryEnumeration }
func (m blockingModule) Description() string                           { return "test" }
func (m blockingModule) Tool() string                                  { return "test" }
func (m blockingModule) Protocol() modules.Protocol                    { return modules.ProtocolLDAP }
func (m blockingModule) RequiredPrivileges() []string                  { return nil }
func (m blockingModule) Prerequisites() []string                       { return nil }
func (m blockingModule) OutputFile() string                            { return m.id + ".txt" }
func (m blockingModule) Sensitivity() modules.Sensitivity              { return modules.SensitivityStandard }
func (m blockingModule) ReadOnly() bool                                { return true }
func (m blockingModule) SecondaryConnections() []string                { return nil }
func (m blockingModule) Check(context.Context, *modules.Runtime) error { return nil }

func (m blockingModule) Run(ctx context.Context, _ *modules.Runtime, sink modules.OutputSink) error {
	if m.runs != nil {
		atomic.AddInt32(m.runs, 1)
	}
	_, _ = sink.Write([]byte(m.id + " started\n"))
	if m.started != nil {
		select {
		case m.started <- struct{}{}:
		default:
		}
	}
	select {
	case <-ctx.Done():
		_, _ = sink.Write([]byte(m.id + " saw the cancellation\n"))
		return ctx.Err()
	case <-time.After(30 * time.Second):
		_, _ = sink.Write([]byte(m.id + " finished on its own\n"))
		return nil
	}
}

// quickModule finishes immediately, so a test can watch what runs after an abort.
type quickModule struct{ blockingModule }

func (m quickModule) Run(_ context.Context, _ *modules.Runtime, sink modules.OutputSink) error {
	_, err := sink.Write([]byte(m.id + " done\n"))
	return err
}

// startBatchRun launches a batch and returns the run plus the started channels of
// the blocking items, so a test can wait for a specific execution to be under way.
func startBatchRun(t *testing.T, items []BatchItem, _ []chan struct{}) (*BatchRun, string) {
	t.Helper()
	run := NewBatchRun(items)
	root := t.TempDir()
	run.Start(context.Background(), items, &modules.Runtime{}, root, Runner{BufferLimit: 4096})
	return run, root
}

// waitUntil polls a condition, so a test never depends on a fixed sleep.
func waitUntil(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func statuses(run *BatchRun) []string {
	states, _, _, _ := run.Snapshot()
	out := make([]string, 0, len(states))
	for _, state := range states {
		out = append(out, state.Status)
	}
	return out
}

// Aborting one execution stops that one and lets the batch continue with the rest:
// the module after it runs normally, and the aborted one is recorded as ABORTED
// rather than as a failure.
func TestAbortStopsOnlyTheSelectedExecution(t *testing.T) {
	var runs int32
	started := make(chan struct{}, 1)
	slow := blockingModule{id: "slow", started: started, runs: &runs}
	after := quickModule{blockingModule{id: "after"}}
	items := []BatchItem{
		{Index: 10, Module: slow, Buffer: NewBuffer(4096)},
		{Index: 11, Module: after, Buffer: NewBuffer(4096)},
	}
	run, root := startBatchRun(t, items, []chan struct{}{started})
	<-started

	if !run.Running(10) {
		t.Fatal("the execution under the arrow does not report itself as running")
	}
	if run.Running(11) {
		t.Fatal("a module that has not started reports itself as running")
	}
	if !run.Abort(10, AbortReason) {
		t.Fatal("the abort was refused for a running execution")
	}
	waitContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := run.Wait(waitContext); err != nil {
		t.Fatal(err)
	}
	got := statuses(run)
	if got[0] != StatusAborted {
		t.Fatalf("the aborted module is %q, want %q", got[0], StatusAborted)
	}
	if got[1] != "completed" {
		t.Fatalf("the next module is %q; the batch did not continue", got[1])
	}
	states, _, _, _ := run.Snapshot()
	if states[0].Result.Err == nil || !strings.Contains(states[0].Result.Err.Error(), "stopped by operator") {
		t.Fatalf("the reason does not name the operator: %v", states[0].Result.Err)
	}
	if atomic.LoadInt32(&runs) != 1 {
		t.Fatalf("the aborted module ran %d time(s); an abort is never retried", runs)
	}
	// Partial output stays in the module's own artifact, marked as partial, with the
	// permissions every other artifact has.
	artifact := filepath.Join(root, slow.OutputFile())
	contents, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatalf("the aborted module's artifact is gone: %v", err)
	}
	if !strings.Contains(string(contents), "slow started") {
		t.Fatalf("the partial output was lost: %q", contents)
	}
	if !strings.Contains(string(contents), "partial") {
		t.Fatalf("the artifact does not say it is partial: %q", contents)
	}
	info, err := os.Stat(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("the artifact mode is %o, want 600", info.Mode().Perm())
	}
}

// Aborting something that already finished changes nothing, and does not attach
// the abort to whatever runs next.
func TestAbortOnAFinishedOrQueuedExecutionIsHarmless(t *testing.T) {
	started := make(chan struct{}, 1)
	blocker := blockingModule{id: "blocker", started: started}
	items := []BatchItem{{Index: 0, Module: blocker, Buffer: NewBuffer(4096)}}
	run, _ := startBatchRun(t, items, []chan struct{}{started})
	<-started
	run.Cancel()
	waitContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := run.Wait(waitContext); err != nil {
		t.Fatal(err)
	}
	before := statuses(run)
	if run.Abort(0, AbortReason) {
		t.Fatal("an abort was accepted for an execution that had finished")
	}
	if run.Abort(7, AbortReason) {
		t.Fatal("an abort was accepted for an item that does not exist")
	}
	if after := statuses(run); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("an abort on a finished execution changed the batch: %v → %v", before, after)
	}
}

// Two requests for the same execution are the same request.
func TestAbortIsIdempotent(t *testing.T) {
	started := make(chan struct{}, 1)
	blocker := blockingModule{id: "blocker", started: started}
	items := []BatchItem{{Index: 0, Module: blocker, Buffer: NewBuffer(4096)}}
	run, _ := startBatchRun(t, items, []chan struct{}{started})
	<-started
	if !run.Abort(0, AbortReason) || !run.Abort(0, AbortReason) {
		t.Fatal("a repeated abort was refused")
	}
	waitContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := run.Wait(waitContext); err != nil {
		t.Fatal(err)
	}
	if got := statuses(run); got[0] != StatusAborted {
		t.Fatalf("the execution is %q after two aborts", got[0])
	}
	reason, abandoned := run.Abandoned(0)
	if !abandoned || !strings.Contains(reason, "stopped by operator") {
		t.Fatalf("the recorded reason is %q (abandoned=%v)", reason, abandoned)
	}
}

// Ctrl+C keeps its meaning: it stops the whole batch, and the executions it stops
// are cancelled, not attributed to an operator abort.
func TestGlobalCancellationIsNotAnAbort(t *testing.T) {
	var runs int32
	started := make(chan struct{}, 1)
	blocker := blockingModule{id: "blocker", started: started, runs: &runs}
	after := quickModule{blockingModule{id: "after"}}
	items := []BatchItem{
		{Index: 0, Module: blocker, Buffer: NewBuffer(4096)},
		{Index: 1, Module: after, Buffer: NewBuffer(4096)},
	}
	run, _ := startBatchRun(t, items, []chan struct{}{started})
	<-started
	run.Cancel()
	waitContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := run.Wait(waitContext); err != nil {
		t.Fatal(err)
	}
	got := statuses(run)
	if got[0] != "cancelled" || got[1] != "cancelled" {
		t.Fatalf("a global cancellation produced %v", got)
	}
	if _, abandoned := run.Abandoned(0); abandoned {
		t.Fatal("a global cancellation was recorded as an operator abort")
	}
	if atomic.LoadInt32(&runs) != 1 {
		t.Fatalf("the module ran %d times", runs)
	}
}

// elevatingModule needs privileges the process does not have, and records how it
// was invoked.
type elevatingModule struct {
	blockingModule
	approvals map[string]bool
}

func (m elevatingModule) ElevationRequired() (bool, string) {
	return true, "the tool needs local privileges"
}

func (m elevatingModule) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	// What the module would do with the operator's answer: run elevated when they
	// approved, and refuse rather than fall back when they did not.
	if runtime == nil || runtime.Elevation == nil || !runtime.Elevation.ElevationApproved(m.id) {
		return errors.New("elevated execution was not approved")
	}
	m.approvals[m.id] = true
	return m.blockingModule.Run(ctx, runtime, sink)
}

// Aborting a privileged module stops that invocation and nothing else: it does not
// retry the module, and it does not retry it unprivileged.
func TestAbortingAPrivilegedModuleDoesNotRetryItUnprivileged(t *testing.T) {
	var runs int32
	started := make(chan struct{}, 1)
	privileged := elevatingModule{
		blockingModule: blockingModule{id: "privileged", started: started, runs: &runs},
		approvals:      map[string]bool{},
	}
	items := []BatchItem{{Index: 0, Module: privileged, Buffer: NewBuffer(4096)}}
	run := NewBatchRun(items)
	approvals := map[string]bool{"privileged": true}
	run.Start(context.Background(), items, &modules.Runtime{Elevation: staticPolicy(approvals)}, t.TempDir(), Runner{BufferLimit: 4096})
	<-started
	if !privileged.approvals["privileged"] {
		t.Fatal("the approved module did not run elevated")
	}
	if !run.Abort(0, AbortReason) {
		t.Fatal("the privileged execution could not be aborted")
	}
	waitContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := run.Wait(waitContext); err != nil {
		t.Fatal(err)
	}
	if got := statuses(run); got[0] != StatusAborted {
		t.Fatalf("the privileged module is %q", got[0])
	}
	if atomic.LoadInt32(&runs) != 1 {
		t.Fatalf("the privileged module ran %d times; an abort is never retried, elevated or not", runs)
	}
}

// staticPolicy is the operator's approval for a run.
type staticPolicy map[string]bool

func (p staticPolicy) ElevationApproved(moduleID string) bool { return p[moduleID] }

func (p staticPolicy) RenewElevation(context.Context, string, string) bool { return false }
