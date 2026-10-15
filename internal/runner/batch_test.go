package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/modules"
)

type batchModule struct {
	name string
	err  error
}

type cancelAwareModule struct{}

func (cancelAwareModule) ID() string                                    { return "cancel-aware" }
func (cancelAwareModule) Name() string                                  { return "cancel-aware" }
func (cancelAwareModule) ToolFamily() modules.ToolFamily                { return modules.ToolFamilyNetExec }
func (cancelAwareModule) Category() modules.Category                    { return modules.CategoryEnumeration }
func (cancelAwareModule) Description() string                           { return "" }
func (cancelAwareModule) Tool() string                                  { return "test" }
func (cancelAwareModule) Protocol() modules.Protocol                    { return modules.ProtocolLDAP }
func (cancelAwareModule) Prerequisites() []string                       { return nil }
func (cancelAwareModule) RequiredPrivileges() []string                  { return nil }
func (cancelAwareModule) OutputFile() string                            { return "cancel-aware.txt" }
func (cancelAwareModule) Sensitivity() modules.Sensitivity              { return modules.SensitivityStandard }
func (cancelAwareModule) ReadOnly() bool                                { return true }
func (cancelAwareModule) SecondaryConnections() []string                { return nil }
func (cancelAwareModule) Check(context.Context, *modules.Runtime) error { return nil }
func (cancelAwareModule) Run(ctx context.Context, _ *modules.Runtime, _ modules.OutputSink) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestBatchCancellationStopsActiveAndSkipsQueuedModules(t *testing.T) {
	items := []BatchItem{
		{Index: 0, Module: cancelAwareModule{}, Buffer: NewBuffer(100)},
		{Index: 1, Module: cancelAwareModule{}, Buffer: NewBuffer(100)},
	}
	batch := NewBatchRun(items)
	batch.Start(context.Background(), items, &modules.Runtime{}, t.TempDir(), Runner{BufferLimit: 100})
	time.Sleep(10 * time.Millisecond)
	batch.Cancel()
	waitContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := batch.Wait(waitContext); err != nil {
		t.Fatal(err)
	}
	states, _, _, _ := batch.Snapshot()
	for index, state := range states {
		if state.Status != "cancelled" {
			t.Fatalf("state %d status=%q", index, state.Status)
		}
	}
}

func (m batchModule) ID() string                                    { return m.name }
func (m batchModule) Name() string                                  { return m.name }
func (m batchModule) ToolFamily() modules.ToolFamily                { return modules.ToolFamilyNetExec }
func (m batchModule) Category() modules.Category                    { return modules.CategoryEnumeration }
func (m batchModule) Description() string                           { return "" }
func (m batchModule) Tool() string                                  { return "test" }
func (m batchModule) Protocol() modules.Protocol                    { return modules.ProtocolLDAP }
func (m batchModule) Prerequisites() []string                       { return nil }
func (m batchModule) RequiredPrivileges() []string                  { return nil }
func (m batchModule) OutputFile() string                            { return m.name + ".txt" }
func (m batchModule) Sensitivity() modules.Sensitivity              { return modules.SensitivityStandard }
func (m batchModule) ReadOnly() bool                                { return true }
func (m batchModule) SecondaryConnections() []string                { return nil }
func (m batchModule) Check(context.Context, *modules.Runtime) error { return nil }
func (m batchModule) Run(_ context.Context, _ *modules.Runtime, sink modules.OutputSink) error {
	_, _ = sink.Write([]byte(m.name))
	return m.err
}

func TestBatchRunsInOrderAndContinuesAfterFailure(t *testing.T) {
	items := []BatchItem{{Index: 0, Module: batchModule{name: "one", err: errors.New("failed")}, Buffer: NewBuffer(100)}, {Index: 1, Module: batchModule{name: "two"}, Buffer: NewBuffer(100)}}
	batch := NewBatchRun(items)
	batch.Start(context.Background(), items, &modules.Runtime{}, t.TempDir(), Runner{BufferLimit: 100})
	<-batch.Done()
	states, _, _, _ := batch.Snapshot()
	if states[0].Status != "failed" || states[1].Status != "completed" {
		t.Fatalf("statuses: %q, %q", states[0].Status, states[1].Status)
	}
}
