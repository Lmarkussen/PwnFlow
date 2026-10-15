package runner

import (
	"context"
	"sync"
	"time"

	"github.com/pwnflow/pwnflow/internal/modules"
)

type BatchItem struct {
	Index    int
	Module   modules.Module
	ModuleID int64
	Buffer   *Buffer
}

type BatchState struct {
	Index   int
	Module  modules.Module
	Status  string
	Result  Result
	Started time.Time
}

type BatchRun struct {
	mu       sync.RWMutex
	states   []BatchState
	active   int
	started  time.Time
	finished time.Time
	cancel   context.CancelFunc
	done     chan struct{}
}

func NewBatchRun(items []BatchItem) *BatchRun {
	states := make([]BatchState, len(items))
	for i, item := range items {
		states[i] = BatchState{Index: item.Index, Module: item.Module, Status: "queued"}
	}
	return &BatchRun{states: states, active: -1, done: make(chan struct{})}
}

func (b *BatchRun) Start(parent context.Context, items []BatchItem, runtime *modules.Runtime, root string, runner Runner) {
	ctx, cancel := context.WithCancel(parent)
	b.cancel = cancel
	b.started = time.Now()
	go func() {
		defer close(b.done)
		for i, item := range items {
			if ctx.Err() != nil {
				now := time.Now()
				b.mu.Lock()
				b.states[i].Status = "cancelled"
				b.states[i].Result = Result{Status: "cancelled", ExitCode: -1, Started: now, Finished: now, Err: ctx.Err()}
				b.mu.Unlock()
				continue
			}
			b.mu.Lock()
			b.active = i
			b.states[i].Status = "running"
			b.states[i].Started = time.Now()
			b.mu.Unlock()
			result := runner.ExecuteWithBuffer(ctx, item.Module, runtime, root, item.Buffer)
			b.mu.Lock()
			b.states[i].Result = result
			b.states[i].Status = result.Status
			b.mu.Unlock()
		}
		b.mu.Lock()
		b.active = -1
		b.finished = time.Now()
		b.mu.Unlock()
	}()
}

func (b *BatchRun) Cancel() {
	if b.cancel != nil {
		b.cancel()
	}
}
func (b *BatchRun) Done() <-chan struct{} { return b.done }

func (b *BatchRun) Wait(ctx context.Context) error {
	select {
	case <-b.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (b *BatchRun) Snapshot() (states []BatchState, active int, started, finished time.Time) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return append([]BatchState(nil), b.states...), b.active, b.started, b.finished
}
