package runner

import (
	"context"
	"errors"
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
	// cancels is one cancellation handle per item, so an operator can stop exactly
	// one execution. abandoned records the items stopped that way, with the reason,
	// which is what makes their terminal state "aborted" rather than "cancelled".
	cancels   map[int]context.CancelFunc
	abandoned map[int]string
	done      chan struct{}
}

func NewBatchRun(items []BatchItem) *BatchRun {
	states := make([]BatchState, len(items))
	for i, item := range items {
		states[i] = BatchState{Index: item.Index, Module: item.Module, Status: "queued"}
	}
	return &BatchRun{
		states: states, active: -1, done: make(chan struct{}),
		cancels: make(map[int]context.CancelFunc), abandoned: make(map[int]string),
	}
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
			// Each execution gets its own handle, derived from the batch context so
			// a global cancel still stops everything, and cancellable on its own so
			// an operator can stop this module without touching the rest.
			// The handle is keyed by the item's registry index, which is the identity
			// every other part of PwnFlow uses for it - the watcher, the output
			// buffers, the history. Keying it by position instead would make an abort
			// address the wrong execution as soon as the two differ.
			itemContext, itemCancel := context.WithCancel(ctx)
			b.mu.Lock()
			b.cancels[item.Index] = itemCancel
			b.mu.Unlock()
			b.mu.Lock()
			b.active = i
			b.states[i].Status = "running"
			b.states[i].Started = time.Now()
			b.mu.Unlock()
			result := runner.ExecuteWithBuffer(itemContext, item.Module, runtime, root, item.Buffer)
			b.mu.Lock()
			delete(b.cancels, item.Index)
			reason, abandoned := b.abandoned[item.Index]
			b.mu.Unlock()
			if abandoned {
				// The operator stopped this one. It is neither a failure nor a
				// global cancellation, and its partial output stays where it is.
				result.Status = StatusAborted
				result.Err = errors.New(reason)
			}
			b.mu.Lock()
			b.states[i].Result = result
			b.states[i].Status = result.Status
			b.mu.Unlock()
			itemCancel()
		}
		b.mu.Lock()
		b.active = -1
		b.finished = time.Now()
		b.cancels = make(map[int]context.CancelFunc)
		b.mu.Unlock()
	}()
}

// StatusAborted is the terminal state of an execution the operator stopped from
// the watcher. It is deliberately not "failed": the module did not fail, and it is
// not "cancelled" either, which is what stopping the whole batch is.
const StatusAborted = "aborted"

// AbortReason is the reason recorded for an execution stopped that way.
const AbortReason = "ABORTED: stopped by operator"

// Abort stops one execution and only that one: it reports whether the item was
// running, and it is safe to call twice, on an item that already finished, or on
// an item that never started. The batch keeps going with the next item.
func (b *BatchRun) Abort(index int, reason string) bool {
	if reason == "" {
		reason = AbortReason
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	cancel, ok := b.cancels[index]
	if !ok {
		return false
	}
	if _, already := b.abandoned[index]; already {
		// A second request for the same execution is the same request.
		return true
	}
	b.abandoned[index] = reason
	cancel()
	return true
}

// Running reports whether the item at that position is executing right now, which
// is what the watcher asks before offering to abort it.
func (b *BatchRun) Running(index int) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.cancels[index]
	return ok
}

// Abandoned reports the reason an item was stopped by the operator, and whether it
// was.
func (b *BatchRun) Abandoned(index int) (string, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	reason, ok := b.abandoned[index]
	return reason, ok
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
