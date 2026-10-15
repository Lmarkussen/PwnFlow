// Package process runs the external tools PwnFlow drives in a way the operator can
// stop: one tool, one process group, and a termination that escalates instead of
// killing outright.
//
// It exists because cancellation has to reach the whole tool, not just the process
// PwnFlow started. A tool that spawns workers - a Python scanner with a thread
// pool, a wrapper that shells out - leaves those children behind if only the parent
// is signalled, and an operator aborting one module must not leave the target
// work running in the background.
package process

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

// GracePeriod is how long a tool is given to stop after a cancellation before the
// next, firmer signal.
var GracePeriod = 2 * time.Second

// Command builds an external tool invocation PwnFlow owns: it runs in its own
// process group, and its context decides when it stops.
//
// The command is deliberately not built with exec.CommandContext: that would kill
// only the process PwnFlow started, with no chance to ask the tool to stop and no
// reach into what the tool started. Wait does that work instead.
func Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	command := exec.Command(name, args...)
	configure(command)
	// PwnFlow reads the tool's output through pipes. If the tool leaves a
	// grandchild holding one open, Wait would block on it; WaitDelay closes that
	// door without weakening the termination above.
	command.WaitDelay = GracePeriod
	return command
}

// Wait starts the command and waits for it. When ctx ends first, the tool's
// process group is asked to stop - interrupt, then terminate, then kill - and the
// context error is returned so the caller can record why the run ended.
func Wait(ctx context.Context, command *exec.Cmd) error {
	if err := command.Start(); err != nil {
		return err
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	select {
	case err := <-waited:
		return err
	case <-ctx.Done():
		terminate(command)
		err := <-waited
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
}

// Run is the whole thing for a command the caller does not need to keep: build it,
// start it, and let the context decide.
func Run(ctx context.Context, command *exec.Cmd) error {
	return Wait(ctx, command)
}

// ErrNotStarted is returned when termination is asked for a command that never
// started, which is a no-op rather than a failure.
var ErrNotStarted = errors.New("process was not started")
