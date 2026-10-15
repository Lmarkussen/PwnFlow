package sccm

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// Sudo authorization, as PwnFlow uses it.
//
// PwnFlow never collects a sudo password. The operator approves elevation for one
// batch, the TUI releases the terminal, and sudo reads the password from it. What
// is left behind is sudo's own cached timestamp, which has a limited lifetime.
//
// Two consequences shape this file:
//
//   - The cache is verified with a noninteractive check before any privileged
//     invocation starts, so sudo never prompts from the background worker.
//   - The check and the privileged invocation have to see the same cache. sudo
//     keys its timestamp on the terminal (or, on other configurations, the user
//     or the parent process), so the check runs with the same environment and
//     terminal as the command it guards, and a failing check is answered by
//     asking the operator again rather than by starting the tool anyway.
//
// On the assessment workstation (sudo 1.9.17p2) the documented default is
// "a separate record for each terminal" - timestamp_type=tty - so the handoff that
// authenticates and the batch children that consume the authorization have to share
// a controlling terminal. They do: PwnFlow never starts a privileged child in its
// own session or process group, so the child inherits the terminal the operator
// authenticated on. The check below verifies that rather than assuming it, which is
// also what keeps a deployment with timestamp_type=global, ppid, or disable
// working: the cache is either valid, or the operator is asked again.

// sudoCheckTimeout bounds the noninteractive check. It is a check, not work: a
// sudo that cannot answer quickly is treated as not authorized.
var sudoCheckTimeout = 5 * time.Second

// sudoCheckFunc runs the noninteractive validation. It is a variable so tests can
// control whether the cache looks valid.
var sudoCheckFunc = func(ctx context.Context, program string, args ...string) error {
	checkContext, cancel := context.WithTimeout(ctx, sudoCheckTimeout)
	defer cancel()
	command := exec.CommandContext(checkContext, program, args...)
	// Nothing is written to the terminal and nothing is read from it: -n makes
	// sudo fail instead of prompting.
	command.Stdin = nil
	return command.Run()
}

// sudoAuthorised reports whether sudo can act without asking for a password,
// using the same form PwnFlow runs its privileged commands with.
func sudoAuthorised(ctx context.Context) bool {
	return sudoCheckFunc(ctx, "sudo", "-n", "-v") == nil
}

// ensureSudoAuthorised makes sure a privileged invocation may start.
//
// A valid cache returns immediately, so an approved batch never re-prompts. An
// expired cache is a safe boundary: the caller is about to start privileged work,
// so the operator is asked once, the terminal is released for sudo's own prompt,
// and the cache is verified again before the work starts. A refusal, or a
// verification that still fails, returns an error the module reports; the batch
// continues with its unprivileged modules.
func ensureSudoAuthorised(ctx context.Context, runtime *modules.Runtime, moduleID, hint string) error {
	if sudoAuthorised(ctx) {
		return nil
	}
	if runtime == nil || runtime.Elevation == nil {
		return fmt.Errorf("%s: sudo authorization is required and cannot be requested in this run", hint)
	}
	if !runtime.Elevation.RenewElevation(ctx, moduleID, hint) {
		return fmt.Errorf("%s: sudo authorization has expired and was not renewed, so this privileged run is skipped (PwnFlow does not retry it unprivileged)", hint)
	}
	if !sudoAuthorised(ctx) {
		return fmt.Errorf("%s: sudo still reports no valid authorization after renewal, so this privileged run is skipped", hint)
	}
	return nil
}
