//go:build unix

package process

import (
	"errors"
	"os/exec"
	"syscall"
	"time"
)

// configure puts the tool in its own process group, so a signal can be addressed
// to the tool and everything it starts, and never to PwnFlow's own group.
func configure(command *exec.Cmd) {
	// An empty SysProcAttr when one is already set keeps an explicit choice from
	// the caller; Setpgid is what makes the group PwnFlow's to signal.
	attributes := command.SysProcAttr
	if attributes == nil {
		attributes = &syscall.SysProcAttr{}
	}
	attributes.Setpgid = true
	command.SysProcAttr = attributes
}

// terminate escalates: an interrupt first, because a tool that handles it can
// close what it opened, then a termination, and only then a kill.
//
// The unit is the process group, not the process PwnFlow started. A tool's children
// can outlive it - a shell that exits while its background worker keeps running is
// the ordinary case, and POSIX shells make background jobs ignore the interrupt -
// so the escalation continues while anything in the group is still there, and stops
// as soon as the group is empty. PwnFlow's own process group is never a target.
func terminate(command *exec.Cmd) {
	if command == nil || command.Process == nil {
		return
	}
	pid := command.Process.Pid
	if pid <= 0 || pid == syscall.Getpid() {
		return
	}
	group, err := syscall.Getpgid(pid)
	if err != nil || group <= 0 {
		// The process is gone, so there is no group to address any more.
		return
	}
	for _, signal := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL} {
		if groupGone(group) {
			return
		}
		signalGroup(pid, group, signal)
		if waitGroupGone(group, GracePeriod) {
			return
		}
	}
}

// signalGroup signals the command's process group, or the process alone when that
// group is PwnFlow's own. Signalling our own group would take the interface down
// with the module, so it is never done.
func signalGroup(pid, group int, signal syscall.Signal) {
	if group == syscall.Getpgrp() {
		// The tool shares PwnFlow's group, which happens when a caller configured
		// the command itself. Signal the process, never the group.
		_ = syscall.Kill(pid, signal)
		return
	}
	_ = syscall.Kill(-group, signal)
}

// groupGone reports whether the process group has no members left. Signal 0 asks
// the question without delivering anything.
func groupGone(group int) bool {
	if group <= 0 {
		return true
	}
	err := syscall.Kill(-group, syscall.Signal(0))
	return errors.Is(err, syscall.ESRCH)
}

// waitGroupGone waits up to the grace period for the group to empty.
func waitGroupGone(group int, grace time.Duration) bool {
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if groupGone(group) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return groupGone(group)
}
