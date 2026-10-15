//go:build unix

package process

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// shortGrace keeps the escalation tests quick without changing the mechanism.
func shortGrace(t *testing.T) {
	t.Helper()
	previous := GracePeriod
	GracePeriod = 300 * time.Millisecond
	t.Cleanup(func() { GracePeriod = previous })
}

// alive reports whether a pid still exists.
func pidAlive(pid int) bool {
	return syscall.Kill(pid, syscall.Signal(0)) == nil
}

// waitGone waits for a pid to disappear, so a test never sleeps blindly.
func waitGone(t *testing.T, pid int, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !pidAlive(pid) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s (pid %d) is still running after cancellation", what, pid)
}

// A cancelled command stops everything it started: the tool's own children are in
// the tool's process group, so they are signalled with it and do not survive the
// abort as orphans.
func TestCancellationReachesTheToolsDescendants(t *testing.T) {
	shortGrace(t)
	directory := t.TempDir()
	pidFile := filepath.Join(directory, "child.pid")
	// The shell records its own pid and then starts a long-running child, which is
	// what a real tool with a worker pool looks like from the outside.
	script := "echo $$ > " + pidFile + "; sleep 60 & echo $! >> " + pidFile + "; wait"
	ctx, cancel := context.WithCancel(context.Background())
	command := Command(ctx, "/bin/sh", "-c", script)
	command.Dir = directory
	done := make(chan error, 1)
	go func() { done <- Wait(ctx, command) }()

	waitForPids(t, pidFile, 2)
	pids := readPids(t, pidFile)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Wait returned %v, want the context error so the run can be classified", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Wait did not return after cancellation")
	}
	for index, pid := range pids {
		what := "the tool"
		if index > 0 {
			what = "the tool's child"
		}
		waitGone(t, pid, what)
	}
}

// A tool that ignores the graceful signals is still stopped, by the firmer one, and
// PwnFlow's own process is never a target.
func TestTerminationEscalatesAndSparesPwnFlow(t *testing.T) {
	shortGrace(t)
	directory := t.TempDir()
	pidFile := filepath.Join(directory, "stubborn.pid")
	// The shell traps INT and TERM: it needs the final signal to stop.
	script := "trap '' INT TERM; echo $$ > " + pidFile + "; sleep 60"
	ctx, cancel := context.WithCancel(context.Background())
	command := Command(ctx, "/bin/sh", "-c", script)
	command.Dir = directory
	done := make(chan error, 1)
	go func() { done <- Wait(ctx, command) }()

	waitForPids(t, pidFile, 1)
	pid := readPids(t, pidFile)[0]
	group, err := syscall.Getpgid(pid)
	if err != nil {
		t.Fatal(err)
	}
	if group == syscall.Getpgrp() {
		t.Fatal("the tool was left in PwnFlow's own process group")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a tool that ignores INT and TERM was never killed")
	}
	waitGone(t, pid, "the stubborn tool")
	// If the escalation had signalled PwnFlow's own group, this test would not be
	// running to read it.
	if !pidAlive(syscall.Getpid()) {
		t.Fatal("PwnFlow signalled itself")
	}
}

// A command that finishes on its own is returned as it finished, with no signals
// involved.
func TestUncanceledCommandReturnsItsOwnResult(t *testing.T) {
	ctx := context.Background()
	command := Command(ctx, "/bin/sh", "-c", "exit 7")
	err := Wait(ctx, command)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
		t.Fatalf("Wait returned %v, want the tool's own exit status", err)
	}
}

// Cancelling a command that never started is a no-op rather than a panic or a
// signal to something else.
func TestTerminationWithoutAProcessIsSafe(t *testing.T) {
	terminate(nil)
	terminate(&exec.Cmd{})
	if _, err := os.Stat("/proc/self"); err != nil {
		t.Skip("no procfs to inspect")
	}
}

func waitForPids(t *testing.T, path string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(readPids(t, path)) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the test tool never reported %d pid(s)", want)
}

func readPids(t *testing.T, path string) []int {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	pids := make([]int, 0, 2)
	for _, line := range strings.Fields(string(contents)) {
		pid, err := strconv.Atoi(line)
		if err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids
}
