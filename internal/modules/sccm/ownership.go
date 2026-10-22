package sccm

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/pwnflow/pwnflow/internal/artifacts"
)

// elevationFailure reports whether output shows sudo refusing to run without a
// password, which happens when the approval has expired by the time an invocation
// runs. PwnFlow never retries such an invocation unprivileged.
func elevationFailure(output string) bool {
	lowered := strings.ToLower(output)
	for _, pattern := range []string{"a password is required", "a terminal is required", "sudo: no tty present", "sudoers"} {
		if strings.Contains(lowered, pattern) {
			return true
		}
	}
	return false
}

// restoreOwnership returns artifacts created by an elevated invocation to the account
// running PwnFlow. It is deliberately narrow: it is only used on the directory of
// that one invocation, it never runs without an approved elevation, and it reports
// what it could not do rather than touching anything else.
func restoreOwnership(ctx context.Context, directory string) error {
	if directory == "" || !foreignOwnedEntry(directory) {
		return nil
	}
	if _, err := os.Stat(directory); err != nil {
		return nil
	}
	if err := artifacts.NormalizeTreeWithSudo(ctx, directory); err != nil {
		return fmt.Errorf("ownership handoff for %s failed: %w", directory, err)
	}
	return nil
}

// discardSink drops output that has no place in the module's log.
type discardSink struct{}

func (discardSink) Write(p []byte) (int, error) { return len(p), nil }
