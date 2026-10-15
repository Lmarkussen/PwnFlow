//go:build !unix

package sccm

// foreignOwnedEntry reports that ownership cannot be inspected on this platform, so
// no privileged hand-back is attempted.
func foreignOwnedEntry(string) bool { return false }
