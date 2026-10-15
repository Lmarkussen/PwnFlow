//go:build unix

package sccm

import (
	"os"
	"syscall"
)

// foreignOwnedEntry reports whether the directory holds an entry that another account
// owns, which is what an elevated child leaves behind.
func foreignOwnedEntry(directory string) bool {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false
	}
	uid := os.Getuid()
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if int(stat.Uid) != uid {
			return true
		}
	}
	return false
}
