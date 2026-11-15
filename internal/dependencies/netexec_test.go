package dependencies

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetExecSelectionPriorityAndFailure(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PWNFLOW_TOOLS_DIR", root)
	t.Setenv("PWNFLOW_NETEXEC", "")
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	write := func(path string) {
		t.Helper()
		os.MkdirAll(filepath.Dir(path), 0700)
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho test-version\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	old := filepath.Join(bin, "nxc")
	write(old)
	path, err := NetExecExecutable(context.Background())
	if err != nil || path != old {
		t.Fatalf("%s %v", path, err)
	}
	env := filepath.Join(root, "NetExec", "versions", "verified")
	managed := filepath.Join(env, "bin", "nxc")
	write(managed)
	current := filepath.Join(root, "NetExec", "current")
	if err := os.Symlink(env, current); err != nil {
		t.Fatal(err)
	}
	path, err = NetExecExecutable(context.Background())
	if err != nil || path != filepath.Join(current, "bin", "nxc") {
		t.Fatalf("managed installation shadowed: %s %v", path, err)
	}
	explicit := filepath.Join(t.TempDir(), "custom-nxc")
	write(explicit)
	t.Setenv("PWNFLOW_NETEXEC", explicit)
	path, err = NetExecExecutable(context.Background())
	if err != nil || path != explicit {
		t.Fatalf("explicit override lost: %s %v", path, err)
	}
	t.Setenv("PWNFLOW_NETEXEC", filepath.Join(bin, "missing"))
	if _, err := NetExecExecutable(context.Background()); err == nil {
		t.Fatal("invalid explicit selection fell back")
	}
	t.Setenv("PWNFLOW_NETEXEC", "")
	os.Remove(managed)
	if _, err := NetExecExecutable(context.Background()); err == nil {
		t.Fatal("broken managed selection fell back")
	}
	os.Remove(current)
	os.WriteFile(filepath.Join(root, "NetExec", "last-update-error"), []byte("update verification failed"), 0600)
	if _, err := NetExecExecutable(context.Background()); err == nil || !strings.Contains(err.Error(), "no PATH fallback") {
		t.Fatalf("%v", err)
	}
}

func TestRetainedNetExecReportsFailedUpdate(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PWNFLOW_TOOLS_DIR", root)
	t.Setenv("PWNFLOW_NETEXEC", "")
	dir := filepath.Join(root, "NetExec", "current", "bin")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "nxc"), []byte("#!/bin/sh\necho usage\n"), 0700)
	os.WriteFile(filepath.Join(root, "NetExec", "last-update-error"), []byte("requested revision failed"), 0600)
	status := DefaultRegistry().CheckOne(context.Background(), NetExec)
	if !status.Available || !strings.Contains(status.Detail, "retained previous verified executable") {
		t.Fatalf("%+v", status)
	}
}
