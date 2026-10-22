package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenReadOnlyDoesNotMigrateOrWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enumeration.db")
	ctx := context.Background()
	writable, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writable.UpsertTarget(ctx, "example.test", "dc01"); err != nil {
		t.Fatal(err)
	}
	if err := writable.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	readonly, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer readonly.Close()
	addresses, err := readonly.TargetAddresses(ctx, "example.test")
	if err != nil || len(addresses) != 1 || addresses[0] != "dc01" {
		t.Fatalf("read-only target query = %v, %v", addresses, err)
	}
	writeErr := readonly.UpsertTarget(ctx, "example.test", "should-not-write")
	if writeErr == nil {
		t.Fatal("read-only database accepted a write")
	}
	if !strings.Contains(strings.ToLower(writeErr.Error()), "readonly") {
		t.Fatalf("write error = %v, want read-only failure", writeErr)
	}
	if after, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if string(after) != string(before) {
		t.Fatal("read-only browsing changed the database bytes")
	}
}

func TestOpenReadOnlyRejectsMissingDatabaseWithoutCreatingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "enumeration.db")
	if _, err := OpenReadOnly(path); err == nil {
		t.Fatal("missing database unexpectedly opened")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("read-only open created parent directory: %v", err)
	}
}
