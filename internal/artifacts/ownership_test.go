package artifacts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeTreeDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(root, "inside")
	if err := os.WriteFile(inside, []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := NormalizeTree(root); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "outside" {
		t.Fatalf("symlink target was touched: %v %q", err, data)
	}
}

func TestOperatorIDsHonorsSudoIdentity(t *testing.T) {
	t.Setenv("SUDO_UID", "1234")
	t.Setenv("SUDO_GID", "2345")
	uid, gid, err := OperatorIDs()
	if err != nil {
		t.Fatal(err)
	}
	if uid != 1234 || gid != 2345 {
		t.Fatalf("operator identity = %d:%d, want 1234:2345", uid, gid)
	}
}
