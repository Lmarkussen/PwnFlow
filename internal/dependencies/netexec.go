package dependencies

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// NetExecExecutable shares the dependency resolver with every execution/probe.
// An explicit override or managed installation is authoritative: an unusable
// selection must not silently fall back to a different PATH executable.
func NetExecExecutable(ctx context.Context) (string, error) {
	path, _, err := findExecutable(ctx, Definition{ID: NetExec, Executable: "nxc"})
	return path, err
}

func selectedNetExec() (string, bool, error) {
	if configured := strings.TrimSpace(os.Getenv("PWNFLOW_NETEXEC")); configured != "" {
		if !filepath.IsAbs(configured) {
			return "", true, fmt.Errorf("PWNFLOW_NETEXEC must be an absolute executable path")
		}
		path, err := exec.LookPath(configured)
		if err != nil {
			return "", true, fmt.Errorf("explicit NetExec %s is unusable: %w", configured, err)
		}
		return path, true, nil
	}
	root, err := filepath.Abs(ToolRoots("NetExec")[0])
	if err != nil {
		return "", true, err
	}
	current := filepath.Join(root, "current")
	_, err = os.Lstat(current)
	if err == nil {
		path := filepath.Join(current, "bin", "nxc")
		found, err := exec.LookPath(path)
		if err != nil {
			return "", true, fmt.Errorf("managed NetExec %s is unusable; run ./install.sh --with-netexec: %w", path, err)
		}
		return found, true, nil
	}
	if !os.IsNotExist(err) {
		return "", true, err
	}
	if data, err := os.ReadFile(filepath.Join(root, "last-update-error")); err == nil {
		return "", true, fmt.Errorf("managed NetExec update failed: %s; no PATH fallback", strings.TrimSpace(string(data)))
	}
	return "", false, nil
}
