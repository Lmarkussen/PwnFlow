package artifacts

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// OperatorIDs returns the account that launched an elevated PwnFlow process when
// sudo supplied it, otherwise the current process identity.
func OperatorIDs() (int, int, error) {
	uid, gid := os.Getuid(), os.Getgid()
	if rawUID, rawGID := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID"); rawUID != "" && rawGID != "" {
		parsedUID, errUID := strconv.Atoi(rawUID)
		parsedGID, errGID := strconv.Atoi(rawGID)
		if errUID == nil && errGID == nil && parsedUID >= 0 && parsedGID >= 0 {
			uid, gid = parsedUID, parsedGID
		}
	}
	return uid, gid, nil
}

// NormalizeTree hands ownership of one newly-created execution tree back to the
// operator. Symlinks are never followed, and callers must pass only a scoped,
// current-run directory—not the historical results root.
func NormalizeTree(root string) error {
	uid, gid, err := OperatorIDs()
	if err != nil {
		return err
	}
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (int(stat.Uid) == uid && int(stat.Gid) == gid) {
			return nil
		}
		if err := os.Chown(path, uid, gid); err != nil {
			return fmt.Errorf("change owner of %s: %w", path, err)
		}
		return nil
	})
}

// NormalizePaths changes ownership only for explicitly named files. It does not
// recurse into their parent directories and therefore cannot rewrite history.
func NormalizePaths(paths ...string) error {
	uid, gid, err := OperatorIDs()
	if err != nil {
		return err
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if ok && int(stat.Uid) == uid && int(stat.Gid) == gid {
			continue
		}
		if err := os.Chown(path, uid, gid); err != nil {
			return fmt.Errorf("change owner of %s: %w", path, err)
		}
	}
	return nil
}

// EnsureDirectory creates a scoped directory without following symlink path
// components and hands only components created by this call to the operator.
func EnsureDirectory(path string, mode os.FileMode) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	parts := filepath.VolumeName(absolute)
	remaining := absolute[len(parts):]
	current := parts + string(filepath.Separator)
	created := make([]string, 0)
	for _, part := range splitPath(remaining) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("directory path component is not a real directory: %s", current)
			}
			continue
		}
		if !os.IsNotExist(err) {
			return err
		}
		if err := os.Mkdir(current, mode); err != nil {
			return err
		}
		created = append(created, current)
	}
	return NormalizePaths(created...)
}

func splitPath(path string) []string {
	var parts []string
	for path != "" {
		part := filepath.Base(path)
		if part == string(filepath.Separator) || part == "." {
			break
		}
		parts = append(parts, part)
		path = filepath.Dir(path)
		if path == string(filepath.Separator) || path == "." {
			break
		}
	}
	for left, right := 0, len(parts)-1; left < right; left, right = left+1, right-1 {
		parts[left], parts[right] = parts[right], parts[left]
	}
	return parts
}
