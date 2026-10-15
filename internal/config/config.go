package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Config struct {
	Target, Domain, Username, Password, Root string
	// InsecureSkipVerify skips LDAPS/StartTLS certificate verification. It is set
	// only by the explicit operator flag and is never enabled by default.
	InsecureSkipVerify bool
}

// New validates operator-supplied assessment configuration. PwnFlow is a
// general-purpose framework: the target, domain, and credentials come from the
// operator, so this validates the shape of the input and the safety of the path
// components instead of comparing it against any fixed assessment scope.
func New(target, domain, username, password, root string) (Config, error) {
	if strings.TrimSpace(target) == "" || strings.TrimSpace(domain) == "" || strings.TrimSpace(username) == "" {
		return Config{}, fmt.Errorf("target, domain, and username are required")
	}
	cleanTarget, err := SafeTargetPart(target)
	if err != nil {
		return Config{}, fmt.Errorf("invalid target: %w", err)
	}
	clean, err := SafePathPart(domain)
	if err != nil {
		return Config{}, fmt.Errorf("invalid domain: %w", err)
	}
	return Config{Target: cleanTarget, Domain: clean, Username: username, Password: password, Root: root}, nil
}
func (c Config) ResultsRoot() string { return filepath.Join(c.Root, "results", c.Domain) }

// SafeTargetPart validates an operator-supplied target address. The value is
// passed to tools as a command argument and used for connection setup, so it must
// be non-empty, must not look like a command-line option, and must contain only
// address characters (IPv4, IPv6, or host name).
func SafeTargetPart(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("target is required")
	}
	if strings.HasPrefix(value, "-") {
		return "", fmt.Errorf("target must not start with '-'")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._:-]*[A-Za-z0-9])?$`).MatchString(value) {
		return "", fmt.Errorf("unsupported target characters")
	}
	return value, nil
}

func SafePathPart(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "." || value == ".." || strings.Contains(value, "..") || strings.ContainsAny(value, `/\\`) {
		return "", fmt.Errorf("path traversal is not allowed")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`).MatchString(value) {
		return "", fmt.Errorf("unsupported path characters")
	}
	return value, nil
}
func ProjectRoot() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return filepath.Dir(exe), nil
}
