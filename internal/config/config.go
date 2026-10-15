package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Config struct{ Target, Domain, Username, Password, Root string }

const (
	AuthorizedTarget = "10.1.10.40"
	AuthorizedDomain = "sccm.lab"
)

func New(target, domain, username, password, root string) (Config, error) {
	if target == "" || domain == "" || username == "" {
		return Config{}, fmt.Errorf("target, domain, and username are required")
	}
	if strings.TrimSpace(target) != AuthorizedTarget || strings.TrimSpace(domain) != AuthorizedDomain {
		return Config{}, fmt.Errorf("target restricted to authorized lab %s/%s", AuthorizedTarget, AuthorizedDomain)
	}
	clean, err := SafePathPart(domain)
	if err != nil {
		return Config{}, fmt.Errorf("invalid domain: %w", err)
	}
	return Config{Target: target, Domain: clean, Username: username, Password: password, Root: root}, nil
}
func (c Config) ResultsRoot() string { return filepath.Join(c.Root, "results", c.Domain) }
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
