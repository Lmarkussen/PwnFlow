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
	// LDAPOptions carries the already-approved transport policy into modules
	// that perform a focused LDAP read after preflight. It is intentionally
	// opaque here to keep config independent from the LDAP transport package.
	LDAPOptions any
	// ModuleOptions carries values only the operator can supply, such as the
	// registry path a query module must read or the search text another module
	// looks for. They are keyed by module ID and option key, and a module that
	// needs one reports UNAVAILABLE until it is present.
	ModuleOptions map[string]map[string]string
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

// ModuleOptionPattern and ModuleOptionKeyPattern describe the shape of one
// operator-supplied module option: "<module-id>.<KEY>=<VALUE>".
var (
	ModuleOptionIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
	ModuleOptionKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// ParseModuleOptions turns repeated --module-options values into the map the
// runtime hands to modules. Each value is one assignment:
//
//	--module-options smb-reg-query.PATH='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
//
// The form is deliberately one option per flag: a module option value such as a
// regex or a Windows path may itself contain '=', ';', and ',', so the operator's
// shell quoting, not a separator inside the value, decides where it ends.
func ParseModuleOptions(values []string) (map[string]map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	options := make(map[string]map[string]string)
	for _, raw := range values {
		spec, value, found := strings.Cut(raw, "=")
		if !found {
			return nil, fmt.Errorf("invalid --module-options value: expected MODULE.KEY=VALUE")
		}
		moduleID, key, found := strings.Cut(spec, ".")
		if !found {
			return nil, fmt.Errorf("module option %q must name the module and the key, as MODULE.KEY=VALUE", spec)
		}
		if !ModuleOptionIDPattern.MatchString(moduleID) {
			return nil, fmt.Errorf("module option %q has an unsupported module identifier", moduleID)
		}
		if !ModuleOptionKeyPattern.MatchString(key) {
			return nil, fmt.Errorf("module option %q has an unsupported option key", key)
		}
		if strings.TrimSpace(value) == "" {
			// The value itself is never echoed: this text reaches the terminal
			// and may end up quoted in a report.
			return nil, fmt.Errorf("module option %q has an empty value", spec)
		}
		if strings.ContainsAny(value, "\x00\n\r") {
			return nil, fmt.Errorf("module option %q contains a control character", spec)
		}
		if options[moduleID] == nil {
			options[moduleID] = make(map[string]string)
		}
		options[moduleID][key] = value
	}
	return options, nil
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
