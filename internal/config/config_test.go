package config

import (
	"strings"
	"testing"
)

// PwnFlow is a general-purpose framework: any operator-supplied assessment
// configuration must be accepted, and no development lab value may be required
// or substituted.
func TestNewAcceptsOperatorSuppliedConfiguration(t *testing.T) {
	for _, test := range []struct{ target, domain string }{
		{"198.51.100.10", "example.test"},
		{"203.0.113.7", "corp.local"},
		{"dc01.example.test", "example.test"},
		{"2001:db8::1", "ipv6.example"},
	} {
		cfg, err := New(test.target, test.domain, "audituser", "secret", t.TempDir())
		if err != nil {
			t.Fatalf("New(%q, %q) rejected operator input: %v", test.target, test.domain, err)
		}
		if cfg.Target != test.target || cfg.Domain != test.domain {
			t.Fatalf("configuration was rewritten: %#v", cfg)
		}
		if want := cfg.Root + "/results/" + test.domain; cfg.ResultsRoot() != want {
			t.Fatalf("results root = %q, want %q", cfg.ResultsRoot(), want)
		}
	}
}

func TestNewRejectsInvalidInput(t *testing.T) {
	for name, test := range map[string]struct{ target, domain, username string }{
		"missing target":     {"", "example.test", "user"},
		"blank target":       {"   ", "example.test", "user"},
		"missing domain":     {"198.51.100.10", "", "user"},
		"missing username":   {"198.51.100.10", "example.test", ""},
		"option-like target": {"--domain", "example.test", "user"},
		"target with space":  {"198.51.100.10 --help", "example.test", "user"},
		"domain traversal":   {"198.51.100.10", "../escape", "user"},
		"domain separator":   {"198.51.100.10", "a/b", "user"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(test.target, test.domain, test.username, "secret", t.TempDir()); err == nil {
				t.Fatalf("expected rejection for %#v", test)
			}
		})
	}
}

// Nothing may silently substitute a development lab value when the operator
// supplies something else.
func TestNewNeverFallsBackToAFixedLab(t *testing.T) {
	cfg, err := New("198.51.100.10", "example.test", "user", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, surface := range []string{cfg.Target, cfg.Domain, cfg.ResultsRoot()} {
		if strings.Contains(surface, "sccm.lab") || strings.Contains(surface, "10.1.10.40") {
			t.Fatalf("configuration leaked a fixed lab value: %q", surface)
		}
	}
}

func TestNewPreservesPasswordExactly(t *testing.T) {
	password := "P@ss word\twith\ncharacters"
	cfg, err := New("198.51.100.10", "example.test", "user", password, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != password {
		t.Fatalf("password changed from %q", cfg.Password)
	}
}

func TestSafePathPart(t *testing.T) {
	for _, value := range []string{"../x", "a/b", `a\b`, ""} {
		if _, err := SafePathPart(value); err == nil {
			t.Errorf("expected rejection for %q", value)
		}
	}
	if got, err := SafePathPart("corp.local"); err != nil || got != "corp.local" {
		t.Fatal(got, err)
	}
}

func TestSafeTargetPart(t *testing.T) {
	for _, value := range []string{"", "  ", "-x", "host name", "a/b", "host\tname"} {
		if _, err := SafeTargetPart(value); err == nil {
			t.Errorf("expected rejection for %q", value)
		}
	}
	for _, value := range []string{"10.1.10.40", "dc01.corp.local", "2001:db8::1", " 198.51.100.10 "} {
		if _, err := SafeTargetPart(value); err != nil {
			t.Errorf("unexpected rejection for %q: %v", value, err)
		}
	}
}
