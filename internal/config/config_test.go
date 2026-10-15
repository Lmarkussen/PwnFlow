package config

import "testing"

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

func TestNewRestrictsAssessmentTarget(t *testing.T) {
	if _, err := New("192.0.2.10", AuthorizedDomain, "user", "password", t.TempDir()); err == nil {
		t.Fatal("expected unauthorized target to be rejected")
	}
	if _, err := New(AuthorizedTarget, "other.lab", "user", "password", t.TempDir()); err == nil {
		t.Fatal("expected unauthorized domain to be rejected")
	}
}

func TestNewPreservesPasswordExactly(t *testing.T) {
	password := "P@ss word\twith\ncharacters"
	cfg, err := New(AuthorizedTarget, AuthorizedDomain, "user", password, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != password {
		t.Fatalf("password changed from %q", password)
	}
}
