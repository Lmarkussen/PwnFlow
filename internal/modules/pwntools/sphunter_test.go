package pwntools

import (
	"context"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
)

func runtimeWithDomain(domain string) *modules.Runtime {
	return &modules.Runtime{ModuleOptions: map[string]map[string]string{sphunterID: {m365DomainOption: domain}}}
}

func TestSPHunterValidatesExplicitMicrosoftDomain(t *testing.T) {
	module := SPHunter{}
	valid := []string{"contoso.com", "tenant.example.co.uk", "a1.example-domain.net"}
	for _, domain := range valid {
		if err := module.ValidateInput(m365DomainOption, domain); err != nil {
			t.Errorf("ValidateInput(%q): %v", domain, err)
		}
	}
	invalid := []string{"", "https://contoso.com", "contoso.com/path", "127.0.0.1", "-contoso.com", "contoso-.com"}
	for _, domain := range invalid {
		if err := module.ValidateInput(m365DomainOption, domain); err == nil {
			t.Errorf("ValidateInput(%q) accepted an invalid discovery domain", domain)
		}
	}
}

func TestSPHunterGlobalPlanSkipsWithoutScope(t *testing.T) {
	module := SPHunter{}
	include, reason := module.IncludeInGlobalPlanForRuntime(&modules.Runtime{})
	if include || reason != "Skipped — Microsoft 365 domain not configured" {
		t.Fatalf("scope-less plan decision = %v, %q", include, reason)
	}
	if got := module.Status(&modules.Runtime{}); got != modules.StatusInputRequired {
		t.Fatalf("scope-less status = %v, want input required", got)
	}
	if got := module.MissingInputs(&modules.Runtime{}); len(got) != 1 || got[0].Key != m365DomainOption {
		t.Fatalf("scope-less inputs = %#v", got)
	}
}

func TestSPHunterGlobalPlanAcceptsOnlyValidConfiguredScope(t *testing.T) {
	module := SPHunter{}
	include, reason := module.IncludeInGlobalPlanForRuntime(runtimeWithDomain("contoso.com"))
	if !include || reason != "" {
		t.Fatalf("valid plan decision = %v, %q", include, reason)
	}
	include, reason = module.IncludeInGlobalPlanForRuntime(runtimeWithDomain("https://contoso.com"))
	if include || !strings.Contains(reason, "invalid") {
		t.Fatalf("invalid plan decision = %v, %q", include, reason)
	}
}

func TestSPHunterCheckNeverContactsNetworkWithoutScope(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (SPHunter{}).Check(ctx, &modules.Runtime{}); err == nil {
		t.Fatal("scope-less Check unexpectedly succeeded")
	}
}
