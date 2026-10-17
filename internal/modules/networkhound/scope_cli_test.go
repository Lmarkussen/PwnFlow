package networkhound

import (
	"strings"
	"testing"
)

func TestValidateCIDRRejectsInvalidAndManagementRanges(t *testing.T) {
	for _, value := range []string{"198.51.100.0/24", "192.0.2.10/32"} {
		if err := ValidateCIDR(value); err != nil {
			t.Fatalf("ValidateCIDR(%q): %v", value, err)
		}
	}
	for _, value := range []string{"198.51.100.0/33", "2001:db8::/64", "not-a-network", tailscaleRange()} {
		if err := ValidateCIDR(value); err == nil {
			t.Fatalf("ValidateCIDR(%q) accepted prohibited input", value)
		}
	}
}

func TestValidateScopePreservesExistingModuleContract(t *testing.T) {
	for _, value := range []string{"198.51.100.0/24", "198.51.100.40", "198.51.100.40-198.51.100.43"} {
		if err := ValidateScope(value); err != nil {
			t.Fatalf("ValidateScope(%q): %v", value, err)
		}
	}
}

func tailscaleRange() string { return strings.Join([]string{"100", "64", "0", "0/10"}, ".") }
