package pwnflow

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// documentationNetworks are the blocks reserved for examples (RFC 5737) plus
// loopback and the unspecified address. The approved test environment block is
// listed separately so its fixtures can remain.
var documentationNetworks = []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8", "0.0.0.0/32"}

// approvedNetworks holds the one environment whose fixtures may stay in the
// repository. Everything else must be supplied by the operator at runtime.
var approvedNetworks = []string{"10.1.10.40/32"}

// RE2 has no lookaround, so the pattern relies on word boundaries: an address is
// a dotted quad of one-to-three digit groups.
var addressPattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

func parseNetworks(t *testing.T, blocks []string) []*net.IPNet {
	t.Helper()
	networks := make([]*net.IPNet, 0, len(blocks))
	for _, block := range blocks {
		_, network, err := net.ParseCIDR(block)
		if err != nil {
			t.Fatalf("bad network block: %v", err)
		}
		networks = append(networks, network)
	}
	return networks
}

// maskAddress keeps a finding identifiable without printing the address.
func maskAddress(value string) string {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return "<address>"
	}
	return parts[0] + ".x.x.x"
}

// disallowedAddresses reports address literals that are neither reserved for
// documentation nor part of the approved environment.
func disallowedAddresses(content string, allowed []*net.IPNet) []string {
	var found []string
	for _, candidate := range addressPattern.FindAllString(content, -1) {
		address := net.ParseIP(candidate)
		if address == nil {
			continue
		}
		permitted := false
		for _, network := range allowed {
			if network.Contains(address) {
				permitted = true
				break
			}
		}
		if !permitted {
			found = append(found, maskAddress(candidate))
		}
	}
	return found
}

// maskIdentifier keeps a finding locatable without printing it in full.
func maskIdentifier(value string) string {
	if len(value) <= 4 {
		return "<identifier>"
	}
	return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
}

// trackedFiles lists the files Git would publish.
func trackedFiles(t *testing.T) []string {
	t.Helper()
	output, err := exec.Command("git", "ls-files", "-z").Output()
	if err != nil {
		t.Skipf("git is unavailable in this environment: %v", err)
	}
	var files []string
	for _, name := range strings.Split(strings.TrimRight(string(output), "\x00"), "\x00") {
		if name != "" {
			files = append(files, name)
		}
	}
	if len(files) < 10 {
		t.Fatalf("tracked file walk returned %d entries", len(files))
	}
	return files
}

func TestTrackedFilesUseOnlyDocumentationOrApprovedAddresses(t *testing.T) {
	allowed := append(parseNetworks(t, documentationNetworks), parseNetworks(t, approvedNetworks)...)
	for _, path := range trackedFiles(t) {
		contents, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if findings := disallowedAddresses(string(contents), allowed); len(findings) > 0 {
			t.Errorf("%s contains a non-documentation address %v; use a reserved example block and keep real values runtime-supplied", path, findings)
		}
	}
}

// denylistedIdentifiers reads the local list of real environment identifiers.
//
// The list is deliberately not part of the repository: it comes from
// PWNFLOW_SANITIZATION_DENYLIST (comma separated) or from the gitignored
// .sanitization-denylist file, one identifier per line. Keeping it outside the
// tracked tree is what lets this check know the real values without publishing
// them, which is also why it skips when nothing is configured.
func denylistedIdentifiers(t *testing.T) []string {
	t.Helper()
	var identifiers []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" && !strings.HasPrefix(value, "#") {
			identifiers = append(identifiers, value)
		}
	}
	for _, value := range strings.Split(os.Getenv("PWNFLOW_SANITIZATION_DENYLIST"), ",") {
		add(value)
	}
	contents, err := os.ReadFile(".sanitization-denylist")
	if err == nil {
		for _, line := range strings.Split(string(contents), "\n") {
			add(line)
		}
	}
	return identifiers
}

func TestTrackedFilesContainNoDenylistedIdentifiers(t *testing.T) {
	identifiers := denylistedIdentifiers(t)
	if len(identifiers) == 0 {
		t.Skip("no local denylist configured; set PWNFLOW_SANITIZATION_DENYLIST or create the gitignored .sanitization-denylist")
	}
	for _, path := range trackedFiles(t) {
		contents, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, identifier := range identifiers {
			if strings.Contains(string(contents), identifier) {
				t.Errorf("%s contains a denylisted environment identifier (masked: %s)", path, maskIdentifier(identifier))
			}
		}
	}
}

// Credentials, results, databases, and generated binaries must not be publishable.
func TestRepositoryPublishesNoGeneratedOrSensitiveArtifacts(t *testing.T) {
	for _, path := range trackedFiles(t) {
		lowered := strings.ToLower(path)
		switch {
		case strings.HasPrefix(lowered, "bin/"), strings.HasPrefix(lowered, "results/"):
			t.Errorf("%s must not be tracked", path)
		case strings.HasSuffix(lowered, ".db"), strings.HasSuffix(lowered, ".db-wal"), strings.HasSuffix(lowered, ".db-shm"):
			t.Errorf("%s must not be tracked", path)
		case strings.HasSuffix(lowered, ".secret"), strings.HasSuffix(lowered, ".credentials"):
			t.Errorf("%s must not be tracked", path)
		}
	}
	output, err := exec.Command("git", "check-ignore", ".sanitization-denylist").Output()
	if err != nil || len(strings.TrimSpace(string(output))) == 0 {
		t.Fatalf("the local denylist path must stay ignored: %v", err)
	}
}

// The detection mechanism is covered with synthetic values so it is exercised
// even when no real denylist is configured, without embedding real identifiers.
func TestSanitizationDetectionMechanism(t *testing.T) {
	synthetic := "synthetic-environment-identifier.invalid"
	if !strings.Contains("prefix "+synthetic+" suffix", synthetic) {
		t.Fatal("substring detection is broken")
	}
	if masked := maskIdentifier(synthetic); strings.Contains(masked, synthetic) || !strings.Contains(masked, "*") {
		t.Fatalf("identifier masking is ineffective: %q", masked)
	}
	allowed := parseNetworks(t, append(append([]string{}, documentationNetworks...), approvedNetworks...))
	// The address that must be flagged is assembled at run time so the check does
	// not report this file, which is exactly what it is supposed to detect.
	unapproved := fmt.Sprintf("%d.%d.%d.%d", 10, 20, 30, 40)
	findings := disallowedAddresses("ok 192.0.2.10 198.51.100.7 127.0.0.1 10.1.10.40; not ok "+unapproved, allowed)
	if len(findings) != 1 || findings[0] != maskAddress(unapproved) {
		t.Fatalf("unexpected findings: %v", findings)
	}
}
