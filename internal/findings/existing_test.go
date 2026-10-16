package findings

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestCertipyOnlyFindsToolFlaggedTemplates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certipy.json")
	document := map[string]any{"Certificate Templates": map[string]any{
		"SafeTemplate":    map[string]any{"Enabled": true},
		"FlaggedTemplate": map[string]any{"Enabled": true, "[!] Vulnerabilities": []any{"ESC1"}, "Owner": "EXAMPLE\\Admins"},
	}}
	writeJSON(t, path, document)
	findings, err := AnalyzeCertipy(context.Background(), path, 4, 9, time.Unix(1, 0))
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	if findings[0].AffectedObject != "FlaggedTemplate" || findings[0].Severity != "high" || findings[0].FindingType != "adcs_esc_esc1" || findings[0].ArtifactRef != "/Certificate Templates/FlaggedTemplate/[!] Vulnerabilities" {
		t.Fatalf("unexpected Certipy finding: %+v", findings[0])
	}
}

func TestCertipyIgnoresNonESCAndUnrelatedText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certipy.json")
	document := map[string]any{"Certificate Templates": map[string]any{
		"InventoryOnly":   map[string]any{"Enabled": true, "[!] Vulnerabilities": []any{}},
		"NumericKey":      map[string]any{"Enabled": true, "[!] Vulnerabilities": []any{"enrollment permissions require review"}},
		"DescriptionOnly": map[string]any{"Enabled": true, "[!] Vulnerabilities": []any{"Review documentation mentioning ESC1, but no classified vulnerability"}},
	}}
	writeJSON(t, path, document)
	findings, err := AnalyzeCertipy(context.Background(), path, 4, 9, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("non-ESC records became findings: %+v", findings)
	}
}

func TestCertipyParsesCALevelAndTemplateESCConditions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certipy.json")
	document := map[string]any{
		"Certificate Authorities": map[string]any{
			"SCCM-LAB-CA": map[string]any{"[!] Vulnerabilities": []any{"ESC7 : dangerous permissions", "ESC8 : HTTP Web Enrollment"}},
		},
		"Certificate Templates": map[string]any{
			"ADEnum-ESC1-Positive":    map[string]any{"Enabled": true, "[!] Vulnerabilities": []any{"ESC1 : enrollee supplies subject", "ESC4 : dangerous permissions"}},
			"ADEnum-ESC1-Unpublished": map[string]any{"Enabled": false, "[!] Vulnerabilities": []any{"ESC4 : reported condition"}},
		},
	}
	writeJSON(t, path, document)
	findings, err := AnalyzeCertipy(context.Background(), path, 4, 9, time.Unix(1, 0))
	if err != nil || len(findings) != 5 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	seen := map[string]storage.FindingInput{}
	for _, finding := range findings {
		seen[finding.AffectedObject+":"+finding.FindingType] = finding
	}
	if seen["SCCM-LAB-CA:adcs_esc_esc7"].ArtifactRef != "/Certificate Authorities/SCCM-LAB-CA/[!] Vulnerabilities" {
		t.Fatalf("CA evidence reference missing: %+v", seen)
	}
	if !strings.Contains(seen["ADEnum-ESC1-Unpublished:adcs_esc_esc4"].Description, "disabled") {
		t.Fatalf("template constraint missing: %+v", seen["ADEnum-ESC1-Unpublished:adcs_esc_esc4"])
	}
}

func TestCertipyParsesESCIdentifiersStoredAsJSONKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certipy.json")
	writeJSON(t, path, map[string]any{"Certificate Templates": map[string]any{
		"0": map[string]any{"Template Name": "Template", "[!] Vulnerabilities": map[string]any{"ESC4": "Template is owned by user."}},
	}})
	findings, err := AnalyzeCertipy(context.Background(), path, 4, 9, time.Unix(1, 0))
	if err != nil || len(findings) != 1 || findings[0].FindingType != "adcs_esc_esc4" || findings[0].AffectedObject != "Template" {
		t.Fatalf("key-based ESC condition was not parsed: findings=%+v err=%v", findings, err)
	}
}

func TestCertipyParsesTextVulnerabilitySections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certipy.txt")
	text := `Certificate Authorities
  0
    CA Name : SCCM-LAB-CA
    [!] Vulnerabilities
      ESC7 : User has dangerous permissions.
      ESC8 : Web Enrollment is enabled over HTTP.

Certificate Templates
  0
    Template Name : ADEnum-ESC1-Positive
    [!] Vulnerabilities
      ESC1 : Enrollee supplies subject.
      ESC4 : User has dangerous permissions.
`
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := AnalyzeCertipy(context.Background(), path, 4, 9, time.Unix(1, 0))
	if err != nil || len(findings) != 4 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	if findings[0].ArtifactPath != path || !strings.Contains(findings[0].ArtifactRef, "/line/") {
		t.Fatalf("text evidence location missing: %+v", findings[0])
	}
}

func TestExtractESCIdentifiersDeduplicatesAndNormalizes(t *testing.T) {
	identifiers := extractESCIdentifiers(map[string]any{"ESC4": "ESC1: condition", "details": []any{"esc4"}})
	if len(identifiers) != 2 || identifiers[0] != "ESC1" || identifiers[1] != "ESC4" {
		t.Fatalf("unexpected ESC identifiers: %#v", identifiers)
	}
}

func TestRelayKingRequiresExplicitPathEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relayking.json")
	document := map[string]any{"relay_paths": []any{
		map[string]any{"level": "high", "dest_host": "dc.example.test", "dest_protocol": "LDAP", "details": "synthetic"},
	}, "host_results": []any{map[string]any{"ntlm_enabled": true}}}
	writeJSON(t, path, document)
	findings, err := AnalyzeRelayKing(context.Background(), path, 4, 9, time.Unix(1, 0))
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	if findings[0].Severity != "high" || findings[0].Confidence != "tool-reported-path" || findings[0].AffectedObject != "dc.example.test" {
		t.Fatalf("unexpected RelayKing finding: %+v", findings[0])
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
