package findings

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
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
	if findings[0].AffectedObject != "FlaggedTemplate" || findings[0].Severity != "medium" || findings[0].ArtifactRef != "/Certificate Templates/FlaggedTemplate" {
		t.Fatalf("unexpected Certipy finding: %+v", findings[0])
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
