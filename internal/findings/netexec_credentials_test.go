package findings

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeNetExecCredentialsUsesSourceReferencesWithoutPersistingValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "LDAP_get_users_description.txt")
	content := "LDAP 10.0.0.1 user=LAB\\svc-backup Description: VPN password: Synthetic\\value!\n" +
		"LDAP 10.0.0.1 user=LAB\\helpdesk Description: Password policy managed by helpdesk\n" +
		"LDAP 10.0.0.1 user=LAB\\svc-deploy Description: Login: svc-deploy Pass: OtherSynthetic!\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := AnalyzeNetExecCredentials(context.Background(), path, 7, 9, timeNowForTest())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	for _, finding := range findings {
		if strings.Contains(finding.EvidenceJSON, "Synthetic") || strings.Contains(finding.Title, "Synthetic") || strings.Contains(finding.Description, "Synthetic") {
			t.Fatalf("secret leaked into finding metadata: %+v", finding)
		}
		if !strings.HasPrefix(finding.ArtifactRef, "line:") {
			t.Fatalf("missing source line: %q", finding.ArtifactRef)
		}
	}
}

func timeNowForTest() (now time.Time) { return time.Unix(1700000000, 0).UTC() }
