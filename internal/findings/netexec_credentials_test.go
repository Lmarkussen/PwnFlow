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
	content := "LDAP 198.51.100.1 user=LAB\\svc-backup Description: VPN password: Synthetic\\value!\n" +
		"LDAP 198.51.100.1 user=LAB\\helpdesk Description: Password policy managed by helpdesk\n" +
		"LDAP 198.51.100.1 user=LAB\\svc-deploy Description: Login: svc-deploy Pass: OtherSynthetic!\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := AnalyzeNetExecCredentials(context.Background(), path, 7, 9, timeNowForTest())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(findings))
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

func TestAnalyzeNetExecCredentialsCapturesKeywordOnlyAttributes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "LDAP_get_users_info.txt")
	content := "" +
		"LDAP User: LAB\\one Info: PWD=synthetic-value\n" +
		"LDAP User: LAB\\two Info: password policy managed by helpdesk\n" +
		"LDAP User: LAB\\three Notes: PASS appears here\n" +
		"LDAP User: LAB\\four Info: API_KEY=synthetic-token\n" +
		"LDAP User: LAB\\five Info: bypass is unrelated text\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := AnalyzeNetExecCredentials(context.Background(), path, 8, 10, timeNowForTest())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 4 {
		t.Fatalf("got %d findings, want 4", len(findings))
	}
	var exposures, observations int
	for _, finding := range findings {
		switch finding.FindingType {
		case "ad_user_description_credential_exposed":
			exposures++
		case "ad_user_description_keyword_observed":
			observations++
			if strings.Contains(finding.AffectedObject, "two") && !strings.Contains(finding.EvidenceJSON, `"value":"password policy managed by helpdesk"`) {
				t.Fatalf("keyword observation did not preserve attribute value: %s", finding.EvidenceJSON)
			}
		default:
			t.Fatalf("unexpected finding type %q", finding.FindingType)
		}
	}
	if exposures != 2 || observations != 2 {
		t.Fatalf("exposures=%d observations=%d, want 2/2", exposures, observations)
	}
}

func timeNowForTest() (now time.Time) { return time.Unix(1700000000, 0).UTC() }
