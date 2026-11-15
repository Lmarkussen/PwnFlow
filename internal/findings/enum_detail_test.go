package findings

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnumCVEOutcomes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SMB_enum_cve.txt")
	positive := "ENUM_CVE 192.0.2.1 445 DC CVE-2025-33073 - NTLM reflection - Relay possible from SMB to any protocol\n"
	data := positive + positive + "ENUM_CVE 192.0.2.1 445 DC Not vulnerable to Ghost SPN (UBR 7000 >= 6899)\nENUM_CVE 192.0.2.1 445 DC Cannot check ESC15: no patched UBR known\nENUM_CVE 192.0.2.1 445 DC DCERPC error: access denied\nENUM_CVE 192.0.2.1 445 DC Exploitation details: https://example.test/CVE-2025-33073\n"
	os.WriteFile(path, []byte(data), 0600)
	rows, err := AnalyzeEnumCVE(context.Background(), path, 1, 2, time.Now())
	if err != nil || len(rows) != 4 {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	for i, outcome := range []string{"potential-exposure", "negative", "unsupported", "execution-failure"} {
		if !strings.Contains(rows[i].EvidenceJSON, outcome) {
			t.Fatal(rows[i])
		}
	}
	if rows[0].Severity != "medium" || rows[0].ArtifactRef != "line:1" {
		t.Fatal(rows[0])
	}
	again, _ := AnalyzeEnumCVE(context.Background(), path, 1, 3, time.Now())
	if again[0].FindingKey != rows[0].FindingKey {
		t.Fatal("unstable dedup key")
	}
}
func TestBloodyADDetailPreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bloodyad.log")
	os.WriteFile(path, []byte("distinguishedName: CN=Lab,DC=example,DC=test\nobjectClass: user\nservicePrincipalName: WRITE\ndn: WRITE_DAC\n"), 0600)
	rows, err := AnalyzeBloodyADWritable(context.Background(), path, 1, 2, time.Now())
	if err != nil || len(rows) != 1 {
		t.Fatalf("%+v %v", rows, err)
	}
	if rows[0].Severity != "informational" || !strings.Contains(rows[0].EvidenceJSON, "servicePrincipalName") {
		t.Fatal(rows[0])
	}
	os.WriteFile(path, []byte("access denied"), 0600)
	rows, err = AnalyzeBloodyADWritable(context.Background(), path, 1, 2, time.Now())
	if err != nil || len(rows) != 0 {
		t.Fatalf("%+v %v", rows, err)
	}
}

func TestEnumCVEUnknownMessageIsInconclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enum_cve.txt")
	os.WriteFile(path, []byte("ENUM_CVE 192.0.2.1 445 DC CVE-2025-33073 - NTLM reflection - unrecognized output\n"), 0600)
	rows, err := AnalyzeEnumCVE(context.Background(), path, 1, 2, time.Now())
	if err != nil || len(rows) != 1 || rows[0].Severity != "informational" || !strings.Contains(rows[0].EvidenceJSON, "inconclusive") {
		t.Fatalf("%+v %v", rows, err)
	}
}
