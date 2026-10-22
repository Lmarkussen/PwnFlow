package findings

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeNetExecGPPFindsRecoverablePasswordsWithEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SMB_gpp_password.txt")
	data := strings.Join([]string{
		"GPP_PASS 198.51.100.40 445 DC [*] Found sccm.lab/Policies/{11111111-2222-3333-4444-555555555555}/Machine/Groups/Groups.xml",
		"GPP_PASS 198.51.100.40 445 DC [+] Decrypted password for SCCM\\svc-deploy: synthetic-secret-should-not-persist",
		"GPP_PASS 198.51.100.40 445 DC [+] Decrypted password for SCCM\\svc-deploy: synthetic-secret-should-not-persist",
		"GPP_PASS 198.51.100.40 445 DC [*] Found sccm.lab/Policies/{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}/Machine/Groups/Groups.xml",
		"GPP_PASS 198.51.100.40 445 DC [+] Recovered GPP password for SCCM\\svc-build: another-secret",
	}, "\n")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	inputs, err := AnalyzeNetExecGPP(context.Background(), path, 7, 9, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 2 {
		t.Fatalf("got %d findings, want two distinct exposures", len(inputs))
	}
	for _, input := range inputs {
		if input.Severity != "high" || input.FindingType != "netexec_gpp_password_exposure" {
			t.Fatalf("unexpected finding: %+v", input)
		}
		if !strings.Contains(input.EvidenceJSON, "synthetic-secret-should-not-persist") && !strings.Contains(input.EvidenceJSON, "another-secret") {
			t.Fatalf("recovered password missing from evidence: %s", input.EvidenceJSON)
		}
		if !strings.Contains(input.EvidenceJSON, "Groups/Groups.xml") || !strings.Contains(input.EvidenceJSON, "recoverable GPP password detected") {
			t.Fatalf("missing sanitized evidence context: %s", input.EvidenceJSON)
		}
	}
}

func TestAnalyzeNetExecGPPIgnoresMetadataAndFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SMB_gpp_password.txt")
	data := "GPP_PASS [*] Searching for potential XML files containing password fields\n" +
		"GPP_PASS [*] Found sccm.lab/Policies/{11111111-2222-3333-4444-555555555555}/Machine/Groups/Groups.xml\n" +
		"GPP_PASS [-] Unable to read SYSVOL file\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	inputs, err := AnalyzeNetExecGPP(context.Background(), path, 1, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 0 {
		t.Fatalf("metadata or failed retrieval created findings: %+v", inputs)
	}
}

func TestAnalyzeNetExecGPPParsesInstalledModuleShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SMB_gpp_password.txt")
	data := strings.Join([]string{
		"SMB [*] Found credentials in sccm.lab/Policies/{11111111-2222-3333-4444-555555555555}/Machine/Groups/Groups.xml",
		"SMB [+] Password: intentionally-redacted-fixture-value",
		"SMB [+] userName: LAB\\\\svc-deploy",
	}, "\n")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	inputs, err := AnalyzeNetExecGPP(context.Background(), path, 2, 3, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 1 || inputs[0].AffectedObject != `LAB\svc-deploy` {
		t.Fatalf("installed module shape=%#v", inputs)
	}
	if !strings.Contains(inputs[0].EvidenceJSON, "intentionally-redacted-fixture-value") {
		t.Fatal("installed module recovered password missing")
	}
}
