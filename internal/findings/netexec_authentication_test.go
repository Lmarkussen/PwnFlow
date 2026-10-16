package findings

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeNetExecAuthenticationSuccessAndPwned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nxc.txt")
	body := "SMB 198.51.100.40 445 DC [+] SCCM\\svc-example:synthetic-password\n" +
		"\x1b[32mWINRM 198.51.100.43 5985 CLIENT [+] SCCM\\svc-example:synthetic-password (Pwn3d!)\x1b[0m\n" +
		"SMB 198.51.100.40 445 DC [-] SCCM\\svc-example:STATUS_LOGON_FAILURE\n" +
		"banner Pwn3d! without an authentication record\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	inputs, err := AnalyzeNetExecAuthentication(context.Background(), path, 7, 9, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 3 {
		t.Fatalf("records=%d, want success plus success/Pwn3d pair", len(inputs))
	}
	for _, input := range inputs {
		if strings.Contains(input.Title+input.Description+input.EvidenceJSON+input.FindingKey, "synthetic-password") {
			t.Fatal("credential value leaked into derived finding metadata")
		}
	}
	var privileged bool
	for _, input := range inputs {
		if input.FindingType == "netexec_privileged_access" {
			privileged = true
			if input.AffectedObject != "198.51.100.43" || input.RelatedObject != "SCCM\\svc-example" {
				t.Fatalf("incorrect privileged association: %#v", input)
			}
		}
	}
	if !privileged {
		t.Fatal("Pwn3d record missing")
	}
}

func TestAnalyzeNetExecAuthenticationSupportsRegisteredProtocols(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protocols.txt")
	protocols := []string{"LDAP", "RDP", "SSH", "WMI", "FTP", "VNC", "MSSQL"}
	var body strings.Builder
	for index, protocol := range protocols {
		body.WriteString(protocol + " host" + string(rune('A'+index)) + " 1000 SERVER [+] EXAMPLE\\user:synthetic\n")
	}
	if err := os.WriteFile(path, []byte(body.String()), 0600); err != nil {
		t.Fatal(err)
	}
	inputs, err := AnalyzeNetExecAuthentication(context.Background(), path, 1, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != len(protocols) {
		t.Fatalf("records=%d, want %d", len(inputs), len(protocols))
	}
}

func TestAnalyzeNetExecAuthenticationIgnoresFailuresAndUnrelatedMarkers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "negative.txt")
	body := "SMB host 445 SERVER [-] EXAMPLE\\user:STATUS_LOGON_FAILURE\n" +
		"Pwn3d! appears in a banner but has no protocol authentication record\n" +
		"SMB host 445 SERVER [*] EXAMPLE\\user:indeterminate\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	inputs, err := AnalyzeNetExecAuthentication(context.Background(), path, 1, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 0 {
		t.Fatalf("negative records=%d, want zero", len(inputs))
	}
}
