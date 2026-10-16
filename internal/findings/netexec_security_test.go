package findings

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeNetExecSecurityFindsSigningAndAccountFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "netexec.txt")
	body := strings.Join([]string{
		"SMB 198.51.100.41 445 MECM [*] Windows Server (signing:False) (SMBv1:False)",
		"\x1b[32mSMB 198.51.100.40 445 DC [*] Windows Server (signing:True) (SMBv1:False)\x1b[0m",
		"LDAP 198.51.100.40 389 DC [+] User: svc-example",
		"userAccountControl: 66080", // PASSWD_NOTREQD + DONT_EXPIRE_PASSWORD + NORMAL_ACCOUNT.
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	inputs, err := AnalyzeNetExecSecurity(context.Background(), path, 7, 9, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 3 {
		t.Fatalf("records=%d, want signing plus two account flags", len(inputs))
	}
	seen := map[string]bool{}
	for _, input := range inputs {
		seen[input.FindingType] = true
		if input.AffectedObject == "" || strings.Contains(input.EvidenceJSON, "password") {
			t.Fatalf("unexpected derived metadata: %#v", input)
		}
	}
	for _, typ := range []string{"smb_signing_not_required", "ad_account_passwd_notreqd", "ad_account_dont_expire_password"} {
		if !seen[typ] {
			t.Fatalf("missing %s: %#v", typ, seen)
		}
	}
	for _, input := range inputs {
		if strings.HasPrefix(input.FindingType, "ad_account_") && input.AffectedObject != "svc-example" {
			t.Fatalf("account flag attributed to %q", input.AffectedObject)
		}
	}
}

func TestAnalyzeNetExecSecurityIgnoresUnsupportedOrUnrelatedText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "negative.txt")
	body := strings.Join([]string{
		"SMB 198.51.100.40 445 DC [*] Windows Server (signing:True)",
		"SMB 198.51.100.42 445 SQL [*] status unknown",
		"LDAP 198.51.100.40 389 DC [+] User: ordinary",
		"description: password never expires; userAccountControl: 512", // no matching UAC flag.
		"banner: signing:False",                                        // no valid SMB result.
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	inputs, err := AnalyzeNetExecSecurity(context.Background(), path, 1, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 0 {
		t.Fatalf("negative records=%d, want zero", len(inputs))
	}
}

func TestAnalyzeNetExecSecurityDeduplicatesConditions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "duplicate.txt")
	body := strings.Join([]string{
		"SMB 198.51.100.41 445 MECM [*] one (signing:False)",
		"SMB 198.51.100.41 445 MECM [*] repeated (signing:False)",
		"LDAP 198.51.100.40 389 DC [+] User: svc-example",
		"userAccountControl: PASSWD_NOTREQD|DONT_EXPIRE_PASSWORD",
		"userAccountControl: PASSWD_NOTREQD|DONT_EXPIRE_PASSWORD",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	inputs, err := AnalyzeNetExecSecurity(context.Background(), path, 1, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 3 {
		t.Fatalf("records=%d, want three unique conditions", len(inputs))
	}
}
