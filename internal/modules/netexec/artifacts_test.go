package netexec

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/runner"
)

// A NetExec module that recovers credentials is a finding-producing module: its
// output has to reach the assessment artifact intact, under the assessment's own
// results root, with permissions only the owner can read.
func TestRecoveredNetExecFindingIsPreservedInTheAssessmentArtifact(t *testing.T) {
	finding := `SMB 198.51.100.10 445 DC [+] example.test\audituser:Sup3rSecret`
	recovered := "[+] GPP password for example.test\\svc-deploy: 'fictional-recovered'"
	installFakeNXC(t, `#!/bin/sh
if [ "$2" = "-L" ]; then
  printf 'LOW PRIVILEGE MODULES\nCREDENTIAL_DUMPING\n[*] gpp_password   Retrieves the plaintext password pushed through Group Policy Preferences.\n'
  exit 0
fi
echo '`+finding+`'
echo "`+recovered+`"
exit 0
`)
	entry := findModule(t, "smb-gpp-password")
	runtime := &modules.Runtime{Target: testTarget, Domain: testDomain, Username: "audituser", Password: "Sup3rSecret"}
	root := t.TempDir()
	result := (runner.Runner{Secrets: []string{runtime.Password}, BufferLimit: 8192}).
		Execute(context.Background(), entry, runtime, root)
	if result.Status != "completed" {
		t.Fatalf("status=%s err=%v", result.Status, result.Err)
	}
	if !strings.HasPrefix(result.OutputPath, root+string(filepath.Separator)) {
		t.Fatalf("the artifact left the assessment root: %s", result.OutputPath)
	}
	persisted, err := os.ReadFile(result.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(persisted), recovered) {
		t.Fatalf("the recovered finding was rewritten:\n%s", persisted)
	}
	info, err := os.Stat(result.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("artifact mode = %o, want 0600", mode)
	}
	dir, err := os.Stat(filepath.Dir(result.OutputPath))
	if err != nil {
		t.Fatal(err)
	}
	// The runner creates artifact directories owner-and-group readable inside a
	// results root that is already restricted; what must never happen is world
	// access to the collected findings.
	if mode := dir.Mode().Perm(); mode&0007 != 0 {
		t.Fatalf("artifact directory mode = %o, want no world access", mode)
	}
}

// The artifact path follows the category the registration is filed under, so a
// credential-access module cannot write into the enumeration tree.
func TestNetExecArtifactPathsFollowTheCategory(t *testing.T) {
	cases := map[string]string{
		"smb-shares":       "Enumeration/NetExec/SMB_shares.txt",
		"smb-gpp-password": "CredentialDumping/NetExec/SMB_gpp_password.txt",
		"kerberoasting":    "CredentialAuditing/NetExec/LDAP_kerberoasting/artifacts",
		"smb-dpapi-hash":   "CredentialDumping/NetExec/SMB_dpapi_hash.txt",
		"smb-add-computer": "PrivilegeEscalation/NetExec/SMB_add_computer.txt",
		"pre2k":            "PrivilegeEscalation/NetExec/LDAP_pre2k.txt",
	}
	for id, want := range cases {
		if got := findModule(t, id).OutputFile(); got != filepath.FromSlash(want) {
			t.Fatalf("%s output = %q, want %q", id, got, filepath.FromSlash(want))
		}
	}
}
