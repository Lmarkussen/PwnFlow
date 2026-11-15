package netexec

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/runner"
)

func TestEnumCVERegistrationAndCapabilities(t *testing.T) {
	defer ResetCapabilities()
	for _, entry := range SMBEnumerationModules() {
		m := entry.(Module)
		if m.ID() != "smb-enum-cve" {
			continue
		}
		r := testRuntime()
		want := []string{"smb", r.Target, "-u", r.Username, "-p", r.Password, "-d", r.Domain, "-M", "enum_cve"}
		if !reflect.DeepEqual(m.CommandArgs(r), want) {
			t.Fatal(m.CommandArgs(r))
		}
		if strings.Contains(m.CommandPreview(r), r.Password) {
			t.Fatal("credential leak")
		}
		if !strings.HasSuffix(m.OutputFile(), "SMB_enum_cve.txt") || !m.ReadOnly() {
			t.Fatal("invalid evidence registration")
		}
		capabilitySnapshot.protocols[modules.ProtocolSMB] = protocolCapability{helpOK: true, probed: true, at: time.Now()}
		if m.checkCapabilities(context.Background()) == nil {
			t.Fatal("unverified listing accepted")
		}
		capabilitySnapshot.protocols[modules.ProtocolSMB] = protocolCapability{helpOK: true, modulesOK: true, modules: []byte("[*] enum_av something"), probed: true, at: time.Now()}
		if m.Status(r) != modules.StatusUnavailable {
			t.Fatal("missing module accepted")
		}
		capabilitySnapshot.protocols[modules.ProtocolSMB] = protocolCapability{helpOK: true, modulesOK: true, modules: []byte("[*] enum_cve Registry checks"), probed: true, at: time.Now()}
		if err := m.checkCapabilities(context.Background()); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("registration missing")
}

func TestEnumCVEMockedExecutionEvidence(t *testing.T) {
	for _, tc := range []struct{ name, output, status string }{
		{"positive", "ENUM_CVE 192.0.2.1 445 DC CVE-2025-33073 - NTLM reflection - Relay possible from SMB to any protocol", "completed"},
		{"failure", "ENUM_CVE 192.0.2.1 445 DC DCERPC error: denied", "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ResetCapabilities()
			defer ResetCapabilities()
			bin := t.TempDir()
			script := "#!/bin/sh\ncase \"$*\" in *--help*) echo usage; exit 0;; *-L*) echo '[*] enum_cve Registry checks'; exit 0;; *--version*) echo test-version; exit 0;; esac\necho 'SMB 192.0.2.1 445 DC [+] example.test/lab:Sup3rSecret'\necho '" + tc.output + "'\n"
			if err := os.WriteFile(filepath.Join(bin, "nxc"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin)
			for _, m := range SMBEnumerationModules() {
				if m.ID() != "smb-enum-cve" {
					continue
				}
				r := testRuntime()
				r.ResultsRoot = t.TempDir()
				result := (runner.Runner{Secrets: []string{r.Password}}).Execute(context.Background(), m, r, r.ResultsRoot)
				if result.Status != tc.status {
					t.Fatalf("%+v", result)
				}
				data, err := os.ReadFile(result.OutputPath)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(data), tc.output) || strings.Contains(string(data), r.Password) {
					t.Fatal(string(data))
				}
				return
			}
			t.Fatal("missing registration")
		})
	}
}

func TestSelectedNetExecUsedForProbesAndExecution(t *testing.T) {
	ResetCapabilities()
	defer ResetCapabilities()
	root := t.TempDir()
	t.Setenv("PWNFLOW_TOOLS_DIR", root)
	t.Setenv("PWNFLOW_NETEXEC", "")
	env := filepath.Join(root, "NetExec", "versions", "verified")
	dir := filepath.Join(env, "bin")
	os.MkdirAll(dir, 0700)
	log := filepath.Join(t.TempDir(), "selected.log")
	t.Setenv("NXC_SELECTION_LOG", log)
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$NXC_SELECTION_LOG"
case "$*" in *--help*) echo usage;exit 0;; *-L*) echo '[*] enum_cve Registry checks';exit 0;; *--version*) echo source-version;exit 0;; esac
echo 'ENUM_CVE 192.0.2.1 445 DC Not vulnerable to NTLM reflection (UBR 9999 >= 4270)'
`
	os.WriteFile(filepath.Join(dir, "nxc"), []byte(script), 0700)
	os.Symlink(env, filepath.Join(root, "NetExec", "current"))
	old := t.TempDir()
	os.WriteFile(filepath.Join(old, "nxc"), []byte("#!/bin/sh\nexit 99\n"), 0700)
	t.Setenv("PATH", old)
	for _, entry := range SMBEnumerationModules() {
		m := entry.(Module)
		if m.ID() != "smb-enum-cve" {
			continue
		}
		r := testRuntime()
		r.ResultsRoot = t.TempDir()
		result := (runner.Runner{}).Execute(context.Background(), m, r, r.ResultsRoot)
		if result.Status != "completed" {
			t.Fatalf("%+v", result)
		}
		if !strings.Contains(strings.Join(m.DetailLines(r), "\n"), filepath.Join(dir, "nxc")) {
			t.Fatal("selected executable missing from module diagnostics")
		}
		calls, _ := os.ReadFile(log)
		for _, want := range []string{"smb --help", "smb -L", "-M enum_cve"} {
			if !strings.Contains(string(calls), want) {
				t.Fatalf("missing selected invocation %s", want)
			}
		}
		second := filepath.Join(root, "NetExec", "versions", "unsupported")
		os.MkdirAll(filepath.Join(second, "bin"), 0700)
		os.WriteFile(filepath.Join(second, "bin", "nxc"), []byte("#!/bin/sh\necho usage\n"), 0700)
		os.Remove(filepath.Join(root, "NetExec", "current"))
		os.Symlink(second, filepath.Join(root, "NetExec", "current"))
		if m.checkCapabilities(context.Background()) == nil {
			t.Fatal("old capability cache reused after selection changed")
		}
		return
	}
	t.Fatal("missing enum_cve registration")
}
