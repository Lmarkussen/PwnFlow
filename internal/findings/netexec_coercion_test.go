package findings

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNetExecCoercionServices(t *testing.T) {
	dir := t.TempDir()
	spooler := filepath.Join(dir, "SMB_spooler.txt")
	webdav := filepath.Join(dir, "SMB_webdav.txt")
	os.WriteFile(spooler, []byte("SMB                      192.0.2.10      445    DC01             [*] Windows Server 2019 (name:DC01) (domain:corp.example) (signing:True) (SMBv1:False)\n"+
		"SPOOLER                  192.0.2.10      445    DC01             Spooler service enabled\n"), 0o600)
	os.WriteFile(webdav, []byte("WEBDAV                   192.0.2.10      445    DC01             WebClient Service enabled on: 192.0.2.10\n"+
		"WEBDAV                   192.0.2.10      445    DC01             [-] Error enumerating WebDAV: STATUS_ACCESS_DENIED\n"), 0o600)
	for path, want := range map[string]string{spooler: "smb_spooler_service_running", webdav: "smb_webclient_service_running"} {
		inputs, err := AnalyzeNetExecCoercion(context.Background(), path, 1, 2, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if len(inputs) != 1 || inputs[0].FindingType != want || inputs[0].AffectedObject != "DC01" || inputs[0].Severity != "medium" {
			t.Fatalf("%s: got %+v", filepath.Base(path), inputs)
		}
	}
	quiet := filepath.Join(dir, "SMB_spooler_quiet.txt")
	os.WriteFile(quiet, []byte("SMB                      192.0.2.10      445    DC01             [+] corp.example\\auditor:x\n"), 0o600)
	if inputs, _ := AnalyzeNetExecCoercion(context.Background(), quiet, 1, 2, time.Now()); len(inputs) != 0 {
		t.Fatalf("no service output produced %+v", inputs)
	}
	for _, name := range []string{"SMB_spooler.txt", "SMB_webdav.txt"} {
		if got := netExecArtifactForExecution("Check", filepath.Join(dir, name)); got == "" {
			t.Fatalf("%s is not routed for reanalysis", name)
		}
	}
}
