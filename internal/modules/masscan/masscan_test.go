package masscan

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
)

func TestTargetValidationAndAuthorization(t *testing.T) {
	valid := []string{"198.51.100.10", "198.51.100.0/24", "198.51.100.10-198.51.100.20"}
	for _, value := range valid {
		if _, err := parseTarget(value); err != nil {
			t.Errorf("parseTarget(%q): %v", value, err)
		}
	}
	for _, value := range []string{"", "-x", "198.51.100.1/33", "198.51.100.20-198.51.100.10", "127.0.0.1", "0.0.0.0", "198.51.100.1;echo"} {
		if _, err := parseTarget(value); err == nil {
			t.Errorf("parseTarget(%q) unexpectedly succeeded", value)
		}
	}
	if err := targetWithinScope("198.51.100.0/25", "198.51.100.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := targetWithinScope("198.51.100.0/23", "198.51.100.0/24"); err == nil {
		t.Fatal("broader target escaped authorized scope")
	}
}

func TestMasscanInputsAndPreview(t *testing.T) {
	module := Module{}
	runtime := &modules.Runtime{ModuleOptions: map[string]map[string]string{moduleID: {optionTarget: "198.51.100.0/24", optionScope: "198.51.100.0/24"}}}
	if got := module.Status(runtime); got != modules.StatusSudoRequired {
		t.Fatalf("status = %v, want SUDO-REQ", got)
	}
	preview := module.CommandPreview(runtime)
	if !strings.Contains(preview, "sudo masscan --rate 4000 198.51.100.0/24 -p "+defaultPorts) || !strings.Contains(preview, "<per-run-artifact>/masscan.log") {
		t.Fatalf("unexpected preview: %s", preview)
	}
	if fields := module.MissingInputs(&modules.Runtime{}); len(fields) != 1 || fields[0].Key != optionTarget {
		t.Fatalf("unexpected input fields: %#v", fields)
	}
}

func TestMasscanScopeIsDistinctFromDependencyAvailability(t *testing.T) {
	module := Module{}
	base := map[string]string{optionTarget: "198.51.100.0/24"}
	if got := module.Status(&modules.Runtime{ModuleOptions: map[string]map[string]string{moduleID: base}}); got != modules.StatusSudoRequired {
		t.Fatalf("missing optional scope status = %v, want SUDO-REQ", got)
	}
	base[optionScope] = "198.51.100.10/32"
	if got := module.Status(&modules.Runtime{ModuleOptions: map[string]map[string]string{moduleID: base}}); got != modules.StatusScopeRequired {
		t.Fatalf("out-of-scope status = %v, want SCOPE-REQ", got)
	}
	base[optionTarget] = "198.51.100.10"
	if got := module.Status(&modules.Runtime{ModuleOptions: map[string]map[string]string{moduleID: base}}); got != modules.StatusSudoRequired {
		t.Fatalf("authorized status = %v, want SUDO-REQ", got)
	}
}

func TestRunUsesSudoAndUniqueGrepableArtifact(t *testing.T) {
	bin := t.TempDir()
	masscanScript := `if [ "$1" = "--version" ]; then echo "masscan version 1.3.2"; exit 1; fi
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-oG" ]; then shift; printf '%s\n' 'Host: 198.51.100.10 () Ports: 443/open/tcp//https///' > "$1"; exit 0; fi
  shift
done
exit 2`
	if err := os.WriteFile(filepath.Join(bin, "masscan"), []byte("#!/bin/sh\n"+masscanScript+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	sudoScript := `if [ "$1" = "-n" ]; then shift; fi
if [ "$1" = "-v" ]; then exit 0; fi
program="$1"; shift; exec "$program" "$@"`
	if err := os.WriteFile(filepath.Join(bin, "sudo"), []byte("#!/bin/sh\n"+sudoScript+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	runtime := &modules.Runtime{
		Target:      "198.51.100.10",
		ResultsRoot: t.TempDir(),
		ModuleOptions: map[string]map[string]string{moduleID: {
			optionTarget: "198.51.100.10", optionScope: "198.51.100.10",
		}},
		Elevation: approvedElevation{},
	}
	var output bytes.Buffer
	if err := (Module{}).Run(context.Background(), runtime, &output); err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(runtime.ResultsRoot, artifactFolder, "*", "masscan.log"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("unexpected run artifacts: %v %v", paths, err)
	}
	data, err := os.ReadFile(paths[0])
	if err != nil || !strings.Contains(string(data), "443/open/tcp") {
		t.Fatalf("grepable artifact was not preserved: %q %v", data, err)
	}
	if !strings.Contains(output.String(), "Masscan target=198.51.100.10") {
		t.Fatalf("execution metadata missing: %s", output.String())
	}
}

type approvedElevation struct{}

func (approvedElevation) ElevationApproved(string) bool                       { return true }
func (approvedElevation) RenewElevation(context.Context, string, string) bool { return true }
