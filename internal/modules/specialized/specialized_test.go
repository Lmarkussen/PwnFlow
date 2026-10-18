package specialized

import (
	"context"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
)

func TestModulesExposeOnlyBoundedModes(t *testing.T) {
	seen := map[string]bool{}
	for _, module := range Modules() {
		if seen[module.ID()] {
			t.Fatalf("duplicate module id %q", module.ID())
		}
		seen[module.ID()] = true
		if module.ID() == "sccmsecrets-offline" && module.ExecutionEnabled() {
			t.Fatal("SCCMSecrets live-capable registration was enabled")
		}
		if strings.Contains(module.CommandPreview(&modules.Runtime{Target: "198.51.100.42", Domain: "example.test", Username: "user", Password: "secret"}), "secret@") || strings.Contains(module.CommandPreview(&modules.Runtime{Target: "198.51.100.42", Domain: "example.test", Username: "user", Password: "secret"}), ":secret") {
			t.Fatalf("secret leaked in preview for %s", module.ID())
		}
	}
	for _, id := range []string{"mssqlrelay-check", "mssqlpwner-enumerate", "gpoparser-local", "gpoparser-remote", "ghostspn-audit", "sccmsecrets-offline"} {
		if !seen[id] {
			t.Fatalf("missing module %q", id)
		}
	}
}

func TestOfflineModuleRequiresExplicitPaths(t *testing.T) {
	for _, module := range Modules() {
		if module.ID() != "gpoparser-local" && module.ID() != "sccmsecrets-offline" {
			continue
		}
		missing := module.MissingInputs(&modules.Runtime{})
		if len(missing) == 0 {
			t.Fatalf("%s accepts no explicit artifact input", module.ID())
		}
		if err := module.Check(context.Background(), &modules.Runtime{Target: "dc", Domain: "example.test", Username: "user"}); err == nil {
			t.Fatalf("%s ran without its explicit input", module.ID())
		}
	}
}

func TestCommandBuildersMatchInstalledCLIs(t *testing.T) {
	runtime := &modules.Runtime{Target: "198.51.100.42", Domain: "example.test", Username: "operator", Password: "synthetic-password"}
	cases := map[string][]string{
		"mssqlrelay-check":     {"check", "-target", "198.51.100.42", "-u", "operator@example.test", "-p", "synthetic-password", "-windows-auth"},
		"mssqlpwner-enumerate": {"example.test/operator:synthetic-password@198.51.100.42", "-windows-auth", "enumerate"},
		"gpoparser-remote":     {"remote", "-s", "198.51.100.42", "-d", "example.test", "-u", "operator", "-p", "synthetic-password", "-o", "artifact"},
		"ghostspn-audit":       {"--server", "198.51.100.42", "--domain", "example.test", "--username", "operator", "--password", "synthetic-password", "--output", "artifact"},
	}
	for _, module := range Modules() {
		want, ok := cases[module.ID()]
		if !ok {
			continue
		}
		got := module.definition.Args(runtime, "artifact")
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("%s args = %#v, want %#v", module.ID(), got, want)
		}
	}
	for _, module := range Modules() {
		if module.ID() == "ghostspn-audit" || strings.HasPrefix(module.ID(), "gpoparser-") {
			if !strings.HasSuffix(module.OutputFile(), ".json") {
				t.Errorf("%s output is not structured JSON: %s", module.ID(), module.OutputFile())
			}
		}
	}
}

func TestMSSQLCommandBuildersUseExplicitMSSQLTarget(t *testing.T) {
	runtime := &modules.Runtime{
		Target: "198.51.100.40", Domain: "example.test", Username: "operator", Password: "synthetic-password",
		ModuleOptions: map[string]map[string]string{
			"mssqlrelay-check":     {"MSSQL_TARGET": "198.51.100.42"},
			"mssqlpwner-enumerate": {"MSSQL_TARGET": "198.51.100.42"},
		},
	}
	for _, module := range Modules() {
		var want []string
		switch module.ID() {
		case "mssqlrelay-check":
			want = []string{"check", "-target", "198.51.100.42", "-u", "operator@example.test", "-p", "synthetic-password", "-windows-auth"}
		case "mssqlpwner-enumerate":
			want = []string{"example.test/operator:synthetic-password@198.51.100.42", "-windows-auth", "enumerate"}
		default:
			continue
		}
		got := module.definition.Args(runtime, "artifact")
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("%s args = %#v, want %#v", module.ID(), got, want)
		}
	}
}

func TestMSSQLRelaySemanticFailureDoesNotLookSuccessful(t *testing.T) {
	output := []byte("[-] [Errno 111] Connection refused\n[-] 'int' object has no attribute 'sendall'\n")
	if err := semanticAssessmentError("mssqlrelay-check", output); err == nil {
		t.Fatal("recognized mssqlrelay failure was classified as success")
	}
	if err := semanticAssessmentError("mssqlrelay-check", []byte("[+] encryption check complete; no qualifying finding")); err != nil {
		t.Fatalf("ordinary no-finding output was classified as failure: %v", err)
	}
	if err := semanticAssessmentError("mssqlpwner-enumerate", output); err != nil {
		t.Fatalf("unrelated tool output was classified as mssqlrelay failure: %v", err)
	}
}

func TestExtractJSONPayloadIgnoresDiagnosticPreamble(t *testing.T) {
	payload, ok := extractJSONPayload([]byte("retrieving {GPO}\n{\"gpos\":[{\"name\":\"synthetic\"}]}\n"))
	if !ok || string(payload) != `{"gpos":[{"name":"synthetic"}]}` {
		t.Fatalf("payload=%q ok=%v", payload, ok)
	}
}

func TestExtractJSONPayloadRejectsMalformedOrDiagnosticOnlyOutput(t *testing.T) {
	for _, input := range []string{"retrieving {GPO}", "{\"gpos\":[", "diagnostic [not-json]"} {
		if _, ok := extractJSONPayload([]byte(input)); ok {
			t.Fatalf("accepted invalid payload %q", input)
		}
	}
}
