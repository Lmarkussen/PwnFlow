package pwntools

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/dependencies"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/runner"
)

func runtimeWithDomain(domain string) *modules.Runtime {
	return &modules.Runtime{ModuleOptions: map[string]map[string]string{sphunterID: {m365DomainOption: domain}}}
}

func TestSPHunterValidatesExplicitMicrosoftDomain(t *testing.T) {
	module := SPHunter{}
	valid := []string{"contoso.com", "tenant.example.co.uk", "a1.example-domain.net"}
	for _, domain := range valid {
		if err := module.ValidateInput(m365DomainOption, domain); err != nil {
			t.Errorf("ValidateInput(%q): %v", domain, err)
		}
	}
	invalid := []string{"", "https://contoso.com", "contoso.com/path", "127.0.0.1", "-contoso.com", "contoso-.com"}
	for _, domain := range invalid {
		if err := module.ValidateInput(m365DomainOption, domain); err == nil {
			t.Errorf("ValidateInput(%q) accepted an invalid discovery domain", domain)
		}
	}
}

func TestSPHunterGlobalPlanSkipsWithoutScope(t *testing.T) {
	module := SPHunter{}
	include, reason := module.IncludeInGlobalPlanForRuntime(&modules.Runtime{})
	if include || reason != "Skipped — Microsoft 365 domain not configured" {
		t.Fatalf("scope-less plan decision = %v, %q", include, reason)
	}
	if got := module.Status(&modules.Runtime{}); got != modules.StatusInputRequired {
		t.Fatalf("scope-less status = %v, want input required", got)
	}
	if got := module.MissingInputs(&modules.Runtime{}); len(got) != 1 || got[0].Key != m365DomainOption {
		t.Fatalf("scope-less inputs = %#v", got)
	}
}

func TestSPHunterGlobalPlanAcceptsOnlyValidConfiguredScope(t *testing.T) {
	module := SPHunter{}
	include, reason := module.IncludeInGlobalPlanForRuntime(runtimeWithDomain("contoso.com"))
	if !include || reason != "" {
		t.Fatalf("valid plan decision = %v, %q", include, reason)
	}
	include, reason = module.IncludeInGlobalPlanForRuntime(runtimeWithDomain("https://contoso.com"))
	if include || !strings.Contains(reason, "invalid") {
		t.Fatalf("invalid plan decision = %v, %q", include, reason)
	}
}

func TestSPHunterCheckNeverContactsNetworkWithoutScope(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (SPHunter{}).Check(ctx, &modules.Runtime{}); err == nil {
		t.Fatal("scope-less Check unexpectedly succeeded")
	}
}

func fakeSPHunterStatus(t *testing.T, body string) dependencies.Status {
	t.Helper()
	script := filepath.Join(t.TempDir(), "fake-sphunter.sh")
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return dependencies.Status{
		Definition:  dependencies.Definition{ID: dependencies.SPHunter, DisplayName: "SPHunter"},
		Available:   true,
		State:       "installed",
		Root:        filepath.Dir(script),
		Interpreter: "/bin/sh",
		Script:      script,
	}
}

func TestSPHunterRunPassesJSONDestinationAndCreatesScopedArtifact(t *testing.T) {
	var recorded string
	recordFile := filepath.Join(t.TempDir(), "argv")
	status := fakeSPHunterStatus(t, "#!/bin/sh\nprintf '%s\\n' \"$@\" > "+shellQuote(recordFile)+"\necho contoso.com\njson=\"\"\nprevious=\"\"\nfor arg in \"$@\"; do if [ \"$previous\" = \"--json\" ]; then json=\"$arg\"; fi; previous=\"$arg\"; done\nprintf '{\"ok\":true,\"input_domain\":\"contoso.com\"}\\n' > \"$json\"\n")
	sphunterDependencyStatus = func(context.Context) dependencies.Status { return status }
	defer func() {
		sphunterDependencyStatus = func(ctx context.Context) dependencies.Status {
			return dependencies.DefaultRegistry().CheckOne(ctx, dependencies.SPHunter)
		}
	}()

	root := t.TempDir()
	runtime := runtimeWithDomain("contoso.com")
	runtime.ResultsRoot = root
	var output bytes.Buffer
	if err := (SPHunter{}).Run(context.Background(), runtime, &output); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(recordFile)
	if err != nil {
		t.Fatal(err)
	}
	recorded = string(data)
	args := strings.Fields(recorded)
	jsonIndex := stringIndex(args, "--json")
	if jsonIndex < 0 || jsonIndex+1 >= len(args) || args[jsonIndex+1] == "" {
		t.Fatalf("recorded argv has no JSON destination: %q", recorded)
	}
	artifact := args[jsonIndex+1]
	if !strings.HasPrefix(artifact, root+string(os.PathSeparator)) || !strings.HasSuffix(artifact, "tenant-discovery.json") {
		t.Fatalf("artifact is not execution-scoped below results root: %q", artifact)
	}
	if _, err := os.Stat(filepath.Dir(artifact)); err != nil {
		t.Fatalf("artifact parent was not created: %v", err)
	}
	jsonData, err := os.ReadFile(artifact)
	if err != nil || !json.Valid(jsonData) {
		t.Fatalf("artifact is not valid JSON: err=%v data=%q", err, jsonData)
	}
	if info, err := os.Stat(artifact); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("artifact permissions = %v, want 0600", info.Mode().Perm())
	}
	if !strings.Contains(output.String(), "contoso.com") {
		t.Fatalf("tool output was not preserved: %q", output.String())
	}

	runtime2 := runtimeWithDomain("contoso.com")
	runtime2.ResultsRoot = root
	if err := (SPHunter{}).Run(context.Background(), runtime2, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	artifacts, err := filepath.Glob(filepath.Join(root, "Enumeration", "PwnTools", "SPHunter", "executions", "*", "tenant-discovery.json"))
	if err != nil || len(artifacts) != 2 {
		t.Fatalf("execution-scoped artifacts = %v, err=%v", artifacts, err)
	}
	if artifacts[0] == artifacts[1] {
		t.Fatal("two executions reused the same artifact path")
	}
}

func TestSPHunterFailureClassificationAndMissingArtifact(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"invalid arguments", "#!/bin/sh\necho 'argument --json: expected one argument' >&2\nexit 2\n", "SPHunter argument error"},
		{"unsuccessful discovery", "#!/bin/sh\necho 'tenant discovery failed' >&2\nexit 1\n", "SPHunter discovery unsuccessful"},
		{"missing JSON", "#!/bin/sh\nexit 0\n", "without producing its JSON artifact"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status := fakeSPHunterStatus(t, test.body)
			sphunterDependencyStatus = func(context.Context) dependencies.Status { return status }
			defer func() {
				sphunterDependencyStatus = func(ctx context.Context) dependencies.Status {
					return dependencies.DefaultRegistry().CheckOne(ctx, dependencies.SPHunter)
				}
			}()
			runtime := runtimeWithDomain("contoso.com")
			runtime.ResultsRoot = t.TempDir()
			err := (SPHunter{}).Run(context.Background(), runtime, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestSPHunterTimeoutAndCancellation(t *testing.T) {
	status := fakeSPHunterStatus(t, "#!/bin/sh\nsleep 2\n")
	sphunterDependencyStatus = func(context.Context) dependencies.Status { return status }
	defer func() {
		sphunterDependencyStatus = func(ctx context.Context) dependencies.Status {
			return dependencies.DefaultRegistry().CheckOne(ctx, dependencies.SPHunter)
		}
	}()

	for _, test := range []struct {
		name        string
		makeContext func() (context.Context, context.CancelFunc)
		want        string
	}{
		{"timeout", func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 20*time.Millisecond)
		}, "SPHunter network timeout"},
		{"cancellation", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		}, "context canceled"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := test.makeContext()
			defer cancel()
			runtime := runtimeWithDomain("contoso.com")
			runtime.ResultsRoot = t.TempDir()
			err := (SPHunter{}).Run(ctx, runtime, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestSPHunterDoesNotUseADDomainAsMicrosoftScope(t *testing.T) {
	module := SPHunter{}
	runtime := &modules.Runtime{Domain: "sccm.lab"}
	include, reason := module.IncludeInGlobalPlanForRuntime(runtime)
	if include || reason != "Skipped — Microsoft 365 domain not configured" {
		t.Fatalf("AD domain was implicitly used: include=%v reason=%q", include, reason)
	}
}

func TestSPHunterRunnerRecordsTheExecutionScopedJSONPath(t *testing.T) {
	status := fakeSPHunterStatus(t, "#!/bin/sh\njson=\"\"\nprevious=\"\"\nfor arg in \"$@\"; do if [ \"$previous\" = \"--json\" ]; then json=\"$arg\"; fi; previous=\"$arg\"; done\nprintf '{\"ok\":true}\\n' > \"$json\"\n")
	sphunterDependencyStatus = func(context.Context) dependencies.Status { return status }
	defer func() {
		sphunterDependencyStatus = func(ctx context.Context) dependencies.Status {
			return dependencies.DefaultRegistry().CheckOne(ctx, dependencies.SPHunter)
		}
	}()

	root := t.TempDir()
	runtime := runtimeWithDomain("contoso.com")
	runtime.ResultsRoot = root
	result := (runner.Runner{}).Execute(context.Background(), SPHunter{}, runtime, root)
	if result.Err != nil || result.Status != "completed" {
		t.Fatalf("runner result = status %q err %v", result.Status, result.Err)
	}
	if !strings.HasSuffix(result.OutputPath, "tenant-discovery.json") {
		t.Fatalf("runner output path = %q", result.OutputPath)
	}
	data, err := os.ReadFile(result.OutputPath)
	if err != nil || !json.Valid(data) {
		t.Fatalf("runner JSON artifact = %q, err=%v", data, err)
	}
	if _, err := os.Stat(filepath.Join(root, sphunterOutput)); !os.IsNotExist(err) {
		t.Fatalf("legacy fixed artifact unexpectedly exists: err=%v", err)
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func stringIndex(values []string, wanted string) int {
	for index, value := range values {
		if value == wanted {
			return index
		}
	}
	return -1
}
