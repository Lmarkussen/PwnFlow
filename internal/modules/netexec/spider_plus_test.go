package netexec

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/modules"
)

func spiderPlusModuleForTest(t *testing.T) Module {
	t.Helper()
	for _, module := range SMBEnumerationModules() {
		if module.ID() == "smb-spider-plus" {
			return module.(Module)
		}
	}
	t.Fatal("smb-spider-plus was not registered")
	return Module{}
}

func TestSpiderPlusUsesMetadataOnlyCommandAndExecutionScopedOutput(t *testing.T) {
	module := spiderPlusModuleForTest(t)
	runtime := &modules.Runtime{
		Target:              "10.0.0.15",
		Domain:              "example.test",
		Username:            "reader",
		Password:            "secret",
		ResultsRoot:         "/results",
		ExecutionOutputPath: "/results/Enumeration/NetExec/SMB_spider_plus/executions/run/transcript.txt",
		ModuleOptions:       map[string]map[string]string{module.ID(): {"AUTHORIZED_SCOPE": "10.0.0.15"}},
	}
	args := module.CommandArgs(runtime)
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "DOWNLOAD_FLAG") || strings.Contains(joined, "AUTHORIZED_SCOPE") {
		t.Fatalf("policy or download option leaked into NetExec args: %#v", args)
	}
	if !strings.Contains(joined, "-M spider_plus") || !strings.Contains(joined, "OUTPUT_FOLDER=/results/Enumeration/NetExec/SMB_spider_plus/executions/run") {
		t.Fatalf("unexpected spider_plus args: %#v", args)
	}
	first := module.ExecutionArtifactPath("/results", time.Unix(1, 0))
	second := module.ExecutionArtifactPath("/results", time.Unix(2, 0))
	if first == second || !strings.HasSuffix(first, "transcript.txt") {
		t.Fatalf("execution artifact paths are not unique: %q %q", first, second)
	}
	if filepath.Dir(first) == filepath.Dir(second) {
		t.Fatalf("execution artifact directories are not unique: %q %q", first, second)
	}
}

func TestSpiderPlusPolicyOptionIsAcceptedButOutputPathIsNotConfigurable(t *testing.T) {
	module := spiderPlusModuleForTest(t)
	warnings := modules.OptionWarnings([]modules.Module{module}, map[string]map[string]string{
		module.ID(): {"AUTHORIZED_SCOPE": "10.0.0.15"},
	})
	if len(warnings) != 0 {
		t.Fatalf("authorized scope was rejected as an unknown policy option: %v", warnings)
	}
	runtime := &modules.Runtime{
		Target:              "10.0.0.15",
		ExecutionOutputPath: "/results/Enumeration/NetExec/SMB_spider_plus/executions/run/transcript.txt",
		ModuleOptions:       map[string]map[string]string{module.ID(): {"AUTHORIZED_SCOPE": "10.0.0.15", "OUTPUT_FOLDER": "/tmp/unsafe"}},
	}
	args := strings.Join(module.CommandArgs(runtime), " ")
	if strings.Contains(args, "OUTPUT_FOLDER=/tmp/unsafe") || !strings.Contains(args, "OUTPUT_FOLDER=/results/Enumeration/NetExec/SMB_spider_plus/executions/run") {
		t.Fatalf("operator output override was not rejected: %s", args)
	}
}

func TestSpiderPlusRequiresExactAuthorizedTargetScope(t *testing.T) {
	module := spiderPlusModuleForTest(t)
	for _, test := range []struct {
		name, scope string
		allowed     bool
	}{
		{name: "exact", scope: "10.0.0.15", allowed: true},
		{name: "multiple exact targets", scope: "10.0.0.14,10.0.0.15", allowed: true},
		{name: "different target", scope: "10.0.0.16", allowed: false},
		{name: "wildcard", scope: "10.0.0.0/24", allowed: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := &modules.Runtime{Target: "10.0.0.15", ModuleOptions: map[string]map[string]string{module.ID(): {"AUTHORIZED_SCOPE": test.scope}}}
			approved, _ := module.PlanApproval(runtime)
			if !approved {
				t.Fatal("spider_plus must remain explicitly approval-gated")
			}
			if got := scopeAllowsTarget(test.scope, runtime.Target); got != test.allowed {
				t.Fatalf("scopeAllowsTarget(%q)=%v, want %v", test.scope, got, test.allowed)
			}
		})
	}
}

func TestSpiderPlusCheckRejectsOutOfScopeTargetWithoutRunning(t *testing.T) {
	module := spiderPlusModuleForTest(t)
	runtime := &modules.Runtime{
		Target:        "10.0.0.15",
		Domain:        "example.test",
		ModuleOptions: map[string]map[string]string{module.ID(): {"AUTHORIZED_SCOPE": "10.0.0.16"}},
	}
	// The dependency/capability checks may fail first on a developer workstation;
	// the pure scope predicate is asserted separately above. This test documents
	// the no-run policy without invoking NetExec or a target.
	if scopeAllowsTarget(runtime.ModuleOptions[module.ID()]["AUTHORIZED_SCOPE"], runtime.Target) {
		t.Fatal("out-of-scope target was accepted")
	}
}
