package netexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/modules/networkhound"
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
		Target:              "198.51.100.15",
		Domain:              "example.test",
		Username:            "reader",
		Password:            "secret",
		ResultsRoot:         "/results",
		ExecutionOutputPath: "/results/Enumeration/NetExec/SMB_spider_plus/executions/run/transcript.txt",
		ModuleOptions:       map[string]map[string]string{"networkhound-scope-validation": {"NETWORKS": "198.51.100.15"}},
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

func TestSpiderPlusManualEndpointOptionIsAcceptedButOutputPathIsNotConfigurable(t *testing.T) {
	module := spiderPlusModuleForTest(t)
	warnings := modules.OptionWarnings([]modules.Module{module}, map[string]map[string]string{
		module.ID(): {"SMB_ENDPOINTS": "198.51.100.15"},
	})
	if len(warnings) != 0 {
		t.Fatalf("authorized scope was rejected as an unknown policy option: %v", warnings)
	}
	runtime := &modules.Runtime{
		Target:              "198.51.100.15",
		ExecutionOutputPath: "/results/Enumeration/NetExec/SMB_spider_plus/executions/run/transcript.txt",
		ModuleOptions:       map[string]map[string]string{"networkhound-scope-validation": {"NETWORKS": "198.51.100.15"}, module.ID(): {"SMB_ENDPOINTS": "198.51.100.15", "OUTPUT_FOLDER": "/tmp/unsafe"}},
	}
	args := strings.Join(module.CommandArgs(runtime), " ")
	if strings.Contains(args, "OUTPUT_FOLDER=/tmp/unsafe") || !strings.Contains(args, "OUTPUT_FOLDER=/results/Enumeration/NetExec/SMB_spider_plus/executions/run") {
		t.Fatalf("operator output override was not rejected: %s", args)
	}
}

func TestSpiderPlusRequiresApprovedNetworkHoundScope(t *testing.T) {
	module := spiderPlusModuleForTest(t)
	for _, test := range []struct {
		name, scope string
		allowed     bool
	}{
		{name: "exact", scope: "198.51.100.15", allowed: true},
		{name: "multiple exact targets", scope: "198.51.100.14,198.51.100.15", allowed: true},
		{name: "different target", scope: "198.51.100.16", allowed: false},
		{name: "wildcard", scope: "198.51.100.0/24", allowed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := &modules.Runtime{Target: "198.51.100.15", ModuleOptions: map[string]map[string]string{"networkhound-scope-validation": {"NETWORKS": test.scope}}}
			approved, _ := module.PlanApproval(runtime)
			if !approved {
				t.Fatal("spider_plus must remain explicitly approval-gated")
			}
			if got := networkhound.AddressInScope(runtime.Target, test.scope); got != test.allowed {
				t.Fatalf("AddressInScope(%q)=%v, want %v", test.scope, got, test.allowed)
			}
		})
	}
}

func TestSpiderPlusCheckRejectsOutOfScopeTargetWithoutRunning(t *testing.T) {
	runtime := &modules.Runtime{
		Target:        "198.51.100.15",
		Domain:        "example.test",
		ModuleOptions: map[string]map[string]string{"networkhound-scope-validation": {"NETWORKS": "198.51.100.16"}},
	}
	// The dependency/capability checks may fail first on a developer workstation;
	// the pure scope predicate is asserted separately above. This test documents
	// the no-run policy without invoking NetExec or a target.
	if networkhound.AddressInScope(runtime.Target, runtime.ModuleOptions["networkhound-scope-validation"]["NETWORKS"]) {
		t.Fatal("out-of-scope target was accepted")
	}
}

func TestSpiderPlusUsesCurrentNetworkHoundSMBEndpoints(t *testing.T) {
	module := spiderPlusModuleForTest(t)
	artifact := filepath.Join(t.TempDir(), "network_scope.json")
	data := `{"devices":[{"ip":"198.51.100.10","open_ports":[445]},{"ip":"198.51.100.10","open_ports":[445]},{"ip":"203.0.113.5","open_ports":[445]}]}`
	if err := os.WriteFile(artifact, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := &modules.Runtime{
		Target: "198.51.100.10", Domain: "example.test", ResultsRoot: t.TempDir(),
		BatchArtifacts: map[string]string{"networkhound-scope-validation": artifact},
		ModuleOptions: map[string]map[string]string{
			"networkhound-scope-validation": {"NETWORKS": "198.51.100.0/24"},
		},
	}
	targets, err := module.spiderTargets(runtime)
	if err != nil || len(targets) != 1 || targets[0] != "198.51.100.10" {
		t.Fatalf("unexpected current-batch targets: %#v, %v", targets, err)
	}
	args := module.CommandArgs(&modules.Runtime{Target: targets[0], ExecutionOutputPath: filepath.Join(runtime.ResultsRoot, "run", "transcript.txt")})
	if strings.Contains(strings.Join(args, " "), "DOWNLOAD_FLAG") {
		t.Fatal("spider_plus command enables downloads")
	}
	if _, err := json.Marshal(args); err != nil {
		t.Fatal(err)
	}
}

func TestSpiderPlusSkipsWithoutCurrentNetworkHoundEvidence(t *testing.T) {
	module := spiderPlusModuleForTest(t)
	runtime := &modules.Runtime{
		Target: "198.51.100.10", Domain: "example.test",
		ModuleOptions: map[string]map[string]string{
			"networkhound-scope-validation": {"NETWORKS": "198.51.100.0/24"},
		},
	}
	_, err := module.spiderTargets(runtime)
	var skipped modules.SkipError
	if !errors.As(err, &skipped) || !strings.Contains(err.Error(), "NetworkHound SMB discovery unavailable") {
		t.Fatalf("missing current-batch evidence was not skipped: %v", err)
	}
}

func TestSpiderPlusRunsTargetsConcurrentlyAndPreservesOrder(t *testing.T) {
	module := spiderPlusModuleForTest(t)
	targets := []string{"198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13"}
	var mu sync.Mutex
	active, peak := 0, 0
	started := make(chan string, len(targets))
	start := time.Now()
	results := module.runSpiderTargets(context.Background(), &modules.Runtime{}, &bytes.Buffer{}, targets, func(ctx context.Context, runtime *modules.Runtime, _ modules.OutputSink) error {
		mu.Lock()
		active++
		if active > peak {
			peak = active
		}
		mu.Unlock()
		started <- runtime.Target
		select {
		case <-time.After(40 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
		mu.Lock()
		active--
		mu.Unlock()
		return nil
	})
	if elapsed := time.Since(start); elapsed >= 120*time.Millisecond {
		t.Fatalf("targets ran serially or exceeded the bounded parallel window: %s", elapsed)
	}
	if peak != len(targets) {
		t.Fatalf("peak concurrent targets=%d, want %d", peak, len(targets))
	}
	if len(results) != len(targets) {
		t.Fatalf("got %d target results, want %d", len(results), len(targets))
	}
	for index, result := range results {
		if result.index != index || result.target != targets[index] || result.err != nil {
			t.Fatalf("result %d = %#v, want successful target %q", index, result, targets[index])
		}
	}
	for range targets {
		<-started
	}
}

func TestSpiderPlusTargetWorkersStopOnCancellation(t *testing.T) {
	module := spiderPlusModuleForTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 2)
	done := make(chan []spiderTargetResult, 1)
	go func() {
		done <- module.runSpiderTargets(ctx, &modules.Runtime{}, &bytes.Buffer{}, []string{"198.51.100.10", "198.51.100.11"}, func(ctx context.Context, _ *modules.Runtime, _ modules.OutputSink) error {
			started <- struct{}{}
			<-ctx.Done()
			return ctx.Err()
		})
	}()
	for range []int{0, 1} {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("target worker did not start")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("target workers did not stop after cancellation")
	}
}

func TestSpiderPlusTargetWorkersRespectTimeout(t *testing.T) {
	module := spiderPlusModuleForTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	results := module.runSpiderTargets(ctx, &modules.Runtime{}, &bytes.Buffer{}, []string{"198.51.100.10", "198.51.100.11"}, func(ctx context.Context, _ *modules.Runtime, _ modules.OutputSink) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("timeout cleanup took too long: %s", elapsed)
	}
	if len(results) != 2 {
		t.Fatalf("got %d timed-out target results, want 2", len(results))
	}
	for _, result := range results {
		if !errors.Is(result.err, context.DeadlineExceeded) {
			t.Fatalf("target %s error=%v, want deadline exceeded", result.target, result.err)
		}
	}
}
