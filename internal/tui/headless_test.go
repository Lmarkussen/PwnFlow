package tui

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/runner"
)

func TestHeadlessProgressTextIsPlainAndSanitized(t *testing.T) {
	value := safeAutoText("\x1b[31mpassword: hidden\x1b[0m")
	if strings.ContainsAny(value, "\x1b") || strings.Contains(value, "hidden") || strings.Contains(value, "31m") {
		t.Fatalf("unsafe progress text: %q", value)
	}
}

func TestHeadlessThemeDisablesColorWhenOutputIsRedirected(t *testing.T) {
	theme := newAutoTheme(&bytes.Buffer{})
	if theme.enabled || strings.Contains(theme.green("done"), "\x1b") {
		t.Fatal("redirected headless output enabled ANSI color")
	}
}

func TestHeadlessUsesTheCuratedDefaultPlanSource(t *testing.T) {
	registry := buildRegistry().All()
	byID := make(map[string]modules.Module, len(registry))
	for _, module := range registry {
		byID[module.ID()] = module
	}
	if len(defaultEnumerationModuleIDs) != 39 {
		t.Fatalf("default profile changed: %d modules", len(defaultEnumerationModuleIDs))
	}
	for _, id := range defaultEnumerationModuleIDs {
		if _, ok := byID[id]; !ok {
			t.Fatalf("default profile module %q is absent from the shared registry", id)
		}
	}
	if _, ok := byID["masscan"]; ok && containsHeadlessString(defaultEnumerationModuleIDs, "masscan") {
		t.Fatal("masscan entered the default profile")
	}
}

func TestGlobalPlanKeepsProfileEntriesAcrossDependencyEnvironments(t *testing.T) {
	registered := buildRegistry().All()
	moduleIDs := make([]int64, len(registered))
	rootModel := newModel(context.Background(), config.Config{Target: "198.51.100.10", Domain: "example.test", Username: "operator", Root: t.TempDir()}, nil, registered, moduleIDs, 1, "production-test")
	userReasons := make(map[string]string)
	for _, module := range registered {
		userReasons[module.ID()] = "dependency unavailable in this environment"
	}
	userModel := newModel(context.Background(), config.Config{Target: "198.51.100.10", Domain: "example.test", Username: "operator", Root: t.TempDir()}, nil, registered, moduleIDs, 1, "production-test", userReasons)
	rootPlan := rootModel.globalPlan()
	userPlan := userModel.globalPlan()
	if len(rootPlan.indices) != len(userPlan.indices) {
		t.Fatalf("dependency environment changed selected count: root=%d user=%d", len(rootPlan.indices), len(userPlan.indices))
	}
	if strings.Join(rootModel.planNames(rootPlan.indices), ",") != strings.Join(userModel.planNames(userPlan.indices), ",") {
		t.Fatalf("dependency environment changed selected module order")
	}
	if len(userPlan.unavailable) == 0 {
		t.Fatal("dependency limitations were not retained for reporting")
	}
}

func containsHeadlessString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestBatchHasFailureOnlyAcceptsCompletedStates(t *testing.T) {
	item := runner.BatchItem{Index: 0, Module: nil, ModuleID: 1}
	batch := runner.NewBatchRun([]runner.BatchItem{item})
	if !batchHasFailure(batch) {
		t.Fatal("queued batch was treated as successful")
	}
}

func TestHeadlessPreflightsElevationForRequestedModules(t *testing.T) {
	module := elevatingModule{
		selectionModule: selectionModule{id: "needs-privileges", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA},
		required:        true,
	}
	m := newModel(context.Background(), config.Config{}, nil, []modules.Module{module}, []int64{1}, 1, "test")
	approvals := headlessElevationApprovals(m, []int{0})
	if len(approvals) != 1 || approvals[0].index != 0 {
		t.Fatalf("headless elevation preflight=%v, want module 0", approvals)
	}
}
