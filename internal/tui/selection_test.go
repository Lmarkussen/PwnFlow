package tui

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
)

// executionLog records which modules actually ran, in order, without running
// anything outside the test.
type executionLog struct {
	mu  sync.Mutex
	ran []string
}

func (l *executionLog) record(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ran = append(l.ran, id)
}

func (l *executionLog) executed() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.ran...)
}

// selectionModule is a registered module from any tool family that records its own
// execution, so a batch can be checked for content, order, and duplicates.
type selectionModule struct {
	id       string
	family   modules.ToolFamily
	category modules.Category
	protocol modules.Protocol
	log      *executionLog
	blocked  bool
	slow     bool
}

func (m selectionModule) ID() string                     { return m.id }
func (m selectionModule) Name() string                   { return m.id }
func (m selectionModule) ToolFamily() modules.ToolFamily { return m.family }
func (m selectionModule) Category() modules.Category     { return m.category }
func (m selectionModule) Tool() string                   { return "test tool" }
func (m selectionModule) Protocol() modules.Protocol     { return m.protocol }
func (m selectionModule) Description() string            { return "test module" }
func (m selectionModule) Prerequisites() []string        { return nil }
func (m selectionModule) RequiredPrivileges() []string   { return nil }
func (m selectionModule) OutputFile() string             { return "test/" + m.id + ".log" }

func (m selectionModule) Sensitivity() modules.Sensitivity { return modules.SensitivityStandard }
func (m selectionModule) ReadOnly() bool                   { return true }
func (m selectionModule) SecondaryConnections() []string   { return nil }
func (m selectionModule) ExecutionEnabled() bool           { return !m.blocked }

func (m selectionModule) AvailabilityReason() string {
	if m.blocked {
		return "scope restricted: policy blocks this module"
	}
	return ""
}

func (m selectionModule) Check(context.Context, *modules.Runtime) error { return nil }

func (m selectionModule) Run(ctx context.Context, _ *modules.Runtime, sink modules.OutputSink) error {
	if m.slow {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	m.log.record(m.id)
	_, err := sink.Write([]byte(m.id + " ran\n"))
	return err
}

// mixedRegistry registers modules across every tool family, category, and protocol
// the navigation can reach, in a deterministic order.
func mixedRegistry(log *executionLog) ([]modules.Module, []int64) {
	definitions := []selectionModule{
		{id: "nxc-ldap-users", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log},
		{id: "nxc-ldap-groups", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log},
		{id: "nxc-smb-shares", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolSMB, log: log},
		{id: "nxc-credential-audit", family: modules.ToolFamilyNetExec, category: modules.CategoryCredentialAuditing, protocol: modules.ProtocolLDAP, log: log},
		{id: "adcs-discovery", family: modules.ToolFamilyADCS, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log},
		{id: "rusthound-collect", family: modules.ToolFamilyActiveDirectory, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log},
		{id: "network-hosts", family: modules.ToolFamilyNetwork, category: modules.Category("Host Discovery"), protocol: modules.ProtocolNA, log: log},
	}
	registered := make([]modules.Module, 0, len(definitions))
	ids := make([]int64, 0, len(definitions))
	for index, module := range definitions {
		registered = append(registered, module)
		ids = append(ids, int64(index+1))
	}
	return registered, ids
}

func testConfig(t *testing.T) config.Config {
	t.Helper()
	return config.Config{Target: testTarget, Domain: testDomain, Username: "audituser", Password: "Sup3rSecret", Root: t.TempDir()}
}

func selectionModel(t *testing.T, log *executionLog, availability ...map[string]string) *model {
	t.Helper()
	registered, ids := mixedRegistry(log)
	cfg := testConfig(t)
	m := newModel(context.Background(), cfg, nil, registered, ids, 1, "test", availability...)
	m.width, m.height = 150, 50
	m.resizeOutput()
	m.focus = focusModules
	return m
}

// press sends one key through the real handler, which is how an operator selects
// and runs modules.
func press(t *testing.T, m *model, key string) {
	t.Helper()
	switch key {
	case " ":
		m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
	case "enter":
		m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	case "r":
		m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	case "a":
		m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	case "tab":
		m.handleKey(tea.KeyMsg{Type: tea.KeyTab})
	case "right":
		m.handleKey(tea.KeyMsg{Type: tea.KeyRight})
	default:
		// Any other single character goes through as itself, so a prompt can be
		// answered in a test exactly as the operator answers it.
		if len([]rune(key)) == 1 {
			m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
			return
		}
		t.Fatalf("unsupported test key %q", key)
	}
}

// rowOf returns the module row in the currently visible scope.
func rowOf(t *testing.T, m *model, id string) int {
	t.Helper()
	for index, module := range m.modules {
		if module.ID() == id {
			return index
		}
	}
	t.Fatalf("%s is not visible in the current scope: %v", id, moduleIDs(m.modules))
	return -1
}

func moduleIDs(registered []modules.Module) []string {
	ids := make([]string, 0, len(registered))
	for _, module := range registered {
		ids = append(ids, module.ID())
	}
	return ids
}

// selectInScope highlights a module in the visible scope and toggles it with
// Space, which is the operator's path for building a global selection.
func selectInScope(t *testing.T, m *model, id string) {
	t.Helper()
	m.focus = focusModules
	m.cursor = rowOf(t, m, id)
	press(t, m, " ")
}

// navigateTo moves the navigation pane to a family and category using the same key
// handling the operator uses.
func navigateTo(t *testing.T, m *model, family modules.ToolFamily, category modules.Category) {
	t.Helper()
	m.focus = focusNavigation
	m.navigationRow = 0
	for attempt := 0; attempt <= len(m.toolFamilies); attempt++ {
		if m.toolFamilies[m.toolFamilyIndex] == family {
			break
		}
		if attempt == len(m.toolFamilies) {
			t.Fatalf("family %q is not reachable from %v", family, m.toolFamilies)
		}
		press(t, m, "right")
	}
	m.navigationRow = 1
	for attempt := 0; attempt <= len(m.categories); attempt++ {
		if m.categoryIndex < len(m.categories) && m.categories[m.categoryIndex] == category {
			break
		}
		if attempt == len(m.categories) {
			t.Fatalf("category %q is not reachable in %q: %v", category, family, m.categories)
		}
		press(t, m, "right")
	}
	m.focus = focusModules
}

// waitForBatch waits for the run to finish and then lets the model notice it the
// way the ticker does, so a completed batch no longer refuses navigation.
func waitForBatch(t *testing.T, m *model) {
	t.Helper()
	if m.batch == nil {
		t.Fatal("no batch was started")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.batch.Wait(ctx); err != nil {
		t.Fatalf("batch did not finish: %v", err)
	}
	m.syncBatch()
	// A cancelled run leaves the quitting state behind; clear it so later keys
	// behave like an idle operator session.
	m.quitAfterCancel = false
}

func batchIDs(m *model) []string {
	ids := make([]string, 0, len(m.batchItems))
	for _, item := range m.batchItems {
		ids = append(ids, item.Module.ID())
	}
	return ids
}

// R does not depend on the visible scope: a selection made in other families runs
// even when the scope currently on screen has no modules of its own, which is what
// makes the selection registry-wide in practice.
func TestRunsAcrossAnEmptyVisibleScope(t *testing.T) {
	log := &executionLog{}
	m := selectionModel(t, log)
	selectInScope(t, m, "nxc-ldap-users")
	navigateTo(t, m, modules.ToolFamilyADCS, modules.CategoryEnumeration)
	selectInScope(t, m, "adcs-discovery")

	// Network has no registered modules in this registry, so the scope is empty.
	navigateTo(t, m, modules.ToolFamilyNetwork, modules.Category("Service Enumeration"))
	if len(m.modules) != 0 {
		t.Fatalf("expected an empty scope, got %v", moduleIDs(m.modules))
	}
	press(t, m, "r")
	if got := batchIDs(m); strings.Join(got, ",") != "nxc-ldap-users,adcs-discovery" {
		t.Fatalf("R did not run the selection from an empty scope: %v", got)
	}
	waitForBatch(t, m)
	if got := log.executed(); strings.Join(got, ",") != "nxc-ldap-users,adcs-discovery" {
		t.Fatalf("unexpected execution from an empty scope: %v", got)
	}
}

// The watcher stays available for a batch that outlives its visible scope.
func TestWatcherOpensForABatchStartedElsewhere(t *testing.T) {
	m := selectionModel(t, &executionLog{})
	selectInScope(t, m, "nxc-ldap-users")
	navigateTo(t, m, modules.ToolFamilyNetwork, modules.Category("Service Enumeration"))
	if len(m.modules) != 0 {
		t.Fatalf("expected an empty scope, got %v", moduleIDs(m.modules))
	}
	press(t, m, "r")
	m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlW})
	if !m.watcher {
		t.Fatalf("the watcher refused a running batch from an empty scope: %q", m.status)
	}
	states := m.watcherStates()
	if len(states) != 1 || states[0].Module.ID() != "nxc-ldap-users" {
		t.Fatalf("the watcher does not show the batch: %v", states)
	}
	m.closeWatcher()
	waitForBatch(t, m)
}

func renderFrame(m *model) string {
	return ansi.Strip(m.View())
}

// Selection is registry-wide: modules selected in different tool families,
// categories, and protocols survive navigation and are executed together by R in
// registry order, exactly once each.
func TestGlobalSelectionSurvivesNavigationAndRunsAcrossFamilies(t *testing.T) {
	log := &executionLog{}
	m := selectionModel(t, log)

	selectInScope(t, m, "nxc-ldap-users")
	selectInScope(t, m, "nxc-ldap-groups")
	navigateTo(t, m, modules.ToolFamilyNetExec, modules.CategoryEnumeration)
	m.setProtocol(1) // SMB
	if m.protocols[m.protocolIndex] != modules.ProtocolSMB {
		t.Fatalf("expected the SMB protocol scope: %v", m.protocols)
	}
	selectInScope(t, m, "nxc-smb-shares")
	navigateTo(t, m, modules.ToolFamilyNetExec, modules.CategoryCredentialAuditing)
	selectInScope(t, m, "nxc-credential-audit")
	navigateTo(t, m, modules.ToolFamilyADCS, modules.CategoryEnumeration)
	selectInScope(t, m, "adcs-discovery")
	navigateTo(t, m, modules.ToolFamilyActiveDirectory, modules.CategoryEnumeration)
	selectInScope(t, m, "rusthound-collect")

	// Returning to an earlier scope keeps every earlier selection.
	navigateTo(t, m, modules.ToolFamilyNetExec, modules.CategoryEnumeration)
	m.setProtocol(0)
	for _, id := range []string{"nxc-ldap-users", "nxc-ldap-groups"} {
		if index := rowOf(t, m, id); !m.selectedModules[m.modules[index].ID()] {
			t.Fatalf("%s lost its selection while navigating", id)
		}
	}
	if selected := m.selectedCount(); selected != 6 {
		t.Fatalf("expected six selected modules, got %d", selected)
	}

	// Focus changes must not drop the selection either.
	for range 3 {
		press(t, m, "tab")
	}
	if selected := m.selectedCount(); selected != 6 {
		t.Fatalf("focus changes dropped selections: %d", selected)
	}

	m.focus = focusModules
	press(t, m, "r")
	want := []string{"nxc-ldap-users", "nxc-ldap-groups", "nxc-smb-shares", "nxc-credential-audit", "adcs-discovery", "rusthound-collect"}
	if got := batchIDs(m); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("R did not batch the global selection in registry order:\ngot  %v\nwant %v", got, want)
	}
	waitForBatch(t, m)
	if got := log.executed(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("executed modules differ from the selection:\ngot  %v\nwant %v", got, want)
	}
	if selected := m.selectedCount(); selected != 6 {
		t.Fatalf("running the selection changed it: %d selected", selected)
	}
}

// Enter stays single-module: the highlighted module runs and the global selection
// is ignored, even when other families are selected.
func TestEnterRunsOnlyTheHighlightedModule(t *testing.T) {
	log := &executionLog{}
	m := selectionModel(t, log)
	selectInScope(t, m, "nxc-ldap-users")
	navigateTo(t, m, modules.ToolFamilyADCS, modules.CategoryEnumeration)
	selectInScope(t, m, "adcs-discovery")

	navigateTo(t, m, modules.ToolFamilyNetExec, modules.CategoryEnumeration)
	m.cursor = rowOf(t, m, "nxc-ldap-groups")
	press(t, m, "enter")
	if got := batchIDs(m); strings.Join(got, ",") != "nxc-ldap-groups" {
		t.Fatalf("Enter ran more than the highlighted module: %v", got)
	}
	waitForBatch(t, m)
	if got := log.executed(); len(got) != 1 || got[0] != "nxc-ldap-groups" {
		t.Fatalf("Enter executed the selection instead of the highlight: %v", got)
	}
	if selected := m.selectedCount(); selected != 2 {
		t.Fatalf("Enter changed the selection: %d", selected)
	}
}

// YOLO stays scoped to the visible navigation context and never uses the global
// selection to widen itself.
func TestYoloIgnoresTheGlobalSelection(t *testing.T) {
	log := &executionLog{}
	m := selectionModel(t, log)
	navigateTo(t, m, modules.ToolFamilyActiveDirectory, modules.CategoryEnumeration)
	selectInScope(t, m, "rusthound-collect")
	navigateTo(t, m, modules.ToolFamilyNetExec, modules.CategoryCredentialAuditing)
	selectInScope(t, m, "nxc-credential-audit")
	navigateTo(t, m, modules.ToolFamilyNetExec, modules.CategoryEnumeration)
	m.setProtocol(0)

	press(t, m, "a")
	if got := batchIDs(m); strings.Join(got, ",") != "nxc-ldap-users,nxc-ldap-groups" {
		t.Fatalf("YOLO left its navigation scope: %v", got)
	}
	waitForBatch(t, m)
	if got := log.executed(); strings.Join(got, ",") != "nxc-ldap-users,nxc-ldap-groups" {
		t.Fatalf("YOLO executed outside its scope: %v", got)
	}
	if selected := m.selectedCount(); selected != 2 {
		t.Fatalf("YOLO changed the global selection: %d", selected)
	}

	// In a non-NetExec family YOLO remains inactive, whatever is selected.
	navigateTo(t, m, modules.ToolFamilyADCS, modules.CategoryEnumeration)
	m.batch, m.batchItems, m.running = nil, nil, false
	press(t, m, "a")
	if m.batch != nil {
		t.Fatalf("YOLO started outside NetExec enumeration: %v", batchIDs(m))
	}
	if !strings.Contains(m.status, "inactive") {
		t.Fatalf("YOLO refusal was not explained: %q", m.status)
	}
}

// An unavailable selected module is reported and skipped instead of being run or
// silently dropped.
func TestUnavailableSelectedModuleIsSkippedAndReported(t *testing.T) {
	log := &executionLog{}
	m := selectionModel(t, log, map[string]string{"rusthound-collect": "policy blocks this module"})
	selectInScope(t, m, "nxc-ldap-users")
	navigateTo(t, m, modules.ToolFamilyActiveDirectory, modules.CategoryEnumeration)
	selectInScope(t, m, "rusthound-collect")

	navigateTo(t, m, modules.ToolFamilyNetExec, modules.CategoryEnumeration)
	press(t, m, "r")
	if got := batchIDs(m); strings.Join(got, ",") != "nxc-ldap-users" {
		t.Fatalf("an unavailable selection entered the batch: %v", got)
	}
	if !strings.Contains(m.status, "rusthound-collect") {
		t.Fatalf("the skipped module was not named: %q", m.status)
	}
	waitForBatch(t, m)
	if got := log.executed(); len(got) != 1 || got[0] != "nxc-ldap-users" {
		t.Fatalf("unexpected execution: %v", got)
	}

	// With nothing eligible, R reports instead of starting an empty batch.
	m.batch, m.batchItems, m.running = nil, nil, false
	m.selectedModules = map[string]bool{"rusthound-collect": true}
	press(t, m, "r")
	if m.batch != nil {
		t.Fatal("R started a batch with no eligible module")
	}
	if !strings.Contains(m.status, "unavailable") {
		t.Fatalf("empty eligible set was not explained: %q", m.status)
	}
}

// R with no selection says so instead of behaving like YOLO.
func TestRWithoutSelectionReportsAndRunsNothing(t *testing.T) {
	m := selectionModel(t, &executionLog{})
	press(t, m, "r")
	if m.batch != nil {
		t.Fatal("R started a batch without a selection")
	}
	if !strings.Contains(m.status, "no modules selected") {
		t.Fatalf("unexpected status: %q", m.status)
	}
}

// Space toggles one module at a time: no other selection is cleared, and a second
// press removes only that module.
func TestSpaceTogglesIndependently(t *testing.T) {
	m := selectionModel(t, &executionLog{})
	selectInScope(t, m, "nxc-ldap-users")
	selectInScope(t, m, "nxc-ldap-groups")
	selectInScope(t, m, "nxc-ldap-users")
	if m.selectedModules["nxc-ldap-users"] {
		t.Fatal("a second Space did not deselect the module")
	}
	if !m.selectedModules["nxc-ldap-groups"] {
		t.Fatal("toggling one module cleared another selection")
	}
	if selected := m.selectedCount(); selected != 1 {
		t.Fatalf("unexpected selection count: %d", selected)
	}
}

// The modules pane states the registry-wide selection count so the operator can
// see that a selection spans scopes.
func TestModulePaneShowsGlobalSelectionCount(t *testing.T) {
	m := selectionModel(t, &executionLog{})
	if strings.Contains(renderFrame(m), "SELECTED") {
		t.Fatal("the pane claims a selection when nothing is selected")
	}
	selectInScope(t, m, "nxc-ldap-users")
	navigateTo(t, m, modules.ToolFamilyActiveDirectory, modules.CategoryEnumeration)
	selectInScope(t, m, "rusthound-collect")
	if frame := renderFrame(m); !strings.Contains(frame, "2 SELECTED") {
		t.Fatalf("the pane does not show the global selection count:\n%s", frame)
	}
}

// A mixed-tool batch is visible and cancellable through the existing watcher.
func TestMixedBatchWatcherAndCancellation(t *testing.T) {
	log := &executionLog{}
	registered, ids := mixedRegistry(log)
	registered[0] = selectionModule{id: "nxc-ldap-users", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log, slow: true}
	cfg := config.Config{Target: testTarget, Domain: testDomain, Username: "audituser", Password: "Sup3rSecret", Root: t.TempDir()}
	m := newModel(context.Background(), cfg, nil, registered, ids, 1, "test")
	m.width, m.height = 150, 50
	m.resizeOutput()
	m.focus = focusModules

	selectInScope(t, m, "nxc-ldap-users")
	navigateTo(t, m, modules.ToolFamilyADCS, modules.CategoryEnumeration)
	selectInScope(t, m, "adcs-discovery")
	press(t, m, "r")

	states := m.watcherStates()
	if len(states) != 2 {
		t.Fatalf("the watcher does not cover the mixed batch: %v", states)
	}
	seen := map[int]bool{}
	for _, state := range states {
		if state.Index < 0 || state.Index >= len(m.allModules) {
			t.Fatalf("watcher index %d is not a registry index", state.Index)
		}
		if seen[state.Index] {
			t.Fatalf("duplicate batch entry for registry index %d", state.Index)
		}
		seen[state.Index] = true
	}
	m.cancelBatch()
	waitForBatch(t, m)
	stopped, _, _, _ := m.batch.Snapshot()
	cancelled := 0
	for _, state := range stopped {
		if state.Status == "cancelled" {
			cancelled++
		}
	}
	if cancelled != len(stopped) {
		t.Fatalf("cancellation did not stop every module: %v", stopped)
	}
	if got := log.executed(); len(got) != 0 {
		t.Fatalf("a cancelled run still executed modules: %v", got)
	}
}

// Batch ordering is deterministic: the same selection produces the same order
// regardless of the scope that is visible when R is pressed.
func TestSelectionBatchOrderIsDeterministic(t *testing.T) {
	orders := make([][]string, 0, 2)
	for _, changeScope := range []bool{false, true} {
		m := selectionModel(t, &executionLog{})
		selectInScope(t, m, "nxc-ldap-users")
		m.setProtocol(1) // SMB scope
		selectInScope(t, m, "nxc-smb-shares")
		navigateTo(t, m, modules.ToolFamilyADCS, modules.CategoryEnumeration)
		selectInScope(t, m, "adcs-discovery")
		if changeScope {
			navigateTo(t, m, modules.ToolFamilyNetwork, modules.Category("Host Discovery"))
		}
		press(t, m, "r")
		orders = append(orders, batchIDs(m))
		m.cancelBatch()
		waitForBatch(t, m)
	}
	if strings.Join(orders[0], ",") != strings.Join(orders[1], ",") {
		t.Fatalf("batch order depends on the visible scope: %v vs %v", orders[0], orders[1])
	}
	if got := strings.Join(orders[0], ","); got != "nxc-ldap-users,nxc-smb-shares,adcs-discovery" {
		t.Fatalf("unexpected order: %v", got)
	}
}
