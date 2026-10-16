package tui

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// inputModule is a registration that needs a value from the operator before it
// can run, and records what it received.
type inputModule struct {
	id       string
	key      string
	family   modules.ToolFamily
	category modules.Category
	protocol modules.Protocol
	log      *executionLog
	values   *valueLog
}

// valueLog records what each module received. It is a pointer so a registration
// can be copied into a registry without copying a lock, and so every copy reports
// the same observations.
type valueLog struct {
	mu     sync.Mutex
	values map[string]string
}

func (v *valueLog) set(id, value string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.values == nil {
		v.values = map[string]string{}
	}
	v.values[id] = value
}

func (v *valueLog) get(id string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.values[id]
}

func (m inputModule) ID() string                       { return m.id }
func (m inputModule) Name() string                     { return "Needs " + m.key }
func (m inputModule) ToolFamily() modules.ToolFamily   { return m.family }
func (m inputModule) Category() modules.Category       { return m.category }
func (m inputModule) Tool() string                     { return "test tool" }
func (m inputModule) Protocol() modules.Protocol       { return m.protocol }
func (m inputModule) Description() string              { return "test module that needs a value" }
func (m inputModule) Prerequisites() []string          { return nil }
func (m inputModule) RequiredPrivileges() []string     { return nil }
func (m inputModule) OutputFile() string               { return "test/" + m.id + ".log" }
func (m inputModule) Sensitivity() modules.Sensitivity { return modules.SensitivityStandard }
func (m inputModule) ReadOnly() bool                   { return true }
func (m inputModule) SecondaryConnections() []string   { return nil }
func (m inputModule) Check(context.Context, *modules.Runtime) error {
	return nil
}

func (m inputModule) Status(runtime *modules.Runtime) modules.Status {
	if _, ok := runtime.ModuleOption(m.id, m.key); !ok {
		return modules.StatusInputRequired
	}
	return modules.StatusAvailable
}

func (m inputModule) StatusReason(runtime *modules.Runtime) string {
	if _, ok := runtime.ModuleOption(m.id, m.key); !ok {
		return fmt.Sprintf("needs %s - the object this module reads", m.key)
	}
	return ""
}

func (m inputModule) MissingInputs(runtime *modules.Runtime) []modules.InputField {
	if _, ok := runtime.ModuleOption(m.id, m.key); ok {
		return nil
	}
	return []modules.InputField{{Key: m.key, Prompt: "which object should be read?", Example: "a name"}}
}

func (m inputModule) Run(_ context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	value, _ := runtime.ModuleOption(m.id, m.key)
	m.values.set(m.id, value)
	m.log.record(m.id)
	_, err := sink.Write([]byte(m.id + " ran with " + m.key + "=" + value + "\n"))
	return err
}

func (m inputModule) recorded(id string) string { return m.values.get(id) }

func inputModel(t *testing.T, log *executionLog) (*model, *inputModule, *inputModule) {
	t.Helper()
	values := &valueLog{}
	dacl := &inputModule{id: "daclread-like", key: "TARGET", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log, values: values}
	find := &inputModule{id: "find-computer-like", key: "TEXT", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log, values: values}
	plain := selectionModule{id: "nxc-ldap-users", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log}
	registered := []modules.Module{*dacl, plain, *find}
	m := newModel(context.Background(), testConfig(t), nil, registered, []int64{1, 2, 3}, 1, "test")
	m.width, m.height = 140, 45
	m.resizeOutput()
	m.focus = focusModules
	return m, dacl, find
}

// typeInput types a value into the open prompt and answers it.
func typeInput(t *testing.T, m *model, value string) {
	t.Helper()
	for _, r := range value {
		m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	press(t, m, "enter")
}

// Enter on a module that needs a value asks for it, and the value reaches the
// command through the module-option mechanism the CLI uses.
func TestEnterPromptsForAMissingValueAndUsesIt(t *testing.T) {
	log := &executionLog{}
	m, dacl, _ := inputModel(t, log)
	if state := m.moduleState(rowOf(t, m, "daclread-like")); state != "INPUT-REQ" {
		t.Fatalf("row is %q, want INPUT-REQ", state)
	}
	frame := ansi.Strip(m.View())
	if !strings.Contains(frame, "Availability: CONFIGURABLE: needs TARGET") {
		t.Fatalf("Module Information does not explain the state:\n%s", frame)
	}

	m.cursor = rowOf(t, m, "daclread-like")
	press(t, m, "enter")
	if !m.inputPrompt || m.running {
		t.Fatalf("Enter did not open the prompt: prompt=%v running=%v status=%q", m.inputPrompt, m.running, m.status)
	}
	if !strings.Contains(m.status, "TARGET") || !strings.Contains(m.status, "which object") {
		t.Fatalf("the prompt does not explain the field: %q", m.status)
	}
	typeInput(t, m, "Domain Admins")
	if m.inputPrompt {
		t.Fatal("the prompt stayed open after the value was entered")
	}
	if !m.running {
		t.Fatalf("the module did not start after its value was entered: %q", m.status)
	}
	waitForBatch(t, m)
	if got := dacl.recorded("daclread-like"); got != "Domain Admins" {
		t.Fatalf("the module ran with %q, want the entered value", got)
	}
	// The runtime the interface reports with carries the value, and the module's
	// option set is what the runner passes on.
	if value, ok := m.moduleRuntime().ModuleOption("daclread-like", "TARGET"); !ok || value != "Domain Admins" {
		t.Fatalf("the runtime does not hold the entered value: %q", value)
	}
}

// An empty answer is refused with an explanation instead of being passed on.
func TestEmptyInputIsRefused(t *testing.T) {
	log := &executionLog{}
	m, _, _ := inputModel(t, log)
	m.cursor = rowOf(t, m, "daclread-like")
	press(t, m, "enter")
	press(t, m, "enter") // answer with nothing
	if !m.inputPrompt {
		t.Fatal("an empty answer closed the prompt")
	}
	if !strings.Contains(m.status, "required") {
		t.Fatalf("an empty answer was not explained: %q", m.status)
	}
	if m.running {
		t.Fatal("an empty answer started the module")
	}
	// The prompt is still usable: a value typed afterwards runs the module.
	typeInput(t, m, "Domain Admins")
	waitForBatch(t, m)
	if got := log.executed(); len(got) != 1 || got[0] != "daclread-like" {
		t.Fatalf("unexpected execution: %v", got)
	}
}

// Esc skips the module that needs the value and runs the rest.
func TestCancellingInputSkipsOnlyThatModule(t *testing.T) {
	log := &executionLog{}
	m, _, _ := inputModel(t, log)
	m.selectedModules["daclread-like"] = true
	m.selectedModules["nxc-ldap-users"] = true
	press(t, m, "ctrl+r")
	if !m.inputPrompt {
		t.Fatalf("R did not ask for the missing value: %q", m.status)
	}
	press(t, m, "esc")
	if m.inputPrompt {
		t.Fatal("Esc did not close the prompt")
	}
	// The skip is reported even though the rest of the plan starts immediately.
	if !strings.Contains(m.status, "skipped") {
		t.Fatalf("the skip was not reported: %q", m.status)
	}
	waitForBatch(t, m)
	got := log.executed()
	if len(got) != 1 || got[0] != "nxc-ldap-users" {
		t.Fatalf("the skipped module's neighbours did not run alone: %v", got)
	}
}

// Ctrl+C while the prompt is open abandons the whole plan.
func TestCancellingThePromptAbandonsThePlan(t *testing.T) {
	log := &executionLog{}
	m, _, _ := inputModel(t, log)
	m.cursor = rowOf(t, m, "daclread-like")
	press(t, m, "enter")
	if !m.inputPrompt {
		t.Fatal("the prompt did not open")
	}
	press(t, m, "ctrl+c")
	if m.inputPrompt || m.running {
		t.Fatalf("Ctrl+C left the plan active: prompt=%v running=%v", m.inputPrompt, m.running)
	}
	if len(log.executed()) != 0 {
		t.Fatalf("cancelling the prompt still ran modules: %v", log.executed())
	}
	// The interface keeps working afterwards.
	press(t, m, "down")
	if state := m.moduleState(0); state != "INPUT-REQ" {
		t.Fatalf("navigation stopped working after a cancellation: %q", state)
	}
}

// A global plan asks for every value it needs before the batch starts, so the run
// is never interrupted by a question.
func TestGlobalPlanCollectsInputBeforeStarting(t *testing.T) {
	log := &executionLog{}
	m, dacl, find := inputModel(t, log)
	press(t, m, "ctrl+a")
	if !m.inputPrompt || m.running {
		t.Fatalf("A did not ask for the values first: prompt=%v running=%v status=%q", m.inputPrompt, m.running, m.status)
	}
	if !strings.Contains(m.status, "TARGET") {
		t.Fatalf("the first question is not the first missing field: %q", m.status)
	}
	typeInput(t, m, "Domain Admins")
	if !m.inputPrompt || m.running {
		t.Fatalf("the plan started before every value was collected: prompt=%v running=%v", m.inputPrompt, m.running)
	}
	if !strings.Contains(m.status, "TEXT") {
		t.Fatalf("the second question is not the second missing field: %q", m.status)
	}
	typeInput(t, m, "SQL")
	if m.inputPrompt {
		t.Fatal("the prompt stayed open after the last value")
	}
	waitForBatch(t, m)
	if got := dacl.recorded("daclread-like"); got != "Domain Admins" {
		t.Fatalf("the first value did not reach its module: %q", got)
	}
	if got := find.recorded("find-computer-like"); got != "SQL" {
		t.Fatalf("the second value did not reach its module: %q", got)
	}
	// No question is left for another module in the same plan.
	if m.inputPrompt {
		t.Fatal("a question was still open after the batch finished")
	}
}

// The I key configures a module without running it.
func TestInputKeyConfiguresWithoutRunning(t *testing.T) {
	log := &executionLog{}
	m, dacl, _ := inputModel(t, log)
	m.cursor = rowOf(t, m, "daclread-like")
	press(t, m, "i")
	if !m.inputPrompt {
		t.Fatalf("I did not open the prompt: %q", m.status)
	}
	typeInput(t, m, "Domain Users")
	if m.running {
		t.Fatal("I started the module")
	}
	if !strings.Contains(m.status, "saved") {
		t.Fatalf("I did not report what it stored: %q", m.status)
	}
	if state := m.moduleState(rowOf(t, m, "daclread-like")); state != "" {
		t.Fatalf("the row is still %q after the value was stored", state)
	}
	// The stored value is used by the next run of that module.
	press(t, m, "enter")
	waitForBatch(t, m)
	if got := dacl.recorded("daclread-like"); got != "Domain Users" {
		t.Fatalf("the stored value was not used: %q", got)
	}
}

// A value entered for one assessment is not visible to the next one: the store
// lives in the model, which is rebuilt for every PwnFlow invocation.
func TestEnteredValuesDoNotLeakToAnotherAssessment(t *testing.T) {
	log := &executionLog{}
	m, _, _ := inputModel(t, log)
	m.cursor = rowOf(t, m, "daclread-like")
	press(t, m, "enter")
	typeInput(t, m, "Domain Admins")
	waitForBatch(t, m)
	if _, ok := m.moduleRuntime().ModuleOption("daclread-like", "TARGET"); !ok {
		t.Fatal("the value did not stay available for the session")
	}

	next := &executionLog{}
	second, _, _ := inputModel(t, next)
	if _, ok := second.moduleRuntime().ModuleOption("daclread-like", "TARGET"); ok {
		t.Fatal("a value entered in one assessment appeared in another")
	}
	if state := second.moduleState(rowOf(t, second, "daclread-like")); state != "INPUT-REQ" {
		t.Fatalf("the second assessment starts with %q", state)
	}
}

// A value passed on the command line with --module-options needs no prompt, and
// the CLI path keeps working for automation.
func TestCommandLineModuleOptionsNeedNoPrompt(t *testing.T) {
	log := &executionLog{}
	dacl := &inputModule{id: "daclread-like", key: "TARGET", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log, values: &valueLog{}}
	cfg := testConfig(t)
	cfg.ModuleOptions = map[string]map[string]string{"daclread-like": {"TARGET": "Domain Admins"}}
	m := newModel(context.Background(), cfg, nil, []modules.Module{*dacl}, []int64{1}, 1, "test")
	m.width, m.height = 140, 45
	m.resizeOutput()
	m.focus = focusModules
	m.cursor = 0
	press(t, m, "enter")
	if m.inputPrompt {
		t.Fatal("a value from the command line still produced a prompt")
	}
	waitForBatch(t, m)
	if got := dacl.recorded("daclread-like"); got != "Domain Admins" {
		t.Fatalf("the command-line value did not reach the module: %q", got)
	}
}
