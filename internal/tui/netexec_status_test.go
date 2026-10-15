package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"

	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/modules/netexec"
	"github.com/pwnflow/pwnflow/internal/modules/rusthound"
)

// statusModule is a registration that reports its own display status, which is
// how a NetExec-style integration answers the question without probing.
type statusModule struct {
	id         string
	name       string
	family     modules.ToolFamily
	category   modules.Category
	protocol   modules.Protocol
	status     modules.Status
	reason     string
	execution  bool
	optionKeys []string
}

func (m statusModule) ID() string { return m.id }
func (m statusModule) Name() string {
	if m.name != "" {
		return m.name
	}
	return m.id
}
func (m statusModule) ToolFamily() modules.ToolFamily   { return m.family }
func (m statusModule) Category() modules.Category       { return m.category }
func (m statusModule) Tool() string                     { return "test tool" }
func (m statusModule) Protocol() modules.Protocol       { return m.protocol }
func (m statusModule) Description() string              { return "test module" }
func (m statusModule) Prerequisites() []string          { return nil }
func (m statusModule) RequiredPrivileges() []string     { return nil }
func (m statusModule) OutputFile() string               { return "test/" + m.id + ".log" }
func (m statusModule) Sensitivity() modules.Sensitivity { return modules.SensitivityStandard }
func (m statusModule) ReadOnly() bool                   { return true }
func (m statusModule) SecondaryConnections() []string   { return nil }
func (m statusModule) ExecutionEnabled() bool           { return m.execution }
func (m statusModule) AvailabilityReason() string       { return m.reason }
func (m statusModule) OptionKeys() []string             { return m.optionKeys }
func (m statusModule) Status(*modules.Runtime) modules.Status {
	return m.status
}
func (m statusModule) StatusReason(*modules.Runtime) string { return m.reason }
func (m statusModule) Check(context.Context, *modules.Runtime) error {
	if !m.execution {
		return errTestUnavailable
	}
	return nil
}
func (m statusModule) Run(context.Context, *modules.Runtime, modules.OutputSink) error { return nil }

type testError string

func (e testError) Error() string { return string(e) }

const errTestUnavailable = testError("execution gated: this module changes state on the target")

// categoryIndex finds a category in the current navigation taxonomy.
func categoryIndex(t *testing.T, m *model, category modules.Category) int {
	t.Helper()
	for index, value := range m.categories {
		if value == category {
			return index
		}
	}
	t.Fatalf("category %s is not offered: %v", category, m.categories)
	return 0
}

func statusModel(t *testing.T, registered []modules.Module) *model {
	t.Helper()
	ids := make([]int64, len(registered))
	for index := range registered {
		ids[index] = int64(index + 1)
	}
	m := newModel(context.Background(), testConfig(t), nil, registered, ids, 1, "test")
	m.width, m.height = 150, 50
	m.resizeOutput()
	m.focus = focusModules
	return m
}

// ADMIN-REQ is shown for a module that needs elevated target-side rights, it
// names the right in Module Information, and it never blocks execution.
func TestAdminRequiredIsLabelledAndStillRuns(t *testing.T) {
	registered := []modules.Module{
		statusModule{id: "needs-admin", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolSMB, status: modules.StatusAdminRequired, reason: "local administrator on the target", execution: true},
		statusModule{id: "plain", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolSMB, status: modules.StatusAvailable, execution: true},
	}
	m := statusModel(t, registered)
	if state := m.moduleState(rowOf(t, m, "needs-admin")); state != "ADMIN-REQ" {
		t.Fatalf("admin row is %q, want ADMIN-REQ", state)
	}
	if state := m.moduleState(rowOf(t, m, "plain")); state != "" {
		t.Fatalf("available row is %q, want no suffix", state)
	}
	m.cursor = rowOf(t, m, "needs-admin")
	frame := ansi.Strip(m.View())
	if !strings.Contains(frame, "Target privilege: ADMIN-REQ (local administrator on the target)") {
		t.Fatalf("Module Information does not name the requirement:\n%s", frame)
	}
	if command := m.execute(m.cursor); command != nil || !m.running {
		t.Fatalf("ADMIN-REQ blocked execution: running=%t status=%q", m.running, m.status)
	}
	// Let the batch finish before the test's temporary results root is removed,
	// so the cleanup never races a module writing its artifact.
	m.cancelBatch()
	waitContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.batch.Wait(waitContext); err != nil {
		t.Fatalf("wait for the run: %v", err)
	}
}

// UNAVAILABLE is shown for a registration that cannot run, it explains itself,
// and it is refused by Enter, R, and the category-wide run.
func TestUnavailableIsLabelledExplainedAndRefused(t *testing.T) {
	registered := []modules.Module{
		statusModule{id: "broken", family: modules.ToolFamilyNetExec, category: modules.CategoryCredentialDumping, protocol: modules.ProtocolSMB, status: modules.StatusUnavailable, reason: errTestUnavailable.Error()},
	}
	m := statusModel(t, registered)
	m.setCategory(categoryIndex(t, m, modules.CategoryCredentialDumping))
	if state := m.moduleState(0); state != "UNAVAILABLE" {
		t.Fatalf("gated row is %q, want UNAVAILABLE", state)
	}
	frame := ansi.Strip(m.View())
	if !strings.Contains(frame, "Availability: UNAVAILABLE: execution gated") {
		t.Fatalf("Module Information does not explain the status:\n%s", frame)
	}
	m.execute(0)
	if m.running {
		t.Fatal("Enter started a module the registry reports as unavailable")
	}
	if !strings.Contains(m.status, "unavailable") {
		t.Fatalf("the refusal was not reported: %q", m.status)
	}
}

// The rendered interface never labels a ready module, in any tool family the
// navigation can reach.
func TestRenderedFramesContainNoReadyLabel(t *testing.T) {
	registered := []modules.Module{}
	registered = append(registered, netexec.EnumerationModules()[:1]...)
	registered = append(registered, netexec.CredentialAuditingModules()...)
	registered = append(registered, rusthound.Module{})
	m := statusModel(t, registered)
	for family := range m.toolFamilies {
		m.setToolFamily(family)
		for category := range m.categories {
			m.setCategory(category)
			for protocol := range m.protocols {
				m.setProtocol(protocol)
				frame := ansi.Strip(m.View())
				if strings.Contains(frame, "REA"+"DY") {
					t.Fatalf("frame for %s/%s/%s still labels a ready module:\n%s",
						m.toolFamilies[family], m.categories[category], m.protocols[protocol], frame)
				}
			}
		}
	}
}

// The real NetExec registrations show the agreed labels: an administrator-level
// enumeration module is ADMIN-REQ, an ordinary one carries nothing, and a gated
// credential module is UNAVAILABLE.
func TestNetExecRegistrationsUseTheAgreedLabels(t *testing.T) {
	registered := append(netexec.EnumerationModules(), netexec.CredentialDumpingModules()...)
	m := statusModel(t, registered)
	m.setToolFamily(0)
	m.setCategory(0)
	m.setProtocol(1) // SMB
	if m.protocols[m.protocolIndex] != modules.ProtocolSMB {
		t.Fatalf("expected the SMB protocol scope, got %v", m.protocols)
	}
	if state := m.moduleState(rowOf(t, m, "smb-shares")); state != "" {
		t.Fatalf("smb-shares is %q, want no suffix", state)
	}
	if state := m.moduleState(rowOf(t, m, "smb-bitlocker")); state != "ADMIN-REQ" {
		t.Fatalf("smb-bitlocker is %q, want ADMIN-REQ", state)
	}
	m.setCategory(2) // Credential Dumping
	m.setProtocol(1) // SMB
	if state := m.moduleState(rowOf(t, m, "smb-gpp-password")); state != "" {
		t.Fatalf("a read-only credential discovery module is %q, want no suffix", state)
	}
	// UNAVAILABLE is reserved for a capability the registered command cannot
	// complete: here, a module that needs the operator to name an object.
	m.setCategory(0) // Enumeration
	m.setProtocol(0) // LDAP
	if state := m.moduleState(rowOf(t, m, "daclread")); state != "UNAVAILABLE" {
		t.Fatalf("daclread is %q until its target is configured, want UNAVAILABLE", state)
	}
}

// Each protocol keeps its own scope: the modules visible under one protocol are
// exactly the ones registered for it.
func TestProtocolScopesAreIsolated(t *testing.T) {
	m := statusModel(t, netexec.EnumerationModules())
	m.setToolFamily(0)
	m.setCategory(0)
	for index, protocol := range m.protocols {
		m.setProtocol(index)
		if len(m.modules) == 0 {
			t.Fatalf("protocol %s has no enumeration modules although it is offered", protocol)
		}
		for _, module := range m.modules {
			if module.Protocol() != protocol {
				t.Fatalf("%s appears in the %s scope", module.ID(), protocol)
			}
		}
	}
	if len(m.protocols) != len(modules.Protocols()) {
		t.Fatalf("the navigator offers %v, want every protocol NetExec advertises: %v", m.protocols, modules.Protocols())
	}
}

// Navigation never asks the executable a question: the capability probe belongs
// to the background refresh, so moving through the interface stays instant even
// when NetExec is slow or missing.
func TestNavigationNeverProbesTheExecutable(t *testing.T) {
	netexec.ResetCapabilities()
	defer netexec.ResetCapabilities()
	m := statusModel(t, netexec.EnumerationModules())
	for index := 0; index < 40; index++ {
		for _, key := range []string{"down", "right", "down", "left", "tab"} {
			press(t, m, key)
		}
		_ = ansi.Strip(m.View())
	}
	for _, protocol := range modules.Protocols() {
		if netexec.Capabilities().Probed(protocol) {
			t.Fatalf("navigation probed the %s protocol; the capability question belongs off the render path", protocol)
		}
	}
}

// A stays scoped to the visible NetExec enumeration scope: a category-wide run
// started from Credential Dumping is refused, because that is not what the key
// means. Enter and R keep running exactly what the operator pointed at.
func TestScopeWideRunStaysInsideEnumeration(t *testing.T) {
	registered := append(netexec.EnumerationModules(), netexec.CredentialDumpingModules()...)
	m := statusModel(t, registered)
	m.setCategory(categoryIndex(t, m, modules.CategoryCredentialDumping))
	press(t, m, "a")
	if m.running {
		t.Fatal("A started a category-wide run outside the enumeration scope")
	}
	if !strings.Contains(m.status, "inactive") {
		t.Fatalf("the refusal was not reported: %q", m.status)
	}
}

// Operator-supplied module options reach the module's runtime, and a value for a
// module that does not accept options is reported rather than ignored.
func TestConfiguredModuleOptionsReachTheRuntime(t *testing.T) {
	registered := []modules.Module{statusModule{id: "needs-option", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolSMB, status: modules.StatusAvailable, execution: true, optionKeys: []string{"PATH"}}}
	cfg := testConfig(t)
	cfg.ModuleOptions = map[string]map[string]string{"needs-option": {"PATH": `HKLM\SYSTEM`}}
	m := newModel(context.Background(), cfg, nil, registered, []int64{1}, 1, "test")
	runtime := m.moduleRuntime()
	if value, ok := runtime.ModuleOption("needs-option", "PATH"); !ok || value != `HKLM\SYSTEM` {
		t.Fatalf("the configured option did not reach the runtime: %q", value)
	}
	warnings := modules.OptionWarnings(registered, cfg.ModuleOptions)
	if len(warnings) != 0 {
		t.Fatalf("a declared option produced a warning: %v", warnings)
	}
	warnings = modules.OptionWarnings(registered, map[string]map[string]string{
		"needs-option": {"NOT_REAL": "x"},
		"typo-module":  {"PATH": "x"},
	})
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "NOT_REAL") || !strings.Contains(joined, "typo-module") {
		t.Fatalf("misconfigured options were accepted silently: %v", warnings)
	}
}
