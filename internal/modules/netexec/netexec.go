// Package netexec integrates the NetExec (nxc) executable.
//
// The package is deliberately table driven. Every registration names what
// NetExec actually executes - a native protocol command or a `-M` module the
// installed build advertises - so the registry can be audited against
// `nxc <protocol> --help` and `nxc <protocol> -L` instead of against
// documentation of some other version.
//
// Three facts about a registration matter to the operator and are kept apart:
//
//   - Transport: every protocol has its own command shape. LDAP runs over
//     LDAPS on port 636, SSH/FTP/VNC/NFS take no domain, VNC authenticates with
//     a password only. Those differences live in protocolSpec, never in a
//     builder that assumes one protocol's flags work everywhere.
//   - Target-side privilege: a module that needs local administrator rights on
//     the target, or a domain administrator, says so and is labelled
//     ADMIN-REQ. The label never blocks execution.
//   - Availability: a module the installed build does not advertise, or that
//     needs a value the operator has not supplied, reports UNAVAILABLE with the
//     reason, and is refused at execution time as well.
package netexec

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/dependencies"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/process"
)

// Definition describes one NetExec invocation.
type Definition struct {
	IDValue, NameValue, DescriptionValue, ToolValue string
	ToolFamilyValue                                 modules.ToolFamily
	CategoryValue                                   modules.Category
	ProtocolValue                                   modules.Protocol
	// Arguments are the protocol flags that select the behaviour, such as
	// "--shares" or "--users". They are passed as a structured list, never as a
	// shell string.
	Arguments []string
	// ModuleName is the value passed to `-M`; it is empty for a native command.
	ModuleName string
	// OptionKeys are the `-o KEY=VALUE` option names the installed module
	// advertises, in the order they are appended. When ModuleName is set the
	// keys are verified against the module's own `--options` output before they
	// are accepted from the operator.
	OptionKeys []string
	// RequiredOptions are option keys without which the module cannot do anything
	// meaningful. A module with an unsatisfied required option reports that it
	// needs input - it is configurable, not unsupported - and PwnFlow asks the
	// operator for the value before the run instead of registering a placeholder
	// argument.
	RequiredOptions []string
	// InputUsage explains each required option in one sentence, so the prompt can
	// say what the value is for instead of only naming the key.
	InputUsage map[string]string
	// OptionDefaults are fixed values PwnFlow passes when the operator has not
	// supplied one. They exist so a module with an obvious starting point - the
	// registry key that names the operating system, the read action of a DACL
	// query - is usable out of the box and still overridable.
	OptionDefaults map[string]string
	// DynamicOptions compute their default from the runtime: the assessment's own
	// output tree, or the account the operator authenticated with.
	DynamicOptions map[string]func(*modules.Runtime) string
	// DynamicArgs contribute arguments that depend on the runtime, such as the
	// file an exported hash list has to be written to.
	DynamicArgs func(*modules.Runtime) []string
	OutputValue string
	// PrerequisiteValues and RequiredPrivilegeValues describe the environment.
	PrerequisiteValues      []string
	RequiredPrivilegeValues []string
	// AdminRequired marks a module that needs elevated rights on the target.
	// AdminReason names the right, so the Module Information pane can
	// distinguish a local administrator from a domain administrator.
	AdminRequiredValue bool
	AdminReasonValue   string
	SensitivityValue   modules.Sensitivity
	ReadOnlyValue      bool
}

type Module struct{ definition Definition }

func (m Module) ID() string                       { return m.definition.IDValue }
func (m Module) Name() string                     { return m.definition.NameValue }
func (m Module) ToolFamily() modules.ToolFamily   { return m.definition.ToolFamilyValue }
func (m Module) Category() modules.Category       { return m.definition.CategoryValue }
func (m Module) Tool() string                     { return m.definition.ToolValue }
func (m Module) Protocol() modules.Protocol       { return m.definition.ProtocolValue }
func (m Module) Description() string              { return m.definition.DescriptionValue }
func (m Module) Sensitivity() modules.Sensitivity { return m.definition.SensitivityValue }
func (m Module) ReadOnly() bool                   { return m.definition.ReadOnlyValue }

func (m Module) Prerequisites() []string {
	return append([]string(nil), m.definition.PrerequisiteValues...)
}

func (m Module) RequiredPrivileges() []string {
	return append([]string(nil), m.definition.RequiredPrivilegeValues...)
}

func (m Module) OutputFile() string {
	return filepath.Join(categoryPath(m.Category()), "NetExec", m.definition.OutputValue)
}

func (m Module) SecondaryConnections() []string { return nil }

// OptionKeys implements modules.OptionDeclarer: the option keys the installed
// module advertises, which is what the startup check compares the operator's
// configuration against.
func (m Module) OptionKeys() []string {
	return append([]string(nil), m.definition.OptionKeys...)
}

// ModuleName is the `-M` value, exposed so the inventory tooling and the tests
// can compare the registry against `nxc <protocol> -L`.
func (m Module) ModuleName() string { return m.definition.ModuleName }

// AdminRequired reports whether the module needs elevated rights on the target
// and what those rights are. It is informational only.
func (m Module) AdminRequired() (bool, string) {
	if !m.definition.AdminRequiredValue {
		return false, ""
	}
	reason := m.definition.AdminReasonValue
	if reason == "" {
		reason = "target-side administrator rights"
	}
	return true, reason
}

// Status implements modules.StatusProvider. It reads only the cached capability
// snapshot, because the TUI asks for it while a frame is rendered.
func (m Module) Status(runtime *modules.Runtime) modules.Status {
	if reason := m.missingOptionReason(runtime); reason != "" {
		return modules.StatusInputRequired
	}
	if reason := m.missingArgumentReason(runtime); reason != "" {
		return modules.StatusUnavailable
	}
	if !m.capabilitySupported() {
		return modules.StatusUnavailable
	}
	if admin, _ := m.AdminRequired(); admin {
		return modules.StatusAdminRequired
	}
	return modules.StatusAvailable
}

// StatusReason explains a StatusUnavailable result. For an ADMIN-REQ row it
// returns the elevated right the module needs, so Module Information can name it.
func (m Module) StatusReason(runtime *modules.Runtime) string {
	if reason := m.missingOptionReason(runtime); reason != "" {
		return reason
	}
	if reason := m.missingArgumentReason(runtime); reason != "" {
		return reason
	}
	if reason := m.capabilityReason(); reason != "" {
		return reason
	}
	if _, reason := m.AdminRequired(); reason != "" {
		return reason
	}
	return ""
}

func (m Module) missingOptionReason(runtime *modules.Runtime) string {
	missing := m.missingOptionValues(runtime)
	if len(missing) == 0 {
		return ""
	}
	return fmt.Sprintf("needs %s - %s", strings.Join(missing, ", "), m.inputUsageList(missing))
}

// MissingInputs implements modules.InputRequester: the values this registration
// still needs before it can run, each with the sentence that explains it.
func (m Module) MissingInputs(runtime *modules.Runtime) []modules.InputField {
	missing := m.missingOptionValues(runtime)
	fields := make([]modules.InputField, 0, len(missing))
	for _, key := range missing {
		usage := m.definition.InputUsage[key]
		if usage == "" {
			usage = fmt.Sprintf("%s needs the %s option before it can run.", m.Name(), key)
		}
		fields = append(fields, modules.InputField{Key: key, Prompt: usage, Example: m.inputExample(key)})
	}
	return fields
}

// inputUsageList renders the explanations for the keys that are still missing.
func (m Module) inputUsageList(missing []string) string {
	parts := make([]string, 0, len(missing))
	for _, key := range missing {
		usage := m.definition.InputUsage[key]
		if usage == "" {
			usage = "the module refuses to run without it"
		}
		parts = append(parts, usage)
	}
	return strings.Join(parts, " ")
}

// inputExample gives the operator a concrete shape for the value, so the prompt
// is answerable without going to find the module's documentation.
func (m Module) inputExample(key string) string {
	switch key {
	case "TARGET":
		return "a sAMAccountName, such as a group or a user name"
	case "TEXT":
		return "a fragment of a computer name or operating system"
	case "PATH":
		return `a registry key, such as HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	default:
		return ""
	}
}

// missingOptionValues reports the required option keys that neither the operator
// nor a default has supplied.
func (m Module) missingOptionValues(runtime *modules.Runtime) []string {
	missing := make([]string, 0, len(m.definition.RequiredOptions))
	for _, key := range m.definition.RequiredOptions {
		if _, ok := m.optionValue(runtime, key); !ok {
			missing = append(missing, key)
		}
	}
	return missing
}

// missingArgumentReason reports an argument the registration cannot build from
// the runtime it was given - currently an export path with no assessment root to
// put it in. A module in that state refuses to run instead of issuing a flag
// whose value never arrived, which the target would reject with a syntax error.
func (m Module) missingArgumentReason(runtime *modules.Runtime) string {
	if m.definition.DynamicArgs == nil {
		return ""
	}
	if len(m.definition.DynamicArgs(runtime)) > 0 {
		return ""
	}
	return "requires the assessment results root, which PwnFlow supplies from the project directory"
}

// optionValue resolves one option: the operator's value first, then the
// registration's default, then the runtime-derived default. A key with any of
// those is not missing, which is what keeps a module with a sensible default out
// of the unavailable list.
func (m Module) optionValue(runtime *modules.Runtime, key string) (string, bool) {
	if value, ok := runtime.ModuleOption(m.ID(), key); ok {
		return value, true
	}
	if compute, ok := m.definition.DynamicOptions[key]; ok {
		if value := compute(runtime); value != "" {
			return value, true
		}
	}
	if value, ok := m.definition.OptionDefaults[key]; ok && value != "" {
		return value, true
	}
	return "", false
}

func (m Module) capabilityReason() string {
	return Capabilities().reason(m.Protocol(), m.definition.ModuleName, m.definition.Arguments)
}

func (m Module) capabilitySupported() bool { return m.capabilityReason() == "" }

// Check validates the registration against the installed executable before
// anything runs: the module has to exist in the installed build, the operator has
// to have supplied what it needs, and the runtime has to be able to build its
// arguments.
func (m Module) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil || strings.TrimSpace(runtime.Target) == "" || strings.TrimSpace(runtime.Domain) == "" {
		return fmt.Errorf("runtime target and domain are required")
	}
	dependency := dependencies.DefaultRegistry().CheckOne(ctx, dependencies.NetExec)
	if !dependency.Available {
		return fmt.Errorf("%s: %s", dependency.DisplayName, dependency.Detail)
	}
	if err := m.checkCapabilities(ctx); err != nil {
		return err
	}
	if reason := m.missingOptionReason(runtime); reason != "" {
		return fmt.Errorf("%s", reason)
	}
	if reason := m.missingArgumentReason(runtime); reason != "" {
		return fmt.Errorf("%s", reason)
	}
	return nil
}

// checkCapabilities performs the live probe. It reuses the cached snapshot when
// one exists and otherwise runs the executable, so both the render path and the
// execution path agree on what the installed build supports.
func (m Module) checkCapabilities(ctx context.Context) error {
	if capability, ok := Capabilities().lookup(ctx, m.Protocol()); !ok || !capability.probed {
		return fmt.Errorf("cannot inspect NetExec %s capabilities", m.Protocol())
	}
	if reason := Capabilities().reason(m.Protocol(), m.definition.ModuleName, m.definition.Arguments); reason != "" {
		return fmt.Errorf("%s", reason)
	}
	return nil
}

// RefreshDetails implements modules.DetailRefresher. The capability probe runs
// here - off the render path, throttled by the snapshot's own age - so pressing
// an arrow key never waits for `nxc`.
func (m Module) RefreshDetails(ctx context.Context, runtime *modules.Runtime) {
	_, _ = Capabilities().lookup(ctx, m.Protocol())
}

// CommandPreview implements modules.CommandPreviewProvider. It exists because
// the Module Information pane must show the exact protocol, target, and flags
// while never printing the operator's runtime password.
func (m Module) CommandPreview(runtime *modules.Runtime) string {
	args := m.CommandArgs(runtime)
	// The preview never carries the runtime password, and it never shows an empty
	// password position either: the operator reads this line to see which protocol
	// and flags a module uses, so the credential is always marked, whatever the
	// runtime happens to hold.
	for index, argument := range args {
		if index > 0 && args[index-1] == "-p" {
			args[index] = "[REDACTED]"
			continue
		}
		if argument == runtime.Password && argument != "" {
			args[index] = "[REDACTED]"
		}
	}
	return strings.Join(args, " ")
}

// DetailLines implements modules.DetailProvider: the fixed configuration of the
// registration, cheap enough to compute while drawing, and free of secrets.
func (m Module) DetailLines(runtime *modules.Runtime) []string {
	transport := spec(m.Protocol()).description
	lines := []string{fmt.Sprintf("Transport: %s (%s)", transport, protocolCommand(m.Protocol()))}
	if m.definition.ModuleName != "" {
		lines = append(lines, fmt.Sprintf("NetExec module: -M %s", m.definition.ModuleName))
	} else {
		lines = append(lines, "NetExec command: native protocol flag, no -M module")
	}
	if len(m.definition.OptionKeys) > 0 {
		lines = append(lines, "Module options: "+strings.Join(m.definition.OptionKeys, ", "))
	}
	configured := make([]string, 0, len(m.definition.OptionKeys))
	defaulted := make([]string, 0, len(m.definition.OptionKeys))
	for _, key := range m.definition.OptionKeys {
		value, ok := m.optionValue(runtime, key)
		if !ok {
			continue
		}
		if _, fromOperator := runtime.ModuleOption(m.ID(), key); fromOperator {
			configured = append(configured, key+"="+value)
		} else {
			defaulted = append(defaulted, key+"="+value)
		}
	}
	if len(configured) > 0 {
		lines = append(lines, "Configured options: "+strings.Join(configured, ", "))
	}
	if len(defaulted) > 0 {
		lines = append(lines, "Default options: "+strings.Join(defaulted, ", "))
	}
	if missing := m.missingOptionValues(runtime); len(missing) > 0 {
		lines = append(lines, "Needs input before it can run: "+strings.Join(missing, ", ")+" (PwnFlow asks for it when you run the module)")
	}
	if admin, reason := m.AdminRequired(); admin {
		lines = append(lines, "Target privilege: ADMIN-REQ ("+reason+")")
	} else {
		lines = append(lines, "Target privilege: none beyond valid credentials")
	}
	return lines
}

// protocolSpec is the transport-specific command shape. A flag only appears
// here when the installed build advertises it for that protocol.
type protocolSpec struct {
	command     string
	description string
	localAuth   bool
	domain      bool
	username    bool
	password    bool
	trailing    []string
	// requiredHelpFlags are transport flags the installed build has to
	// advertise for the protocol's registrations to be usable at all. They are
	// checked against `nxc <protocol> --help`, so a build that changed the flag
	// reports the protocol as unavailable instead of issuing a bad command.
	requiredHelpFlags []string
}

// ldapSecurePort is the port NetExec's LDAP protocol treats as LDAPS: the
// installed version builds ldaps://<target> whenever the port is 636, and
// NetExec exposes no separate --ldaps switch.
const ldapSecurePort = "636"

func spec(protocol modules.Protocol) protocolSpec {
	switch protocol {
	case modules.ProtocolLDAP:
		return protocolSpec{command: "ldap", description: "LDAP over LDAPS (port " + ldapSecurePort + ")", domain: true, username: true, password: true, trailing: []string{"--port", ldapSecurePort}, requiredHelpFlags: []string{"--port"}}
	case modules.ProtocolSMB:
		return protocolSpec{command: "smb", description: "SMB (port 445)", domain: true, username: true, password: true}
	case modules.ProtocolWinRM:
		return protocolSpec{command: "winrm", description: "WinRM over HTTP/HTTPS", domain: true, username: true, password: true}
	case modules.ProtocolWMI:
		return protocolSpec{command: "wmi", description: "WMI over DCOM/RPC (port 135)", domain: true, username: true, password: true}
	case modules.ProtocolMSSQL:
		return protocolSpec{command: "mssql", description: "MSSQL (port 1433)", domain: true, username: true, password: true}
	case modules.ProtocolSSH:
		return protocolSpec{command: "ssh", description: "SSH (port 22)", username: true, password: true}
	case modules.ProtocolFTP:
		return protocolSpec{command: "ftp", description: "FTP (port 21)", username: true, password: true}
	case modules.ProtocolRDP:
		return protocolSpec{command: "rdp", description: "RDP (port 3389)", domain: true, username: true, password: true}
	case modules.ProtocolVNC:
		// VNC authenticates with a password only; the assessment username is not
		// a VNC credential and is deliberately not passed.
		return protocolSpec{command: "vnc", description: "VNC (port 5900)", password: true}
	case modules.ProtocolNFS:
		// NFS exports are enumerated without credentials.
		return protocolSpec{command: "nfs", description: "NFS (portmapper, port 111)"}
	default:
		return protocolSpec{command: protocolCommand(protocol), description: string(protocol)}
	}
}

func protocolCommand(protocol modules.Protocol) string { return strings.ToLower(string(protocol)) }

// CommandArgs builds the argument vector for one run. The order is fixed so a
// preview, an execution, and a test all agree.
func (m Module) CommandArgs(runtime *modules.Runtime) []string {
	protocol := spec(m.Protocol())
	args := []string{protocol.command, runtime.Target}
	if protocol.username {
		args = append(args, "-u", runtime.Username)
	}
	if protocol.password {
		args = append(args, "-p", runtime.Password)
	}
	if protocol.domain && strings.TrimSpace(runtime.Domain) != "" {
		args = append(args, "-d", runtime.Domain)
	}
	args = append(args, m.definition.Arguments...)
	if m.definition.DynamicArgs != nil {
		args = append(args, m.definition.DynamicArgs(runtime)...)
	}
	if m.definition.ModuleName != "" {
		args = append(args, "-M", m.definition.ModuleName)
	}
	args = append(args, m.optionArgs(runtime)...)
	args = append(args, protocol.trailing...)
	return args
}

// optionArgs renders the operator-supplied module options in the order the
// registration declares, so a run is reproducible. Options the module does not
// declare are never passed: an unknown `-o` key would silently do nothing.
func (m Module) optionArgs(runtime *modules.Runtime) []string {
	values := make([]string, 0, len(m.definition.OptionKeys))
	for _, key := range m.definition.OptionKeys {
		if value, ok := m.optionValue(runtime, key); ok {
			values = append(values, key+"="+value)
		}
	}
	if len(values) == 0 {
		return nil
	}
	return append([]string{"-o"}, values...)
}

func (m Module) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	cmd := process.Command(ctx, "nxc", m.CommandArgs(runtime)...)
	cmd.Stdout, cmd.Stderr = sink, sink
	started := time.Now()
	if err := process.Wait(ctx, cmd); err != nil {
		return fmt.Errorf("netexec failed after %s: %w", time.Since(started).Round(time.Millisecond), err)
	}
	return nil
}

func categoryPath(category modules.Category) string {
	switch category {
	case modules.CategoryCredentialAuditing:
		return "CredentialAuditing"
	case modules.CategoryCredentialDumping:
		return "CredentialDumping"
	case modules.CategoryPrivilegeEscalation:
		return "PrivilegeEscalation"
	default:
		return "Enumeration"
	}
}

// helpSource is the part of the executable's output a capability question is
// answered from.
type helpSource struct {
	help    []byte
	modules []byte
	probed  bool
}

func (h helpSource) supports(argument string) bool {
	if len(argument) < 2 || !strings.HasPrefix(argument, "--") {
		return true
	}
	return bytes.Contains(h.help, []byte(argument))
}

// RegisteredModules returns every module the registry builds, across protocols
// and categories. It exists for the coverage tests and the inventory tooling.
func RegisteredModules() []modules.Module {
	builders := []func() []modules.Module{
		LDAPEnumerationModules, SMBEnumerationModules, WinRMEnumerationModules,
		WMIEnumerationModules, MSSQLEnumerationModules, SSHEnumerationModules,
		FTPEnumerationModules, RDPEnumerationModules, VNCEnumerationModules,
		NFSEnumerationModules,
		CredentialAuditingModules, CredentialDumpingModules,
	}
	result := make([]modules.Module, 0)
	for _, builder := range builders {
		result = append(result, builder()...)
	}
	return result
}

func buildModules(definitions []Definition) []modules.Module {
	result := make([]modules.Module, 0, len(definitions))
	for _, definition := range definitions {
		result = append(result, Module{definition: definition})
	}
	return result
}

// sortedIDs is a test helper that keeps failure messages deterministic.
func sortedIDs(entries []modules.Module) []string {
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		ids = append(ids, entry.ID())
	}
	sort.Strings(ids)
	return ids
}
