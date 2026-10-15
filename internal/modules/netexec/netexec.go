package netexec

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/dependencies"
	"github.com/pwnflow/pwnflow/internal/modules"
)

type Definition struct {
	IDValue, NameValue, DescriptionValue, ToolValue string
	ToolFamilyValue                                 modules.ToolFamily
	CategoryValue                                   modules.Category
	ProtocolValue                                   modules.Protocol
	Arguments                                       []string
	OutputValue                                     string
	PrerequisiteValues                              []string
	RequiredPrivilegeValues                         []string
	SensitivityValue                                modules.Sensitivity
	ReadOnlyValue                                   bool
	SecondaryConnectionValues                       []string
	Enabled                                         bool
}

type Module struct{ definition Definition }

func (m Module) ID() string                     { return m.definition.IDValue }
func (m Module) Name() string                   { return m.definition.NameValue }
func (m Module) ToolFamily() modules.ToolFamily { return m.definition.ToolFamilyValue }
func (m Module) Category() modules.Category     { return m.definition.CategoryValue }
func (m Module) Tool() string                   { return m.definition.ToolValue }
func (m Module) Protocol() modules.Protocol     { return m.definition.ProtocolValue }
func (m Module) Description() string            { return m.definition.DescriptionValue }
func (m Module) Prerequisites() []string {
	return append([]string(nil), m.definition.PrerequisiteValues...)
}
func (m Module) RequiredPrivileges() []string {
	return append([]string(nil), m.definition.RequiredPrivilegeValues...)
}
func (m Module) OutputFile() string {
	return filepath.Join(categoryPath(m.Category()), "NetExec", m.definition.OutputValue)
}
func (m Module) Sensitivity() modules.Sensitivity { return m.definition.SensitivityValue }
func (m Module) ReadOnly() bool                   { return m.definition.ReadOnlyValue }
func (m Module) SecondaryConnections() []string {
	return append([]string(nil), m.definition.SecondaryConnectionValues...)
}

func (m Module) ExecutionEnabled() bool { return m.definition.Enabled }

func (m Module) AvailabilityReason() string {
	if !m.definition.Enabled {
		return "not implemented: sensitive-artifact workflow is disabled"
	}
	return ""
}

func (m Module) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil || strings.TrimSpace(runtime.Target) == "" || strings.TrimSpace(runtime.Domain) == "" {
		return fmt.Errorf("runtime target and domain are required")
	}
	dependency := dependencies.DefaultRegistry().CheckOne(ctx, dependencies.NetExec)
	if !dependency.Available {
		return fmt.Errorf("%s: %s", dependency.DisplayName, dependency.Detail)
	}
	protocol := protocolCommand(m.Protocol())
	help, err := exec.CommandContext(ctx, "nxc", protocol, "--help").CombinedOutput()
	if len(help) == 0 && err != nil {
		return fmt.Errorf("cannot inspect NetExec %s capabilities: %w", m.Protocol(), err)
	}
	if plugin := pluginArgument(m.definition.Arguments); plugin != "" {
		listing, listingErr := exec.CommandContext(ctx, "nxc", protocol, "-L").CombinedOutput()
		if listingErr == nil {
			help = append(help, listing...)
		}
		if !bytes.Contains(help, []byte(plugin)) {
			return fmt.Errorf("NetExec %s module %s is unsupported by the installed version", m.Protocol(), plugin)
		}
	}
	for _, argument := range m.definition.Arguments {
		if len(argument) > 2 && argument[:2] == "--" && !bytes.Contains(help, []byte(argument)) {
			return fmt.Errorf("NetExec %s option %s is unsupported by the installed version", m.Protocol(), argument)
		}
	}
	if m.Protocol() == modules.ProtocolLDAP && !bytes.Contains(help, []byte("--port")) {
		return fmt.Errorf("NetExec LDAP option --port is unsupported by the installed version")
	}
	if reason := m.AvailabilityReason(); reason != "" {
		return fmt.Errorf("%s", reason)
	}
	return nil
}

func pluginArgument(arguments []string) string {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == "-M" {
			return arguments[index+1]
		}
	}
	return ""
}

// ldapSecurePort is the port NetExec's LDAP protocol treats as LDAPS: the
// installed version builds ldaps://<target> whenever the port is 636, and
// NetExec exposes no separate --ldaps switch. SMB modules keep their own
// defaults.
const ldapSecurePort = "636"

func (m Module) CommandArgs(runtime *modules.Runtime) []string {
	args := []string{protocolCommand(m.Protocol()), runtime.Target, "-u", runtime.Username, "-p", runtime.Password}
	args = append(args, m.definition.Arguments...)
	if m.Protocol() == modules.ProtocolLDAP {
		args = append(args, "--port", ldapSecurePort)
	}
	return args
}

func protocolCommand(protocol modules.Protocol) string { return strings.ToLower(string(protocol)) }

func (m Module) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	cmd := exec.CommandContext(ctx, "nxc", m.CommandArgs(runtime)...)
	cmd.Stdout, cmd.Stderr = sink, sink
	started := time.Now()
	if err := cmd.Run(); err != nil {
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

func definition(id, name string, category modules.Category, protocol modules.Protocol, args []string, output string) Definition {
	// The LDAP protocol is run over LDAPS; SMB keeps its own defaults.
	transport := string(protocol)
	if protocol == modules.ProtocolLDAP {
		transport = "LDAP over LDAPS (port " + ldapSecurePort + ")"
	}
	return Definition{
		IDValue: id, NameValue: name, ToolValue: "NetExec (nxc)", ToolFamilyValue: modules.ToolFamilyNetExec,
		CategoryValue: category, ProtocolValue: protocol, DescriptionValue: name + " through NetExec " + transport + ".",
		Arguments: args, OutputValue: output, PrerequisiteValues: []string{"nxc executable"},
		SensitivityValue: modules.SensitivityStandard, ReadOnlyValue: true, Enabled: true,
	}
}
