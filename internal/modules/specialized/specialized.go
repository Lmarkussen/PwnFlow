package specialized

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pwnflow/pwnflow/internal/dependencies"
	"github.com/pwnflow/pwnflow/internal/modules"
)

type Definition struct {
	IDValue, NameValue, ToolValue, SlugValue, DescriptionValue string
	Family                                                     modules.ToolFamily
	CategoryValue                                              modules.Category
	ProtocolValue                                              modules.Protocol
	Dependency                                                 dependencies.ID
	Args                                                       func(*modules.Runtime, string) []string
	Enabled                                                    bool
	Approval                                                   string
	Options                                                    []string
}

type Module struct{ definition Definition }

const outputRoot = "Enumeration/Specialized"

func Modules() []Module {
	return []Module{
		{definition: Definition{IDValue: "mssqlrelay-check", NameValue: "MSSQL Encryption Assessment", ToolValue: "mssqlrelay", SlugValue: "mssqlrelay-check", Family: modules.ToolFamilyNetwork, CategoryValue: modules.CategorySecurityAuditing, ProtocolValue: modules.ProtocolMSSQL, Dependency: dependencies.MSSQLRelay, Enabled: true, DescriptionValue: "Runs mssqlrelay check against only the configured MSSQL target. This reads encryption and login configuration; relay, coercion and command execution are not invoked.", Args: mssqlRelayArgs}},
		{definition: Definition{IDValue: "mssqlpwner-enumerate", NameValue: "MSSQL Linked-Server and Impersonation Enumeration", ToolValue: "MSSqlPwner", SlugValue: "mssqlpwner-enumerate", Family: modules.ToolFamilyNetwork, CategoryValue: modules.CategoryPermissionsAuditing, ProtocolValue: modules.ProtocolMSSQL, Dependency: dependencies.MSSqlPwner, Enabled: true, Approval: "enumerates linked-server and impersonation relationships through the selected MSSQL connection", DescriptionValue: "Runs MSSqlPwner enumerate only. It collects server, linked-server and impersonation relationship evidence; command execution, relay and write-capable modules are not registered.", Args: mssqlPwnerArgs}},
		{definition: Definition{IDValue: "gpoparser-local", NameValue: "GPO Offline Analysis", ToolValue: "gpoParser", SlugValue: "gpoparser-local", Family: modules.ToolFamilyActiveDirectory, CategoryValue: modules.CategoryConfigurationAuditing, ProtocolValue: modules.ProtocolNA, Dependency: dependencies.GPOParser, Enabled: true, Options: []string{"SYSVOL", "LDAP_EXPORT"}, DescriptionValue: "Analyzes explicitly supplied SYSVOL and directory-export paths with gpoParser local. It does not contact the network or enrich an external graph database.", Args: gpoLocalArgs}},
		{definition: Definition{IDValue: "gpoparser-remote", NameValue: "GPO Remote Analysis", ToolValue: "gpoParser", SlugValue: "gpoparser-remote", Family: modules.ToolFamilyActiveDirectory, CategoryValue: modules.CategoryConfigurationAuditing, ProtocolValue: modules.ProtocolLDAP, Dependency: dependencies.GPOParser, Enabled: true, Approval: "reads LDAP and SYSVOL policy data from the configured domain controller", DescriptionValue: "Runs gpoParser remote against the configured domain controller. The enrich mode and external database writes are not invoked.", Args: gpoRemoteArgs}},
		{definition: Definition{IDValue: "ghostspn-audit", NameValue: "Ghost SPN Audit", ToolValue: "ghostSPN", SlugValue: "ghostspn-audit", Family: modules.ToolFamilyActiveDirectory, CategoryValue: modules.CategorySecurityAuditing, ProtocolValue: modules.ProtocolLDAP, Dependency: dependencies.GhostSPN, Enabled: true, DescriptionValue: "Audits SPNs through the configured domain controller and stores ghostSPN JSON output. It does not reclassify ordinary SPNs as Kerberoastable findings.", Args: ghostSPNArgs}},
		{definition: Definition{IDValue: "sccmsecrets-offline", NameValue: "SCCMSecrets Offline Artifact Analysis", ToolValue: "SCCMSecrets", SlugValue: "sccmsecrets-offline", Family: modules.ToolFamilySCCM, CategoryValue: modules.CategoryConfigurationAuditing, ProtocolValue: modules.ProtocolNA, Dependency: dependencies.SCCMSecrets, Enabled: false, Options: []string{"ARTIFACT"}, DescriptionValue: "Reserved for offline analysis of explicitly supplied SCCMSecrets output. Live policies/files workflows remain disabled because they can register or impersonate clients and retrieve protected deployment content.", Args: sccmOfflineArgs}},
	}
}

func (m Module) ID() string                     { return m.definition.IDValue }
func (m Module) Name() string                   { return m.definition.NameValue }
func (m Module) ToolFamily() modules.ToolFamily { return m.definition.Family }
func (m Module) Category() modules.Category     { return m.definition.CategoryValue }
func (m Module) Tool() string                   { return m.definition.ToolValue }
func (m Module) Protocol() modules.Protocol     { return m.definition.ProtocolValue }
func (m Module) Description() string            { return m.definition.DescriptionValue }
func (m Module) Prerequisites() []string {
	return []string{"verified upstream installation for " + m.Tool()}
}
func (m Module) RequiredPrivileges() []string { return nil }
func (m Module) OutputFile() string {
	extension := ".log"
	if m.definition.IDValue == "ghostspn-audit" || m.definition.IDValue == "gpoparser-local" || m.definition.IDValue == "gpoparser-remote" {
		extension = ".json"
	}
	return filepath.Join(outputRoot, m.definition.SlugValue+extension)
}
func (m Module) Sensitivity() modules.Sensitivity { return modules.SensitivitySensitive }
func (m Module) ReadOnly() bool                   { return m.definition.Enabled }
func (m Module) SecondaryConnections() []string {
	if m.definition.IDValue == "gpoparser-local" || m.definition.IDValue == "sccmsecrets-offline" {
		return []string{"reads only explicitly supplied local artifacts"}
	}
	if m.definition.IDValue == "mssqlrelay-check" || m.definition.IDValue == "mssqlpwner-enumerate" {
		return []string{"contacts only the configured MSSQL target"}
	}
	return []string{"contacts only the configured domain controller and its SYSVOL path"}
}
func (m Module) DependencyKey() string  { return string(m.definition.Dependency) }
func (m Module) OptionKeys() []string   { return append([]string(nil), m.definition.Options...) }
func (m Module) ExecutionEnabled() bool { return m.definition.Enabled }
func (m Module) AvailabilityReason() string {
	if m.definition.Enabled {
		return ""
	}
	return "disabled: upstream workflow may register/impersonate SCCM clients or retrieve protected deployment content; use offline analysis only"
}
func (m Module) PlanApproval(runtime *modules.Runtime) (bool, string) {
	return m.definition.Approval != "", m.definition.Approval
}
func (m Module) MissingInputs(runtime *modules.Runtime) []modules.InputField {
	missing := make([]modules.InputField, 0)
	for _, key := range m.definition.Options {
		if _, ok := runtime.ModuleOption(m.ID(), key); !ok {
			missing = append(missing, modules.InputField{Key: key, Prompt: "path for " + key, Example: "/path/to/input"})
		}
	}
	return missing
}
func (m Module) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil {
		return fmt.Errorf("runtime configuration is required")
	}
	if !m.definition.Enabled {
		return fmt.Errorf("%s", m.AvailabilityReason())
	}
	status := dependencies.DefaultRegistry().CheckOne(ctx, m.definition.Dependency)
	if !status.Available {
		return fmt.Errorf("%s: %s", status.DisplayName, status.Detail)
	}
	if m.definition.IDValue != "gpoparser-local" && (runtime.Target == "" || runtime.Domain == "" || runtime.Username == "") {
		return fmt.Errorf("target, domain and username are required")
	}
	for _, key := range m.definition.Options {
		if _, ok := runtime.ModuleOption(m.ID(), key); !ok {
			return fmt.Errorf("module option %s is required", key)
		}
	}
	return nil
}
func (m Module) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	if err := m.Check(ctx, runtime); err != nil {
		return err
	}
	status := dependencies.DefaultRegistry().CheckOne(ctx, m.definition.Dependency)
	program, base := status.FoundExecutable, []string(nil)
	if status.Interpreter != "" && status.Script != "" {
		program, base = status.Interpreter, []string{status.Script}
	}
	outputPath := filepath.Join(runtime.ResultsRoot, m.OutputFile())
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return err
	}
	args := append(base, m.definition.Args(runtime, outputPath)...)
	command := exec.CommandContext(ctx, program, args...)
	command.Dir = filepath.Dir(outputPath)
	output, err := command.CombinedOutput()
	if strings.HasSuffix(outputPath, ".json") {
		stdoutPath := strings.TrimSuffix(outputPath, ".json") + ".log"
		if writeErr := os.WriteFile(stdoutPath, output, 0o600); writeErr != nil {
			return writeErr
		}
		if err == nil {
			if _, statErr := os.Stat(outputPath); os.IsNotExist(statErr) {
				if writeErr := os.WriteFile(outputPath, []byte("[]\n"), 0o600); writeErr != nil {
					return writeErr
				}
			}
		}
	} else if writeErr := os.WriteFile(outputPath, output, 0o600); writeErr != nil {
		return writeErr
	}
	if _, writeErr := sink.Write(output); writeErr != nil {
		return writeErr
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%s failed: %w", m.Tool(), err)
	}
	if semanticErr := semanticAssessmentError(m.ID(), output); semanticErr != nil {
		return semanticErr
	}
	return nil
}

// semanticAssessmentError catches the mssqlrelay 1.1 failure mode where the
// Python wrapper prints a refused connection and traceback but exits zero. Raw
// output remains persisted; only the execution result is corrected.
func semanticAssessmentError(moduleID string, output []byte) error {
	if moduleID != "mssqlrelay-check" {
		return nil
	}
	text := strings.ToLower(string(output))
	for _, marker := range []string{"connection refused", "'int' object has no attribute 'sendall'", "traceback (most recent call last)"} {
		if strings.Contains(text, marker) {
			return fmt.Errorf("mssqlrelay reported an assessment failure: %s", marker)
		}
	}
	return nil
}

func (m Module) CommandPreview(runtime *modules.Runtime) string {
	args := m.definition.Args(runtime, "<artifact>")
	if runtime != nil && runtime.Password != "" {
		for index := range args {
			args[index] = strings.ReplaceAll(args[index], runtime.Password, "<password>")
		}
	}
	return m.Tool() + " " + strings.Join(args, " ")
}

func mssqlRelayArgs(r *modules.Runtime, _ string) []string {
	return []string{"check", "-target", r.Target, "-u", r.Username + "@" + r.Domain, "-p", r.Password, "-windows-auth"}
}
func mssqlPwnerArgs(r *modules.Runtime, _ string) []string {
	return []string{"" + r.Domain + "/" + r.Username + ":" + r.Password + "@" + r.Target, "-windows-auth", "enumerate"}
}
func gpoLocalArgs(r *modules.Runtime, output string) []string {
	return []string{"local", moduleOptionValue(r, "gpoparser-local", "SYSVOL"), moduleOptionValue(r, "gpoparser-local", "LDAP_EXPORT"), "-o", output}
}
func gpoRemoteArgs(r *modules.Runtime, output string) []string {
	return []string{"remote", "-s", r.Target, "-d", r.Domain, "-u", r.Username, "-p", r.Password, "-o", output}
}
func ghostSPNArgs(r *modules.Runtime, output string) []string {
	return []string{"--server", r.Target, "--domain", r.Domain, "--username", r.Username, "--password", r.Password, "--output", output}
}
func sccmOfflineArgs(r *modules.Runtime, output string) []string {
	return []string{"--help", "--output", output}
}

func moduleOptionValue(r *modules.Runtime, id, key string) string {
	if value, ok := r.ModuleOption(id, key); ok {
		return value
	}
	return ""
}

var _ modules.Module = Module{}
var _ modules.ExecutionPolicy = Module{}
var _ modules.DependencyKeyProvider = Module{}
var _ modules.OptionDeclarer = Module{}
var _ modules.ApprovalRequester = Module{}
