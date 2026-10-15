package rusthound

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/dependencies"
	"github.com/pwnflow/pwnflow/internal/modules"
)

const (
	moduleID       = "rusthound-ce"
	artifactFolder = "Enumeration/RustHoundCE/artifacts"
	logFile        = "Enumeration/RustHoundCE/rusthound-ce.log"
)

// Module describes RustHound-CE independently from the NetExec BloodHound
// capability and from both Python collector variants.
type Module struct{}

func (Module) ID() string                     { return moduleID }
func (Module) Name() string                   { return "RustHound-CE" }
func (Module) ToolFamily() modules.ToolFamily { return modules.ToolFamilyActiveDirectory }
func (Module) Category() modules.Category     { return modules.CategoryEnumeration }
func (Module) Tool() string                   { return "RustHound-CE" }
func (Module) Protocol() modules.Protocol     { return modules.ProtocolNA }
func (Module) Description() string {
	return "BloodHound Community Edition relationship collection through RustHound-CE; disabled until destination confinement is verified."
}
func (Module) Prerequisites() []string {
	return []string{"rusthound-ce executable", "authorized single-host collection workflow"}
}
func (Module) RequiredPrivileges() []string     { return nil }
func (Module) OutputFile() string               { return logFile }
func (Module) Sensitivity() modules.Sensitivity { return modules.SensitivitySensitive }
func (Module) ReadOnly() bool                   { return true }
func (Module) SecondaryConnections() []string {
	return []string{"may contact domain hosts and services beyond the supplied DC"}
}
func (Module) ExecutionEnabled() bool { return false }
func (Module) AvailabilityReason() string {
	return "scope restricted: RustHound-CE secondary connections are not verified to remain on the authorized DC"
}
func (Module) ArtifactDirectory(runtime *modules.Runtime) string {
	return filepath.Join(runtime.ResultsRoot, artifactFolder)
}

func (m Module) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil || runtime.Target != config.AuthorizedTarget || runtime.Domain != config.AuthorizedDomain {
		return fmt.Errorf("target is outside the authorized assessment scope")
	}
	dependency := dependencies.DefaultRegistry().CheckOne(ctx, dependencies.RustHoundCE)
	if !dependency.Available {
		return fmt.Errorf("%s: %s", dependency.DisplayName, dependency.Detail)
	}
	path := dependency.Detail
	if path == "" {
		path = dependency.FoundExecutable
	}
	help, err := exec.CommandContext(ctx, path, "--help").CombinedOutput()
	if err != nil {
		return fmt.Errorf("RustHound-CE capability probe failed: %w", err)
	}
	for _, option := range []string{"-d", "-u", "-p", "-i", "-o"} {
		if !bytes.Contains(help, []byte(option)) {
			return fmt.Errorf("RustHound-CE option %s is unsupported by the installed version", option)
		}
	}
	if reason := m.AvailabilityReason(); reason != "" {
		return fmt.Errorf("%s", reason)
	}
	return nil
}

func (m Module) CommandArgs(runtime *modules.Runtime) []string {
	return []string{"-d", runtime.Domain, "-u", runtime.Username, "-p", runtime.Password, "-i", runtime.Target, "-o", m.ArtifactDirectory(runtime)}
}

func (m Module) CommandPreview(runtime *modules.Runtime) string {
	args := m.CommandArgs(runtime)
	for index, argument := range args {
		if argument == "-p" && index+1 < len(args) {
			args[index+1] = "[REDACTED]"
		}
	}
	return strings.Join(append([]string{"rusthound-ce"}, args...), " ")
}

func (m Module) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	dependency := dependencies.DefaultRegistry().CheckOne(ctx, dependencies.RustHoundCE)
	if !dependency.Available {
		return fmt.Errorf("%s: %s", dependency.DisplayName, dependency.Detail)
	}
	artifactDirectory := m.ArtifactDirectory(runtime)
	if err := os.MkdirAll(artifactDirectory, 0750); err != nil {
		return fmt.Errorf("create RustHound-CE working directory: %w", err)
	}
	path := dependency.Detail
	if path == "" {
		path = dependency.FoundExecutable
	}
	command := exec.CommandContext(ctx, path, m.CommandArgs(runtime)...)
	command.Dir = artifactDirectory
	command.Stdout, command.Stderr = sink, sink
	if err := command.Run(); err != nil {
		return fmt.Errorf("RustHound-CE failed: %w", err)
	}
	return nil
}
