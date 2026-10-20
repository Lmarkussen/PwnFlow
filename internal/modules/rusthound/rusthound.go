// Package rusthound integrates RustHound-CE as an Active Directory enumeration
// module.
//
// The integration is deliberately narrower than the installed CLI. The
// collection method is fixed at LdapOnly - the CLI defaults to All, which adds
// SMB/SYSVOL and member-machine contact - the transport is pinned to LDAPS, and
// the domain and DC address come from the operator-supplied runtime, so this
// module can neither select the default collection nor be pointed at another
// host. Those arguments express the intended scope; they are not a network
// boundary, and the module does not claim one.
package rusthound

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/dependencies"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/process"
)

const (
	moduleID = "rusthound-ce"

	// collectionMethod is fixed and always passed explicitly. RustHound-CE's own
	// default is All, which is never used here.
	collectionMethod = "LdapOnly"

	// secureTransport forces LDAPS (port 636); the installed CLI documents it as
	// "--ldaps" and uses it for every request it makes.
	secureTransport = "--ldaps"

	artifactFolder = "Enumeration/RustHoundCE/artifacts"
	outputFolder   = "Enumeration/RustHoundCE"
	logFile        = "Enumeration/RustHoundCE/rusthound-ce.log"
	runTimeLayout  = "20060102-150405"
	redactedValue  = "[REDACTED]"
)

// commandProbe describes the arguments this module relies on. The long forms are
// matched against the installed --help output so a version that renames or drops
// one is reported instead of producing a silently different command.
var commandProbe = []string{"-d, --domain", "-u, --ldapusername", "-p, --ldappassword", "-i, --ldapip", "-c, --collectionmethod", "-o, --output", secureTransport}

// secretOptions carry a value that must never reach a display, a log, or the
// execution history. -p is used for the accepted native LDAP password; the
// remaining entries cover the flags the installed CLI also accepts so a preview
// or a log line can never carry one of their values.
var secretOptions = map[string]bool{
	"-p":             true,
	"--ldappassword": true,
	"-H":             true,
	"--hashes":       true,
	"--pfx-pass":     true,
}

// authNote records the credential decision: the operator accepts RustHound's
// native -p argument for this private single-operator lab, so the password is
// passed to the collector but is never displayed, logged, or recorded.
const authNote = "native LDAP password (-p; accepted for this single-operator lab, redacted in previews and history)"

// scopeNote is the informational line shown in Module Information. LdapOnly and
// the operator-supplied target narrow what the collector asks for, but nothing
// restricts where it may connect, so the module states that plainly instead of
// implying confinement.
const scopeNote = "Network scope: LdapOnly over LDAPS against the supplied target; not kernel-enforced"

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
	return "BloodHound CE compatible LDAP collection through RustHound-CE with a fixed LdapOnly method, the operator-supplied DC address, and native LDAP password authentication."
}
func (Module) Prerequisites() []string {
	return []string{"rusthound-ce executable"}
}
func (Module) RequiredPrivileges() []string     { return nil }
func (Module) OutputFile() string               { return logFile }
func (Module) Sensitivity() modules.Sensitivity { return modules.SensitivitySensitive }
func (Module) ReadOnly() bool                   { return true }
func (Module) SecondaryConnections() []string {
	return []string{"LdapOnly contacts the supplied DC over LDAPS (port 636); DNS lookups and LDAP referrals are not restricted to that DC"}
}
func (Module) ExecutionEnabled() bool { return true }
func (Module) AvailabilityReason() string {
	return ""
}

// DetailLines reports the fixed configuration for the Module Information pane.
// They are placed ahead of the free-text description there, because the pane
// clips long content and the configuration and the blocking reason are what an
// operator must be able to read.
func (Module) DetailLines(runtime *modules.Runtime) []string {
	return []string{
		"Execution: enabled",
		"Authentication: " + authNote,
		"Collection method: " + collectionMethod + " (LDAP only; no member-machine or SYSVOL contact)",
		"Transport: LDAPS (" + secureTransport + "; port 636)",
		"Output directory: " + outputDirectory(runtime),
		scopeNote,
	}
}

// outputDirectory is the per-domain root for RustHound-CE logs and artifacts.
func outputDirectory(runtime *modules.Runtime) string {
	if runtime == nil || runtime.ResultsRoot == "" {
		return outputFolder
	}
	return filepath.Join(runtime.ResultsRoot, outputFolder)
}

// ArtifactDirectory is the stable parent for RustHound-CE JSON output.
func (m Module) ArtifactDirectory(runtime *modules.Runtime) string {
	if runtime == nil || runtime.ResultsRoot == "" {
		return artifactFolder
	}
	return filepath.Join(runtime.ResultsRoot, artifactFolder)
}

// RunArtifactDirectory scopes one collection's artifacts so a later run never
// overwrites an earlier run's JSON output.
func (m Module) RunArtifactDirectory(runtime *modules.Runtime, started time.Time) string {
	return filepath.Join(m.ArtifactDirectory(runtime), started.Format(runTimeLayout))
}

func (Module) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil || strings.TrimSpace(runtime.Target) == "" || strings.TrimSpace(runtime.Domain) == "" {
		return fmt.Errorf("runtime target and domain are required")
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
	for _, option := range commandProbe {
		if !bytes.Contains(help, []byte(option)) {
			return fmt.Errorf("RustHound-CE option %s is unsupported by the installed version", option)
		}
	}
	if !bytes.Contains(help, []byte(collectionMethod)) {
		return fmt.Errorf("RustHound-CE collection method %s is unsupported by the installed version", collectionMethod)
	}
	return nil
}

// CommandArgs returns the fixed argument vector for the authorized collection.
// The domain and DC address come from the authorized configuration constants, so
// a caller cannot redirect the collector by supplying a different runtime. The
// LDAP password is passed because the operator accepted RustHound's native -p
// argument for this private single-operator lab; every preview, log, and
// history record redacts it.
func (m Module) CommandArgs(runtime *modules.Runtime) []string {
	return m.commandArgs(runtime, m.ArtifactDirectory(runtime))
}

func (m Module) commandArgs(runtime *modules.Runtime, output string) []string {
	args := make([]string, 0, 10)
	if runtime != nil {
		if domain := strings.TrimSpace(runtime.Domain); domain != "" {
			args = append(args, "-d", domain)
		}
		if target := strings.TrimSpace(runtime.Target); target != "" {
			args = append(args, "-i", target)
		}
	}
	args = append(args, secureTransport)
	args = append(args, "-c", collectionMethod)
	if runtime != nil {
		if username := strings.TrimSpace(runtime.Username); username != "" {
			args = append(args, "-u", username)
		}
		if password := runtime.Password; password != "" {
			args = append(args, "-p", password)
		}
	}
	return append(args, "-o", output)
}

// redactArguments replaces the value of any credential-bearing option so it can
// never be shown, logged, or recorded.
func redactArguments(args []string) []string {
	redacted := append([]string(nil), args...)
	for index, argument := range redacted {
		if secretOptions[argument] && index+1 < len(redacted) {
			redacted[index+1] = redactedValue
		}
	}
	return redacted
}

func (m Module) CommandPreview(runtime *modules.Runtime) string {
	return strings.Join(append([]string{"rusthound-ce"}, redactArguments(m.CommandArgs(runtime))...), " ")
}

// Run is only reached when Check has passed. It keeps the pinned scope and writes
// JSON artifacts into a per-run directory; the accepted native credential travels
// on the command line, which the runner redacts from every display and log.
func (m Module) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	dependency := dependencies.DefaultRegistry().CheckOne(ctx, dependencies.RustHoundCE)
	if !dependency.Available {
		return fmt.Errorf("%s: %s", dependency.DisplayName, dependency.Detail)
	}
	started := time.Now()
	runDirectory := m.RunArtifactDirectory(runtime, started)
	if err := os.MkdirAll(runDirectory, 0750); err != nil {
		return fmt.Errorf("create RustHound-CE artifact directory: %w", err)
	}
	path := dependency.Detail
	if path == "" {
		path = dependency.FoundExecutable
	}
	command := process.Command(ctx, path, m.commandArgs(runtime, runDirectory)...)
	command.Dir = runDirectory
	command.Stdout, command.Stderr = sink, sink
	if err := process.Wait(ctx, command); err != nil {
		return fmt.Errorf("RustHound-CE failed after %s: %w", time.Since(started).Round(time.Millisecond), err)
	}
	if runtime != nil {
		if runtime.BatchArtifacts == nil {
			runtime.BatchArtifacts = make(map[string]string)
		}
		runtime.BatchArtifacts[moduleID] = runDirectory
	}
	return nil
}
