// Package rusthound integrates RustHound-CE as an Active Directory enumeration
// module.
//
// The integration is deliberately narrower than the installed CLI. The
// collection method is fixed at LdapOnly - the CLI defaults to All, which adds
// SMB/SYSVOL and member-machine contact - and the domain and DC address come
// from the authorized configuration constants, so this module can neither
// select the default collection nor be pointed at another host. Execution stays
// blocked until LDAP credential transport and destination confinement are both
// verified; see Module.AvailabilityReason.
package rusthound

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/confinement"
	"github.com/pwnflow/pwnflow/internal/dependencies"
	"github.com/pwnflow/pwnflow/internal/modules"
)

const (
	moduleID = "rusthound-ce"

	// collectionMethod is fixed and always passed explicitly. RustHound-CE's own
	// default is All, which is never used here.
	collectionMethod = "LdapOnly"

	artifactFolder = "Enumeration/RustHoundCE/artifacts"
	outputFolder   = "Enumeration/RustHoundCE"
	logFile        = "Enumeration/RustHoundCE/rusthound-ce.log"
	runTimeLayout  = "20060102-150405"
	redactedValue  = "[REDACTED]"
)

// commandProbe describes the arguments this module relies on. The long forms are
// matched against the installed --help output so a version that renames or drops
// one is reported instead of producing a silently different command.
var commandProbe = []string{"-d, --domain", "-u, --ldapusername", "-p, --ldappassword", "-i, --ldapip", "-c, --collectionmethod", "-o, --output"}

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

// blockedNote and remedyNote are the short, actionable lines shown in Module
// Information; the full launch command is in the README under "Confined launch".
const (
	blockedNote = "Blocked by: no enforced process-specific egress boundary"
	remedyNote  = "Remedy: cgroup restricted to " + config.AuthorizedTarget + " (README: Confined launch)"
)

// egressEnforced answers once per process whether a kernel-enforced egress
// boundary is in place. The TUI asks for it on every frame, so the verdict is
// cached; it is a variable so tests can supply one without a confined kernel.
var egressEnforced = sync.OnceValue(confinement.Probe)

// egressProbe re-checks the boundary immediately before a collection instead of
// trusting the cached verdict the interface was rendered with.
var egressProbe = confinement.Probe

// confinementBlocker explains why collection is refused while no boundary is
// verified. Pinning the DC address and using LdapOnly is intent, not a boundary.
func confinementBlocker(err error) string {
	return "scope restricted: no enforced process-specific egress boundary (" + err.Error() + "); " + remedyNote
}

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
	return "BloodHound CE compatible LDAP collection through RustHound-CE with a fixed LdapOnly method, the authorized DC address, and native LDAP password authentication; it runs only while a process-specific egress boundary to that DC is enforced and verified."
}
func (Module) Prerequisites() []string {
	return []string{"rusthound-ce executable", "enforced DC-only egress boundary for this process"}
}
func (Module) RequiredPrivileges() []string     { return nil }
func (Module) OutputFile() string               { return logFile }
func (Module) Sensitivity() modules.Sensitivity { return modules.SensitivitySensitive }
func (Module) ReadOnly() bool                   { return true }
func (Module) SecondaryConnections() []string {
	return []string{"LdapOnly contacts the authorized DC over LDAP; DNS and LDAP referral behaviour is not yet confined to that DC"}
}
func (Module) ExecutionEnabled() bool { return egressEnforced() == nil }
func (Module) AvailabilityReason() string {
	if err := egressEnforced(); err != nil {
		return confinementBlocker(err)
	}
	return ""
}

// DetailLines reports the fixed configuration for the Module Information pane.
// They are placed ahead of the free-text description there, because the pane
// clips long content and the configuration and the blocking reason are what an
// operator must be able to read.
func (Module) DetailLines(runtime *modules.Runtime) []string {
	lines := make([]string, 0, 6)
	if err := egressEnforced(); err != nil {
		lines = append(lines, "Execution: blocked - Scope Restricted")
	} else {
		lines = append(lines, "Execution: enabled - egress confined to "+config.AuthorizedTarget)
	}
	lines = append(lines,
		"Authentication: "+authNote,
		"Collection method: "+collectionMethod+" (LDAP only; no member-machine or SYSVOL contact)",
		"Output directory: "+outputDirectory(runtime),
	)
	if err := egressEnforced(); err != nil {
		lines = append(lines, blockedNote, remedyNote)
	}
	return lines
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
	for _, option := range commandProbe {
		if !bytes.Contains(help, []byte(option)) {
			return fmt.Errorf("RustHound-CE option %s is unsupported by the installed version", option)
		}
	}
	if !bytes.Contains(help, []byte(collectionMethod)) {
		return fmt.Errorf("RustHound-CE collection method %s is unsupported by the installed version", collectionMethod)
	}
	if reason := (Module{}).AvailabilityReason(); reason != "" {
		return fmt.Errorf("%s", reason)
	}
	return nil
}

// CommandArgs returns the fixed argument vector for the authorized collection.
// The domain and DC address come from the confined configuration constants, so
// a caller cannot redirect the collector by supplying a different runtime. The
// LDAP password is passed because the operator accepted RustHound's native -p
// argument for this private single-operator lab; every preview, log, and
// history record redacts it.
func (m Module) CommandArgs(runtime *modules.Runtime) []string {
	return m.commandArgs(runtime, m.ArtifactDirectory(runtime))
}

func (m Module) commandArgs(runtime *modules.Runtime, output string) []string {
	args := []string{"-d", config.AuthorizedDomain, "-i", config.AuthorizedTarget, "-c", collectionMethod}
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

// Run is only reached when Check has passed; it keeps the pinned scope, writes
// JSON artifacts into a per-run directory, and never passes credentials.
func (m Module) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	// Fail closed: never start the collector without a freshly verified boundary.
	if err := egressProbe(); err != nil {
		return fmt.Errorf("refusing to run RustHound-CE without an enforced egress boundary: %w", err)
	}
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
	command := exec.CommandContext(ctx, path, m.commandArgs(runtime, runDirectory)...)
	command.Dir = runDirectory
	command.Stdout, command.Stderr = sink, sink
	if err := command.Run(); err != nil {
		return fmt.Errorf("RustHound-CE failed after %s: %w", time.Since(started).Round(time.Millisecond), err)
	}
	return nil
}
