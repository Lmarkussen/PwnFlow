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
	"time"

	"github.com/pwnflow/pwnflow/internal/config"
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
var commandProbe = []string{"-d, --domain", "-i, --ldapip", "-c, --collectionmethod", "-o, --output"}

// secretOptions carry a value that must never reach a display, a log, or the
// execution history. The command builder does not use them; redaction is
// defence in depth for previews and for any future credential transport.
var secretOptions = map[string]bool{
	"-p":             true,
	"--ldappassword": true,
	"-H":             true,
	"--hashes":       true,
	"--pfx-pass":     true,
}

// credentialReason records the verified credential-transport problem: the
// installed 2.5.25 CLI takes the LDAP password (and NT hash) only as a
// command-line value, which would be visible in /proc/<pid>/cmdline for the
// whole collection. The only argument-free transport it offers is --kerberos
// with an operator-supplied KRB5CCNAME credential cache, and no such cache
// exists on the assessment host.
const credentialReason = "RustHound-CE 2.5.25 accepts the LDAP password only on the command line, which would expose it in the process list, and no Kerberos credential cache has been supplied"

// confinementReason records what is still unproven: pinning the DC address and
// using LdapOnly narrows collection to LDAP against one host, but nothing
// enforces that DNS resolution or LDAP referrals cannot reach another system.
const confinementReason = "LdapOnly with a pinned DC address does not prove that DNS lookups and LDAP referrals stay on " + config.AuthorizedTarget

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
	return "BloodHound CE compatible LDAP collection through RustHound-CE with a fixed LdapOnly method and the authorized DC address only; blocked until LDAP credential transport and DC-only confinement are verified."
}
func (Module) Prerequisites() []string {
	return []string{"rusthound-ce executable", "argument-free LDAP credential transport", "verified DC-only destination confinement"}
}
func (Module) RequiredPrivileges() []string     { return nil }
func (Module) OutputFile() string               { return logFile }
func (Module) Sensitivity() modules.Sensitivity { return modules.SensitivitySensitive }
func (Module) ReadOnly() bool                   { return true }
func (Module) SecondaryConnections() []string {
	return []string{"LdapOnly contacts the authorized DC over LDAP; DNS and LDAP referral behaviour is not yet proven to stay on that DC"}
}
func (Module) ExecutionEnabled() bool { return false }
func (Module) AvailabilityReason() string {
	return "scope restricted: " + credentialReason + "; " + confinementReason
}

// DetailLines reports the fixed configuration for the Module Information pane.
// They are placed ahead of the free-text description there, because the pane
// clips long content and the configuration and the blocking reason are what an
// operator must be able to read.
func (Module) DetailLines(runtime *modules.Runtime) []string {
	lines := []string{
		"Execution: blocked - Scope Restricted",
		"Collection method: " + collectionMethod + " (LDAP only; no member-machine or SYSVOL contact)",
	}
	if runtime == nil || runtime.ResultsRoot == "" {
		return append(lines, "Output directory: "+outputFolder, "Blocked by: "+credentialReason+"; "+confinementReason)
	}
	return append(lines, "Output directory: "+filepath.Join(runtime.ResultsRoot, outputFolder), "Blocked by: "+credentialReason+"; "+confinementReason)
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
// a caller cannot redirect the collector by supplying a different runtime, and
// no credential is ever placed on the command line.
func (m Module) CommandArgs(runtime *modules.Runtime) []string {
	return m.commandArgs(runtime, m.ArtifactDirectory(runtime))
}

func (m Module) commandArgs(runtime *modules.Runtime, output string) []string {
	args := []string{"-d", config.AuthorizedDomain, "-i", config.AuthorizedTarget, "-c", collectionMethod}
	if runtime != nil {
		if username := strings.TrimSpace(runtime.Username); username != "" {
			args = append(args, "-u", username)
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
