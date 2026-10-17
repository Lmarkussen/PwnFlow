// Package certipy integrates Certipy's read-oriented AD CS enumeration.
//
// Only the `find` action is used. Certipy is pointed at the configured domain
// controller for LDAP, while its CA-level checks remain enabled so explicit
// Web Enrollment conditions such as ESC8 are collected.
// Certipy still performs its own DNS resolution and LDAP referral handling, so
// the pinned arguments express the intended collection scope rather than a
// network boundary, and the module says so instead of implying one.
//
// The transport is pinned to LDAPS, which is Certipy's own default for `find`,
// and is never silently downgraded to unsigned LDAP.
package certipy

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
	// toolName is the command Certipy's AD CS package installs as on Kali; the
	// pipx/PyPI distribution exposes the same tool as `certipy`. Detection tries
	// both and always verifies the AD CS capability before accepting either.
	toolName = "certipy-ad"

	// adcsMarker and findMarker identify Certipy's AD CS tool rather than an
	// unrelated program that happens to be named certipy. The shipped find
	// subcommand describes itself as discovering and analyzing these components,
	// so the same phrase is what the find help is matched against; the action
	// list that names "Enumerate AD CS" appears only in the top-level help.
	adcsMarker = "Active Directory Certificate Services"

	artifactFolder = "Enumeration/Certipy/artifacts"
	outputFolder   = "Enumeration/Certipy"
	runTimeLayout  = "20060102-150405"
	redactedValue  = "[REDACTED]"

	// ldapScheme and ldapPort pin the protected transport. Certipy already
	// defaults to LDAPS for `find`; passing both arguments keeps the choice
	// explicit and visible in the command preview.
	ldapScheme = "ldaps"
	ldapPort   = "636"
)

// baseOptions are the `find` arguments every module in this package relies on.
// They are matched against the installed version's own help output, so a version
// that renames or drops one is reported instead of producing a different command
// than the module advertises.
var baseOptions = []string{
	"-dc-ip", "-u", "-p", "-ldap-scheme", "-ldap-port", "-stdout", "-json", "-text", "-output",
}

// secretOptions carry a value that must never reach a display, a log, or the
// execution history. Only -p is emitted by these modules; the remaining entries
// are the credential-bearing options Certipy documents, so no preview or log
// line can carry one of their values either.
var secretOptions = map[string]bool{
	"-p":            true,
	"-password":     true,
	"-hashes":       true,
	"-aes":          true,
	"-pfx-password": true,
	"-key":          true,
}

// authNote records the credential decision: the operator accepts Certipy's
// native -p argument for this private single-operator lab, so the password is
// passed to the tool but is never displayed, logged, or recorded.
const authNote = "native AD credentials (-u/-p; accepted for this single-operator lab, redacted in previews, logs, and history)"

// scopeNote is the informational line shown in Module Information. Certipy's
// CA checks may contact the CA host reported by the directory.
const scopeNote = "Network scope: LDAP against the supplied DC plus Certipy CA checks; not kernel-enforced"

// Definition describes one Certipy enumeration module.
type Definition struct {
	IDValue          string
	NameValue        string
	DescriptionValue string
	SlugValue        string
	FilterValue      string
	Options          []string
}

type Module struct{ definition Definition }

// EnumerationModules returns the AD CS enumeration modules registered under
// Tool Family -> Category -> Tool as AD CS -> Enumeration -> Certipy.
func EnumerationModules() []Module {
	return []Module{
		{definition: Definition{
			IDValue:     "certipy-adcs-discovery",
			NameValue:   "AD CS Discovery",
			SlugValue:   "adcs-discovery",
			FilterValue: "no template filter (all discovered AD CS objects)",
			DescriptionValue: "Discovers Active Directory Certificate Services objects with Certipy find: " +
				"certificate authorities, templates, and their configuration, collected over LDAP against the configured domain controller. " +
				"Vulnerability scoring for nested group membership is not requested here.",
		}},
		{definition: Definition{
			IDValue:     "certipy-adcs-enabled-templates",
			NameValue:   "Enabled Certificate Templates",
			SlugValue:   "enabled-templates",
			FilterValue: "-enabled (enabled certificate templates only)",
			Options:     []string{"-enabled"},
			DescriptionValue: "Enumerates enabled Active Directory certificate templates with Certipy find, " +
				"reporting template permissions and issuance settings published by the configured domain controller.",
		}},
		{definition: Definition{
			IDValue:     "certipy-adcs-vulnerable-templates",
			NameValue:   "Potentially Vulnerable Certificate Templates",
			SlugValue:   "vulnerable-templates",
			FilterValue: "-vulnerable (templates flagged by nested group membership)",
			Options:     []string{"-vulnerable"},
			DescriptionValue: "Enumerates certificate templates Certipy flags as vulnerable from nested group memberships, " +
				"so potential certificate-based privilege escalation is visible before any request is made. " +
				"The flags are Certipy's assessment of published template settings, not a validated exploitation path.",
		}},
	}
}

func (m Module) ID() string                     { return m.definition.IDValue }
func (m Module) Name() string                   { return m.definition.NameValue }
func (m Module) ToolFamily() modules.ToolFamily { return modules.ToolFamilyADCS }
func (m Module) Category() modules.Category     { return modules.CategoryEnumeration }
func (m Module) Tool() string                   { return "Certipy" }
func (m Module) Protocol() modules.Protocol     { return modules.ProtocolLDAP }
func (m Module) Description() string            { return m.definition.DescriptionValue }

// DependencyKey reports that every module in this package is gated by the single
// installed Certipy program, whose registry entry is keyed by "certipy" while
// each module carries its own ID.
func (m Module) DependencyKey() string { return string(dependencies.Certipy) }

func (m Module) Prerequisites() []string {
	return []string{"Certipy AD CS executable (certipy-ad from Kali, or certipy from pipx)"}
}
func (m Module) RequiredPrivileges() []string { return nil }
func (m Module) OutputFile() string {
	return filepath.Join(outputFolder, m.definition.SlugValue+".log")
}
func (m Module) Sensitivity() modules.Sensitivity { return modules.SensitivitySensitive }

// ReadOnly reports that `find` enumerates AD CS configuration without modifying
// the directory; it only writes its own report files.
func (m Module) ReadOnly() bool { return true }

func (m Module) SecondaryConnections() []string {
	return []string{"Certipy may contact the CA host reported by LDAP for CA registry and Web Enrollment checks; no member-machine collection is requested"}
}

// DetailLines reports the fixed configuration for the Module Information pane,
// ahead of the free-text description, because the pane clips long content.
func (m Module) DetailLines(runtime *modules.Runtime) []string {
	return []string{
		"Execution: enabled",
		"Authentication: " + authNote,
		"Collection scope: configured DC LDAP plus CA registry/Web Enrollment checks; no member-machine collection",
		fmt.Sprintf("Transport: %s (explicit -ldap-scheme %s -ldap-port %s; never downgraded to unsigned LDAP)", strings.ToUpper(ldapScheme), ldapScheme, ldapPort),
		"Filter: " + m.definition.FilterValue,
		"Output directory: " + outputDirectory(runtime),
		scopeNote,
	}
}

// outputDirectory is the per-domain root for Certipy logs and artifacts.
func outputDirectory(runtime *modules.Runtime) string {
	if runtime == nil || runtime.ResultsRoot == "" {
		return outputFolder
	}
	return filepath.Join(runtime.ResultsRoot, outputFolder)
}

// ArtifactDirectory is the stable parent for Certipy report files.
func (m Module) ArtifactDirectory(runtime *modules.Runtime) string {
	if runtime == nil || runtime.ResultsRoot == "" {
		return artifactFolder
	}
	return filepath.Join(runtime.ResultsRoot, artifactFolder)
}

// RunArtifactDirectory scopes one enumeration's reports so a later run never
// overwrites an earlier run's JSON or text output.
func (m Module) RunArtifactDirectory(runtime *modules.Runtime, started time.Time) string {
	return filepath.Join(m.ArtifactDirectory(runtime), started.Format(runTimeLayout))
}

// executable resolves the installed AD CS Certipy and verifies that the program
// itself is Certipy, so an unrelated command named certipy is never run.
func executable(ctx context.Context) (string, error) {
	dependency := dependencies.DefaultRegistry().CheckOne(ctx, dependencies.Certipy)
	if !dependency.Available {
		return "", fmt.Errorf("%s: %s", dependency.DisplayName, dependency.Detail)
	}
	path := dependency.Detail
	if path == "" {
		path = dependency.FoundExecutable
	}
	if path == "" {
		return "", fmt.Errorf("Certipy AD CS executable could not be resolved; install with ./install.sh --with-certipy")
	}
	return path, nil
}

// verifyADCS confirms the resolved program is the AD CS Certipy that supports
// the options this module passes, rather than an unrelated tool of the same name
// or a version without the required arguments.
func (m Module) verifyADCS(ctx context.Context, path string) error {
	help, err := exec.CommandContext(ctx, path, "--help").CombinedOutput()
	if err != nil {
		return fmt.Errorf("Certipy capability probe failed: %w", err)
	}
	if !bytes.Contains(help, []byte(adcsMarker)) {
		return fmt.Errorf("the executable at %s is not AD CS Certipy (its help does not report %q); install the certipy-ad package", path, adcsMarker)
	}
	findHelp, err := exec.CommandContext(ctx, path, "find", "--help").CombinedOutput()
	if err != nil {
		return fmt.Errorf("Certipy find capability probe failed: %w", err)
	}
	if !bytes.Contains(findHelp, []byte(adcsMarker)) {
		return fmt.Errorf("the installed Certipy does not report a find (AD CS enumeration) action")
	}
	for _, option := range append(append([]string(nil), baseOptions...), m.definition.Options...) {
		if !bytes.Contains(findHelp, []byte(option)) {
			return fmt.Errorf("Certipy find option %s is unsupported by the installed version", option)
		}
	}
	return nil
}

func (m Module) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil || strings.TrimSpace(runtime.Target) == "" || strings.TrimSpace(runtime.Domain) == "" {
		return fmt.Errorf("runtime target and domain are required")
	}
	path, err := executable(ctx)
	if err != nil {
		return err
	}
	return m.verifyADCS(ctx, path)
}

// bindIdentity states the domain explicitly, because Certipy takes the domain
// from the identity when the target is an address.
func bindIdentity(runtime *modules.Runtime) string {
	username := strings.TrimSpace(runtime.Username)
	domain := strings.TrimSpace(runtime.Domain)
	if username == "" || domain == "" || strings.Contains(username, "@") {
		return username
	}
	return username + "@" + domain
}

// CommandArgs returns the argument vector for this module's enumeration. The
// domain, DC address, and credentials come from the operator-supplied runtime,
// so the module follows the configured assessment instead of any fixed lab.
func (m Module) CommandArgs(runtime *modules.Runtime) []string {
	return m.commandArgs(runtime, m.artifactPrefix(runtime, time.Now()))
}

// artifactPrefix names the report files Certipy writes into the run directory.
// It is a bare prefix with no path separator, so the files cannot escape the
// per-run directory the module sets as the working directory.
func (m Module) artifactPrefix(runtime *modules.Runtime, started time.Time) string {
	return started.Format(runTimeLayout) + "_" + m.definition.SlugValue
}

func (m Module) commandArgs(runtime *modules.Runtime, prefix string) []string {
	args := []string{"find"}
	if runtime != nil {
		if target := strings.TrimSpace(runtime.Target); target != "" {
			args = append(args, "-dc-ip", target)
		}
		if identity := bindIdentity(runtime); identity != "" {
			args = append(args, "-u", identity)
		}
		if runtime.Password != "" {
			args = append(args, "-p", runtime.Password)
		}
	}
	args = append(args, "-stdout")
	args = append(args, m.definition.Options...)
	args = append(args, "-ldap-scheme", ldapScheme, "-ldap-port", ldapPort, "-json", "-text", "-output", prefix)
	return args
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
	return strings.Join(append([]string{toolName, "find"}, redactArguments(m.CommandArgs(runtime))[1:]...), " ")
}

// Run is only reached when Check has passed. Reports are written into a per-run
// directory, and the accepted native credential travels on the command line,
// which the runner redacts from every display and log.
func (m Module) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	path, err := executable(ctx)
	if err != nil {
		return err
	}
	if err := m.verifyADCS(ctx, path); err != nil {
		return err
	}
	started := time.Now()
	runDirectory := m.RunArtifactDirectory(runtime, started)
	if err := os.MkdirAll(runDirectory, 0750); err != nil {
		return fmt.Errorf("create Certipy artifact directory: %w", err)
	}
	command := process.Command(ctx, path, m.commandArgs(runtime, m.artifactPrefix(runtime, started))...)
	command.Dir = runDirectory
	command.Stdout, command.Stderr = sink, sink
	if err := process.Wait(ctx, command); err != nil {
		return fmt.Errorf("Certipy %s failed after %s: %w", m.definition.SlugValue, time.Since(started).Round(time.Millisecond), err)
	}
	return nil
}
