// Package relayking integrates RelayKing, the NTLM and Kerberos relay exposure
// assessment tool.
//
// Upstream: https://github.com/depthsecurity/RelayKing-Depth (Depth Security).
// PwnFlow drives the installed checkout; it does not vendor or redistribute it.
//
// Two registrations cover the two ways the tool is meant to be used:
//
//   - Relay Exposure Assessment (Targeted) applies the full detection profile -
//     protocol checks, port pre-scan, the domain NTLMv1 policy check and the relay
//     target list - to the single host the operator configured, in RelayKing's
//     single-target mode.
//   - Relay Exposure Audit (Full Domain) is the same profile with --audit, which
//     enumerates the computers of the domain and assesses each one. That is a
//     domain-wide active scan, so it is held for an explicit approval before a
//     batch starts and it is never launched by a global run on its own.
//
// The coercion options are deliberately not registered. --coerce and --coerce-all
// trigger authentication from the target to a listener the operator would have to
// run; that is an attack, not an exposure assessment, and it belongs to an
// engagement step with its own authorization. --ntlmv1-all is likewise excluded:
// it reads each host's registry with administrative rights, which the domain-wide
// policy check (--ntlmv1) does not need.
package relayking

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/dependencies"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/process"
)

const (
	script = "relayking.py"

	outputFolder  = "Enumeration/RelayKing"
	artifactRel   = "Enumeration/RelayKing/artifacts"
	runTimeLayout = "20060102-150405"

	redactedValue = "[REDACTED]"

	// defaultProtocols is the set RelayKing documents for a full relay assessment.
	// The protocols upstream still marks as work in progress - smtp, imap, winrm -
	// are not requested.
	defaultProtocols = "smb,ldap,ldaps,mssql,http,https"
)

// requiredOptions are the upstream options both registrations build. They are
// matched against the installed checkout's own help, so a revision that renames or
// drops one is reported instead of producing a different command.
var requiredOptions = []string{"--protocols", "--dc-ip", "--output-file", "--proto-portscan", "--ntlmv1", "--gen-relay-list", "--threads", "-o", "--audit"}

type Definition struct {
	IDValue          string
	NameValue        string
	DescriptionValue string
	SlugValue        string
	CategoryValue    modules.Category
}

type Module struct{ definition Definition }

// EnumerationModules returns the RelayKing registrations under Network →
// Enumeration: the targeted assessment first, because it is what an assessment
// starts with, then the domain-wide audit.
func EnumerationModules() []Module {
	return []Module{
		{definition: Definition{
			IDValue:   "relayking-target-assessment",
			NameValue: "Relay Exposure Assessment (Targeted)",
			SlugValue: "target",
			// Security Auditing: relay exposure is an authentication and signing
			// configuration finding about the host.
			CategoryValue: modules.CategorySecurityAuditing,
			DescriptionValue: "Assesses NTLM and Kerberos relay exposure on the configured target with RelayKing: SMB and LDAP signing, " +
				"LDAPS channel binding, HTTP/HTTPS authentication protection, MSSQL relay-related settings, and the domain NTLMv1 policy. " +
				"Operates on the single host the operator configured, enumerates nothing from the directory beyond what the checks need, " +
				"and writes both plaintext and JSON reports plus the relay target list into this run's artifact directory.",
		}},
		{definition: Definition{
			IDValue:       "relayking-domain-audit",
			NameValue:     "Relay Exposure Audit (Full Domain)",
			SlugValue:     "audit",
			CategoryValue: modules.CategorySecurityAuditing,
			DescriptionValue: "Runs RelayKing's audit profile: it enumerates the computers of the domain with the operator's low-privilege " +
				"credentials and assesses each one for relay exposure, with the port pre-scan, the domain NTLMv1 policy check and the relay " +
				"target list. This contacts every computer RelayKing discovers, which is a domain-wide active scan, so PwnFlow asks for " +
				"approval before the batch starts and a global run never begins it on its own. Coercion is not part of this profile.",
		}},
	}
}

func (m Module) ID() string                       { return m.definition.IDValue }
func (m Module) Name() string                     { return m.definition.NameValue }
func (m Module) ToolFamily() modules.ToolFamily   { return modules.ToolFamilyNetwork }
func (m Module) Category() modules.Category       { return m.definition.CategoryValue }
func (m Module) Tool() string                     { return "RelayKing" }
func (m Module) Protocol() modules.Protocol       { return modules.ProtocolNA }
func (m Module) Description() string              { return m.definition.DescriptionValue }
func (m Module) Sensitivity() modules.Sensitivity { return modules.SensitivityStandard }
func (m Module) ReadOnly() bool                   { return true }
func (m Module) RequiredPrivileges() []string     { return nil }
func (m Module) DependencyKey() string            { return string(dependencies.RelayKing) }

func (m Module) Prerequisites() []string {
	return []string{"RelayKing checkout with its own virtual environment (install.sh)", "low-privilege domain credentials"}
}

func (m Module) OutputFile() string {
	return filepath.Join(outputFolder, m.definition.SlugValue+".log")
}

// audit reports whether this registration is the domain-wide audit.
func (m Module) audit() bool { return m.definition.SlugValue == "audit" }

// SecondaryConnections states what the registration reaches, so the difference
// between the two is explicit rather than implied.
func (m Module) SecondaryConnections() []string {
	if m.audit() {
		return []string{
			"enumerates the domain's computer objects through the configured domain controller",
			"contacts every computer it enumerates for protocol checks",
			"scans only the ports of the selected protocols (--proto-portscan), not every port",
		}
	}
	return []string{
		"contacts only the configured target",
		"reads the domain NTLMv1 policy through the configured domain controller",
	}
}

// PlanApproval implements modules.ApprovalRequester. A domain-wide audit is not
// something a global run may start on its own; the targeted assessment runs on the
// host the operator already named, so it needs no extra question.
func (m Module) PlanApproval(runtime *modules.Runtime) (bool, string) {
	if !m.audit() {
		return false, ""
	}
	return true, "enumerates the domain's computers and contacts each one for relay-exposure checks"
}

// DetailLines implements modules.DetailProvider: the pinned profile, the protocol
// list, and the operations this registration deliberately does not perform.
func (m Module) DetailLines(runtime *modules.Runtime) []string {
	lines := []string{"Transport: RelayKing over the installed checkout (no shell)"}
	if m.audit() {
		lines = append(lines, "Mode: --audit (enumerate the domain's computers, then assess each one)")
	} else {
		lines = append(lines, "Mode: single target ("+runtime.Target+"), no domain enumeration")
	}
	lines = append(lines,
		"Protocols: "+m.protocols(runtime),
		"Threads: "+m.value(runtime, "THREADS", "10")+", port pre-scan enabled (--proto-portscan)",
		"Domain NTLMv1 policy: checked (--ntlmv1)",
		"Relay target list: written into this run's artifact directory",
		"Not requested: --coerce, --coerce-all, --ntlmv1-all, CIDR/range targets, target files",
	)
	return lines
}

func (m Module) value(runtime *modules.Runtime, key, fallback string) string {
	if value, ok := runtime.ModuleOption(m.ID(), key); ok {
		return value
	}
	return fallback
}

func (m Module) protocols(runtime *modules.Runtime) string {
	return m.value(runtime, "PROTOCOLS", defaultProtocols)
}

// status resolves the installed checkout.
func status(ctx context.Context) dependencies.Status {
	return dependencies.DefaultRegistry().CheckOne(ctx, dependencies.RelayKing)
}

// command resolves how the tool is invoked: the checkout's own interpreter, run
// against the entry script by path.
func command(found dependencies.Status) (string, []string, error) {
	if found.Interpreter != "" && found.Script != "" {
		return found.Interpreter, []string{found.Script}, nil
	}
	if found.FoundExecutable != "" {
		return found.FoundExecutable, nil, nil
	}
	return "", nil, fmt.Errorf("%s: installed location could not be resolved", found.DisplayName)
}

// Check validates the registration against the installed checkout and the runtime
// configuration before anything runs.
func (m Module) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil || strings.TrimSpace(runtime.Target) == "" {
		return fmt.Errorf("runtime target is required")
	}
	if strings.TrimSpace(runtime.Username) == "" || strings.TrimSpace(runtime.Password) == "" {
		return fmt.Errorf("RelayKing authenticates with the operator's credentials; a username and password are required")
	}
	if m.audit() && strings.TrimSpace(runtime.Domain) == "" {
		return fmt.Errorf("the domain-wide audit needs the domain and the domain controller address")
	}
	found := status(ctx)
	if !found.Available {
		return fmt.Errorf("%s: %s", found.DisplayName, found.Detail)
	}
	help, err := installedHelp(ctx, found)
	if err != nil {
		return err
	}
	for _, option := range requiredOptions {
		if !strings.Contains(help, option) {
			return fmt.Errorf("the installed RelayKing does not document %s, which this registration uses", option)
		}
	}
	for _, protocol := range strings.Split(m.protocols(runtime), ",") {
		protocol = strings.TrimSpace(protocol)
		switch protocol {
		case "smb", "http", "https", "ldap", "ldaps", "mssql", "rpc":
		case "smtp", "imap", "imaps", "winrm", "winrms":
			// Upstream marks these as work in progress. PwnFlow does not present
			// them as supported checks, so it does not run them either.
			return fmt.Errorf("%s is marked work in progress upstream and is not assessed here", protocol)
		default:
			return fmt.Errorf("%s is not a protocol the installed RelayKing documents", protocol)
		}
	}
	if _, err := strconv.Atoi(m.value(runtime, "THREADS", "10")); err != nil {
		return fmt.Errorf("THREADS must be a number")
	}
	return nil
}

// installedHelp reads the checkout's usage text. RelayKing prints its usage and
// then exits non-zero, so the text is what is checked.
func installedHelp(ctx context.Context, found dependencies.Status) (string, error) {
	program, base, err := command(found)
	if err != nil {
		return "", err
	}
	probeContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	output, _ := exec.CommandContext(probeContext, program, append(base, "-h")...).CombinedOutput()
	if len(output) == 0 {
		return "", fmt.Errorf("%s did not produce usage output", found.DisplayName)
	}
	return string(output), nil
}

// RunArtifactDirectory is this run's directory: one per run, so reports and relay
// lists from earlier runs are never overwritten.
func (m Module) RunArtifactDirectory(runtime *modules.Runtime, started time.Time) string {
	return filepath.Join(runtime.ResultsRoot, artifactRel, m.definition.SlugValue+"-"+started.Format(runTimeLayout))
}

// CommandArgs builds the argument vector, which is also what the preview shows.
func (m Module) CommandArgs(runtime *modules.Runtime) []string {
	return m.commandArgs(runtime, m.RunArtifactDirectory(runtime, time.Now()))
}

// commandArgs is the profile the operator asked for: authentication, the selected
// protocols, the port pre-scan, the domain NTLMv1 policy check, the relay target
// list, both output formats, and the target mode of this registration.
func (m Module) commandArgs(runtime *modules.Runtime, runDirectory string) []string {
	args := []string{
		"-u", runtime.Username,
		"-p", runtime.Password,
		"-d", runtime.Domain,
		"--dc-ip", runtime.Target,
		"-vv",
		"--protocols", m.protocols(runtime),
		"--threads", m.value(runtime, "THREADS", "10"),
		"-o", "plaintext,json",
		"--output-file", filepath.Join(runDirectory, "relayking-scan"),
		"--proto-portscan",
		"--ntlmv1",
		"--gen-relay-list", filepath.Join(runDirectory, "relaytargets.txt"),
	}
	if m.audit() {
		args = append(args, "--audit")
		return args
	}
	// Single-target mode: the host the operator configured, named at the end.
	return append(args, runtime.Target)
}

// CommandPreview implements modules.CommandPreviewProvider: the credential is never
// part of a preview.
func (m Module) CommandPreview(runtime *modules.Runtime) string {
	args := m.CommandArgs(runtime)
	for index := range args {
		if index > 0 && args[index-1] == "-p" {
			args[index] = redactedValue
		}
	}
	return "relayking.py " + strings.Join(args, " ")
}

// Run executes the assessment in its own per-run directory and tightens what the
// tool leaves behind.
func (m Module) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	found := status(ctx)
	if !found.Available {
		return fmt.Errorf("%s: %s", found.DisplayName, found.Detail)
	}
	program, base, err := command(found)
	if err != nil {
		return err
	}
	started := time.Now()
	runDirectory := m.RunArtifactDirectory(runtime, started)
	if err := os.MkdirAll(runDirectory, 0750); err != nil {
		return fmt.Errorf("create RelayKing run directory: %w", err)
	}
	fmt.Fprintf(sink, "[i] RelayKing %s: writing reports and the relay target list into %s\n", m.definition.SlugValue, runDirectory)
	args := append(append([]string(nil), base...), m.commandArgs(runtime, runDirectory)...)
	command := process.Command(ctx, program, args...)
	command.Dir = runDirectory
	command.Stdout, command.Stderr = sink, sink
	command.WaitDelay = 2 * time.Second
	runErr := process.Wait(ctx, command)
	// The reports name relayable hosts, so they are assessment data: whatever the
	// tool left behind is restricted to the owner, on the failure path too.
	if err := hardenRunDirectory(runDirectory); err != nil {
		fmt.Fprintf(sink, "[i] RelayKing artifacts could not be restricted to your account: %v\n", err)
	}
	if runErr != nil {
		return fmt.Errorf("RelayKing %s failed after %s: %w", m.definition.SlugValue, time.Since(started).Round(time.Millisecond), runErr)
	}
	return nil
}

// hardenRunDirectory makes one run's artifacts owner-only: directories 0750, files
// 0600.
func hardenRunDirectory(directory string) error {
	return filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o750)
		}
		return os.Chmod(path, 0o600)
	})
}
