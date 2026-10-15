package sccm

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/dependencies"
	"github.com/pwnflow/pwnflow/internal/modules"
)

// commandProbe are the subcommands and options the installed CLI has to document.
// They are matched against the tool's own help output, so a version that renames or
// drops one is reported instead of producing a different command than advertised.
var commandProbe = []string{"find", "show", "-u", "-p", "-d", "-dc-ip", "-ldaps"}

// SCCMHunter discovers SCCM infrastructure through Active Directory.
type SCCMHunter struct {
	// Resolver is the name service used to turn discovered host names into the
	// addresses PXEThief can be pointed at. Tests supply a resolver so discovery
	// never touches a network.
	Resolver Resolver
}

func (SCCMHunter) ID() string                     { return moduleIDSCCMHunter }
func (SCCMHunter) Name() string                   { return "SCCMhunter" }
func (SCCMHunter) ToolFamily() modules.ToolFamily { return modules.ToolFamilySCCM }
func (SCCMHunter) Category() modules.Category     { return modules.CategoryEnumeration }
func (SCCMHunter) Tool() string                   { return "SCCMhunter" }
func (SCCMHunter) Protocol() modules.Protocol     { return modules.ProtocolNA }
func (SCCMHunter) Description() string {
	return "Discovers SCCM/MECM site systems through Active Directory with SCCMhunter's read-only find and show -all " +
		"workflow over LDAPS, then records the discovered systems, their SCCM role, and their addresses as this " +
		"assessment's endpoint list."
}
func (SCCMHunter) Prerequisites() []string {
	return []string{"SCCMhunter source checkout with its own virtual environment"}
}
func (SCCMHunter) RequiredPrivileges() []string     { return nil }
func (SCCMHunter) OutputFile() string               { return sccmHunterLog }
func (SCCMHunter) Sensitivity() modules.Sensitivity { return modules.SensitivitySensitive }
func (SCCMHunter) ReadOnly() bool                   { return true }
func (SCCMHunter) DependencyKey() string            { return string(dependencies.SCCMHunter) }

// SecondaryConnections states the scope plainly: the discovery itself is LDAP
// against the configured domain controller, while turning discovered names into
// addresses uses the host resolver.
func (SCCMHunter) SecondaryConnections() []string {
	return []string{"LDAP over LDAPS against the configured domain controller; discovered site-system names are resolved through the host resolver to addresses"}
}

// CommandArgs returns the pinned discovery command. The domain, DC, and credentials
// come from the operator-supplied runtime, and LDAPS is requested explicitly, which
// the installed CLI documents as -ldaps.
func (SCCMHunter) CommandArgs(runtime *modules.Runtime) []string {
	args := []string{"find"}
	if runtime != nil {
		if username := strings.TrimSpace(runtime.Username); username != "" {
			args = append(args, "-u", username)
		}
		if runtime.Password != "" {
			args = append(args, "-p", runtime.Password)
		}
		if domain := strings.TrimSpace(runtime.Domain); domain != "" {
			args = append(args, "-d", domain)
		}
		if target := strings.TrimSpace(runtime.Target); target != "" {
			args = append(args, "-dc-ip", target)
		}
	}
	return append(args, "-ldaps")
}

func (SCCMHunter) showArgs() []string { return []string{"show", "-all"} }

func (SCCMHunter) CommandPreview(runtime *modules.Runtime) string {
	return strings.Join(append([]string{"sccmhunter.py"}, redactArguments(SCCMHunter{}.CommandArgs(runtime))...), " ")
}

// DiscoveryDirectory is the stable parent of this assessment's discovery runs.
func (SCCMHunter) DiscoveryDirectory(runtime *modules.Runtime) string {
	return filepath.Join(outputDirectory(runtime, sccmHunterFolder), "artifacts")
}

// RunDirectory scopes one discovery run, including the isolated home that holds the
// tool's database, so a run never reads an earlier assessment's results.
func (SCCMHunter) RunDirectory(runtime *modules.Runtime, started time.Time) string {
	return artifactDirectory(runtime, sccmHunterFolder, started)
}

// DetailLines reports the configuration for Module Information.
func (m SCCMHunter) DetailLines(runtime *modules.Runtime) []string {
	target, domain := "-", "-"
	if runtime != nil {
		target, domain = runtime.Target, runtime.Domain
	}
	dependencyLine := dependencyLine(context.Background(), dependencies.SCCMHunter, "SCCMhunter", "./install.sh --with-sccmhunter")
	total, usable, detail := endpointCounts(context.Background(), runtime)
	return []string{
		"Execution: enabled",
		dependencyLine,
		"Authentication: native AD credentials (-u/-p; accepted for this single-operator lab, redacted in previews, logs, and history)",
		"Collection method: find then show -all over LDAPS (-ldaps)",
		fmt.Sprintf("Domain controller: %s (domain %s)", target, domain),
		fmt.Sprintf("Discovered endpoints: %d stored, %d with a usable address%s", total, usable, describeRoles(detail)),
		"Discovery output directory: " + outputDirectory(runtime, sccmHunterFolder),
		"Network scope: LDAP against the configured domain controller; the endpoint list is not a network boundary",
	}
}

func describeRoles(detail string) string {
	if detail == "" {
		return ""
	}
	return " (" + detail + ")"
}

// Check verifies the dependency and that the installed CLI documents the workflow
// this module runs.
func (m SCCMHunter) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil || strings.TrimSpace(runtime.Target) == "" || strings.TrimSpace(runtime.Domain) == "" {
		return fmt.Errorf("runtime target and domain are required")
	}
	status, err := dependency(ctx, dependencies.SCCMHunter)
	if err != nil {
		return err
	}
	program, base, err := interpreterCommand(status)
	if err != nil {
		return err
	}
	help, probeErr := runCombined(ctx, program, append(append([]string(nil), base...), "--help"), status.Root)
	if probeErr != nil {
		return fmt.Errorf("SCCMhunter capability probe failed: %w", probeErr)
	}
	for _, required := range commandProbe {
		if !bytes.Contains(help, []byte(required)) {
			return fmt.Errorf("SCCMhunter option %s is unsupported by the installed version", required)
		}
	}
	return nil
}

// Run performs discovery, then reads the structured result the tool stored and
// records it as this assessment's endpoint list.
func (m SCCMHunter) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	if runtime == nil {
		return fmt.Errorf("runtime configuration is required")
	}
	status, err := dependency(ctx, dependencies.SCCMHunter)
	if err != nil {
		return err
	}
	program, base, err := interpreterCommand(status)
	if err != nil {
		return err
	}
	started := time.Now()
	runDirectory := m.RunDirectory(runtime, started)
	if err := prepareDirectory(runDirectory); err != nil {
		return fmt.Errorf("create SCCMhunter run directory: %w", err)
	}
	// The tool writes $HOME/.sccmhunter/logs/db/find.db with no option to redirect
	// it, so the run gets its own home: discovery can then never read an earlier
	// assessment's database.
	home := filepath.Join(runDirectory, discoveryHomeDirectory)
	if err := prepareDirectory(home); err != nil {
		return fmt.Errorf("create SCCMhunter data directory: %w", err)
	}

	output := newRedactingSink(sink)
	defer output.Flush()
	if err := runCommand(ctx, program, append(append([]string(nil), base...), m.CommandArgs(runtime)...), runDirectory, home, output); err != nil {
		// A non-zero exit is a discovery failure, which is not the same as a
		// successful discovery with no results.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("SCCMhunter find failed after %s: %w", time.Since(started).Round(time.Millisecond), err)
	}

	showOutput, showErr := runCaptured(ctx, program, append(append([]string(nil), base...), m.showArgs()...), runDirectory, home)
	if showErr != nil {
		return fmt.Errorf("SCCMhunter show -all failed: %w", showErr)
	}
	if _, err := output.Write(showOutput); err != nil {
		return err
	}
	showPath := filepath.Join(runDirectory, discoveryShowFile)
	if err := writeRedactedFile(showPath, showOutput, runtime.Password); err != nil {
		return fmt.Errorf("store SCCMhunter output: %w", err)
	}

	databasePath := filepath.Join(home, discoveryDBRelative)
	records, databaseErr := readDiscoveryDatabase(databasePath)
	source := "sccmhunter find (database)"
	if databaseErr != nil {
		// The database is the primary, structured source. The tool's own table
		// output is parsed as a fallback so a schema change does not lose the
		// discovery, and the operator is told which source was used.
		records = parseDiscoveryTables(string(showOutput))
		source = "sccmhunter show -all (table output; " + databaseErr.Error() + ")"
		fmt.Fprintf(output, "[i] SCCMhunter database not read (%v); parsed the show -all tables instead.\n", databaseErr)
	}
	records = dedupeRecords(records)
	endpoints := discoveryEndpoints(ctx, m.Resolver, records, runtime.Domain, source, started.UTC())
	if runtime.Endpoints == nil {
		return fmt.Errorf("no assessment discovery store is available; discovered endpoints were not persisted")
	}
	if err := runtime.Endpoints.RecordEndpoints(ctx, endpoints); err != nil {
		return fmt.Errorf("store discovered endpoints: %w", err)
	}
	withAddress := 0
	for _, endpoint := range endpoints {
		if endpoint.Address != "" {
			withAddress++
		}
	}
	fmt.Fprintf(output, "[i] SCCMhunter discovery recorded %d endpoint record(s); %d have an address PXEThief can use.\n", len(endpoints), withAddress)
	if withAddress == 0 {
		fmt.Fprintln(output, "[i] No usable address was discovered. PXEThief will use its explicitly requested mode 1 if you run it.")
	}
	return nil
}

// dedupeRecords removes repeated host name/Role pairs so the endpoint list reflects
// distinct systems.
func dedupeRecords(records []discoveredRecord) []discoveredRecord {
	seen := make(map[string]bool, len(records))
	unique := make([]discoveredRecord, 0, len(records))
	for _, record := range records {
		key := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(record.Hostname), ".")) + "|" + record.Role
		if seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, record)
	}
	return unique
}

// writeRedactedFile writes tool output to an artifact with the password and any
// secret-labelled value removed.
func writeRedactedFile(path string, contents []byte, secrets ...string) error {
	log, err := newArtifactLog(path, secrets...)
	if err != nil {
		return err
	}
	if _, err := log.Write(contents); err != nil {
		log.Close()
		return err
	}
	return log.Close()
}

// runCombined runs a tool and returns its combined output.
func runCombined(ctx context.Context, program string, args []string, directory string) ([]byte, error) {
	command := commandContext(ctx, program, args, directory)
	return command.CombinedOutput()
}

// runCaptured runs a tool with an isolated home and returns its combined output.
func runCaptured(ctx context.Context, program string, args []string, directory, home string) ([]byte, error) {
	command := commandContext(ctx, program, args, directory)
	command.Env = runEnvironment(home)
	return command.CombinedOutput()
}
