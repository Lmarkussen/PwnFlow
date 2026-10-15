package sccm

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/dependencies"
	"github.com/pwnflow/pwnflow/internal/modules"
)

// pxeThiefMarker is the file install.sh writes after it has verified that the
// checkout is the required PR #11 revision. Its contents are the verified commit.
const pxeThiefMarker = ".pwnflow-pr11"

// PXEThief operates against the PXE endpoints this assessment discovered.
type PXEThief struct{}

func (PXEThief) ID() string                     { return moduleIDPXEThief }
func (PXEThief) Name() string                   { return "PXEThief" }
func (PXEThief) ToolFamily() modules.ToolFamily { return modules.ToolFamilySCCM }
func (PXEThief) Category() modules.Category     { return modules.CategoryEnumeration }
func (PXEThief) Tool() string                   { return "PXEThief" }
func (PXEThief) Protocol() modules.Protocol     { return modules.ProtocolNA }
func (PXEThief) Description() string {
	return "Runs PXEThief against this assessment's discovered SCCM endpoints: mode 1 (DHCP PXE broadcast discovery) " +
		"when nothing has been discovered, and one mode 2 invocation per stored endpoint address otherwise. " +
		"PXEThief crafts raw DHCP packets, so it needs raw-socket privileges, and it follows the operator's own " +
		"settings.ini, including its automatic blank-password exploitation setting."
}
func (PXEThief) Prerequisites() []string {
	return []string{"PXEThief source checkout at pull/11 with its own virtual environment"}
}
func (PXEThief) RequiredPrivileges() []string {
	return []string{"raw-socket privileges for DHCP packet crafting (PXEThief's own requirement)"}
}
func (PXEThief) OutputFile() string               { return pxeThiefLog }
func (PXEThief) Sensitivity() modules.Sensitivity { return modules.SensitivitySensitive }
func (PXEThief) ReadOnly() bool                   { return false }
func (PXEThief) DependencyKey() string            { return string(dependencies.PXEThief) }

// BatchPrerequisites makes the discovery dependency explicit: a batch that selects
// both SCCM modules runs SCCMhunter first, so PXEThief reads the endpoints of the
// current run rather than whatever was stored before it.
func (PXEThief) BatchPrerequisites() []string { return []string{moduleIDSCCMHunter} }

// SecondaryConnections states what the tool may contact, so the operator knows what
// an explicitly requested run can reach.
func (PXEThief) SecondaryConnections() []string {
	return []string{
		"mode 1 broadcasts a DHCP discover on the local segment and follows the PXE server it finds",
		"mode 2 contacts one stored endpoint address directly",
	}
}

// ArtifactDirectory is the stable parent of this assessment's PXEThief runs.
func (PXEThief) ArtifactDirectory(runtime *modules.Runtime) string {
	return filepath.Join(outputDirectory(runtime, pxeThiefFolder), "artifacts")
}

// RunDirectory scopes one execution, with one directory per endpoint inside it.
func (PXEThief) RunDirectory(runtime *modules.Runtime, started time.Time) string {
	return artifactDirectory(runtime, pxeThiefFolder, started)
}

// CommandArgs summarises the invocation for one planned target. PXEThief takes a
// single target per invocation, so a run with endpoints issues one command per
// endpoint; the preview names the first and how many follow.
func (m PXEThief) CommandArgs(endpoints []modules.Endpoint) []string {
	if len(endpoints) == 0 {
		return []string{"1"}
	}
	return []string{"2", endpoints[0].Address}
}

func (m PXEThief) CommandPreview(runtime *modules.Runtime) string {
	endpoints, err := m.plannedEndpoints(context.Background(), runtime)
	if err != nil || len(endpoints) == 0 {
		return "pxethief.py 1   (no stored endpoints: DHCP PXE broadcast discovery)"
	}
	preview := "pxethief.py 2 " + endpoints[0].Address
	if len(endpoints) > 1 {
		preview += fmt.Sprintf("   (+%d more endpoint(s), one invocation each)", len(endpoints)-1)
	}
	return preview
}

// plannedEndpoints reads the assessment's endpoint list at run time. Nothing is
// prepared in advance, which is what makes a batch see SCCMhunter's fresh results.
func (m PXEThief) plannedEndpoints(ctx context.Context, runtime *modules.Runtime) ([]modules.Endpoint, error) {
	stored, err := discoveredEndpoints(ctx, runtime)
	if err != nil {
		return nil, err
	}
	domain := ""
	if runtime != nil {
		domain = runtime.Domain
	}
	return usableEndpoints(stored, domain), nil
}

// DetailLines reports the dependency, the stored endpoint count, the mode this run
// would use, and where per-endpoint output goes.
func (m PXEThief) DetailLines(runtime *modules.Runtime) []string {
	ctx := context.Background()
	endpoints, endpointErr := m.plannedEndpoints(ctx, runtime)
	total, _, roles := endpointCounts(ctx, runtime)
	mode := "mode 1 (DHCP PXE broadcast discovery): no stored endpoint address for this assessment"
	if len(endpoints) > 0 {
		mode = fmt.Sprintf("mode 2: one invocation per stored endpoint address (%d planned)", len(endpoints))
	}
	if endpointErr != nil {
		mode = "endpoint list unreadable: " + endpointErr.Error()
	}
	lines := []string{
		"Execution: enabled",
		dependencyLine(ctx, dependencies.PXEThief, "PXEThief", "./install.sh --with-pxethief"),
		prerequisiteLine(ctx),
		fmt.Sprintf("Stored endpoints: %d recorded, %d usable%s", total, len(endpoints), describeRoles(roles)),
		"Planned mode: " + mode,
		"Artifacts: " + filepath.Join(m.ArtifactDirectory(runtime), "<run>/<endpoint>"),
		"Settings: the operator's settings.ini is copied into each endpoint directory; PXEThief's automatic blank-password exploitation is controlled there",
		scopeNote,
	}
	return lines
}

// scopeNote states what the endpoint list is and is not.
const scopeNote = "Network scope: only endpoints discovered for this assessment domain are used; the list is not a network boundary"

// prerequisiteLine reports whether the checkout is the required PR #11 revision.
func prerequisiteLine(ctx context.Context) string {
	status, err := dependency(ctx, dependencies.PXEThief)
	if err != nil {
		return "Required revision: not verified - PXEThief is not installed"
	}
	if status.Root == "" {
		return "Required revision: not verified - PXEThief location is not a managed checkout"
	}
	verified, err := verifyPullRequest(ctx, status.Root)
	if err != nil {
		return "Required revision: not verified - " + err.Error()
	}
	return "Required revision: pull/11 verified (" + verified + ")"
}

// Check verifies the dependency, the required revision, and the runtime scope.
func (m PXEThief) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil || strings.TrimSpace(runtime.Domain) == "" {
		return fmt.Errorf("runtime domain is required")
	}
	status, err := dependency(ctx, dependencies.PXEThief)
	if err != nil {
		return err
	}
	if status.Root == "" {
		return fmt.Errorf("PXEThief must be installed by ./install.sh --with-pxethief so its revision can be verified")
	}
	verified, err := verifyPullRequest(ctx, status.Root)
	if err != nil {
		return fmt.Errorf("PXEThief checkout is not the required pull/11 revision: %w", err)
	}
	program, base, err := interpreterCommand(status)
	if err != nil {
		return err
	}
	if _, probeErr := runCombined(ctx, program, append(append([]string(nil), base...), "-h"), status.Root); probeErr != nil {
		return fmt.Errorf("PXEThief capability probe failed: %w", probeErr)
	}
	_ = verified
	return nil
}

// Run executes mode 1 or one mode 2 invocation per stored endpoint address. Each
// invocation gets its own directory, its own redacted log, and its own status; a
// failure is reported per endpoint without stopping the remaining endpoints, and
// cancellation stops the run immediately.
func (m PXEThief) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	if runtime == nil {
		return fmt.Errorf("runtime configuration is required")
	}
	status, err := dependency(ctx, dependencies.PXEThief)
	if err != nil {
		return err
	}
	program, base, err := interpreterCommand(status)
	if err != nil {
		return err
	}
	endpoints, err := m.plannedEndpoints(ctx, runtime)
	if err != nil {
		return err
	}
	started := time.Now()
	runDirectory := m.RunDirectory(runtime, started)
	if err := prepareDirectory(runDirectory); err != nil {
		return fmt.Errorf("create PXEThief run directory: %w", err)
	}
	output := newRedactingSink(sink)
	defer output.Flush()
	if len(endpoints) == 0 {
		fmt.Fprintln(output, "[i] No stored endpoint address for this assessment: running PXEThief mode 1 (DHCP PXE broadcast discovery) as explicitly requested.")
		if err := m.runOne(ctx, program, base, []string{"1"}, runDirectory, "mode-1", status.Root, runtime.Password, output); err != nil {
			return err
		}
		return nil
	}
	fmt.Fprintf(output, "[i] Running PXEThief mode 2 against %d stored endpoint(s), one invocation each.\n", len(endpoints))
	failures := make([]string, 0)
	for _, endpoint := range endpoints {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		directory := filepath.Join(runDirectory, filepath.Base(endpoint.Address))
		fmt.Fprintf(output, "[i] %s (%s): PXEThief mode 2\n", endpoint.Address, endpoint.Role)
		if err := m.runOne(ctx, program, base, []string{"2", endpoint.Address}, directory, endpoint.Address, status.Root, runtime.Password, output); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			failures = append(failures, fmt.Sprintf("%s (%s): %v", endpoint.Address, endpoint.Role, err))
			continue
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("PXEThief failed for %d of %d endpoint(s): %s", len(failures), len(endpoints), strings.Join(failures, "; "))
	}
	return nil
}

// runOne executes one PXEThief invocation in its own directory, with the operator's
// settings copied in so the tool's own outputs land next to its artifacts.
func (m PXEThief) runOne(ctx context.Context, program string, base, args []string, directory, label, installRoot string, password string, sink modules.OutputSink) error {
	if err := prepareDirectory(directory); err != nil {
		return fmt.Errorf("create %s directory: %w", label, err)
	}
	if err := copySettings(installRoot, directory); err != nil {
		return err
	}
	log, err := newArtifactLog(filepath.Join(directory, "pxethief.log"), password)
	if err != nil {
		return fmt.Errorf("create %s log: %w", label, err)
	}
	defer log.Close()
	started := time.Now()
	err = runCommand(ctx, program, append(append([]string(nil), base...), args...), directory, "", multiSink{sink, log})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%s failed after %s: %w", label, time.Since(started).Round(time.Millisecond), err)
	}
	return nil
}

// copySettings puts a copy of the tool's settings.ini in the run directory.
// PXEThief reads its configuration from the working directory, and copying it keeps
// the tool's own outputs inside the assessment hierarchy without editing the
// operator's file.
func copySettings(installRoot, directory string) error {
	if installRoot == "" {
		return nil
	}
	settings := filepath.Join(installRoot, "settings.ini")
	contents, err := os.ReadFile(settings)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("PXEThief settings.ini is missing from %s; restore it before running", installRoot)
		}
		return err
	}
	if err := os.WriteFile(filepath.Join(directory, "settings.ini"), contents, 0600); err != nil {
		return err
	}
	return nil
}

// verifyPullRequest confirms the checkout is the required pull/11 revision. The
// installer records the verified commit after the fetch, and the marker is checked
// against the checkout's current HEAD so a later branch switch is caught.
func verifyPullRequest(ctx context.Context, root string) (string, error) {
	marker := filepath.Join(root, pxeThiefMarker)
	recorded, err := os.ReadFile(marker)
	if err != nil {
		return "", fmt.Errorf("re-run ./install.sh --with-pxethief to fetch and verify pull/11 (%s is missing)", pxeThiefMarker)
	}
	commit := strings.TrimSpace(strings.SplitN(string(recorded), "\n", 2)[0])
	if commit == "" {
		return "", fmt.Errorf("the recorded pull/11 revision is empty; re-run ./install.sh --with-pxethief")
	}
	head, err := gitOutput(ctx, root, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(head, commit) {
		return "", fmt.Errorf("the checkout is at %s, not the verified pull/11 revision %s; re-run ./install.sh --with-pxethief", head, commit)
	}
	return commit, nil
}

// gitOutput runs one read-only git query inside a checkout.
func gitOutput(ctx context.Context, root string, args ...string) (string, error) {
	command := commandContext(ctx, "git", append([]string{"-C", root}, args...), root)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("git %s failed: %s", strings.Join(args, " "), message)
	}
	return strings.TrimSpace(stdout.String()), nil
}
