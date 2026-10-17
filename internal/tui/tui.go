package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/modules/certipy"
	"github.com/pwnflow/pwnflow/internal/modules/masscan"
	"github.com/pwnflow/pwnflow/internal/modules/netexec"
	"github.com/pwnflow/pwnflow/internal/modules/networkhound"
	"github.com/pwnflow/pwnflow/internal/modules/relayking"
	"github.com/pwnflow/pwnflow/internal/modules/rusthound"
	"github.com/pwnflow/pwnflow/internal/modules/sccm"
	"github.com/pwnflow/pwnflow/internal/modules/specialized"
	"github.com/pwnflow/pwnflow/internal/modules/trustinventory"
	"github.com/pwnflow/pwnflow/internal/runner"
	"github.com/pwnflow/pwnflow/internal/storage"
	"golang.org/x/term"
)

func Run(ctx context.Context, cfg config.Config, db *storage.DB, version string, dependencyReasons ...map[string]string) error {
	registry := buildRegistry()
	registered := registry.All()
	for _, warning := range modules.OptionWarnings(registered, cfg.ModuleOptions) {
		fmt.Fprintln(os.Stderr, "[!] module option: "+warning)
	}
	targetID, err := db.TargetID(ctx, cfg.Domain, cfg.Target)
	if err != nil {
		return err
	}
	moduleIDs := make([]int64, len(registered))
	for i, module := range registered {
		id, err := db.RegisterModule(ctx, module.Name(), module.Tool(), string(module.Protocol()), module.Description(), module.OutputFile())
		if err != nil {
			return err
		}
		moduleIDs[i] = id
	}
	model := newModel(ctx, cfg, db, registered, moduleIDs, targetID, version, dependencyReasons...)
	_, err = tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion(), tea.WithContext(ctx)).Run()
	if model.batch != nil {
		model.cancelBatch()
		waitContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = model.batch.Wait(waitContext)
		cancel()
	}
	return err
}

func buildRegistry() *modules.Registry {
	registry := &modules.Registry{}
	for _, module := range netexec.EnumerationModules() {
		registry.Register(module)
	}
	for _, module := range netexec.CredentialAuditingModules() {
		registry.Register(module)
	}
	// Credential access and escalation registrations are listed so their
	// requirements are visible, and they stay outside the Enumeration scope so a
	// category-wide run can never include them.
	for _, module := range netexec.CredentialDumpingModules() {
		registry.Register(module)
	}
	registry.Register(rusthound.Module{})
	registry.Register(trustinventory.Module{})
	for _, module := range certipy.EnumerationModules() {
		registry.Register(module)
	}
	// SCCMhunter is registered before PXEThief: a batch that selects both has to
	// discover before it probes, and PXEThief consumes whatever the assessment's
	// endpoint store holds when it runs.
	registry.Register(sccm.SCCMHunter{Resolver: sccm.SystemResolver{}})
	registry.Register(sccm.PXEThief{})
	// The network assessment tools sit under Network → Enumeration. NetworkHound's
	// directory collection is registered before its scoped validation, because the
	// collection is what an assessment starts with.
	for _, module := range networkhound.EnumerationModules() {
		registry.Register(module)
	}
	for _, module := range relayking.EnumerationModules() {
		registry.Register(module)
	}
	for _, module := range specialized.Modules() {
		registry.Register(module)
	}
	registry.Register(masscan.Module{})
	return registry
}

// RunAuto executes the same explicit Default Enumeration plan as Ctrl+A without
// constructing a Bubble Tea program. It intentionally reuses model.runBatch,
// model.syncBatch, and the established post-analysis exporters.
func RunAuto(ctx context.Context, cfg config.Config, db *storage.DB, version string, out io.Writer, dependencyReasons ...map[string]string) error {
	if out == nil {
		out = io.Discard
	}
	colors := newAutoTheme(out)
	fmt.Fprintln(out, colors.green(embeddedBanner))
	fmt.Fprintln(out, colors.cyan("PwnFlow — Automated Active Directory Assessment"))
	registry := buildRegistry()
	registered := registry.All()
	for _, warning := range modules.OptionWarnings(registered, cfg.ModuleOptions) {
		fmt.Fprintln(out, "[warning] module option: "+safeAutoText(warning))
	}
	targetID, err := db.TargetID(ctx, cfg.Domain, cfg.Target)
	if err != nil {
		return err
	}
	moduleIDs := make([]int64, len(registered))
	for i, module := range registered {
		id, err := db.RegisterModule(ctx, module.Name(), module.Tool(), string(module.Protocol()), module.Description(), module.OutputFile())
		if err != nil {
			return err
		}
		moduleIDs[i] = id
	}
	m := newModel(ctx, cfg, db, registered, moduleIDs, targetID, version, dependencyReasons...)
	defer func() {
		if m.findings != nil {
			m.findings.Close()
		}
	}()
	plan := m.globalPlan()
	approvals := append([]approval(nil), plan.approvals...)
	approvals = append(approvals, headlessElevationApprovals(m, plan.indices)...)
	if len(approvals) > 0 {
		for _, approval := range approvals {
			if approval.index < 0 || approval.index >= len(m.allModules) {
				continue
			}
			if _, requiresElevation := m.allModules[approval.index].(modules.ElevationRequester); !requiresElevation {
				continue
			}
			if err := headlessAuthorize(ctx, m, approval); err != nil {
				fmt.Fprintf(out, "%s\n", colors.yellow(fmt.Sprintf("Local privilege unavailable for %s: %s; the affected module will be recorded unavailable", safeAutoText(m.allModules[approval.index].ID()), safeAutoText(err.Error()))))
			}
		}
	}
	if len(plan.indices) == 0 {
		return fmt.Errorf("Default Enumeration has no available modules")
	}
	fmt.Fprintf(out, "\nTarget:       %s\nDomain:       %s\nMode:         Headless Default Enumeration\nModules:      %d\nScope CIDR:   %s\n", safeAutoText(cfg.Target), safeAutoText(cfg.Domain), len(plan.indices), safeAutoText(autoScope(cfg)))
	if len(plan.skipped) > 0 {
		fmt.Fprintf(out, "%s\n", colors.yellow(fmt.Sprintf("Modules skipped by the existing plan: %d", len(plan.skipped))))
	}
	for _, limitation := range plan.unavailable {
		fmt.Fprintf(out, "%s\n", colors.yellow("Module limitation: "+safeAutoText(limitation)))
	}
	fmt.Fprintln(out, colors.heading("ENUMERATION"))
	if cmd := m.runBatch(plan.indices, plan.name); cmd != nil {
		return fmt.Errorf("headless batch did not start")
	}
	if err := reportAutoProgress(ctx, out, m, colors); err != nil {
		if ctx.Err() != nil {
			_ = m.syncBatchError()
		}
		return err
	}
	if err := m.syncBatchError(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var findingsErr error
	if m.findings != nil {
		fmt.Fprintln(out, "Findings analysis ... running")
		findingsErr = m.findings.Wait(ctx)
		if findingsErr != nil {
			fmt.Fprintln(out, "Findings analysis ... failed (see saved analysis status)")
		} else {
			fmt.Fprintln(out, "Findings analysis ... completed")
		}
	}
	ids := uniqueInt64Values(m.batchExecutionIDs)
	generatedAt := time.Now().UTC()
	if err := writeFindingsSummary(ctx, db, cfg.ResultsRoot(), cfg.Domain, targetID, ids, generatedAt); err != nil {
		return fmt.Errorf("findings summary export: %w", err)
	}
	fmt.Fprintln(out, colors.green("✔ Findings summary generated"))
	if err := publishDefaultResults(ctx, db, cfg.ResultsRoot(), cfg.Domain, targetID, ids, generatedAt); err != nil {
		return fmt.Errorf("flat results publication: %w", err)
	}
	fmt.Fprintln(out, colors.green("✔ Flat tool results and inventories published"))
	if err := writeCollectionQuality(ctx, db, cfg.ResultsRoot(), cfg.Domain, targetID, ids, generatedAt); err != nil {
		return fmt.Errorf("collection quality export: %w", err)
	}
	fmt.Fprintln(out, colors.green("✔ Collection quality report generated"))
	if err := writeADPrivilegedAccess(ctx, db, cfg.ResultsRoot(), cfg.Domain, targetID, ids, generatedAt); err != nil {
		return fmt.Errorf("privileged access report: %w", err)
	}
	fmt.Fprintln(out, colors.green("✔ Privileged access inventory generated"))
	for _, label := range []string{"findings_summary.txt", "collection_completeness.txt", "AD_PRIVILEGED_ACCESS.txt", "AD_USERS.txt", "DNS_NAMES.txt", "DNS_NAME_IP.txt", "IP_ADDRESSES.txt", "published_results_manifest.txt"} {
		if _, statErr := os.Stat(filepath.Join(cfg.ResultsRoot(), label)); statErr != nil {
			return fmt.Errorf("required report %s was not generated", label)
		}
	}
	if findingsErr != nil {
		return errors.New("findings analysis reported one or more failures")
	}
	completed, unavailable, failed := batchStatusCounts(m.batch)
	fmt.Fprintln(out, colors.heading("ASSESSMENT SUMMARY"))
	fmt.Fprintf(out, "Completed:    %d\nUnavailable:  %d\nFailed:       %d\n\nResults: %s\n", completed, unavailable, failed, safeAutoText(cfg.ResultsRoot()))
	if batchHasFailure(m.batch) {
		fmt.Fprintln(out, colors.yellow("Assessment completed with module limitations."))
		return errors.New("one or more Default Enumeration modules failed or did not complete")
	}
	fmt.Fprintln(out, colors.green("Assessment completed."))
	return nil
}

func headlessElevationApprovals(m *model, indices []int) []approval {
	needed, _ := m.elevationNeeded(indices)
	if len(needed) == 0 {
		return nil
	}
	byID := make(map[string]int, len(m.allModules))
	for index, module := range m.allModules {
		byID[module.ID()] = index
	}
	approvals := make([]approval, 0, len(needed))
	for _, id := range needed {
		if index, ok := byID[id]; ok {
			approvals = append(approvals, approval{index: index, reason: "headless local privilege preflight"})
		}
	}
	return approvals
}

func headlessAuthorize(ctx context.Context, m *model, approval approval) error {
	if approval.index < 0 || approval.index >= len(m.allModules) {
		return errors.New("invalid module authorization request")
	}
	if err := exec.CommandContext(ctx, "sudo", "-n", "-v").Run(); err != nil {
		return errors.New("sudo authorization is not already available; run --auto from an authorized privileged session")
	}
	m.batchElevation[m.allModules[approval.index].ID()] = true
	return nil
}

func reportAutoProgress(ctx context.Context, out io.Writer, m *model, colors autoTheme) error {
	seen := make(map[int]string)
	for {
		states, _, _, _ := m.batch.Snapshot()
		for index, state := range states {
			if state.Status == "queued" || state.Status == "running" || seen[index] == state.Status {
				continue
			}
			seen[index] = state.Status
			fmt.Fprintf(out, "[%02d/%02d] %-44s %s\n", index+1, len(states), safeAutoText(state.Module.Name()), colors.status(state.Status))
		}
		select {
		case <-m.batch.Done():
			states, _, _, _ = m.batch.Snapshot()
			for index, state := range states {
				if seen[index] == state.Status || state.Status == "queued" || state.Status == "running" {
					continue
				}
				seen[index] = state.Status
				fmt.Fprintf(out, "[%02d/%02d] %-44s %s\n", index+1, len(states), safeAutoText(state.Module.Name()), colors.status(state.Status))
			}
			return nil
		case <-ctx.Done():
			m.cancelBatch()
			_ = m.batch.Wait(context.Background())
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (m *model) syncBatchError() error {
	if m.batch == nil {
		return errors.New("headless batch is unavailable")
	}
	if cmd := m.syncBatch(); cmd != nil {
		// The command returned here only waits for Findings; headless mode waits
		// directly on the manager so no Bubble Tea message loop is needed.
	}
	states, _, _, _ := m.batch.Snapshot()
	if !m.batchRecorded || len(m.batchExecutionIDs) != len(states) {
		return errors.New("execution records were not persisted for every batch item")
	}
	return nil
}

func batchHasFailure(batch *runner.BatchRun) bool {
	states, _, _, _ := batch.Snapshot()
	for _, state := range states {
		if !strings.EqualFold(state.Status, "completed") {
			return true
		}
	}
	return false
}

func batchStatusCounts(batch *runner.BatchRun) (completed, unavailable, failed int) {
	states, _, _, _ := batch.Snapshot()
	for _, state := range states {
		switch strings.ToLower(state.Status) {
		case "completed":
			completed++
		case "unavailable", "skipped":
			unavailable++
		default:
			failed++
		}
	}
	return
}

func autoScope(cfg config.Config) string {
	if values := cfg.ModuleOptions["networkhound-scope-validation"]; values != nil && strings.TrimSpace(values["NETWORKS"]) != "" {
		return values["NETWORKS"]
	}
	return "not supplied (scope validation unavailable)"
}

type autoTheme struct{ enabled bool }

func newAutoTheme(out io.Writer) autoTheme {
	file, ok := out.(*os.File)
	return autoTheme{enabled: ok && term.IsTerminal(int(file.Fd())) && os.Getenv("NO_COLOR") == ""}
}

func (theme autoTheme) paint(code, value string) string {
	if !theme.enabled {
		return value
	}
	return code + value + "\x1b[0m"
}
func (theme autoTheme) green(value string) string  { return theme.paint("\x1b[32m", value) }
func (theme autoTheme) cyan(value string) string   { return theme.paint("\x1b[36m", value) }
func (theme autoTheme) yellow(value string) string { return theme.paint("\x1b[33m", value) }
func (theme autoTheme) red(value string) string    { return theme.paint("\x1b[31m", value) }
func (theme autoTheme) dim(value string) string    { return theme.paint("\x1b[90m", value) }
func (theme autoTheme) heading(value string) string {
	return theme.cyan("\n" + strings.Repeat("─", 60) + "\n" + value + "\n" + strings.Repeat("─", 60))
}
func (theme autoTheme) status(status string) string {
	switch strings.ToLower(status) {
	case "completed":
		return theme.green("✔ Done")
	case "unavailable", "skipped":
		return theme.yellow("! " + strings.Title(strings.ToLower(status)))
	case "failed", "aborted", "cancelled":
		return theme.red("✖ " + strings.Title(strings.ToLower(status)))
	default:
		return theme.dim(safeAutoText(status))
	}
}

func safeAutoText(value string) string {
	value = ansi.Strip(value)
	value = summarySafeText(value)
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
}
