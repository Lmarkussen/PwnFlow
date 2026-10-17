package tui

import (
	"context"
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
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
	"github.com/pwnflow/pwnflow/internal/storage"
)

func Run(ctx context.Context, cfg config.Config, db *storage.DB, version string, dependencyReasons ...map[string]string) error {
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
