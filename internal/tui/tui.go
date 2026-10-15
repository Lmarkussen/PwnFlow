package tui

import (
	"context"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/modules/certipy"
	"github.com/pwnflow/pwnflow/internal/modules/netexec"
	"github.com/pwnflow/pwnflow/internal/modules/rusthound"
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
	registry.Register(rusthound.Module{})
	for _, module := range certipy.EnumerationModules() {
		registry.Register(module)
	}
	registered := registry.All()
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
	_, err = tea.NewProgram(model, tea.WithAltScreen(), tea.WithContext(ctx)).Run()
	if model.batch != nil {
		model.cancelBatch()
		waitContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = model.batch.Wait(waitContext)
		cancel()
	}
	return err
}
