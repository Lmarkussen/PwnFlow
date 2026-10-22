package tui

import (
	"context"
	"testing"

	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
)

func TestDefaultEnumerationOpensWatcherAfterElevationPrompt(t *testing.T) {
	log := &executionLog{}
	module := elevatingModule{
		selectionModule: selectionModule{
			id:       "needs-privileges",
			family:   modules.ToolFamilySCCM,
			category: modules.CategoryEnumeration,
			protocol: modules.ProtocolNA,
			log:      log,
		},
		required: true,
	}
	m := newModel(context.Background(), config.Config{Target: "198.51.100.10", Domain: "example.test", Root: t.TempDir()}, nil, []modules.Module{module}, []int64{1}, 1, "test")
	m.focus = focusModules
	m.pending = plan{name: "Default Enumeration", requested: 1, indices: []int{0}}

	stubSudo(t, nil)
	m.startPlan(m.pending)
	if !m.elevationPrompt || m.running || m.watcher {
		t.Fatalf("automatic enumeration started before elevation approval: prompt=%v running=%v watcher=%v", m.elevationPrompt, m.running, m.watcher)
	}

	approveElevationIfAsked(t, m)
	if !m.running || !m.watcher {
		t.Fatalf("automatic enumeration did not open Watcher after starting: running=%v watcher=%v status=%q", m.running, m.watcher, m.status)
	}

	m.cancelBatch()
	if err := m.batch.Wait(context.Background()); err != nil {
		t.Fatalf("cancelled test batch did not finish: %v", err)
	}
}

func TestFreshAutomaticBatchRestoresWatcherAutoFollow(t *testing.T) {
	log := &executionLog{}
	module := selectionModule{id: "automatic-follow", family: modules.ToolFamilySCCM,
		category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log}
	m := newModel(context.Background(), config.Config{Target: "198.51.100.10", Domain: "example.test", Root: t.TempDir()}, nil, []modules.Module{module}, []int64{1}, 1, "test")
	m.watcherAuto = false
	m.watcherListCursor = 7
	m.running = true
	m.openWatcherForAutomaticBatch("Default Enumeration")
	if !m.watcher || !m.watcherAuto || m.watcherListCursor != 0 {
		t.Fatalf("automatic watcher did not reset follow state: watcher=%v auto=%v cursor=%d", m.watcher, m.watcherAuto, m.watcherListCursor)
	}
}
