package tui

import (
	"context"
	"testing"

	"github.com/pwnflow/pwnflow/internal/config"
)

func TestDefaultEnumerationProfileHas32EntriesAndExcludesMSSQL(t *testing.T) {
	if len(defaultEnumerationModuleIDs) != 32 {
		t.Fatalf("Default Enumeration has %d entries, want 32", len(defaultEnumerationModuleIDs))
	}
	for _, id := range defaultEnumerationModuleIDs {
		if id == "mssqlrelay-check" || id == "mssqlpwner-enumerate" || id == "masscan" {
			t.Fatalf("excluded module %q entered Default Enumeration", id)
		}
	}
}

func TestDefaultEnumerationDoesNotOpenGroupedApprovalPrompt(t *testing.T) {
	log := &executionLog{}
	registered, ids := yoloRegistry(log)
	m := newModel(context.Background(), config.Config{Target: "198.51.100.10", Domain: "example.test", Username: "operator", Root: t.TempDir()}, nil, registered, ids, 1, "production-test")
	m.width, m.height = 140, 45
	m.resizeOutput()
	m.focus = focusModules
	m.pending = plan{
		name:      "Default Enumeration",
		requested: 2,
		indices:   []int{0, 1},
		approvals: []approval{{index: 0, reason: "credential material"}},
	}
	m.startPlan(m.pending)
	if m.approvalPrompt {
		t.Fatal("Default Enumeration opened the grouped approval prompt")
	}
	if !m.running {
		t.Fatalf("Default Enumeration did not start after filtering unauthorized work: %q", m.status)
	}
	if len(m.batchItems) != 1 || m.batchItems[0].Module.ID() != registered[1].ID() {
		t.Fatalf("unexpected Default Enumeration queue: %v", batchIDs(m))
	}
	m.cancelBatch()
}
