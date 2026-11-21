package tui

import (
	"context"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestNotReobservedFindingsAreHiddenUntilToggled(t *testing.T) {
	current := storage.Finding{ID: 1, FindingInput: storage.FindingInput{FindingType: "smb_spooler_service_running", Title: "Print Spooler reachable: DC01", Severity: "medium", SourceTool: "NetExec (nxc)", EvidenceJSON: "{}"}}
	stale := storage.Finding{ID: 2, FindingInput: storage.FindingInput{FindingType: "smb_v1_enabled", Title: "SMBv1 enabled: DC01", Severity: "medium", SourceTool: "NetExec (nxc)", EvidenceJSON: "{}"}, NotReobserved: true}
	m := &model{ctx: context.Background(), findingsView: true, findingCategoryView: true, width: 120, height: 40}
	m.setFindingRows([]storage.Finding{current, stale})
	if m.notReobservedHidden != 1 {
		t.Fatalf("hidden count %d, want 1", m.notReobservedHidden)
	}
	for _, row := range m.findingAllRows {
		if row.ID == 2 {
			t.Fatal("not re-observed Finding is visible by default")
		}
	}
	if frame := ansi.Strip(m.View()); !strings.Contains(frame, "1 Finding(s) not re-observed by the latest run of their module are hidden; H shows them.") {
		t.Fatalf("hidden notice missing:\n%s", frame)
	}

	m.handleFindingsKey("H")
	shown := false
	for _, row := range m.findingAllRows {
		shown = shown || row.ID == 2
	}
	if !shown || m.notReobservedHidden != 0 {
		t.Fatalf("toggle did not reveal the Finding (hidden=%d)", m.notReobservedHidden)
	}
	if title := displayFindingTitle(stale); title != "SMBv1 enabled: DC01 · not re-observed" {
		t.Fatalf("marker missing: %q", title)
	}
	m.handleFindingsKey("h")
	if m.notReobservedHidden != 1 {
		t.Fatal("second toggle did not hide the Finding again")
	}
}

func TestFindingsFromRetiredModulesAreTreatedAsNotReobserved(t *testing.T) {
	rows := markRetiredSources([]storage.Finding{
		{FindingInput: storage.FindingInput{Title: "retired"}, SourceModule: "Enumerate CVE Patch Exposure", SourceModuleTool: "NetExec (nxc)"},
		{FindingInput: storage.FindingInput{Title: "current"}, SourceModule: "Check Print Spooler", SourceModuleTool: "NetExec (nxc)"},
		{FindingInput: storage.FindingInput{Title: "unknown source"}},
	})
	if !rows[0].NotReobserved || !rows[0].SourceModuleRetired {
		t.Fatalf("retired module not flagged: %+v", rows[0])
	}
	if rows[1].NotReobserved || rows[2].NotReobserved {
		t.Fatalf("registered or unknown module flagged: %+v %+v", rows[1], rows[2])
	}
}
