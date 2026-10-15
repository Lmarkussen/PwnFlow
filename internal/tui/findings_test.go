package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/runner"
	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestFindingsViewFiltersAndDoesNotRenderEvidenceSecrets(t *testing.T) {
	model := &model{findingsView: true, width: 100, height: 24, findingRows: []storage.Finding{{FindingInput: storage.FindingInput{Title: "Potential Shadow Credentials exposure", Severity: "high", Confidence: "potential-condition", AffectedObject: "APP01$", RelatedObject: "svc-a", SourceTool: "RustHound-CE", EvidenceJSON: `{"secret":"fictional-password"}`, ArtifactPath: "restricted.json", ArtifactRef: "/data/0/Aces/0"}, FirstSeen: time.Now()}}}
	frame := ansi.Strip(model.View())
	if !strings.Contains(frame, "Potential Shadow Credentials exposure") {
		t.Fatal("finding title missing")
	}
	if strings.Contains(frame, "fictional-password") {
		t.Fatal("finding summary leaked evidence secret")
	}
	if _, command := model.handleFindingsKey("enter"); command != nil || !model.findingDetail {
		t.Fatal("detail view did not open")
	}
	if !strings.Contains(ansi.Strip(model.View()), "restricted.json") {
		t.Fatal("detail omitted artifact reference")
	}
}

func TestFindingsWarningWrappingAndWatcherNavigation(t *testing.T) {
	wrapped := ansi.Strip(wrapPaneStyle(warn, "Abort this deliberately long operator warning [y/N]", 18))
	for _, line := range strings.Split(wrapped, "\n") {
		if ansi.StringWidthWc(line) > 18 {
			t.Fatalf("warning overflowed: %q", line)
		}
	}
	m := &model{width: 80, height: 24, batch: &runner.BatchRun{}, findingsView: true}
	updated, _ := m.handleFindingsKey("ctrl+w")
	if !updated.(*model).watcher {
		t.Fatal("Ctrl+W did not return to watcher")
	}
	updated, _ = updated.(*model).handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if updated.(*model).watcher {
		t.Fatal("Esc did not leave watcher")
	}
}

func TestFindingsViewportHandlesLargeResultSets(t *testing.T) {
	rows := make([]storage.Finding, 10000)
	for index := range rows {
		rows[index] = storage.Finding{FindingInput: storage.FindingInput{
			Title: fmt.Sprintf("Synthetic condition %05d", index), Severity: "medium", AffectedObject: fmt.Sprintf("object-%05d", index),
		}}
	}
	model := &model{findingsView: true, findingViewMode: "all", width: 100, height: 24, findingRows: rows}
	frame := ansi.Strip(model.View())
	if strings.Count(frame, "Synthetic condition") > model.findingPageSize() {
		t.Fatalf("rendered more than one viewport page: %d", strings.Count(frame, "Synthetic condition"))
	}
	if _, command := model.handleFindingsKey("end"); command != nil || model.findingCursor != len(rows)-1 {
		t.Fatalf("End did not select final finding: cursor=%d", model.findingCursor)
	}
	if model.findingTop <= 0 {
		t.Fatalf("End did not move viewport: top=%d", model.findingTop)
	}
	if !strings.Contains(ansi.Strip(model.View()), "Synthetic condition 09999") {
		t.Fatal("final finding is not visible after End")
	}
	_, _ = model.handleFindingsKey("home")
	if model.findingCursor != 0 || model.findingTop != 0 {
		t.Fatalf("Home did not restore first page: cursor=%d top=%d", model.findingCursor, model.findingTop)
	}
}

func TestFindingsViewportHandlesMouseWheel(t *testing.T) {
	rows := make([]storage.Finding, 50)
	model := &model{findingsView: true, findingViewMode: "all", width: 100, height: 24, findingRows: rows}
	_, _ = model.Update(tea.MouseMsg{Button: tea.MouseButtonWheelDown})
	if model.findingCursor != 3 {
		t.Fatalf("wheel down moved cursor to %d, want 3", model.findingCursor)
	}
	_, _ = model.Update(tea.MouseMsg{Button: tea.MouseButtonWheelUp})
	if model.findingCursor != 0 {
		t.Fatalf("wheel up moved cursor to %d, want 0", model.findingCursor)
	}
}
