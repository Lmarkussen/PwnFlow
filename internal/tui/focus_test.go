package tui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
)

func TestPaneHeaderKeepsFocusIndicatorVisibleAtWidth(t *testing.T) {
	const width = 24
	header := paneHeader("A deliberately long pane title", true, width)
	if !strings.Contains(ansi.Strip(header), focusText) {
		t.Fatalf("focus indicator missing: %q", ansi.Strip(header))
	}
	if got := ansi.StringWidthWc(header); got > width {
		t.Fatalf("header width %d exceeds %d: %q", got, width, ansi.Strip(header))
	}
	if strings.Count(ansi.Strip(header), focusText) != 1 {
		t.Fatalf("expected one focus indicator: %q", ansi.Strip(header))
	}
}

func TestMainViewFocusIndicatorFollowsTab(t *testing.T) {
	m := newModel(context.Background(), config.Config{}, nil, []modules.Module{viewTestModule{}}, []int64{1}, 1, "test")
	m.width, m.height = 100, 30
	m.resizeOutput()

	initial := ansi.Strip(m.View())
	if strings.Contains(initial, focusText) {
		t.Fatalf("navigation focus rendered a pane indicator: %q", initial)
	}

	updated, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyTab})
	modulesView := ansi.Strip(updated.(*model).View())
	if strings.Count(modulesView, focusText) != 1 {
		t.Fatalf("module pane did not receive focus indicator: %q", modulesView)
	}

	updated, _ = updated.(*model).handleKey(tea.KeyMsg{Type: tea.KeyTab})
	output := ansi.Strip(updated.(*model).View())
	if strings.Count(output, focusText) != 1 || !strings.Contains(output, "OUTPUT // View Module") {
		t.Fatalf("output pane did not receive focus indicator: %q", output)
	}
}

func TestWatcherFocusIndicatorFollowsTab(t *testing.T) {
	m := newModel(context.Background(), config.Config{}, nil, []modules.Module{viewTestModule{}}, []int64{1}, 1, "test")
	m.width, m.height = 100, 30
	m.watcher = true
	m.resizeWatcher()

	initial := ansi.Strip(m.View())
	if strings.Count(initial, focusText) != 1 || !strings.Contains(initial, "MODULE EXECUTION HISTORY") {
		t.Fatalf("watcher module pane is not initially focused: %q", initial)
	}

	updated, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyTab})
	output := ansi.Strip(updated.(*model).View())
	if strings.Count(output, focusText) != 1 || !strings.Contains(output, "OUTPUT //") {
		t.Fatalf("watcher output pane did not receive focus: %q", output)
	}
}

func TestFocusIndicatorStyleUsesBlueForeground(t *testing.T) {
	rendered := focus.Render(focusText)
	if !strings.Contains(rendered, "\x1b[") {
		t.Skip("lipgloss color profile disables ANSI in this test environment")
	}
	if ansi.Strip(rendered) != focusText {
		t.Fatalf("styled indicator changed its text: %q", ansi.Strip(rendered))
	}
}
