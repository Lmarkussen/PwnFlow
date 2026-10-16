package tui

import (
	"context"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
)

type viewTestModule struct{}

func (viewTestModule) ID() string                                                      { return "view" }
func (viewTestModule) Name() string                                                    { return "View Module" }
func (viewTestModule) ToolFamily() modules.ToolFamily                                  { return modules.ToolFamilyNetExec }
func (viewTestModule) Category() modules.Category                                      { return modules.CategoryEnumeration }
func (viewTestModule) Description() string                                             { return "test" }
func (viewTestModule) Tool() string                                                    { return "test" }
func (viewTestModule) Protocol() modules.Protocol                                      { return modules.ProtocolLDAP }
func (viewTestModule) RequiredPrivileges() []string                                    { return nil }
func (viewTestModule) ReadOnly() bool                                                  { return true }
func (viewTestModule) SecondaryConnections() []string                                  { return nil }
func (viewTestModule) Prerequisites() []string                                         { return nil }
func (viewTestModule) OutputFile() string                                              { return "view.txt" }
func (viewTestModule) Sensitivity() modules.Sensitivity                                { return modules.SensitivityStandard }
func (viewTestModule) Check(context.Context, *modules.Runtime) error                   { return nil }
func (viewTestModule) Run(context.Context, *modules.Runtime, modules.OutputSink) error { return nil }

func TestMainViewKeepsUpperPanelTopBorders(t *testing.T) {
	m := newModel(context.Background(), config.Config{}, nil, []modules.Module{viewTestModule{}}, []int64{1}, 1, "test")
	m.width, m.height = 120, 40
	m.outputViewport = viewport.New(112, 9)
	view := ansi.Strip(m.View())
	for _, line := range strings.Split(view, "\n") {
		if strings.Count(line, "╭") == 2 {
			return
		}
	}
	t.Fatalf("upper panel top borders missing: %q", view)
}

func TestMainViewFitsSupportedTerminalWidths(t *testing.T) {
	m := newModel(context.Background(), config.Config{}, nil, []modules.Module{viewTestModule{}}, []int64{1}, 1, "test")
	for _, size := range []struct{ width, height int }{{60, 20}, {80, 24}, {100, 30}, {120, 40}} {
		m.width, m.height = size.width, size.height
		m.resizeOutput()
		for _, line := range strings.Split(ansi.Strip(m.View()), "\n") {
			if ansi.StringWidthWc(line) > size.width {
				t.Fatalf("%dx%d line width %d exceeds terminal: %q", size.width, size.height, ansi.StringWidthWc(line), line)
			}
		}
	}
}

func TestMainViewFitsTerminalHeightsAfterRepeatedResize(t *testing.T) {
	m := newModel(context.Background(), config.Config{}, nil, []modules.Module{viewTestModule{}}, []int64{1}, 1, "test")
	sizes := []struct{ width, height int }{
		{60, 20}, {80, 24}, {100, 30}, {120, 40}, {160, 50}, {200, 80},
	}
	for pass := 0; pass < 3; pass++ {
		for _, size := range sizes {
			m.width, m.height = size.width, size.height
			m.resizeOutput()
			frame := ansi.Strip(m.View())
			lines := strings.Split(frame, "\n")
			if len(lines) > size.height {
				t.Fatalf("%dx%d rendered %d lines", size.width, size.height, len(lines))
			}
			for _, line := range lines {
				if ansi.StringWidthWc(line) > size.width {
					t.Fatalf("%dx%d line width %d exceeds terminal: %q", size.width, size.height, ansi.StringWidthWc(line), line)
				}
			}
		}
	}
}

func TestNavigationPaneIsFullyRenderedAtSmallestSupportedSize(t *testing.T) {
	m := newModel(context.Background(), config.Config{}, nil, []modules.Module{viewTestModule{}}, []int64{1}, 1, "test")
	m.width, m.height = 60, 20
	m.resizeOutput()
	view := ansi.Strip(m.View())
	for _, want := range []string{"╭", "NAVIGATION", "[FOCUS]", "TOOL FAMILY", "CATEGORY", "PROTOCOL"} {
		if !strings.Contains(view, want) {
			t.Fatalf("navigation pane missing %q: %q", want, view)
		}
	}
}

func TestModuleHeaderPlacesFocusIndicatorOnVersionRow(t *testing.T) {
	m := newModel(context.Background(), config.Config{}, nil, []modules.Module{viewTestModule{}}, []int64{1}, 1, "test")
	m.focus = focusModules
	m.width, m.height = 100, 30
	m.resizeOutput()
	view := ansi.Strip(m.View())
	for _, line := range strings.Split(view, "\n") {
		if strings.Contains(line, "PwnFlow vtest") {
			if !strings.Contains(line, "[FOCUS]") {
				t.Fatalf("module version row missing focus indicator: %q", line)
			}
			return
		}
	}
	t.Fatalf("module version row not rendered: %q", view)
}

func TestMainViewInitialRenderContainsAllPanes(t *testing.T) {
	m := newModel(context.Background(), config.Config{}, nil, []modules.Module{viewTestModule{}}, []int64{1}, 1, "test")
	frame := ansi.Strip(m.View())
	for _, want := range []string{"NAVIGATION", "ENUMERATION MODULES", "MODULE INFORMATION", "OUTPUT // View Module"} {
		if !strings.Contains(frame, want) {
			t.Fatalf("initial frame missing %q: %q", want, frame)
		}
	}
}

func TestMainViewKeepsAllPanesAcrossDependencyStatusesAndResize(t *testing.T) {
	statuses := []string{"installed", "failed", "skipped", "cancelled"}
	sizes := []struct{ width, height int }{{60, 20}, {80, 24}, {100, 30}, {120, 40}}
	for _, status := range statuses {
		for _, size := range sizes {
			m := newModel(context.Background(), config.Config{}, nil, []modules.Module{viewTestModule{}}, []int64{1}, 1, "test", map[string]string{"dependency": status})
			m.Update(tea.WindowSizeMsg{Width: size.width, Height: size.height})
			frame := ansi.Strip(m.View())
			for _, want := range []string{"NAVIGATION", "ENUMERATION MODULES", "MODULE INFORMATION", "OUTPUT // View Module"} {
				if !strings.Contains(frame, want) {
					t.Fatalf("%s %dx%d frame missing %q: %q", status, size.width, size.height, want, frame)
				}
			}
		}
	}
}

func TestMainViewIgnoresTransientZeroWindowSize(t *testing.T) {
	m := newModel(context.Background(), config.Config{}, nil, []modules.Module{viewTestModule{}}, []int64{1}, 1, "test")
	m.Update(tea.WindowSizeMsg{Width: 0, Height: 0})
	frame := ansi.Strip(m.View())
	for _, want := range []string{"NAVIGATION", "ENUMERATION MODULES", "MODULE INFORMATION", "OUTPUT // View Module"} {
		if !strings.Contains(frame, want) {
			t.Fatalf("zero-size frame missing %q: %q", want, frame)
		}
	}
}
