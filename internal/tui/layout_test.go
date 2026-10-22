package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/modules/netexec"
)

// The three panes divide the terminal exactly, at every height, and a short
// terminal keeps module rows by shrinking the output pane rather than the list
// the operator is navigating.
func TestPanesDivideTheTerminalAtEveryHeight(t *testing.T) {
	for _, height := range []int{60, 50, 45, 38, 30, 24, 18} {
		m := statusModel(t, netexec.EnumerationModules())
		m.width, m.height = 140, height
		m.resizeOutput()
		m.setToolFamily(0)
		m.setCategory(0)
		m.setProtocol(0)
		navigation, modulePane, outputPane := m.layoutHeights()
		if navigation+modulePane+outputPane != height {
			t.Fatalf("height %d: navigation %d + module %d + output %d does not fill the terminal",
				height, navigation, modulePane, outputPane)
		}
		if rows := m.moduleViewportRows(); rows < 1 {
			t.Fatalf("height %d: the module pane shows %d rows", height, rows)
		}
		if m.outputViewport.Height < 1 {
			t.Fatalf("height %d: the output viewport is %d lines", height, m.outputViewport.Height)
		}
		// The module pane keeps its minimum as long as the terminal can hold it.
		if height >= 30 && modulePane < minModulePaneHeight {
			t.Fatalf("height %d: the module pane dropped to %d lines, below its minimum", height, modulePane)
		}
	}
}

func TestModulePaneFooterStaysAnchoredAcrossListLengthsAndResizes(t *testing.T) {
	for _, width := range []int{160, 120, 100, 80, 60} {
		for _, height := range []int{60, 45, 30, 24, 18} {
			expectedFooterLine := -1
			for _, moduleCount := range []int{1, 3, 7, 40} {
				m := statusModel(t, netexec.EnumerationModules())
				m.width, m.height = width, height
				m.modules = append([]modules.Module(nil), m.modules[:min(moduleCount, len(m.modules))]...)
				m.resizeOutput()
				frame := strings.Split(ansi.Strip(m.View()), "\n")
				footer, _ := m.modulePaneLayout()
				if footer == "" {
					continue
				}
				footerLine := -1
				for index, line := range frame {
					if strings.Contains(line, "Quit") {
						footerLine = index
					}
				}
				if footerLine < 0 {
					t.Fatalf("width=%d height=%d modules=%d: navigation footer missing compact=%t pane=%d rows=%d", width, height, moduleCount, m.modulePaneCompact(), m.modulePaneHeight(), m.moduleViewportRows())
				}
				paneBottom := lipgloss.Height(m.navigationView()) + m.modulePaneHeight()
				if footerLine >= paneBottom {
					t.Fatalf("width=%d height=%d modules=%d: footer line=%d is below module pane bottom=%d", width, height, moduleCount, footerLine, paneBottom)
				}
				if expectedFooterLine < 0 {
					expectedFooterLine = footerLine
				} else if footerLine != expectedFooterLine {
					t.Fatalf("width=%d height=%d modules=%d: footer line=%d moved from %d", width, height, moduleCount, footerLine, expectedFooterLine)
				}
			}
		}
	}
}

func TestNavigationValuesDoNotPushToolRunnerOffScreen(t *testing.T) {
	m := statusModel(t, netexec.EnumerationModules())
	m.width, m.height = 80, 18
	m.categories = []modules.Category{modules.Category("a deliberately long category value that must stay on one row")}
	m.categoryIndex = 0
	navigation, modulePane, outputPane := m.layoutHeights()
	if navigation+modulePane+outputPane != m.height {
		t.Fatalf("layout does not fill terminal: navigation=%d module=%d output=%d", navigation, modulePane, outputPane)
	}
	if navigation >= m.height {
		t.Fatalf("navigation consumed the terminal: %d/%d", navigation, m.height)
	}
	if rows := strings.Count(ansi.Strip(m.navigationView()), "\n") + 1; rows > navigation {
		t.Fatalf("navigation rendered beyond its measured height: rows=%d height=%d", rows, navigation)
	}
	if !strings.Contains(ansi.Strip(m.View()), "ENUMERATION MODULES") {
		t.Fatal("module/configuration pane is not visible below navigation")
	}
}
