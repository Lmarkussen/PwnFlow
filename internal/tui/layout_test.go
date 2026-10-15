package tui

import (
	"testing"

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
