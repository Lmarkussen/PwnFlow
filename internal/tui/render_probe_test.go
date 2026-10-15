package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/modules/netexec"
)

func TestProbeScrolledFrame(t *testing.T) {
	m := statusModel(t, netexec.EnumerationModules())
	m.width, m.height = 140, 45
	m.resizeOutput()
	m.focus = focusModules
	m.setToolFamily(0)
	m.setCategory(0)
	m.setProtocol(0)
	for index := 0; index < 20; index++ {
		press(t, m, "down")
	}
	frame := ansi.Strip(m.View())
	lines := 0
	for _, line := range strings.Split(frame, "\n") {
		if strings.TrimSpace(line) != "" {
			lines++
		}
	}
	t.Logf("cursor=%d top=%d rows=%d frameLines=%d terminalHeight=%d", m.cursor, m.moduleTop, m.moduleViewportRows(), lines, m.height)
	for _, line := range strings.Split(frame, "\n") {
		if strings.Contains(line, "[ ]") || strings.Contains(line, "MODULES //") {
			t.Logf("%s", line)
		}
	}
}
