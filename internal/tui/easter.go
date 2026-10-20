package tui

import (
	_ "embed"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// The source artwork is embedded so the installed binary never depends on the
// developer's filesystem.
//
//go:embed assets/easter_asc.asc
var easterArtwork string

func isEasterEggKey(msg tea.KeyMsg) bool {
	// Bubble Tea 1.3 has no KeyCtrlEqual. Terminals that expose the key as a
	// named modified key use ctrl+=; legacy terminals encode it as the control
	// byte Bubble Tea names ctrl+]. Plain '=' is intentionally not accepted.
	return msg.String() == "ctrl+=" || msg.Type == tea.KeyCtrlCloseBracket
}

func (m *model) easterEggView() string {
	width := max(1, m.width-4)
	height := max(1, m.height-4)
	lines := strings.Split(strings.TrimSuffix(easterArtwork, "\n"), "\n")
	if len(lines) > height {
		start := (len(lines) - height) / 2
		lines = lines[start : start+height]
	}
	for index, line := range lines {
		lines[index] = ansi.TruncateWc(line, width, "")
	}
	art := lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, strings.Join(lines, "\n"))
	return paneStyle(true).Width(max(1, m.width-2)).Height(max(1, m.height-2)).Render(art)
}
