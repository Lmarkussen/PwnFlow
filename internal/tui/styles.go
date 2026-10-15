package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

var (
	green     = lipgloss.Color("#00FF87")
	muted     = lipgloss.Color("#789485")
	focusBlue = lipgloss.Color("#42A5FF")
	title     = lipgloss.NewStyle().Bold(true).Foreground(green)
	dim       = lipgloss.NewStyle().Foreground(muted)
	focus     = lipgloss.NewStyle().Bold(true).Foreground(focusBlue)
)

const focusText = "[FOCUS]"

// paneHeader keeps the focus label inside the available content width. The
// title is shortened first so the operator can always see the focus state.
func paneHeader(label string, focused bool, width int) string {
	if !focused {
		return title.Render(label)
	}
	if width < 1 {
		width = 1
	}
	indicatorWidth := ansi.StringWidthWc(focusText)
	if width <= indicatorWidth {
		return focus.Render(ansi.TruncateWc(focusText, width, ""))
	}
	labelWidth := width - indicatorWidth - 1
	if labelWidth < 0 {
		labelWidth = 0
	}
	if ansi.StringWidthWc(label) > labelWidth {
		label = ansi.TruncateWc(label, labelWidth, "")
	}
	spaces := width - ansi.StringWidthWc(label) - indicatorWidth
	if spaces < 1 {
		spaces = 1
	}
	return title.Render(label) + strings.Repeat(" ", spaces) + focus.Render(focusText)
}

func paneStyle(focused bool) lipgloss.Style {
	border := lipgloss.Color("#245238")
	if focused {
		border = green
	}
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(border).Padding(0, 1)
}
