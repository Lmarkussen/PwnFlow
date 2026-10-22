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
	infoBlue  = lipgloss.Color("#62D8FF")
	red       = lipgloss.Color("#FF5F6D")
	// amber marks a decision the operator has to make. It is deliberately unlike
	// the green used for progress and results, so a privilege confirmation cannot be
	// mistaken for one of them.
	amber      = lipgloss.Color("#FFAA33")
	title      = lipgloss.NewStyle().Bold(true).Foreground(green)
	dim        = lipgloss.NewStyle().Foreground(muted)
	focus      = lipgloss.NewStyle().Bold(true).Foreground(focusBlue)
	warn       = lipgloss.NewStyle().Bold(true).Foreground(amber)
	unverified = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#D8A7FF"))
)

var (
	selectedArrowStyle    = lipgloss.NewStyle().Foreground(focusBlue).Bold(true)
	selectedLabelStyle    = lipgloss.NewStyle().Foreground(green).Bold(true)
	severityCriticalStyle = lipgloss.NewStyle().Foreground(red).Bold(true)
	severityHighStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF7A7A")).Bold(true)
	severityMediumStyle   = lipgloss.NewStyle().Foreground(amber).Bold(true)
	severityLowStyle      = dim
	severityInfoStyle     = lipgloss.NewStyle().Foreground(infoBlue)
	watcherInfoStyle      = lipgloss.NewStyle().Foreground(infoBlue).Bold(true)
	abortedStyle          = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF8C42")).Bold(true)
)

func selectionPrefix(selected bool) string {
	if selected {
		return selectedArrowStyle.Render(">") + " "
	}
	return "  "
}

func selectionLabel(label string, selected bool) string {
	if selected {
		return selectedLabelStyle.Render(label)
	}
	return label
}

func severityStyle(value string) lipgloss.Style {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return severityCriticalStyle
	case "high":
		return severityHighStyle
	case "medium":
		return severityMediumStyle
	case "low":
		return severityLowStyle
	default:
		return severityInfoStyle
	}
}

func lifecycleStyle(value string) lipgloss.Style {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "completed", "complete":
		return lipgloss.NewStyle().Foreground(green).Bold(true)
	case "failed", "unavailable":
		return lipgloss.NewStyle().Foreground(red).Bold(true)
	case "aborted":
		return abortedStyle
	case "cancelled":
		return lipgloss.NewStyle().Foreground(red)
	case "queued":
		return lipgloss.NewStyle().Foreground(amber)
	case "skipped":
		return dim
	case "running":
		return lipgloss.NewStyle().Foreground(infoBlue).Bold(true)
	default:
		return dim
	}
}

const focusText = "[FOCUS]"

// paneHeader keeps the focus label inside the available content width. The
// title is shortened first so the operator can always see the focus state.
func paneHeader(label string, focused bool, width int) string {
	return paneHeaderWith(title, label, focused, width)
}

// paneHeaderWith renders a pane header with a chosen label style, so a pane that is
// asking the operator something can stand out without changing any other pane.
func paneHeaderWith(style lipgloss.Style, label string, focused bool, width int) string {
	if width < 1 {
		width = 1
	}
	if !focused {
		return style.Render(ansi.TruncateWc(label, width, "…"))
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
	return style.Render(label) + strings.Repeat(" ", spaces) + focus.Render(focusText)
}

func paneStyle(focused bool) lipgloss.Style {
	border := lipgloss.Color("#245238")
	if focused {
		border = green
	}
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(border).Padding(0, 1)
}
