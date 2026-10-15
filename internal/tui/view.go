package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/modules"
)

func (m *model) View() string {
	if m.watcher {
		return m.watcherView()
	}
	width := max(16, (m.width-4)/2)
	var left strings.Builder
	left.WriteString(title.Render(fmt.Sprintf("PwnFlow v%s", m.version)) + "\n")
	// The count is registry-wide, because R runs the selection across every tool
	// family rather than only what the current scope shows.
	modulesHeader := "ENUMERATION MODULES"
	if selected := m.selectedCount(); selected > 0 {
		modulesHeader = fmt.Sprintf("ENUMERATION MODULES // %d SELECTED", selected)
	}
	left.WriteString(paneHeader(modulesHeader, m.focus == focusModules, width) + "\n")
	left.WriteString(fmt.Sprintf("TARGET: %s\nDOMAIN: %s\nUSER:   %s\nAUTH:   %s\n\n", m.cfg.Target, m.cfg.Domain, m.cfg.Username, lipgloss.NewStyle().Foreground(green).Render("OK")))
	for i, module := range m.modules {
		mark := "[ ]"
		if m.selectedModules[m.modules[i].ID()] {
			mark = lipgloss.NewStyle().Foreground(green).Bold(true).Render("[x]")
		}
		if i == m.cursor {
			mark = "> " + mark
		}
		state := m.moduleState(i)
		left.WriteString(fmt.Sprintf("%s %-22s %s\n", mark, module.Name(), state))
	}
	left.WriteString("\n" + dim.Render("────────────────────────────────────────────") + "\n")
	left.WriteString(dim.Render(wrapFooter(helpText, max(20, widthForFooter(m.width)))))
	right := m.infoView()
	navigation := m.navigationView()
	navigationHeight := lipgloss.Height(navigation)
	outputHeight := m.outputViewport.Height + 4
	// Height is the content height for a styled pane. Reserve the border rows
	// for both module panes so the navigation pane and output pane remain in
	// the terminal instead of being clipped from the top or bottom.
	topHeight := max(1, m.height-navigationHeight-outputHeight-2)
	leftPane := paneStyle(m.focus == focusModules).Width(width).Height(topHeight).MaxHeight(topHeight).Render(left.String())
	rightPane := paneStyle(false).Width(width).Height(topHeight).MaxHeight(topHeight).Render(right)
	top := lipgloss.JoinHorizontal(lipgloss.Top, leftPane, rightPane)
	return lipgloss.JoinVertical(lipgloss.Left, navigation, top, m.outputView())
}

func widthForFooter(width int) int {
	if width < 1 {
		return 32
	}
	return width/2 - 4
}

func wrapFooter(text string, width int) string {
	if width < 1 {
		width = 1
	}
	return ansi.HardwrapWc(text, width, true)
}

func (m *model) navigationView() string {
	width := max(20, m.width-4)
	var content strings.Builder
	content.WriteString(paneHeader("NAVIGATION", m.focus == focusNavigation, width-4) + "\n")
	rows := []struct {
		label string
		value string
	}{
		{"TOOL FAMILY", navigationValue(m.toolFamilies, m.toolFamilyIndex)},
		{"CATEGORY", navigationValue(m.categories, m.categoryIndex)},
		{"PROTOCOL", navigationValue(m.protocols, m.protocolIndex)},
	}
	for index, row := range rows {
		prefix := "  "
		if index == m.navigationRow {
			prefix = "> "
		}
		line := fmt.Sprintf("%s%-14s  ◀ %s ▶", prefix, row.label, row.value)
		if index == m.navigationRow && m.focus == focusNavigation {
			line = title.Render(line)
		}
		content.WriteString(line + "\n")
	}
	content.WriteString(dim.Render("↑↓ Select row   ←→ Change value   Tab Next"))
	return paneStyle(m.focus == focusNavigation).Width(width - 2).Render(content.String())
}

func navigationValue[T ~string](values []T, index int) string {
	if index < 0 || index >= len(values) {
		return "N/A"
	}
	return string(values[index])
}

func (m *model) moduleState(index int) string {
	if reason := m.moduleAvailability(m.modules[index]); reason != "" {
		return "UNAVAILABLE"
	}
	if m.batch != nil {
		global, ok := m.globalIndex(index)
		if !ok {
			return "READY"
		}
		states, _, _, _ := m.batch.Snapshot()
		for _, state := range states {
			if state.Index == global {
				return strings.ToUpper(state.Status)
			}
		}
	}
	return "READY"
}

func (m *model) infoView() string {
	if len(m.modules) == 0 {
		return title.Render("MODULE INFORMATION") + "\n\nCategory inactive; no modules are available."
	}
	module := m.modules[m.cursor]
	availability := "READY"
	if reason := m.moduleAvailability(module); reason != "" {
		availability = "UNAVAILABLE: " + reason
	} else if m.batch != nil {
		states, _, _, _ := m.batch.Snapshot()
		for _, state := range states {
			if state.Index == m.cursor && state.Status == "unavailable" && state.Result.Err != nil {
				availability = "UNAVAILABLE: " + state.Result.Err.Error()
				break
			}
		}
	}
	command := fmt.Sprintf("%s %s %s -u %s -p [REDACTED] ...", module.Tool(), strings.ToLower(string(module.Protocol())), m.cfg.Target, m.cfg.Username)
	runtime := &modules.Runtime{Target: m.cfg.Target, Domain: m.cfg.Domain, Username: m.cfg.Username, ResultsRoot: m.cfg.ResultsRoot()}
	if preview, ok := module.(modules.CommandPreviewProvider); ok {
		command = preview.CommandPreview(runtime)
	}
	details := ""
	if provider, ok := module.(modules.DetailProvider); ok {
		for _, line := range provider.DetailLines(runtime) {
			details += line + "\n"
		}
		if details != "" {
			// Keep the module-supplied configuration distinct from the
			// free-text description that follows it.
			details += "\n"
		}
	}
	return title.Render("MODULE INFORMATION") + "\n\n" + fmt.Sprintf("Name: %s\nFamily: %s\nCategory: %s\nTool: %s\nProtocol: %s\nSensitivity: %s\nRead-only: %t\n\n%s%s\n\nCommand: %s\n\nAvailability: %s\nStatus: %s\nOutput: %s\n", module.Name(), module.ToolFamily(), module.Category(), module.Tool(), module.Protocol(), module.Sensitivity(), module.ReadOnly(), details, module.Description(), command, availability, m.status, module.OutputFile())
}

func (m *model) moduleAvailability(module modules.Module) string {
	dependencyKey := module.ID()
	if provider, ok := module.(modules.DependencyKeyProvider); ok {
		if key := provider.DependencyKey(); key != "" {
			dependencyKey = key
		}
	}
	if policy, ok := module.(modules.ExecutionPolicy); ok && !policy.ExecutionEnabled() {
		reason := policy.AvailabilityReason()
		if dependencyReason := m.availability[dependencyKey]; dependencyReason != "" {
			return reason + "; " + dependencyReason
		}
		return reason
	}
	if reason := m.availability[dependencyKey]; reason != "" {
		return reason
	}
	if module.ToolFamily() == modules.ToolFamilyNetExec {
		return m.availability["netexec"]
	}
	return ""
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
