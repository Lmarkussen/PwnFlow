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
	// The count is registry-wide, because R runs the selection across every tool
	// family rather than only what the current scope shows.
	modulesHeader := "ENUMERATION MODULES"
	if selected := m.selectedCount(); selected > 0 {
		modulesHeader = fmt.Sprintf("ENUMERATION MODULES // %d SELECTED", selected)
	}
	// The window is computed before the rows are written, so the pane shows the
	// rows that contain the selection instead of being clipped from the bottom.
	windowTop, windowRows := m.moduleWindow()
	if len(m.modules) > windowRows {
		modulesHeader = fmt.Sprintf("%s // %d-%d/%d", modulesHeader, windowTop+1, min(windowTop+windowRows, len(m.modules)), len(m.modules))
	}
	compact := m.modulePaneCompact()
	if !compact {
		left.WriteString(title.Render(fmt.Sprintf("PwnFlow v%s", m.version)) + "\n")
	}
	left.WriteString(paneHeader(modulesHeader, m.focus == focusModules, width) + "\n")
	if compact {
		// Too short for the full identity block: keep the values, spend the lines
		// on module rows instead.
		left.WriteString(fmt.Sprintf("TARGET: %s  DOMAIN: %s\nUSER: %s  AUTH: %s\n", m.cfg.Target, m.cfg.Domain, m.cfg.Username, lipgloss.NewStyle().Foreground(green).Render("OK")))
	} else {
		left.WriteString(fmt.Sprintf("TARGET: %s\nDOMAIN: %s\nUSER:   %s\nAUTH:   %s\n\n", m.cfg.Target, m.cfg.Domain, m.cfg.Username, lipgloss.NewStyle().Foreground(green).Render("OK")))
	}
	for i := windowTop; i < len(m.modules) && i < windowTop+windowRows; i++ {
		module := m.modules[i]
		mark := "[ ]"
		if m.selectedModules[m.modules[i].ID()] {
			mark = lipgloss.NewStyle().Foreground(green).Bold(true).Render("[x]")
		}
		if i == m.cursor {
			mark = "> " + mark
		}
		state := m.moduleState(i)
		// An available module carries no suffix: a label that says "fine" on
		// every row is noise, and the two labels that do appear - ADMIN-REQ and
		// UNAVAILABLE - have to stand out from the names beside them.
		left.WriteString(strings.TrimRight(fmt.Sprintf("%s %-30s %s", mark, module.Name(), state), " ") + "\n")
	}
	if !compact {
		left.WriteString("\n" + dim.Render("────────────────────────────────────────────") + "\n")
		if footer, _ := m.modulePaneLayout(); footer != "" {
			left.WriteString(dim.Render(footer))
		}
	}
	right := m.infoView()
	navigation := m.navigationView()
	// The pane height is the same number modulePaneHeight used to decide how many
	// module rows fit, so the list always ends above the pane's bottom border.
	topHeight := m.modulePaneHeight()
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
	}
	if !m.isFlatFamily() {
		rows = append(rows,
			struct{ label, value string }{"CATEGORY", navigationValue(m.categories, m.categoryIndex)},
			struct{ label, value string }{"PROTOCOL", navigationValue(m.protocols, m.protocolIndex)},
		)
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
	module := m.modules[index]
	// A row that is running, or has just run, shows that instead: the live state
	// is the more specific answer while a batch is in flight.
	if m.batch != nil {
		global, ok := m.globalIndex(index)
		if ok {
			states, _, _, _ := m.batch.Snapshot()
			for _, state := range states {
				if state.Index == global {
					return strings.ToUpper(state.Status)
				}
			}
		}
	}
	switch status, _ := m.moduleStatus(module); status {
	case "UNAVAILABLE":
		return "UNAVAILABLE"
	case "ADMIN-REQ":
		return "ADMIN-REQ"
	case "INPUT-REQ":
		return "INPUT-REQ"
	}
	return ""
}

// moduleStatus answers two questions about one module with data that is already
// in memory: whether it can run at all, and whether the target has to grant it
// elevated rights. It never probes: the TUI asks while a frame is drawn.
func (m *model) moduleStatus(module modules.Module) (status string, reason string) {
	if reason := m.moduleAvailability(module); reason != "" {
		return "UNAVAILABLE", reason
	}
	provider, ok := module.(modules.StatusProvider)
	if !ok {
		return "AVAILABLE", ""
	}
	runtime := m.moduleRuntime()
	switch provider.Status(runtime) {
	case modules.StatusUnavailable:
		return "UNAVAILABLE", provider.StatusReason(runtime)
	case modules.StatusAdminRequired:
		return "ADMIN-REQ", provider.StatusReason(runtime)
	case modules.StatusInputRequired:
		return "INPUT-REQ", provider.StatusReason(runtime)
	}
	return "AVAILABLE", ""
}

func (m *model) infoView() string {
	if len(m.modules) == 0 {
		return title.Render("MODULE INFORMATION") + "\n\nCategory inactive; no modules are available."
	}
	module := m.modules[m.cursor]
	status, statusReason := m.moduleStatus(module)
	availability := "AVAILABLE"
	privilege := "none beyond valid credentials"
	switch status {
	case "UNAVAILABLE":
		availability = "UNAVAILABLE: " + statusReason
	case "ADMIN-REQ":
		privilege = "ADMIN-REQ (" + statusReason + ")"
	case "INPUT-REQ":
		availability = "CONFIGURABLE: " + statusReason + " - press Enter to be asked for it, or pass it with --module-options"
	}
	if m.batch != nil {
		states, _, _, _ := m.batch.Snapshot()
		for _, state := range states {
			if state.Index == m.cursor && state.Status == "unavailable" && state.Result.Err != nil {
				availability = "UNAVAILABLE: " + state.Result.Err.Error()
				break
			}
		}
	}
	command := fmt.Sprintf("%s %s %s -u %s -p [REDACTED] ...", module.Tool(), strings.ToLower(string(module.Protocol())), m.cfg.Target, m.cfg.Username)
	runtime := m.moduleRuntime()
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
	// Availability and the target-side privilege come before the free text: an
	// operator has to be able to read what a module needs without scrolling past
	// a description that may be longer than the pane.
	return title.Render("MODULE INFORMATION") + "\n\n" + fmt.Sprintf("Name: %s\nFamily: %s\nCategory: %s\nTool: %s\nProtocol: %s\nSensitivity: %s\nRead-only: %t\n\nAvailability: %s\nTarget privilege: %s\n\n%s%s\n\nCommand: %s\n\nStatus: %s\nOutput: %s\n", module.Name(), module.ToolFamily(), module.Category(), module.Tool(), module.Protocol(), module.Sensitivity(), module.ReadOnly(), availability, privilege, details, module.Description(), command, m.statusText(""), module.OutputFile())
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
