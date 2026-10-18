package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/runner"
)

func (m *model) resizeWatcher() {
	width := m.width - 4
	if width < 1 {
		width = 1
	}
	if m.watcherListViewport.Width == 0 {
		m.watcherListViewport = viewport.New(1, 1)
	}
	// Reserve the fixed dashboard chrome first: title, four summary rows, the
	// contextual status line, footer, pane borders, and the separator between
	// panes. The remaining space belongs to the two viewports. This keeps the
	// dashboard inside the terminal even at its smallest supported height.
	available := m.height - 16
	if available < 2 {
		available = 2
	}
	listHeight := available / 2
	if listHeight < 1 {
		listHeight = 1
	}
	outputHeight := available - listHeight
	if outputHeight < 1 {
		outputHeight = 1
	}
	m.watcherListViewport.Width = width - 2
	if m.watcherListViewport.Width < 1 {
		m.watcherListViewport.Width = 1
	}
	m.watcherListViewport.Height = listHeight
	wasAtBottom := m.watcherViewport.AtBottom()
	m.watcherViewport.Width = width - 2
	if m.watcherViewport.Width < 1 {
		m.watcherViewport.Width = 1
	}
	m.watcherViewport.Height = outputHeight
	if m.watcherFollow || wasAtBottom {
		m.watcherViewport.GotoBottom()
	}
	m.refreshWatcherList()
	m.refreshWatcher()
}

func (m *model) watcherStates() []runner.BatchState {
	if m.batch != nil {
		states, _, _, _ := m.batch.Snapshot()
		return states
	}
	indices := m.pendingIndices
	if len(indices) == 0 {
		indices = m.pending.indices
	}
	if len(indices) == 0 {
		if len(m.modules) == 1 && len(m.moduleKeys) == 1 {
			return []runner.BatchState{{Index: m.moduleKeys[0], Module: m.modules[0], Status: "queued"}}
		}
		return nil
	}
	states := make([]runner.BatchState, 0, len(indices))
	for _, index := range indices {
		if index < 0 || index >= len(m.allModules) || index >= len(m.allModuleIDs) {
			continue
		}
		states = append(states, runner.BatchState{Index: index, Module: m.allModules[index], Status: "queued"})
	}
	return states
}

func (m *model) refreshWatcherList() {
	states := m.watcherStates()
	if len(states) == 0 {
		m.watcherListContent = "No executed modules in this scope."
		m.watcherListViewport.SetContent(m.watcherListContent)
		return
	}
	if m.watcherListCursor >= len(states) {
		m.watcherListCursor = len(states) - 1
	}
	if m.watcherListCursor < 0 {
		m.watcherListCursor = 0
	}
	var content strings.Builder
	statusColumn := watcherStatusColumnWidth(states, m.watcherListViewport.Width)
	for index, state := range states {
		selected := index == m.watcherListCursor && m.watcherFocus == focusModules
		status := watcherDisplayStatus(state, statusColumn)
		icon := watcherIcon(state.Status) + " "
		nameWidth := max(1, m.watcherListViewport.Width-ansi.StringWidthWc(selectionPrefix(selected))-ansi.StringWidthWc(icon)-statusColumn-1)
		name := ansi.TruncateWc(state.Module.Name(), nameWidth, "…")
		padding := max(1, m.watcherListViewport.Width-ansi.StringWidthWc(selectionPrefix(selected))-ansi.StringWidthWc(icon)-ansi.StringWidthWc(name)-statusColumn)
		content.WriteString(selectionPrefix(selected) + lifecycleStyle(state.Status).Render(icon) + selectionLabel(name, selected) + strings.Repeat(" ", padding) + lifecycleStyle(state.Status).Render(status) + "\n")
	}
	m.watcherListContent = strings.TrimSuffix(content.String(), "\n")
	m.watcherListViewport.SetContent(m.watcherListContent)
	m.ensureWatcherListCursorVisible()
}

func watcherStatusColumnWidth(states []runner.BatchState, width int) int {
	limit := max(8, width/3)
	column := 8
	for _, state := range states {
		column = max(column, ansi.StringWidthWc(watcherStatus(state)))
	}
	return min(column, limit)
}

func watcherDisplayStatus(state runner.BatchState, width int) string {
	status := watcherStatus(state)
	if ansi.StringWidthWc(status) <= width {
		return status
	}
	return ansi.TruncateWc(status, width, "…")
}

func (m *model) ensureWatcherListCursorVisible() {
	if m.watcherListCursor < m.watcherListViewport.YOffset {
		m.watcherListViewport.YOffset = m.watcherListCursor
	}
	lastVisible := m.watcherListViewport.YOffset + m.watcherListViewport.Height - 1
	if m.watcherListCursor > lastVisible {
		m.watcherListViewport.YOffset = m.watcherListCursor - m.watcherListViewport.Height + 1
		if m.watcherListViewport.YOffset < 0 {
			m.watcherListViewport.YOffset = 0
		}
	}
}

func watcherStateLine(state runner.BatchState) string {
	return fmt.Sprintf("%s %-30s %s", watcherIcon(state.Status), state.Module.Name(), watcherStatus(state))
}

func watcherIcon(status string) string {
	switch status {
	case "completed":
		return "✓"
	case "failed", "unavailable":
		return "!"
	case runner.StatusAborted:
		// Stopped by the operator, which is neither a failure nor a cancellation of
		// the whole run.
		return "⊘"
	case "cancelled":
		return "×"
	case "skipped":
		return "-"
	case "running":
		return "▶"
	default:
		return "·"
	}
}

func watcherStatus(state runner.BatchState) string {
	status := strings.ToUpper(state.Status)
	switch state.Status {
	case "completed":
		return fmt.Sprintf("%s (exit %d)", status, state.Result.ExitCode)
	case "failed":
		if state.Result.ExitCode >= 0 {
			return fmt.Sprintf("%s (exit %d)", status, state.Result.ExitCode)
		}
		return status + " (abnormal exit)"
	case "cancelled", "unavailable", "skipped":
		return status
	case runner.StatusAborted:
		return status + ": stopped by operator"
	default:
		return status
	}
}

func (m *model) refreshWatcher() {
	states := m.watcherStates()
	if len(states) == 0 {
		m.watcherContent = "No output available."
		m.watcherViewport.SetContent(m.watcherContent)
		return
	}
	if m.watcherListCursor >= len(states) {
		m.watcherListCursor = len(states) - 1
	}
	if m.watcherListCursor < 0 {
		m.watcherListCursor = 0
	}
	state := states[m.watcherListCursor]
	if state.Index >= 0 && state.Index < len(m.allModules) {
		m.watcherSelected = state.Index
	}
	buffer := m.bufferFor(m.watcherSelected)
	if buffer == nil {
		m.watcherContent = "No output yet for this module."
		m.watcherViewport.SetContent(m.watcherContent)
		return
	}
	rawChange := buffer.Changed()
	if rawChange.Equal(m.watcherRawChange) && m.watcherWidth == m.watcherViewport.Width && m.watcherModule == m.watcherSelected {
		if m.watcherFollow {
			m.watcherViewport.GotoBottom()
		}
		return
	}
	m.watcherRawChange = rawChange
	m.watcherWidth = m.watcherViewport.Width
	m.watcherModule = m.watcherSelected
	m.watcherContent = displayOutput(string(buffer.Snapshot()), m.watcherViewport.Width)
	m.watcherViewport.SetContent(m.watcherContent)
	if m.watcherFollow {
		m.watcherViewport.GotoBottom()
	}
}

func wrapWatcherOutput(output string, width int) string {
	if width < 1 {
		width = 1
	}
	const breakSpace = "\ue000"
	wordWrapped := ansi.WrapWc(strings.ReplaceAll(output, " ", breakSpace), width, breakSpace+"\t/-")
	wordWrapped = strings.ReplaceAll(wordWrapped, breakSpace, " ")
	if removeNewlines(wordWrapped) == removeNewlines(output) && fitsWatcherWidth(wordWrapped, width) {
		return wordWrapped
	}
	return ansi.HardwrapWc(output, width, true)
}

func fitsWatcherWidth(output string, width int) bool {
	for _, line := range strings.Split(output, "\n") {
		if ansi.StringWidthWc(line) > width {
			return false
		}
	}
	return true
}

func removeNewlines(value string) string { return strings.ReplaceAll(value, "\n", "") }

func (m *model) watcherView() string {
	if len(m.modules) == 0 && m.batch == nil {
		return title.Render("PwnFlow // EXECUTION WATCHER") + "\n\nNo modules available in this category."
	}
	m.refreshWatcherList()
	m.refreshWatcher()
	states := m.watcherStates()
	if len(states) == 0 {
		return title.Render("PwnFlow // EXECUTION WATCHER") + "\n\nNo executed modules in this scope."
	}
	state := states[m.watcherListCursor]
	module := state.Module
	elapsed := "-"
	if !m.started.IsZero() {
		elapsed = time.Since(m.started).Round(time.Second).String()
	}
	listStyle := paneStyle(m.watcherFocus == focusModules)
	outputStyle := paneStyle(m.watcherFocus == focusOutput)
	headerWidth := m.width - 4
	if headerWidth < 1 {
		headerWidth = 1
	}
	listTitle := paneHeader("MODULE EXECUTION HISTORY", m.watcherFocus == focusModules, headerWidth)
	outputTitle := paneHeader(fmt.Sprintf("OUTPUT // %s", module.Name()), m.watcherFocus == focusOutput, headerWidth)
	return watcherTitle() + "\n" +
		m.batchSummary() + m.watcherSelectionSummary(module.Name(), elapsed) +
		// The status line is where a request to abort is asked and answered, so the
		// watcher has to show it: the confirmation is useless if it is invisible.
		m.watcherStatusLine() +
		listStyle.Render(listTitle+"\n"+m.watcherListViewport.View()) + "\n" +
		outputStyle.Render(outputTitle+"\n"+m.watcherViewport.View()) + "\n" +
		dim.Render(m.watcherFooter())
}

func watcherTitle() string {
	return title.Render("PwnFlow // EXECUTION WATCHER")
}

func (m *model) watcherSelectionSummary(moduleName string, elapsed string) string {
	active := "IDLE"
	if m.batch != nil {
		states, activeIndex, _, _ := m.batch.Snapshot()
		if activeIndex >= 0 && activeIndex < len(states) {
			active = states[activeIndex].Module.Name() + " — " + watcherStatus(states[activeIndex])
		} else if m.running {
			active = "RUNNING"
		}
	}
	width := max(20, m.width-6)
	active = ansi.TruncateWc(active, max(8, width-8), "…")
	states := m.watcherStates()
	selectedStatus := "IDLE"
	if m.watcherListCursor >= 0 && m.watcherListCursor < len(states) {
		selectedStatus = watcherStatus(states[m.watcherListCursor])
	}
	selected := ansi.TruncateWc(moduleName+" — "+selectedStatus, max(8, width-10), "…")
	return fmt.Sprintf("Active:   %s\nSelected: %s\nElapsed:  %s\n", watcherInfoStyle.Render(active), selectedLabelStyle.Render(selected), dim.Render(elapsed))
}

// watcherStatusLine renders the operator-facing status inside the watcher, amber
// while a confirmation is pending and quiet otherwise.
func (m *model) watcherStatusLine() string {
	if m.status == "" {
		return "\n"
	}
	status := m.status
	if status == "Module is not running" {
		status = "Selected action: " + status
	}
	if m.watcherAbortConfirm {
		return wrapPaneStyle(warn, status, max(1, m.width-6)) + "\n"
	}
	return wrapPaneStyle(dim, status, max(1, m.width-6)) + "\n"
}

// watcherFooter advertises the watcher's keys, including the abort binding, and
// drops the least important hint before it would wrap on a narrow terminal.
func (m *model) watcherFooter() string {
	full := "Tab focus   ↑↓/PgUp/PgDn navigate or scroll   Home/End   x abort selected   Q quit   Ctrl+W/Esc close"
	if ansi.StringWidthWc(full)+2 <= max(1, m.width) {
		return full
	}
	short := "↑↓ navigate   x abort selected   Q quit   Ctrl+W/Esc close"
	if ansi.StringWidthWc(short)+2 <= max(1, m.width) {
		return short
	}
	return "x abort selected · Q quit"
}

func (m *model) batchSummary() string {
	width := max(20, m.width-6)
	if m.batch == nil {
		return fmt.Sprintf("%s  %s\n%s\n%s\n", title.Render("MODE"), dim.Render("IDLE"), watcherProgressLine(0, 0, width), dim.Render("COMPLETED 0   RUNNING 0   QUEUED 0   FAILED 0   SKIPPED 0"))
	}
	states, _, _, _ := m.batch.Snapshot()
	completed, running, failed, unavailable, cancelled, skipped, queued := 0, 0, 0, 0, 0, 0, 0
	for _, state := range states {
		switch state.Status {
		case "completed":
			completed++
		case "running":
			running++
		case "failed":
			failed++
		case "unavailable":
			unavailable++
		case "cancelled":
			cancelled++
		case "skipped":
			skipped++
		default:
			queued++
		}
	}
	progress := completed + failed + unavailable + cancelled + skipped
	requested := m.batchRequested
	if requested == 0 {
		requested = len(states)
	}
	mode := ansi.TruncateWc(m.batchName, max(8, width/3), "…")
	modeLine := fmt.Sprintf("%s  %s    %s", title.Render("MODE"), lifecycleStyle(statusForBatch(running, failed, len(states), progress)).Render(mode), dim.Render(ansi.TruncateWc(m.cfg.Domain, max(8, width/3), "…")))
	resolution := fmt.Sprintf("Requested: %d   Executed: %d   Planned-skip: %d", requested, len(states), len(m.batchSkipped))
	metrics := fmt.Sprintf("COMPLETED %d   RUNNING %d   QUEUED %d   FAILED %d   SKIPPED %d", completed, running, queued, failed, skipped)
	return modeLine + "\n" + watcherProgressLine(progress, len(states), width) + "\n" + dim.Render(resolution) + "\n" + watcherMetricLine(metrics, width) + "\n"
}

func statusForBatch(running, failed, total, finished int) string {
	if running > 0 {
		return "running"
	}
	if failed > 0 {
		return "failed"
	}
	if total > 0 && finished == total {
		return "completed"
	}
	return "queued"
}

func watcherProgressLine(done, total, width int) string {
	barWidth := max(8, min(32, width-34))
	filled := 0
	percent := 0
	if total > 0 {
		filled = done * barWidth / total
		percent = done * 100 / total
	}
	bar := lifecycleStyle("completed").Render(strings.Repeat("█", filled)) + dim.Render(strings.Repeat("░", barWidth-filled))
	return fmt.Sprintf("%s %d/%d  [%s] %3d%%", title.Render("PROGRESS"), done, total, bar, percent)
}

func watcherMetricLine(metrics string, width int) string {
	if ansi.StringWidthWc(metrics) <= width {
		return metrics
	}
	return ansi.TruncateWc(metrics, width, "…")
}
