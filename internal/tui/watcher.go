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
	listHeight := (m.height - 11) / 2
	if listHeight < 3 {
		listHeight = 3
	}
	outputHeight := m.height - 10 - listHeight
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
	states := make([]runner.BatchState, len(m.modules))
	for index, module := range m.modules {
		states[index] = runner.BatchState{Index: index, Module: module, Status: "queued"}
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
	for index, state := range states {
		prefix := "  "
		if index == m.watcherListCursor {
			prefix = "> "
		}
		content.WriteString(prefix + watcherStateLine(state) + "\n")
	}
	m.watcherListContent = strings.TrimSuffix(content.String(), "\n")
	m.watcherListViewport.SetContent(m.watcherListContent)
	m.ensureWatcherListCursorVisible()
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
	if state.Index >= 0 && state.Index < len(m.modules) {
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
	return title.Render("PwnFlow // EXECUTION WATCHER") + "\n\n" +
		m.batchSummary() + fmt.Sprintf("Selected: %s   Elapsed: %s\n", module.Name(), elapsed) +
		listStyle.Render(listTitle+"\n"+m.watcherListViewport.View()) + "\n" +
		outputStyle.Render(outputTitle+"\n"+m.watcherViewport.View()) + "\n" +
		dim.Render("Tab focus   ↑↓/PgUp/PgDn navigate or scroll   Home/End   Ctrl+W/Esc close")
}

func (m *model) batchSummary() string {
	if m.batch == nil {
		return "Mode: IDLE   Progress: 0/0\n"
	}
	states, active, _, _ := m.batch.Snapshot()
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
	barWidth := 24
	filled := 0
	if len(states) > 0 {
		filled = progress * barWidth / len(states)
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	activeName := "-"
	if active >= 0 && active < len(states) {
		activeName = states[active].Module.Name()
	}
	return fmt.Sprintf("Mode: %s   Target: %s\nProgress: [%s] %d/%d   Completed: %d   Running: %d   Failed: %d   Unavailable: %d   Cancelled: %d   Skipped: %d   Queued: %d   Active: %s\n", m.batchName, m.cfg.Domain, bar, progress, len(states), completed, running, failed, unavailable, cancelled, skipped, queued, activeName)
}
