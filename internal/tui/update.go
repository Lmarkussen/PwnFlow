package tui

import (
	"errors"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/runner"
)

var ErrQuit = errors.New("quit")

func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// Ignore transient zero dimensions during alternate-screen transitions;
		// retain the last known safe size until the terminal reports a real one.
		if msg.Width > 0 {
			m.width = msg.Width
		}
		if msg.Height > 0 {
			m.height = msg.Height
		}
		if m.width <= 0 {
			m.width = 80
		}
		if m.height <= 0 {
			m.height = 24
		}
		m.resizeWatcher()
		m.resizeOutput()
	case tickMsg:
		quit := m.syncBatch()
		m.refreshWatcher()
		m.refreshOutput()
		if quit != nil {
			return m, quit
		}
		return m, tickCmd()
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if m.quitConfirm {
		switch key {
		case "y", "Y":
			m.quitConfirm = false
			m.quitAfterCancel = true
			m.status = "cancelling; waiting for the active batch to stop"
			m.cancelBatch()
		case "n", "N", "esc":
			m.quitConfirm = false
			m.status = "running"
		}
		return m, nil
	}

	// Handle process-wide controls before any focus-specific handler. The
	// latter intentionally return early for navigation and watcher keys.
	switch key {
	case "q":
		if m.running {
			m.quitConfirm = true
			m.status = "batch is running; cancel and quit? [y/N]"
			return m, nil
		}
		return m, tea.Quit
	case "ctrl+c":
		if m.running {
			m.cancelBatch()
			m.status = "cancelling"
			return m, nil
		}
		return m, tea.Quit
	case "esc":
		if m.watcher {
			m.closeWatcher()
		} else {
			m.focus = focusNavigation
		}
		return m, nil
	case "ctrl+w":
		if m.watcher {
			m.closeWatcher()
			return m, nil
		}
		if len(m.modules) == 0 {
			m.status = "category is inactive; no watcher output"
			return m, nil
		}
		m.focusBeforeWatcher = m.focus
		m.watcher = true
		m.watcherFocus = focusModules
		m.watcherFollow = true
		m.resizeWatcher()
		m.refreshWatcher()
		return m, nil
	}

	if m.watcher {
		if key == "tab" {
			if m.watcherFocus == focusModules {
				m.watcherFocus = focusOutput
			} else {
				m.watcherFocus = focusModules
			}
			return m, nil
		}
		if m.watcherFocus == focusModules {
			switch key {
			case "up", "k":
				m.moveWatcherSelection(-1)
			case "down", "j":
				m.moveWatcherSelection(1)
			case "pgup", "ctrl+u":
				m.moveWatcherSelection(-max(1, m.watcherListViewport.Height))
			case "pgdown", "ctrl+d":
				m.moveWatcherSelection(max(1, m.watcherListViewport.Height))
			case "home":
				m.setWatcherSelection(0, true)
			case "end":
				m.setWatcherSelection(len(m.watcherStates())-1, true)
			default:
				return m, nil
			}
			return m, nil
		}
		switch key {
		case "up", "k":
			m.watcherFollow = false
			m.watcherViewport.LineUp(1)
		case "down", "j":
			m.watcherViewport.LineDown(1)
		case "pgup", "ctrl+u":
			m.watcherFollow = false
			m.watcherViewport.ViewUp()
		case "pgdown", "ctrl+d":
			m.watcherViewport.ViewDown()
		case "end":
			m.watcherFollow = true
			m.watcherViewport.GotoBottom()
		case "home":
			m.watcherFollow = false
			m.watcherViewport.GotoTop()
		default:
			return m, nil
		}
		return m, nil
	}
	if key == "tab" {
		m.focus = (m.focus + 1) % 3
		return m, nil
	}
	if key == "shift+tab" {
		m.focus = (m.focus + 2) % 3
		return m, nil
	}
	if m.focus == focusNavigation {
		switch key {
		case "up", "k":
			m.navigationRow = (m.navigationRow + 2) % 3
		case "down", "j":
			m.navigationRow = (m.navigationRow + 1) % 3
		case "left", "h", "right", "l":
			if !m.running {
				delta := 1
				if key == "left" || key == "h" {
					delta = -1
				}
				m.changeNavigationValue(delta)
			}
		}
		return m, nil
	}
	if m.focus == focusOutput {
		switch key {
		case "up", "k":
			m.outputFollow = false
			m.outputViewport.LineUp(1)
			return m, nil
		case "down", "j":
			m.outputViewport.LineDown(1)
			return m, nil
		case "pgup", "ctrl+u":
			m.outputFollow = false
			m.outputViewport.ViewUp()
			return m, nil
		case "pgdown", "ctrl+d":
			m.outputViewport.ViewDown()
			return m, nil
		case "home":
			m.outputFollow = false
			m.outputViewport.GotoTop()
			return m, nil
		case "end":
			m.outputFollow = true
			m.outputViewport.GotoBottom()
			return m, nil
		}
	}
	switch key {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.modules)-1 {
			m.cursor++
		}
	case " ":
		if len(m.modules) > 0 {
			moduleID := m.modules[m.cursor].ID()
			m.selectedModules[moduleID] = !m.selectedModules[moduleID]
			m.selected = m.cursor
		}
	case "enter", "r":
		if !m.running {
			if len(m.modules) == 0 {
				return m, nil
			}
			if key == "r" {
				return m, m.executeSelected()
			}
			return m, m.execute(m.cursor)
		}
	case "a":
		if !m.running {
			return m, m.executeAll()
		}
	case "pgup", "ctrl+u":
		if m.watcher {
			m.watcherFollow = false
			m.watcherViewport.ViewUp()
		}
	case "pgdown", "ctrl+d":
		if m.watcher {
			m.watcherViewport.ViewDown()
		}
	case "end":
		if m.watcher {
			m.watcherFollow = true
			m.watcherViewport.GotoBottom()
		}
	case "home":
		if m.watcher {
			m.watcherFollow = false
			m.watcherViewport.GotoTop()
		}
	case "?":
		m.status = helpText
	}
	return m, nil
}

func (m *model) cancelBatch() {
	if m.batch != nil {
		m.batch.Cancel()
	}
}

func (m *model) closeWatcher() {
	m.watcher = false
	m.focus = m.focusBeforeWatcher
}

// execute runs the highlighted module. Eligibility is decided per module through
// moduleAvailability, so an enabled module in any registered family can run while
// policy-disabled modules stay unavailable. YOLO keeps its own narrower gate.
func (m *model) execute(index int) tea.Cmd {
	if index < 0 || index >= len(m.modules) {
		return nil
	}
	if reason := m.moduleAvailability(m.modules[index]); reason != "" {
		m.status = "selected module is unavailable: " + reason
		return nil
	}
	return m.startBatch([]int{index}, "RUN")
}

func (m *model) executeSelected() tea.Cmd {
	indices := make([]int, 0, len(m.modules))
	blocked := false
	for i := range m.modules {
		if !m.selectedModules[m.modules[i].ID()] {
			continue
		}
		if m.moduleAvailability(m.modules[i]) != "" {
			blocked = true
			continue
		}
		indices = append(indices, i)
	}
	if len(indices) == 0 {
		if blocked {
			m.status = "selected modules are unavailable in the current scope"
			return nil
		}
		m.status = "no modules selected; press Space to select a module"
		return nil
	}
	return m.startBatch(indices, "SELECTED")
}

func (m *model) setWatcherSelection(position int, manual bool) {
	states := m.watcherStates()
	if len(states) == 0 {
		return
	}
	if position < 0 {
		position = 0
	}
	if position >= len(states) {
		position = len(states) - 1
	}
	m.watcherListCursor = position
	if manual {
		m.watcherAuto = false
	}
	if states[position].Index >= 0 {
		m.watcherSelected = states[position].Index
	}
	m.watcherModule = -1
	m.refreshWatcherList()
	m.refreshWatcher()
}

func (m *model) moveWatcherSelection(delta int) {
	m.setWatcherSelection(m.watcherListCursor+delta, true)
}

func (m *model) executeAll() tea.Cmd {
	if !m.yoloScope() {
		m.status = "category is inactive; no modules executed"
		return nil
	}
	indices := make([]int, 0, len(m.modules))
	for i := range m.modules {
		if m.moduleAvailability(m.modules[i]) == "" {
			indices = append(indices, i)
		}
	}
	if len(indices) == 0 {
		m.status = "no available modules in the current scope"
		return nil
	}
	return m.startBatch(indices, "YOLO")
}

// yoloScope gates category-scoped YOLO runs. It stays limited to NetExec
// enumeration so a module registered in another family - RustHound-CE, for
// instance - can never be swept into a YOLO batch.
func (m *model) yoloScope() bool {
	return m.toolFamilyIndex < len(m.toolFamilies) && m.categoryIndex < len(m.categories) && m.categories[m.categoryIndex] == modules.CategoryEnumeration && m.toolFamilies[m.toolFamilyIndex] == modules.ToolFamilyNetExec
}

func (m *model) startBatch(indices []int, name string) tea.Cmd {
	items := make([]runner.BatchItem, 0, len(indices))
	for _, index := range indices {
		buffer := runner.NewBuffer(512 * 1024)
		m.outputBuffers[m.moduleKeys[index]] = buffer
		items = append(items, runner.BatchItem{Index: index, Module: m.modules[index], ModuleID: m.moduleIDs[index], Buffer: buffer})
	}
	m.batchItems = items
	m.batch = runner.NewBatchRun(items)
	m.batchRecorded = false
	m.batchName = name
	m.running = true
	m.status = "running"
	m.started = time.Now()
	m.outputRawChange = time.Time{}
	m.outputFollow = true
	runtime := &modules.Runtime{Target: m.cfg.Target, Domain: m.cfg.Domain, Username: m.cfg.Username, Password: m.cfg.Password, ResultsRoot: m.cfg.ResultsRoot()}
	r := runner.Runner{Secrets: []string{m.cfg.Password}, BufferLimit: 512 * 1024}
	m.batch.Start(m.ctx, items, runtime, m.cfg.ResultsRoot(), r)
	return nil
}

func (m *model) syncBatch() tea.Cmd {
	if m.batch == nil {
		return nil
	}
	states, active, _, finished := m.batch.Snapshot()
	if m.watcherAuto && active >= 0 && active < len(states) {
		m.setWatcherSelection(active, false)
	}
	select {
	case <-m.batch.Done():
		m.running = false
		if !m.batchRecorded {
			if m.db != nil {
				for _, state := range states {
					if state.Index >= 0 && state.Index < len(m.moduleIDs) {
						_ = m.db.RecordExecution(m.ctx, m.targetID, m.moduleIDs[state.Index], state.Result.Started, state.Result.Finished, state.Status, state.Result.ExitCode, state.Result.OutputPath, errorText(state.Result.Err))
					}
				}
			}
			m.batchRecorded = true
			m.status = fmt.Sprintf("%s complete: %d modules, finished %s", m.batchName, len(states), finished.Format("15:04:05"))
		}
		if m.quitAfterCancel {
			return tea.Quit
		}
	default:
	}
	return nil
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
