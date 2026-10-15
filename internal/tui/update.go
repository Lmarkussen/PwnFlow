package tui

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	findingengine "github.com/pwnflow/pwnflow/internal/findings"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/runner"
)

var ErrQuit = errors.New("quit")

// detailsRefreshedMsg reports that a module's Module Information snapshot was
// recomputed; the frame after it shows the new content.
type detailsRefreshedMsg struct{}

// detailsRefreshInterval throttles the asynchronous refresh. The module decides
// whether the work is actually needed, so this only bounds how often the question is
// asked.
const detailsRefreshInterval = time.Second

// refreshDetailsCommand recomputes the Module Information of the visible modules off
// the render path. The work behind it - a Python capability probe, a revision check, a
// store read - must never run while a frame is drawn, and it is skipped entirely while
// the snapshots are fresh.
func (m *model) refreshDetailsCommand() tea.Cmd {
	refreshers := make([]modules.DetailRefresher, 0, len(m.modules))
	for _, module := range m.modules {
		if refresher, ok := module.(modules.DetailRefresher); ok {
			refreshers = append(refreshers, refresher)
		}
	}
	if len(refreshers) == 0 {
		return nil
	}
	runtime := m.moduleRuntime()
	return func() tea.Msg {
		for _, refresher := range refreshers {
			refresher.RefreshDetails(context.Background(), runtime)
		}
		return detailsRefreshedMsg{}
	}
}

// sudoAuthorisedMsg carries the outcome of the terminal handover that lets sudo
// authenticate the operator. PwnFlow never sees the password: sudo reads it from the
// terminal while the TUI is paused.
type sudoAuthorisedMsg struct{ err error }

// sudoAuthenticate releases the terminal for sudo's own prompt. It is a variable so
// the approval flow can be exercised without a real terminal.
var sudoAuthenticate = func(command *exec.Cmd) tea.Cmd {
	return tea.ExecProcess(command, func(err error) tea.Msg { return sudoAuthorisedMsg{err: err} })
}

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
		// A resize changes how many module rows fit, so the window is recomputed
		// to keep the highlighted module inside the pane.
		m.scrollModuleList()
	case tickMsg:
		quit := m.syncBatch()
		m.refreshFindings()
		if !m.running && m.batchRecorded && !m.analysisPending && !m.batchSummaryShown && m.findings != nil {
			if summary, err := m.findings.Summary(m.ctx, m.targetID); err == nil && summary != "" {
				m.status = summary
				if strings.HasSuffix(summary, "0 pending)") {
					m.batchSummaryShown = true
				}
			}
		}
		m.refreshWatcher()
		m.refreshOutput()
		// A privileged module waiting for renewed authorization is picked up here,
		// off the render path: the batch is paused at that boundary until the
		// operator answers, and the prompt is drawn on the next frame.
		if request, waiting := m.nextRenewal(); waiting {
			m.requestRenewalPrompt(request)
		}
		if quit != nil {
			return m, quit
		}
		// Module Information is recomputed away from rendering, and only when it is
		// stale, so arrow navigation never waits on a probe.
		if time.Since(m.detailsRefreshed) >= detailsRefreshInterval {
			m.detailsRefreshed = time.Now()
			if refresh := m.refreshDetailsCommand(); refresh != nil {
				return m, tea.Batch(tickCmd(), refresh)
			}
		}
		return m, tickCmd()
	case findingsCompleteMsg:
		m.analysisPending = false
		m.batchSummaryShown = true
		if msg.err != nil {
			m.status = "Findings analysis partial: " + msg.err.Error()
		} else if m.findings != nil {
			if summary, err := m.findings.Summary(m.ctx, m.targetID); err == nil {
				m.status = summary
			}
		}
		return m, nil
	case findingsReanalysisMsg:
		if msg.err != nil {
			m.status = "PXEThief reanalysis failed: " + msg.err.Error()
		} else {
			m.status = "PXEThief historical reanalysis queued"
		}
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	case sudoAuthorisedMsg:
		return m, m.finishElevation(msg.err)
	case detailsRefreshedMsg:
		return m, nil
	case tea.MouseMsg:
		if m.findingsView {
			switch msg.Button {
			case tea.MouseButtonWheelUp:
				m.findingCursor -= 3
			case tea.MouseButtonWheelDown:
				m.findingCursor += 3
			default:
				return m, nil
			}
			if m.findingCursor < 0 {
				m.findingCursor = 0
			}
			if m.findingCursor >= len(m.findingRows) {
				m.findingCursor = max(0, len(m.findingRows)-1)
			}
			m.keepFindingVisible()
		}
		return m, nil
	}
	return m, nil
}

func (m *model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if m.findingsView {
		return m.handleFindingsKey(key)
	}
	if m.quitConfirm {
		switch key {
		case "y", "Y":
			if m.batchComplete() {
				m.quitConfirm = false
				m.running = false
				return m, tea.Quit
			}
			m.quitConfirm = false
			m.quitAfterCancel = true
			m.quitCancelDeadline = time.Now().Add(5 * time.Second)
			m.status = "cancelling; waiting for the active batch to stop"
			m.cancelBatch()
		case "n", "N", "esc":
			m.quitConfirm = false
			m.status = "running"
		}
		return m, nil
	}

	// A module that needs privileges the process does not have asks here, before
	// anything runs. Only an explicit "y" approves; any other key, including an empty
	// answer, declines and lets the rest of the selected modules run.
	if m.elevationPrompt {
		switch key {
		case "y", "Y":
			m.elevationPrompt = false
			if m.renewing {
				m.status = "authenticating sudo again for " + m.renewalModule + "; complete sudo's own prompt"
				return m, sudoAuthenticate(exec.Command("sudo", "-v"))
			}
			m.status = "authenticating sudo for " + strings.Join(m.elevationModules, ", ") + "; complete sudo's own prompt"
			return m, sudoAuthenticate(exec.Command("sudo", "-v"))
		case "ctrl+c", "q":
			// Fall through to the process-wide handlers, so those keys keep working.
		default:
			if m.renewing {
				// The batch keeps running: the module that asked is told no, and
				// its privileged work is skipped.
				m.elevationPrompt = false
				m.answerRenewal(false)
				m.status = "sudo authorization was not renewed; the privileged module is skipped and the batch continues"
				return m, nil
			}
			return m, m.declineElevation("elevated execution was not approved")
		}
	}

	// The interactive input prompt owns the keyboard while it is open: the value
	// is typed, stored for this assessment, or skipped, and the plan continues
	// afterwards. Ctrl+C abandons the whole plan.
	if m.inputPrompt {
		switch key {
		case "enter":
			return m, m.acceptInput()
		case "esc":
			return m, m.skipInput()
		case "ctrl+c":
			m.cancelPlan()
			return m, nil
		}
		var command tea.Cmd
		m.textInput, command = m.textInput.Update(msg)
		return m, command
	}

	// A plan that is not plain enumeration asks for one decision, naming the
	// modules it will run: only "y" approves them, and any other answer runs the
	// rest of the plan without them.
	if m.approvalPrompt {
		switch key {
		case "y", "Y":
			return m, m.approvePlan()
		case "ctrl+c":
			m.cancelPlan()
			return m, nil
		case "q":
			// Fall through to the process-wide handlers.
		default:
			return m, m.declinePlan()
		}
	}

	// An operator abort is confirmed here, and applies to the execution they
	// selected when they asked. Only an explicit yes confirms; every other answer,
	// Escape included, leaves the module running.
	if m.watcherAbortConfirm {
		switch key {
		case "y", "Y":
			return m, m.confirmWatcherAbort()
		case "ctrl+c", "q":
			// These keep their process-wide meaning: give up the question and let the
			// handler below act on it.
			m.watcherAbortConfirm = false
			m.watcherAbortIndex, m.watcherAbortName = 0, ""
		default:
			return m, m.declineWatcherAbort()
		}
	}

	// Handle process-wide controls before any focus-specific handler. The
	// latter intentionally return early for navigation and watcher keys.
	switch key {
	case "q":
		if m.running && !m.batchComplete() {
			m.quitConfirm = true
			m.status = "batch is running; cancel and quit? [y/N]"
			return m, nil
		}
		m.running = false
		return m, tea.Quit
	case "ctrl+c":
		if m.running && !m.batchComplete() {
			m.cancelBatch()
			m.status = "cancelling"
			return m, nil
		}
		m.running = false
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
		// A registry-wide batch keeps its history and output even when the scope it
		// was started from is no longer visible.
		if len(m.modules) == 0 && m.batch == nil {
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
	case "f":
		if m.watcher {
			m.findingsFromWatcher = true
			m.watcher = false
			m.findingsView = true
			m.findingDetail = false
			m.findingCategoryView = true
			m.findingCategory = ""
			m.findingCursor = 0
			m.refreshFindings()
			return m, nil
		}
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
			case "x":
				return m, m.requestWatcherAbort()
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
			rows := m.navigationRows()
			m.navigationRow = (m.navigationRow + rows - 1) % rows
		case "down", "j":
			m.navigationRow = (m.navigationRow + 1) % m.navigationRows()
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
		m.moveModuleCursor(-1)
	case "down", "j":
		m.moveModuleCursor(1)
	case "pgup", "ctrl+u":
		m.pageModuleCursor(-1)
	case "pgdown", "ctrl+d":
		m.pageModuleCursor(1)
	case "home":
		m.goModuleEdge(false)
	case "end":
		m.goModuleEdge(true)
	case " ":
		if len(m.modules) > 0 {
			moduleID := m.modules[m.cursor].ID()
			m.selectedModules[moduleID] = !m.selectedModules[moduleID]
			m.selected = m.cursor
			// Toggling leaves the cursor where it is, so the window only has to
			// be re-checked, not recomputed.
			m.scrollModuleList()
		}
	case "enter":
		if !m.running {
			if len(m.modules) == 0 {
				return m, nil
			}
			return m, m.execute(m.cursor)
		}
	case "r":
		// R is registry-wide: it never depends on which scope is visible, so an
		// empty or different scope cannot hide the operator's selection.
		if !m.running {
			return m, m.executeSelected()
		}
	case "a":
		if !m.running {
			return m, m.executeAll()
		}
	case "i":
		if !m.running {
			return m, m.executeInput(m.cursor)
		}
	case "?":
		m.status = helpText
	case "f":
		m.findingsView = true
		m.findingsFromWatcher = false
		m.findingDetail = false
		m.findingSearchMode = false
		m.findingCategoryView = true
		m.findingCategory = ""
		m.findingCursor = 0
		m.refreshFindings()
	}
	return m, nil
}

func (m *model) handleFindingsKey(key string) (tea.Model, tea.Cmd) {
	if m.findingSearchMode {
		switch key {
		case "enter", "esc":
			m.findingSearchMode = false
		case "backspace":
			if len(m.findingSearch) > 0 {
				m.findingSearch = m.findingSearch[:len(m.findingSearch)-1]
			}
		default:
			if len(key) == 1 && key >= " " && key <= "~" {
				m.findingSearch += key
			}
		}
		m.refreshFindings()
		return m, nil
	}
	if m.findingCategoryView {
		switch key {
		case "ctrl+w":
			m.findingsView = false
			m.watcher = m.findingsFromWatcher || m.batch != nil
			if m.watcher {
				m.resizeWatcher()
			}
			m.findingsFromWatcher = false
		case "esc":
			if m.findingCategory != "" {
				m.findingCategory = ""
				m.findingCursor = 0
				m.refreshFindings()
				return m, nil
			}
			m.findingsView = false
			if m.findingsFromWatcher {
				m.watcher = true
				m.resizeWatcher()
			}
			m.findingsFromWatcher = false
		case "up", "k":
			m.findingCursor--
		case "down", "j":
			m.findingCursor++
		case "home":
			m.findingCursor = 0
		case "end":
			m.findingCursor = len(m.findingCategories) - 1
		case "pgup":
			m.findingCursor -= 5
		case "pgdown":
			m.findingCursor += 5
		case "enter":
			if len(m.findingCategories) > 0 {
				m.findingCategory = m.findingCategories[m.findingCursor].Key
				m.findingCategoryView = false
				m.findingCursor = 0
				m.findingTop = 0
				m.refreshFindings()
			}
		case "/":
			m.findingSearchMode = true
		case "f":
			m.findingViewMode = "findings"
		case "o":
			m.findingViewMode = "observations"
		case "a":
			m.findingViewMode = "all"
		}
		if m.findingCursor < 0 {
			m.findingCursor = 0
		}
		if m.findingCursor >= len(m.findingCategories) {
			m.findingCursor = max(0, len(m.findingCategories)-1)
		}
		m.refreshFindings()
		return m, nil
	}
	if m.findingDetail {
		switch key {
		case "esc", "enter":
			m.findingDetail = false
		case "up", "k":
			m.findingCursor--
		case "down", "j":
			m.findingCursor++
		}
		if m.findingCursor < 0 {
			m.findingCursor = 0
		}
		if m.findingCursor >= len(m.findingRows) {
			m.findingCursor = max(0, len(m.findingRows)-1)
		}
		return m, nil
	}
	switch key {
	case "ctrl+w":
		m.findingsView = false
		m.watcher = m.findingsFromWatcher || m.batch != nil
		if m.watcher {
			m.resizeWatcher()
		}
		m.findingsFromWatcher = false
	case "esc":
		if m.findingCategory != "" {
			m.findingCategory = ""
			m.findingCategoryView = true
			m.findingCursor = 0
			m.findingDetail = false
			m.refreshFindings()
			return m, nil
		}
		m.findingsView = false
		if m.findingsFromWatcher {
			m.watcher = true
			m.resizeWatcher()
		}
		m.findingsFromWatcher = false
	case "up", "k":
		m.findingCursor--
	case "down", "j":
		m.findingCursor++
	case "pgup":
		m.findingCursor -= 10
	case "pgdown":
		m.findingCursor += m.findingPageSize()
	case "home":
		m.findingCursor = 0
	case "end":
		m.findingCursor = len(m.findingRows) - 1
	case "f":
		m.findingViewMode = "findings"
	case "o":
		m.findingViewMode = "observations"
	case "a":
		m.findingViewMode = "all"
	case "enter":
		if len(m.findingRows) > 0 {
			m.findingDetail = true
		}
	case "/":
		m.findingSearchMode = true
	case "1":
		m.findingSeverity = "high"
	case "2":
		m.findingSeverity = "medium"
	case "3":
		m.findingSeverity = "informational"
	case "0":
		m.findingSeverity = ""
	case "p":
		return m, m.reanalyzePXEThief()
	}
	if m.findingCursor < 0 {
		m.findingCursor = 0
	}
	if m.findingCursor >= len(m.findingRows) {
		m.findingCursor = max(0, len(m.findingRows)-1)
	}
	m.keepFindingVisible()
	m.refreshFindings()
	return m, nil
}

func (m *model) reanalyzePXEThief() tea.Cmd {
	if m.findings == nil || m.db == nil {
		m.status = "PXEThief reanalysis requires the assessment database"
		return nil
	}
	return func() tea.Msg {
		executionID, err := m.db.LatestExecutionForTool(context.Background(), m.targetID, "PXEThief")
		if err != nil {
			return findingsReanalysisMsg{err: err}
		}
		artifactRoot := filepath.Join(m.cfg.ResultsRoot(), "Enumeration", "PXEThief", "artifacts")
		return findingsReanalysisMsg{err: m.findings.Submit(findingengine.Job{AssessmentID: m.targetID, ExecutionID: executionID, SourceTool: "PXEThief", ArtifactPath: artifactRoot, ObservedAt: time.Now().UTC(), Force: true})}
	}
}

func (m *model) cancelBatch() {
	if m.batch != nil {
		m.batch.Cancel()
	}
}

func (m *model) batchComplete() bool {
	if m.batch == nil {
		return !m.running
	}
	select {
	case <-m.batch.Done():
		return true
	default:
		return false
	}
}

func (m *model) closeWatcher() {
	m.watcher = false
	m.focus = m.focusBeforeWatcher
}

// execute runs the highlighted module, and only that module. A module that needs
// a value from the operator is asked before anything starts.
func (m *model) execute(index int) tea.Cmd {
	if index < 0 || index >= len(m.modules) {
		return nil
	}
	module := m.modules[index]
	if reason := m.moduleAvailability(module); reason != "" {
		m.status = "selected module is unavailable: " + reason
		return nil
	}
	if status, reason := m.moduleStatus(module); status == "UNAVAILABLE" {
		m.status = "selected module is unavailable: " + reason
		return nil
	}
	return m.startPlan(m.singlePlan(module))
}

// executeSelected builds the batch from the global selected-module set: every
// explicitly selected module in the registry, whatever tool family, category, or
// protocol happens to be visible. Registry order keeps the batch deterministic,
// and a module the operator selected is an explicit decision, so no further
// approval is asked for.
func (m *model) executeSelected() tea.Cmd {
	if len(m.selectedModuleIDs()) == 0 {
		m.status = "no modules selected; press Space to select a module"
		return nil
	}
	p := m.selectionPlan()
	if len(p.indices) == 0 && !p.configureOnly {
		m.status = "selected modules cannot run: " + strings.Join(p.skipped, "; ")
		return nil
	}
	return m.startPlan(p)
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

// executeAll is the YOLO key. It builds its plan from the entire registry - every
// tool family, category, and protocol - so nothing about the visible scope, the
// focus, the scroll offset, or the selection can change what it considers. Values
// the plan needs are collected first, and modules that are not plain enumeration
// are approved by the operator, in the plan, before anything runs.
func (m *model) executeAll() tea.Cmd {
	return m.startPlan(m.globalPlan())
}

// executeInput opens the prompt for the highlighted module's required values
// without running it, so an operator can configure a module now and run it later.
func (m *model) executeInput(index int) tea.Cmd {
	if index < 0 || index >= len(m.modules) {
		return nil
	}
	module := m.modules[index]
	requester, ok := module.(modules.InputRequester)
	if !ok || len(requester.MissingInputs(m.moduleRuntime())) == 0 {
		m.status = module.Name() + " needs no input"
		return nil
	}
	return m.startPlan(m.configurePlan(module))
}

// startBatch runs the supplied registry-wide module indices as one batch. Items,
// output buffers, watcher state, and history all use registry indices, so a batch
// can mix tool families without depending on what is currently visible.
// startBatch asks for any elevation the batch needs before it starts. A module that
// cannot run without privileges is never started silently and never elevates itself:
// the operator answers once for the run, and only that module is affected either way.
func (m *model) startBatch(indices []int, name string) tea.Cmd {
	m.batchElevation = map[string]bool{}
	needed, reason := m.elevationNeeded(indices)
	if len(needed) > 0 {
		m.pendingIndices, m.pendingName, m.elevationModules = indices, name, needed
		m.elevationPrompt = true
		m.status = fmt.Sprintf("%s includes tools requiring local sudo privileges (%s): %s. Authenticate with sudo before starting? [y/N]",
			name, strings.Join(needed, ", "), reason)
		return nil
	}
	return m.runBatch(indices, name)
}

// elevationNeeded reports which modules in the batch need privileges the process does
// not have, and why the first of them needs them.
func (m *model) elevationNeeded(indices []int) ([]string, string) {
	needed := make([]string, 0)
	reason := ""
	for _, index := range indices {
		if index < 0 || index >= len(m.allModules) {
			continue
		}
		requester, ok := m.allModules[index].(modules.ElevationRequester)
		if !ok {
			continue
		}
		required, why := requester.ElevationRequired()
		if !required || m.batchElevation[m.allModules[index].ID()] {
			continue
		}
		needed = append(needed, m.allModules[index].ID())
		if reason == "" {
			reason = why
		}
	}
	return needed, reason
}

// finishElevation continues the batch once sudo has answered. A successful
// authentication marks the approved modules for this run only; a refused or cancelled
// one skips exactly those modules.
func (m *model) finishElevation(err error) tea.Cmd {
	if m.renewing {
		// A renewal happens while the batch is paused before a privileged module:
		// there is nothing to start, only an answer to give.
		m.answerRenewal(err == nil)
		if err != nil {
			m.status = "sudo authentication failed or was cancelled; the privileged module is skipped and the batch continues"
			return nil
		}
		m.status = "sudo authorization renewed; the batch continues"
		return nil
	}
	if err != nil {
		return m.declineElevation("sudo authentication failed or was cancelled; " + err.Error())
	}
	for _, id := range m.elevationModules {
		m.batchElevation[id] = true
	}
	indices, name := m.pendingIndices, m.pendingName
	m.pendingIndices, m.pendingName, m.elevationModules = nil, "", nil
	return m.runBatch(indices, name)
}

// declineElevation reports the decision and runs the rest of the batch, so an
// unrelated selected module is never held up by a module that needs privileges.
func (m *model) declineElevation(message string) tea.Cmd {
	skipped, indices, name := m.elevationModules, m.pendingIndices, m.pendingName
	m.elevationPrompt, m.pendingIndices, m.pendingName, m.elevationModules = false, nil, "", nil
	remaining := make([]int, 0, len(indices))
	for _, index := range indices {
		if index >= 0 && index < len(m.allModules) && contains(skipped, m.allModules[index].ID()) {
			continue
		}
		remaining = append(remaining, index)
	}
	if len(remaining) == 0 {
		m.status = message + "; no other selected module to run"
		return nil
	}
	// The status is set after the batch starts, because starting it reports "running".
	command := m.runBatch(remaining, name)
	m.status = message + "; running the remaining selected module(s)"
	return command
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// runBatch starts the batch itself, with the operator's approval already established.
func (m *model) runBatch(indices []int, name string) tea.Cmd {
	items := make([]runner.BatchItem, 0, len(indices))
	for _, index := range indices {
		if index < 0 || index >= len(m.allModules) {
			continue
		}
		buffer := runner.NewBuffer(512 * 1024)
		m.outputBuffers[index] = buffer
		items = append(items, runner.BatchItem{Index: index, Module: m.allModules[index], ModuleID: m.allModuleIDs[index], Buffer: buffer})
	}
	if len(items) == 0 {
		m.status = "no eligible modules to run"
		return nil
	}
	items = orderBatch(items)
	m.batchItems = items
	m.batch = runner.NewBatchRun(items)
	m.batchRecorded = false
	m.batchSummaryShown = false
	m.analysisPending = false
	m.batchName = name
	m.running = true
	m.status = "running"
	m.started = time.Now()
	m.outputRawChange = time.Time{}
	m.outputFollow = true
	runtime := m.moduleRuntime()
	runtime.Password = m.cfg.Password
	r := runner.Runner{Secrets: []string{m.cfg.Password}, BufferLimit: 512 * 1024}
	m.batch.Start(m.ctx, items, runtime, m.cfg.ResultsRoot(), r)
	return nil
}

// orderBatch keeps the batch in registry order except where a module declares that
// it must run after another one, such as a prober that consumes a discovery
// module's fresh results. The relation is resolved by a stable topological pass, so
// the order stays deterministic whatever order the items arrived in.
func orderBatch(items []runner.BatchItem) []runner.BatchItem {
	position := make(map[string]int, len(items))
	for index, item := range items {
		position[item.Module.ID()] = index
	}
	ordered := make([]runner.BatchItem, 0, len(items))
	placed := make(map[int]bool, len(items))
	var visit func(index int)
	visit = func(index int) {
		if placed[index] {
			return
		}
		placed[index] = true
		if provider, ok := items[index].Module.(modules.BatchPrerequisiteProvider); ok {
			for _, required := range provider.BatchPrerequisites() {
				if requiredIndex, found := position[required]; found && requiredIndex != index {
					visit(requiredIndex)
				}
			}
		}
		ordered = append(ordered, items[index])
	}
	for index := range items {
		visit(index)
	}
	return ordered
}

func (m *model) syncBatch() tea.Cmd {
	if m.batch == nil {
		if m.quitAfterCancel && !m.quitCancelDeadline.IsZero() && time.Now().After(m.quitCancelDeadline) {
			m.running = false
			m.quitAfterCancel = false
			m.status = "active process did not stop within the shutdown window; exiting"
			return tea.Quit
		}
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
					if state.Index >= 0 && state.Index < len(m.allModuleIDs) {
						executionID, err := m.db.RecordExecutionID(m.ctx, m.targetID, m.allModuleIDs[state.Index], state.Result.Started, state.Result.Finished, state.Status, state.Result.ExitCode, state.Result.OutputPath, errorText(state.Result.Err))
						if err == nil && m.findings != nil {
							module := state.Module
							artifact := findingengine.DiscoverArtifact(module.Tool(), state.Result.OutputPath)
							_ = m.findings.Submit(findingengine.Job{AssessmentID: m.targetID, ExecutionID: executionID, SourceTool: module.Tool(), ArtifactPath: artifact, ObservedAt: state.Result.Finished})
						}
					}
				}
			}
			m.batchRecorded = true
			m.analysisPending = m.findings != nil
			m.batchElevation = map[string]bool{}
			m.detailsRefreshed = time.Time{}
			m.status = fmt.Sprintf("%s complete: %d modules, finished %s", m.batchName, len(states), finished.Format("15:04:05"))
		}
		if m.quitAfterCancel {
			m.quitCancelDeadline = time.Time{}
			return tea.Quit
		}
		if m.analysisPending && !m.batchSummaryShown {
			m.status = "enumeration complete; findings analysis pending"
			m.batchSummaryShown = true
			return m.waitForFindings()
		}
	default:
		if m.quitAfterCancel && !m.quitCancelDeadline.IsZero() && time.Now().After(m.quitCancelDeadline) {
			m.running = false
			m.quitAfterCancel = false
			m.status = "active process did not stop within the shutdown window; exiting"
			return tea.Quit
		}
	}
	return nil
}

func (m *model) waitForFindings() tea.Cmd {
	return func() tea.Msg {
		if m.findings == nil {
			return findingsCompleteMsg{}
		}
		return findingsCompleteMsg{err: m.findings.Wait(context.Background())}
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
