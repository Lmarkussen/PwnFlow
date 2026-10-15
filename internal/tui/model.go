package tui

import (
	"context"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/runner"
	"github.com/pwnflow/pwnflow/internal/storage"
)

type model struct {
	ctx                 context.Context
	cfg                 config.Config
	db                  *storage.DB
	modules             []modules.Module
	moduleIDs           []int64
	moduleKeys          []int
	allModules          []modules.Module
	allModuleIDs        []int64
	endpoints           modules.EndpointStore
	availability        map[string]string
	toolFamilies        []modules.ToolFamily
	toolFamilyIndex     int
	categories          []modules.Category
	categoryIndex       int
	protocols           []modules.Protocol
	protocolIndex       int
	targetID            int64
	selected, cursor    int
	selectedModules     map[string]bool
	running             bool
	watcher             bool
	focusBeforeWatcher  paneFocus
	quitConfirm         bool
	quitAfterCancel     bool
	buffer              *runner.Buffer
	last                []byte
	status              string
	started             time.Time
	width, height       int
	version             string
	outputBuffers       map[int]*runner.Buffer
	batch               *runner.BatchRun
	batchItems          []runner.BatchItem
	batchRecorded       bool
	batchName           string
	watcherSelected     int
	watcherListCursor   int
	watcherAuto         bool
	watcherFocus        paneFocus
	watcherListViewport viewport.Model
	watcherListContent  string
	watcherListWidth    int
	focus               paneFocus
	navigationRow       int
	outputViewport      viewport.Model
	outputFollow        bool
	outputContent       string
	outputRawChange     time.Time
	outputWidth         int
	outputModule        int
	watcherViewport     viewport.Model
	watcherFollow       bool
	watcherContent      string
	watcherRawChange    time.Time
	watcherWidth        int
	watcherModule       int
}

type tickMsg time.Time

func newModel(ctx context.Context, cfg config.Config, db *storage.DB, registered []modules.Module, moduleIDs []int64, targetID int64, version string, availability ...map[string]string) *model {
	moduleAvailability := map[string]string{}
	if len(availability) > 0 && availability[0] != nil {
		moduleAvailability = availability[0]
	}
	m := &model{ctx: ctx, cfg: cfg, db: db, allModules: registered, allModuleIDs: moduleIDs, availability: moduleAvailability, toolFamilies: modules.ToolFamilies(), targetID: targetID, version: version, selectedModules: make(map[string]bool), outputBuffers: make(map[int]*runner.Buffer), outputViewport: viewport.New(1, 1), outputFollow: true, outputModule: -1, watcherViewport: viewport.New(1, 1), watcherListViewport: viewport.New(1, 1), watcherFollow: true, watcherModule: -1, watcherAuto: true, watcherFocus: focusModules, focusBeforeWatcher: focusNavigation, width: 80, height: 24}
	m.endpoints = newEndpointStore(db)
	m.refreshNavigation()
	m.resizeOutput()
	return m
}

// moduleRuntime is the configuration modules run and report with: the operator's
// target, domain, and credentials, and the assessment's discovery store.
func (m *model) moduleRuntime() *modules.Runtime {
	runtime := &modules.Runtime{Target: m.cfg.Target, Domain: m.cfg.Domain, Username: m.cfg.Username, ResultsRoot: m.cfg.ResultsRoot()}
	if m.endpoints != nil {
		runtime.Endpoints = m.endpoints
	}
	return runtime
}

func (m *model) refreshNavigation() {
	if len(m.toolFamilies) == 0 {
		m.categories, m.protocols = nil, []modules.Protocol{modules.ProtocolNA}
		m.filterModules()
		return
	}
	if m.toolFamilyIndex >= len(m.toolFamilies) {
		m.toolFamilyIndex = 0
	}
	m.categories = modules.CategoriesForFamily(m.toolFamilies[m.toolFamilyIndex])
	if len(m.categories) == 0 {
		m.categoryIndex, m.protocolIndex = 0, 0
		m.protocols = []modules.Protocol{modules.ProtocolNA}
		m.filterModules()
		return
	}
	if m.categoryIndex >= len(m.categories) {
		m.categoryIndex = 0
	}
	m.protocols = modules.ProtocolsForScope(m.allModules, m.toolFamilies[m.toolFamilyIndex], m.categories[m.categoryIndex])
	if m.protocolIndex >= len(m.protocols) {
		m.protocolIndex = 0
	}
	m.filterModules()
}

func (m *model) setCategory(index int) {
	if index < 0 || index >= len(m.categories) {
		return
	}
	m.categoryIndex = index
	m.protocolIndex = 0
	m.protocols = modules.ProtocolsForScope(m.allModules, m.toolFamilies[m.toolFamilyIndex], m.categories[index])
	m.filterModules()
}

func (m *model) setToolFamily(index int) {
	if index < 0 || index >= len(m.toolFamilies) {
		return
	}
	m.toolFamilyIndex = index
	m.categoryIndex, m.protocolIndex = 0, 0
	m.refreshNavigation()
}

func (m *model) setProtocol(index int) {
	if index < 0 || index >= len(m.protocols) {
		return
	}
	m.protocolIndex = index
	m.filterModules()
}

func (m *model) changeNavigationValue(delta int) {
	switch m.navigationRow {
	case 0:
		if len(m.toolFamilies) > 0 {
			m.setToolFamily((m.toolFamilyIndex + delta + len(m.toolFamilies)) % len(m.toolFamilies))
		}
	case 1:
		if len(m.categories) > 0 {
			m.setCategory((m.categoryIndex + delta + len(m.categories)) % len(m.categories))
		}
	case 2:
		if len(m.protocols) > 0 {
			m.setProtocol((m.protocolIndex + delta + len(m.protocols)) % len(m.protocols))
		}
	}
}

func (m *model) filterModules() {
	m.modules, m.moduleIDs, m.moduleKeys = nil, nil, nil
	for globalIndex, module := range m.allModules {
		if m.toolFamilyIndex < len(m.toolFamilies) && m.categoryIndex < len(m.categories) && m.protocolIndex < len(m.protocols) && module.ToolFamily() == m.toolFamilies[m.toolFamilyIndex] && module.Category() == m.categories[m.categoryIndex] && module.Protocol() == m.protocols[m.protocolIndex] {
			m.modules = append(m.modules, module)
			m.moduleIDs = append(m.moduleIDs, m.allModuleIDs[globalIndex])
			m.moduleKeys = append(m.moduleKeys, globalIndex)
		}
	}
	if m.cursor >= len(m.modules) {
		m.cursor = max(0, len(m.modules)-1)
	}
	// Batch items and output buffers are keyed by the registry-wide index, so the
	// watcher cursor is bounded by the registry rather than the visible scope.
	m.watcherSelected = min(m.watcherSelected, max(0, len(m.allModules)-1))
}

// globalIndex maps a module row in the visible scope to its index in the
// registry-wide module list. Execution is built from registry indices so a batch
// can span tool families, categories, and protocols.
func (m *model) globalIndex(visible int) (int, bool) {
	if visible < 0 || visible >= len(m.moduleKeys) {
		return 0, false
	}
	return m.moduleKeys[visible], true
}

// selectedModuleIDs reports the registry-wide selections in registry order, so a
// batch built from them is deterministic and free of duplicates.
func (m *model) selectedModuleIDs() map[string]bool {
	selected := make(map[string]bool, len(m.selectedModules))
	for id, marked := range m.selectedModules {
		if marked {
			selected[id] = true
		}
	}
	return selected
}

// selectedCount reports how many registered modules are currently selected.
func (m *model) selectedCount() int {
	count := 0
	for _, module := range m.allModules {
		if m.selectedModules[module.ID()] {
			count++
		}
	}
	return count
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type paneFocus uint8

const (
	focusNavigation paneFocus = iota
	focusModules
	focusOutput
)

func (m *model) Init() tea.Cmd { return tea.Batch(tickCmd(), tea.WindowSize()) }
