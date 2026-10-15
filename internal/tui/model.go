package tui

import (
	"context"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/pwnflow/pwnflow/internal/config"
	findingengine "github.com/pwnflow/pwnflow/internal/findings"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/runner"
	"github.com/pwnflow/pwnflow/internal/storage"
)

type model struct {
	ctx                    context.Context
	cfg                    config.Config
	db                     *storage.DB
	findings               *findingengine.Manager
	findingsView           bool
	findingsFromWatcher    bool
	findingDetail          bool
	findingRows            []storage.Finding
	findingCursor          int
	findingTop             int
	findingSearch          string
	findingSearchMode      bool
	findingSeverity        string
	findingViewMode        string
	findingCategoryView    bool
	findingCategory        string
	findingSubcategoryView bool
	findingSubcategory     string
	findingSubcategories   []findingSubcategory
	findingCategories      []findingCategory
	findingAllRows         []storage.Finding
	modules                []modules.Module
	moduleIDs              []int64
	moduleKeys             []int
	allModules             []modules.Module
	allModuleIDs           []int64
	endpoints              modules.EndpointStore
	availability           map[string]string
	toolFamilies           []modules.ToolFamily
	toolFamilyIndex        int
	categories             []modules.Category
	categoryIndex          int
	protocols              []modules.Protocol
	protocolIndex          int
	targetID               int64
	selected, cursor       int
	selectedModules        map[string]bool
	running                bool
	watcher                bool
	focusBeforeWatcher     paneFocus
	quitConfirm            bool
	quitAfterCancel        bool
	quitCancelDeadline     time.Time
	elevationPrompt        bool
	elevationModules       []string
	// elevationRenewal carries a privileged module's request for fresh sudo
	// authorization while the batch waits before it. The module blocks on the
	// reply channel; the model answers after the terminal handoff.
	elevationRenewal chan renewalRequest
	renewing         bool
	renewalModule    string
	renewalReply     chan bool
	pendingIndices   []int
	pendingName      string
	// pending is the plan a key press asked for, before it is handed to the batch
	// runner. It carries the values the operator still has to supply and the
	// modules that need an explicit approval.
	pending         plan
	planLine        string
	inputPrompt     bool
	inputQueue      []inputRequest
	inputRequest    inputRequest
	inputField      modules.InputField
	approvalPrompt  bool
	approvalIndices []int
	// moduleInputs holds the values the operator typed in this session, keyed by
	// module then option key. It is never persisted, so it cannot reach another
	// assessment.
	moduleInputs      map[string]map[string]string
	textInput         textinput.Model
	batchElevation    map[string]bool
	detailsRefreshed  time.Time
	buffer            *runner.Buffer
	last              []byte
	status            string
	started           time.Time
	width, height     int
	version           string
	outputBuffers     map[int]*runner.Buffer
	batch             *runner.BatchRun
	batchItems        []runner.BatchItem
	batchRecorded     bool
	batchSummaryShown bool
	analysisPending   bool
	batchName         string
	watcherSelected   int
	watcherListCursor int
	// watcherAbort holds the execution an operator asked to abort, captured when
	// they pressed x: the confirmation and the abort apply to exactly that run, not
	// to whatever is selected by the time they answer.
	watcherAbortConfirm bool
	watcherAbortIndex   int
	watcherAbortName    string
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
	// moduleTop is the first module row the pane draws, and moduleRows is how
	// many rows it can draw. The pair keeps the highlighted module on screen
	// whatever the terminal height or the size of the scope.
	moduleTop        int
	moduleRows       int
	watcherViewport  viewport.Model
	watcherFollow    bool
	watcherContent   string
	watcherRawChange time.Time
	watcherWidth     int
	watcherModule    int
}

type tickMsg time.Time
type findingsCompleteMsg struct{ err error }
type findingsReanalysisMsg struct{ err error }

// newTextInput builds the field the interactive prompt uses. It is a single-line
// field with a plain prompt, deliberately without suggestions or history: the
// value belongs to this assessment and nowhere else.
func newTextInput() textinput.Model {
	input := textinput.New()
	input.Prompt = "> "
	input.CharLimit = 256
	input.Placeholder = "type a value, then press Enter"
	return input
}

func newModel(ctx context.Context, cfg config.Config, db *storage.DB, registered []modules.Module, moduleIDs []int64, targetID int64, version string, availability ...map[string]string) *model {
	moduleAvailability := map[string]string{}
	if len(availability) > 0 && availability[0] != nil {
		moduleAvailability = availability[0]
	}
	m := &model{ctx: ctx, cfg: cfg, db: db, allModules: registered, allModuleIDs: moduleIDs, availability: moduleAvailability, toolFamilies: modules.ToolFamilies(), targetID: targetID, version: version, selectedModules: make(map[string]bool), outputBuffers: make(map[int]*runner.Buffer), outputViewport: viewport.New(1, 1), outputFollow: true, outputModule: -1, watcherViewport: viewport.New(1, 1), watcherListViewport: viewport.New(1, 1), watcherFollow: true, watcherModule: -1, watcherAuto: true, watcherFocus: focusModules, focusBeforeWatcher: focusNavigation, width: 80, height: 24, findingViewMode: "findings"}
	if db != nil {
		m.findings = findingengine.NewManager(ctx, db)
	}
	// A model without a database - a test, or a run that could not open the
	// assessment store - keeps a nil store rather than an interface holding a nil
	// pointer, so a module asking it a question gets an error it can report.
	if store := newEndpointStore(db); store != nil {
		m.endpoints = store
	}
	m.batchElevation = map[string]bool{}
	m.textInput = newTextInput()
	// The renewal channel is buffered so a module can hand over its request even
	// while the loop is drawing a frame.
	m.elevationRenewal = make(chan renewalRequest, 1)
	m.refreshNavigation()
	m.resizeOutput()
	return m
}

// moduleRuntime is the configuration modules run and report with: the operator's
// target, domain, and credentials, and the assessment's discovery store.
func (m *model) moduleRuntime() *modules.Runtime {
	runtime := &modules.Runtime{Target: m.cfg.Target, Domain: m.cfg.Domain, Username: m.cfg.Username, ResultsRoot: m.cfg.ResultsRoot()}
	// The command line wins where it supplies a value; values the operator typed
	// in this session fill in the rest.
	options := make(map[string]map[string]string, len(m.cfg.ModuleOptions)+len(m.moduleInputs))
	for id, values := range m.cfg.ModuleOptions {
		options[id] = values
	}
	for id, values := range m.moduleInputs {
		if options[id] == nil {
			options[id] = make(map[string]string, len(values))
		}
		for key, value := range values {
			options[id][key] = value
		}
	}
	if len(options) > 0 {
		runtime.ModuleOptions = options
	}
	if m.endpoints != nil {
		runtime.Endpoints = m.endpoints
	}
	runtime.Elevation = m
	return runtime
}

// ElevationApproved implements modules.ElevationPolicy: only a module the operator
// explicitly approved for the run that is under way may elevate, and the approval is
// not carried into a later run.
func (m *model) ElevationApproved(moduleID string) bool { return m.batchElevation[moduleID] }

func (m *model) refreshNavigation() {
	if len(m.toolFamilies) == 0 {
		m.categories, m.protocols = nil, []modules.Protocol{modules.ProtocolNA}
		m.filterModules()
		return
	}
	if m.toolFamilyIndex >= len(m.toolFamilies) {
		m.toolFamilyIndex = 0
	}
	if modules.NavigationModeForFamily(m.toolFamilies[m.toolFamilyIndex]) == modules.NavigationFlat {
		m.categories = modules.CategoriesForFamily(m.toolFamilies[m.toolFamilyIndex])
		m.categoryIndex, m.protocolIndex, m.navigationRow = 0, 0, 0
		m.protocols = modules.ProtocolsForScope(m.allModules, m.toolFamilies[m.toolFamilyIndex], m.categories[0])
		m.filterModules()
		return
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

func (m *model) isFlatFamily() bool {
	return m.toolFamilyIndex >= 0 && m.toolFamilyIndex < len(m.toolFamilies) && modules.NavigationModeForFamily(m.toolFamilies[m.toolFamilyIndex]) == modules.NavigationFlat
}

func (m *model) navigationRows() int {
	if m.isFlatFamily() {
		return 1
	}
	return 3
}

func (m *model) filterModules() {
	m.modules, m.moduleIDs, m.moduleKeys = nil, nil, nil
	for globalIndex, module := range m.allModules {
		inScope := m.toolFamilyIndex < len(m.toolFamilies) && module.ToolFamily() == m.toolFamilies[m.toolFamilyIndex]
		if !m.isFlatFamily() {
			inScope = inScope && m.categoryIndex < len(m.categories) && m.protocolIndex < len(m.protocols) && module.Category() == m.categories[m.categoryIndex] && module.Protocol() == m.protocols[m.protocolIndex]
		}
		if inScope {
			m.modules = append(m.modules, module)
			m.moduleIDs = append(m.moduleIDs, m.allModuleIDs[globalIndex])
			m.moduleKeys = append(m.moduleKeys, globalIndex)
		}
	}
	// A different scope is a different list, so it starts at the top: a position
	// carried over from another scope means nothing here, and keeping the old
	// offset is what used to leave the highlight outside the pane.
	m.cursor = 0
	// Batch items and output buffers are keyed by the registry-wide index, so the
	// watcher cursor is bounded by the registry rather than the visible scope.
	m.watcherSelected = min(m.watcherSelected, max(0, len(m.allModules)-1))
	m.moduleTop = 0
	m.scrollModuleList()
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
