package tui

import (
	"context"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestPrompt112SelectionStylesAreDistinct(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })
	if selectionPrefix(true) == selectionPrefix(false) || selectionLabel("selected", true) == selectionLabel("selected", false) {
		t.Fatal("selected and unselected rows rendered identically")
	}
	if selectedArrowStyle.GetForeground() != focusBlue {
		t.Fatalf("selection arrow foreground=%v, want %v", selectedArrowStyle.GetForeground(), focusBlue)
	}
	if selectedLabelStyle.GetForeground() != green {
		t.Fatalf("selection label foreground=%v, want %v", selectedLabelStyle.GetForeground(), green)
	}
}

func TestPrompt112ModuleSearchSelectsStableModule(t *testing.T) {
	first := selectionModule{id: "first", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA}
	second := selectionModule{id: "manual-only", family: modules.ToolFamilySCCM, category: modules.CategoryCredentialAuditing, protocol: modules.ProtocolNA}
	m := newModel(context.Background(), configForPrompt112(), nil, []modules.Module{first, second}, []int64{1, 2}, 1, "test")
	m.modules = []modules.Module{first, second}
	m.moduleKeys = []int{0, 1}
	m.startSearch("modules")
	m.searchInput.SetValue("manual-only")
	m.refreshSearchResults()
	if len(m.searchModuleResults) != 1 || m.searchModuleResults[0] != 1 {
		t.Fatalf("module search results=%v, want [1]", m.searchModuleResults)
	}
	m.handleSearchKey(tea.KeyMsg{Type: tea.KeyEnter})
	if m.searchMode || m.cursor != 1 {
		t.Fatalf("module search did not restore main selection: search=%t cursor=%d", m.searchMode, m.cursor)
	}
}

func TestPrompt112FindingsSearchRestoresContext(t *testing.T) {
	rows := []storage.Finding{
		{ID: 1, FindingInput: storage.FindingInput{FindingKey: "one", FindingType: "adcs_esc_esc1", Title: "Web Template", Severity: "high", AffectedObject: "WebTemplate"}},
		{ID: 2, FindingInput: storage.FindingInput{FindingKey: "two", FindingType: "kerberoastable_account", Title: "Service Account", Severity: "medium", AffectedObject: "svc-web"}},
	}
	m := &model{findingsView: true, findingCategoryView: true, findingCategories: buildFindingCategories(rows), findingAllRows: rows, findingRows: rows, findingsLoaded: true, findingCursor: 0, width: 100, height: 30}
	m.handleFindingsKey("ctrl+s")
	m.searchInput.SetValue("svc-web")
	m.refreshSearchResults()
	if len(m.searchFindingResults) != 1 || m.searchFindingResults[0].FindingKey != "two" {
		t.Fatalf("finding search results=%v, want svc-web", m.searchFindingResults)
	}
	m.handleSearchKey(tea.KeyMsg{Type: tea.KeyEnter})
	if !m.findingDetail || m.searchMode || m.findingRows[0].FindingKey != "two" {
		t.Fatalf("finding search did not open selected result: detail=%t search=%t", m.findingDetail, m.searchMode)
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if !m.searchMode || m.findingDetail {
		t.Fatal("Esc from search-opened detail did not return to search results")
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if m.searchMode || !m.findingCategoryView || m.findingCursor != 0 || len(m.findingRows) != 2 {
		t.Fatalf("search cancel did not restore Findings context: search=%t category=%t cursor=%d rows=%d", m.searchMode, m.findingCategoryView, m.findingCursor, len(m.findingRows))
	}
}

func TestPrompt112QIsSafeForTextInput(t *testing.T) {
	m := &model{inputPrompt: true, textInput: newTextInput()}
	m.textInput.Focus()
	m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if m.textInput.Value() != "q" {
		t.Fatalf("q was intercepted while text input was focused: %q", m.textInput.Value())
	}
	search := &model{modules: []modules.Module{selectionModule{id: "searchable"}}}
	search.startSearch("modules")
	search.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if !search.searchMode || search.searchInput.Value() != "q" {
		t.Fatalf("q was intercepted while search input was focused: search=%t value=%q", search.searchMode, search.searchInput.Value())
	}

	findings := &model{findingsView: true, findingCategoryView: true, findingCategories: buildFindingCategories(nil)}
	_, command := findings.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'Q'}})
	if command == nil {
		t.Fatal("Q did not quit from Findings")
	}
}

func configForPrompt112() config.Config {
	return config.Config{Domain: "example.test", Target: "192.0.2.1"}
}
