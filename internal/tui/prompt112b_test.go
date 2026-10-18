package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/modules"
)

func TestPrompt112BOnlyFocusedPanelHasActiveArrow(t *testing.T) {
	m := &model{width: 100, height: 30, modules: []modules.Module{statusModule{id: "module", name: "Module", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP}}, selectedModules: map[string]bool{}, focus: focusModules, cursor: 0, navigationRow: 0, toolFamilies: []modules.ToolFamily{modules.ToolFamilyNetExec}}
	m.categories = []modules.Category{modules.CategoryEnumeration}
	m.protocols = []modules.Protocol{modules.ProtocolLDAP}
	m.resizeOutput()
	frame := ansi.Strip(m.View())
	if strings.Count(frame, "> [ ]") != 1 {
		t.Fatalf("modules focus should show one active arrow:\n%s", frame)
	}
	m.focus = focusNavigation
	frame = ansi.Strip(m.View())
	if strings.Contains(frame, "> [ ]") {
		t.Fatalf("navigation focus left an active module arrow:\n%s", frame)
	}
	if !strings.Contains(frame, "> TOOL FAMILY") {
		t.Fatalf("navigation focus did not show its active arrow:\n%s", frame)
	}
}

func TestPrompt112BInputRequiredMarkerStaysOnOneLine(t *testing.T) {
	for _, width := range []int{120, 80, 44} {
		m := &model{width: width, height: 30, modules: []modules.Module{
			statusModule{id: "dacl", name: "Read Object DACL", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, status: modules.StatusInputRequired},
			statusModule{id: "computers", name: "Find Computers by Text", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, status: modules.StatusInputRequired},
		}, selectedModules: map[string]bool{}, focus: focusModules, cursor: 0}
		m.resizeOutput()
		frame := ansi.Strip(m.View())
		if strings.Contains(frame, "INPUT-\nREQ") || strings.Contains(frame, "\nREQ") {
			t.Fatalf("input marker wrapped at width %d:\n%s", width, frame)
		}
		if strings.Count(frame, "INPUT") != 2 && strings.Count(frame, "INPUT-REQ") != 2 {
			t.Fatalf("both input markers were not rendered at width %d:\n%s", width, frame)
		}
	}
}

func TestPrompt112BFindingsCategoryUsesCombinedNavigableCount(t *testing.T) {
	severities := []string{"critical", "high", "medium", "low", "informational"}
	for _, width := range []int{160, 120, 100, 80, 60} {
		categories := make([]findingCategory, 0, len(severities))
		for index, severity := range severities {
			categories = append(categories, findingCategory{Name: "Active Directory ACLs", Description: "Direct control relationships and object permissions", Findings: 1386 + index, Highest: severity})
		}
		m := &model{findingsView: true, findingCategoryView: true, width: width, height: 40, findingCursor: 0, findingCategories: categories}
		frame := ansi.Strip(m.View())
		if strings.Contains(frame, "OBSERVED") || strings.Contains(frame, "observations") {
			t.Fatalf("category overview still exposes a separate observations column at width %d:\n%s", width, frame)
		}
		for _, category := range categories {
			for _, line := range strings.Split(frame, "\n") {
				if strings.Contains(line, category.Name) && strings.Contains(line, fmt.Sprintf("%d", category.Findings)) {
					if !strings.Contains(line, strings.ToUpper(category.Highest)) {
						t.Fatalf("severity wrapped away from category at width %d: %q\n%s", width, line, frame)
					}
					break
				}
			}
		}
		header := ""
		for _, line := range strings.Split(frame, "\n") {
			if strings.Contains(line, "CATEGORY") && (strings.Contains(line, "FINDINGS") || strings.Contains(line, "COUNT")) {
				header = line
				break
			}
		}
		if !strings.Contains(header, "CATEGORY") || (!strings.Contains(header, "FINDINGS") && !strings.Contains(header, "COUNT")) || !strings.Contains(header, "SEV") && !strings.Contains(header, "SEVERITY") {
			t.Fatalf("category headers are incomplete at width %d: %q", width, header)
		}
		for _, line := range strings.Split(frame, "\n") {
			if ansi.StringWidthWc(line) > width {
				t.Fatalf("rendered line exceeds terminal width %d: %d %q", width, ansi.StringWidthWc(line), line)
			}
		}
	}
}

func TestPrompt112BCtrlSIsNoOp(t *testing.T) {
	m := &model{width: 100, height: 30, focus: focusModules, cursor: 2}
	before := m.cursor
	_, cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlS})
	if cmd != nil || m.cursor != before {
		t.Fatalf("Ctrl+S changed the main view")
	}
	m.findingsView = true
	m.findingCategoryView = true
	m.findingCategories = []findingCategory{{Name: "AD CS"}}
	_, cmd = m.handleFindingsKey("ctrl+s")
	if cmd != nil || m.findingCursor != 0 {
		t.Fatalf("Ctrl+S changed Findings state")
	}
}
