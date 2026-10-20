package tui

import (
	"context"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/modules/netexec"
)

// scrollTestModule is a registration with a recognisable name, so a rendered
// frame can be checked for exactly the row the operator selected.
type scrollTestModule struct {
	statusModule
}

func scrollModules(count int) []modules.Module {
	registered := make([]modules.Module, 0, count)
	for index := 0; index < count; index++ {
		id := fmt.Sprintf("scroll-module-%02d", index)
		registered = append(registered, scrollTestModule{statusModule{
			id: id, name: "Module " + id, family: modules.ToolFamilyNetExec,
			category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP,
			status: modules.StatusAvailable, execution: true,
		}})
	}
	return registered
}

// scrollModel builds a model whose module list is longer than the pane.
func scrollModel(t *testing.T, count, height int) *model {
	t.Helper()
	m := statusModel(t, scrollModules(count))
	m.width, m.height = 120, height
	m.resizeOutput()
	m.scrollModuleList()
	m.focus = focusModules
	return m
}

// renderedRows returns the module rows the operator can see, and the highlighted
// one. A module row is the only pane row that carries a selection box, which
// keeps the navigation rows out of the result.
func renderedRows(frame string) (rows []string, highlighted string) {
	for _, line := range strings.Split(ansi.Strip(frame), "\n") {
		// Panes are joined side by side, so keep the left cell only: the module
		// rows live there, and the pane on the right carries the same line.
		if index := strings.Index(line, "││"); index >= 0 {
			line = line[:index]
		}
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "│"))
		line = strings.TrimSpace(strings.TrimSuffix(line, "│"))
		if !strings.Contains(line, "[ ]") && !strings.Contains(line, "[x]") {
			continue
		}
		rows = append(rows, line)
		if strings.HasPrefix(line, "> ") {
			highlighted = line
		}
	}
	return rows, highlighted
}

// The reported bug: NetExec LDAP enumeration has more modules than the pane can
// show, and the highlight used to walk out of the visible area.
func TestModuleListScrollsWithTheSelection(t *testing.T) {
	registered := netexec.EnumerationModules()
	m := statusModel(t, registered)
	m.setToolFamily(0)
	m.setCategory(0)
	m.setProtocol(0)
	if m.protocols[0] != modules.ProtocolLDAP {
		t.Fatalf("expected the LDAP scope, got %v", m.protocols)
	}
	if len(m.modules) <= 10 {
		t.Fatalf("the LDAP enumeration scope has only %d modules; the case under test needs a longer list", len(m.modules))
	}
	m.width, m.height = 120, 45
	m.resizeOutput()
	m.focus = focusModules
	if rows := m.moduleViewportRows(); rows >= len(m.modules) {
		t.Fatalf("%d rows fit %d modules; the window would never scroll", rows, len(m.modules))
	}

	for index := range m.modules {
		frame := m.View()
		rows, highlighted := renderedRows(frame)
		if highlighted == "" {
			t.Fatalf("row %d: no highlighted module is visible:\n%s", index, ansi.Strip(frame))
		}
		if !strings.Contains(highlighted, m.modules[m.cursor].Name()) {
			t.Fatalf("row %d: the highlight shows %q but the selection is %q", index, highlighted, m.modules[m.cursor].Name())
		}
		if len(rows) > m.moduleViewportRows() {
			t.Fatalf("row %d: %d module rows rendered, only %d fit", index, len(rows), m.moduleViewportRows())
		}
		if index < len(m.modules)-1 {
			press(t, m, "down")
		}
	}
	if m.cursor != len(m.modules)-1 {
		t.Fatalf("selection ended at %d, want the last module", m.cursor)
	}
}

// Scrolling back up has to follow the selection too, and the list returns to the
// first module without an off-by-one gap.
func TestModuleListScrollsBackToTheTop(t *testing.T) {
	m := scrollModel(t, 40, 45)
	press(t, m, "end")
	if m.cursor != 39 || m.moduleTop == 0 {
		t.Fatalf("end: cursor=%d top=%d", m.cursor, m.moduleTop)
	}
	for m.cursor > 0 {
		press(t, m, "up")
		_, highlighted := renderedRows(m.View())
		if !strings.Contains(highlighted, m.modules[m.cursor].Name()) {
			t.Fatalf("cursor %d is not visible while scrolling up", m.cursor)
		}
	}
	if m.moduleTop != 0 {
		t.Fatalf("the window did not return to the first module: top=%d", m.moduleTop)
	}
	// The first module does not scroll past the top, and the last does not scroll
	// past the bottom.
	press(t, m, "up")
	if m.cursor != 0 || m.moduleTop != 0 {
		t.Fatalf("up at the first module moved: cursor=%d top=%d", m.cursor, m.moduleTop)
	}
	press(t, m, "home")
	if m.cursor != 0 || m.moduleTop != 0 {
		t.Fatalf("home: cursor=%d top=%d", m.cursor, m.moduleTop)
	}
	press(t, m, "end")
	press(t, m, "down")
	if m.cursor != 39 || m.moduleTop != 39-m.moduleViewportRows()+1 {
		t.Fatalf("down at the last module moved: cursor=%d top=%d rows=%d", m.cursor, m.moduleTop, m.moduleViewportRows())
	}
	_, highlighted := renderedRows(m.View())
	if !strings.Contains(highlighted, m.modules[39].Name()) {
		t.Fatalf("the last module is not visible: %q", highlighted)
	}
}

// Paging moves by a window and keeps the highlighted module on screen.
func TestModuleListPagingKeepsTheSelectionVisible(t *testing.T) {
	m := scrollModel(t, 40, 45)
	rows := m.moduleViewportRows()
	press(t, m, "pgdown")
	if m.cursor != rows {
		t.Fatalf("pgdown moved to %d, want %d", m.cursor, rows)
	}
	if _, highlighted := renderedRows(m.View()); !strings.Contains(highlighted, m.modules[m.cursor].Name()) {
		t.Fatalf("pgdown lost the selection: %q", highlighted)
	}
	press(t, m, "pgup")
	if m.cursor != 0 {
		t.Fatalf("pgup returned to %d, want 0", m.cursor)
	}
	press(t, m, "end")
	press(t, m, "pgdown")
	if m.cursor != len(m.modules)-1 {
		t.Fatalf("pgdown past the end left the cursor at %d", m.cursor)
	}
	if _, highlighted := renderedRows(m.View()); !strings.Contains(highlighted, m.modules[m.cursor].Name()) {
		t.Fatalf("paging past the end lost the selection: %q", highlighted)
	}
}

// A list shorter than the pane shows every row and never scrolls.
func TestShortModuleListDoesNotScroll(t *testing.T) {
	m := scrollModel(t, 3, 45)
	if m.moduleViewportRows() < 3 {
		t.Fatalf("the pane shows only %d rows", m.moduleViewportRows())
	}
	rows, _ := renderedRows(m.View())
	if len(rows) != 3 {
		t.Fatalf("rendered %d rows for a three-module list: %v", len(rows), rows)
	}
	press(t, m, "down")
	press(t, m, "down")
	if m.cursor != 2 || m.moduleTop != 0 {
		t.Fatalf("cursor=%d top=%d, want the third row without scrolling", m.cursor, m.moduleTop)
	}
}

// An empty list is not a crash: navigation, paging, and execution all no-op.
func TestEmptyModuleListIsSafe(t *testing.T) {
	m := statusModel(t, nil)
	m.focus = focusModules
	for _, key := range []string{"down", "up", "pgdown", "pgup", "home", "end", " ", "enter", "r", "a"} {
		press(t, m, key)
	}
	frame := ansi.Strip(m.View())
	if !strings.Contains(frame, "MODULE INFORMATION") {
		t.Fatalf("an empty scope did not render:\n%s", frame)
	}
	if m.running || m.moduleTop != 0 || m.cursor != 0 {
		t.Fatalf("an empty scope changed state: running=%t top=%d cursor=%d", m.running, m.moduleTop, m.cursor)
	}
}

// Shrinking the terminal has to keep the selection visible, and growing it keeps
// the same module selected.
func TestResizeKeepsTheSelectionVisible(t *testing.T) {
	m := scrollModel(t, 40, 45)
	press(t, m, "end")
	selected := m.modules[m.cursor].Name()
	for _, height := range []int{30, 24, 18, 45} {
		m.Update(tea.WindowSizeMsg{Width: m.width, Height: height})
		rows, highlighted := renderedRows(m.View())
		if !strings.Contains(highlighted, selected) {
			t.Fatalf("height %d: the selection is not visible: %q of %v", height, highlighted, rows)
		}
		if len(rows) > m.moduleViewportRows() {
			t.Fatalf("height %d: %d rows rendered, %d fit", height, len(rows), m.moduleViewportRows())
		}
	}
}

// Changing the scope is a new list: the window starts at the top again.
func TestScopeChangeResetsTheWindow(t *testing.T) {
	m := statusModel(t, netexec.EnumerationModules())
	m.width, m.height = 120, 45
	m.resizeOutput()
	m.focus = focusModules
	m.setToolFamily(0)
	m.setCategory(0)
	m.setProtocol(0)
	press(t, m, "end")
	if m.moduleTop == 0 {
		t.Fatal("the window did not scroll before the scope change")
	}
	m.focus = focusNavigation
	press(t, m, "down")
	press(t, m, "down")
	press(t, m, "right") // LDAP -> SMB
	if m.moduleTop != 0 {
		t.Fatalf("the new scope kept the previous offset: %d", m.moduleTop)
	}
	if m.cursor != 0 {
		t.Fatalf("the new scope kept the previous cursor: %d", m.cursor)
	}
	if _, highlighted := renderedRows(m.View()); highlighted != "" {
		t.Fatal("module list displayed an active arrow while navigation had focus")
	}
}

// Switching focus away and back leaves the window where it was, so the operator
// returns to what they were looking at.
func TestFocusSwitchPreservesTheWindow(t *testing.T) {
	m := scrollModel(t, 40, 45)
	for index := 0; index < 20; index++ {
		press(t, m, "down")
	}
	top, cursor := m.moduleTop, m.cursor
	press(t, m, "tab") // output
	press(t, m, "tab") // navigation
	press(t, m, "tab") // modules
	if m.moduleTop != top || m.cursor != cursor {
		t.Fatalf("focus switch moved the window: top=%d cursor=%d, want %d/%d", m.moduleTop, m.cursor, top, cursor)
	}
	if _, highlighted := renderedRows(m.View()); !strings.Contains(highlighted, m.modules[cursor].Name()) {
		t.Fatalf("the selection was not visible after returning: %q", highlighted)
	}
}

// Module Information always describes the highlighted module, scrolled or not.
func TestModuleInformationFollowsTheScrolledSelection(t *testing.T) {
	m := scrollModel(t, 40, 45)
	for index := 0; index < 25; index++ {
		press(t, m, "down")
	}
	frame := ansi.Strip(m.View())
	if !strings.Contains(frame, "Name: "+m.modules[m.cursor].Name()) {
		t.Fatalf("Module Information does not describe the selection %q:\n%s", m.modules[m.cursor].Name(), frame)
	}
	if strings.Contains(frame, "Name: "+m.modules[0].Name()) {
		t.Fatalf("Module Information still describes the first module:\n%s", frame)
	}
}

// Space marks the highlighted row, not the row that happens to be drawn first,
// and the checkbox follows the module across a scroll.
func TestSelectionWhileScrolling(t *testing.T) {
	m := scrollModel(t, 40, 45)
	for index := 0; index < 12; index++ {
		press(t, m, "down")
	}
	press(t, m, " ")
	marked := m.modules[m.cursor].ID()
	if !m.selectedModules[marked] {
		t.Fatalf("space did not mark the highlighted module %s", marked)
	}
	press(t, m, "end")
	rows, _ := renderedRows(m.View())
	for _, row := range rows {
		if strings.Contains(row, marked) {
			t.Fatal("a marked module outside the window was rendered")
		}
	}
	press(t, m, "home")
	rows, _ = renderedRows(m.View())
	found := false
	for _, row := range rows {
		if strings.Contains(row, m.modules[0].Name()) {
			found = true
		}
	}
	if !found {
		t.Fatalf("the first module is not visible after home: %v", rows)
	}

	other := scrollModel(t, 40, 45)
	markedCount := 0
	for index := 0; index < 4; index++ {
		press(t, other, "down")
		press(t, other, " ")
		markedCount++
	}
	if len(other.selectedModules) != markedCount {
		t.Fatalf("expected %d marked modules, got %d", markedCount, len(other.selectedModules))
	}
	// Space on a marked row clears it again.
	last := other.modules[other.cursor].ID()
	press(t, other, " ")
	if other.selectedModules[last] {
		t.Fatalf("space did not unmark %s", last)
	}
}

// Global R and scoped A keep working after the list has been scrolled.
func TestExecutionAfterScrolling(t *testing.T) {
	log := &executionLog{}
	registered := []modules.Module{
		selectionModule{id: "nxc-ldap-users", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log},
		selectionModule{id: "nxc-ldap-groups", family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration, protocol: modules.ProtocolLDAP, log: log},
	}
	for index := 0; index < 30; index++ {
		registered = append(registered, scrollTestModule{statusModule{
			id: fmt.Sprintf("filler-%02d", index), name: fmt.Sprintf("Filler %02d", index),
			family: modules.ToolFamilyNetExec, category: modules.CategoryEnumeration,
			protocol: modules.ProtocolLDAP, status: modules.StatusAvailable, execution: true,
		}})
	}
	ids := make([]int64, len(registered))
	for index := range registered {
		ids[index] = int64(index + 1)
	}
	m := newModel(context.Background(), testConfig(t), nil, registered, ids, 1, "test")
	m.width, m.height = 120, 45
	m.resizeOutput()
	m.focus = focusModules

	// Enter runs the highlighted module even when the highlight is only reachable
	// by scrolling.
	press(t, m, "end")
	press(t, m, "up")
	highlighted := m.modules[m.cursor].ID()
	if highlighted == "nxc-ldap-users" {
		t.Fatal("the test needs the highlight on a module that records its own run")
	}
	press(t, m, "enter")
	if !m.running || m.batchItems[0].Module.ID() != highlighted {
		t.Fatalf("Enter ran %v, want %s", m.batchItems, highlighted)
	}
	if err := m.batch.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.running = false

	// A scoped run after scrolling runs the visible scope's modules, in order.
	beforeScoped := len(log.executed())
	press(t, m, "ctrl+a")
	if !m.running || len(m.batchItems) != len(registered) {
		t.Fatalf("A ran %d modules, want %d", len(m.batchItems), len(registered))
	}
	if err := m.batch.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.running = false
	ran := log.executed()
	if len(ran)-beforeScoped != 2 {
		t.Fatalf("the scoped run should have executed both recording modules, got %v", ran)
	}

	// A global selection made while scrolled still runs through R.
	press(t, m, " ")
	press(t, m, "ctrl+r")
	if !m.running {
		t.Fatalf("R refused the selected module: %q", m.status)
	}
	if err := m.batch.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.status, "SELECTED") && m.batchName != "SELECTED" {
		t.Fatalf("R did not run the global selection: %q", m.batchName)
	}
}
