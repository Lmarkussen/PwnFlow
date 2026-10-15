package tui

import "github.com/charmbracelet/lipgloss"

// The module list is longer than the pane in several scopes - NetExec LDAP
// enumeration alone has more rows than fit on a normal terminal - so it is
// rendered through a window over m.modules. The window, not the pane's clipping,
// decides which rows are drawn: a pane that silently cuts off its tail also cuts
// off the highlighted row, which is exactly how the selection used to disappear.

// modulePaneChromeLines counts the lines the module pane spends on something
// other than a module row: the version title, the pane header, the four-line
// target block plus its blank line, and the blank line and rule above the footer.
const modulePaneChromeLines = 1 + 1 + 5 + 2

// compactModulePaneChromeLines is what the pane keeps when the terminal is too
// short for the full header block. The module rows are the last thing to go, so
// the version title and the rule give way first.
const compactModulePaneChromeLines = 3

// minModuleRows is the number of module rows the pane keeps before it starts
// shortening the key hint. The list is what the operator is reading, so the hint
// gives way first.
const minModuleRows = 4

// moduleViewportRows reports how many module rows fit in the module pane at the
// current terminal size. It is arithmetic over state the interface already has -
// no dependency probe, no subprocess - so it is safe on the render path and in a
// key handler.
func (m *model) moduleViewportRows() int {
	_, rows := m.modulePaneLayout()
	if rows < 1 {
		return 1
	}
	return rows
}

// modulePaneLayout decides how the module pane spends its height: the key hint it
// can afford, and the module rows that are left. Both View and the scroll
// arithmetic use it, so the window a key handler computes is the window the
// renderer draws.
func (m *model) modulePaneLayout() (footer string, rows int) {
	// A bordered pane of Height(n) is n lines in total, so the two border rows
	// are not available for content.
	budget := m.modulePaneHeight() - 2
	if budget < modulePaneChromeLines+minModuleRows {
		return "", max(1, budget-compactModulePaneChromeLines)
	}
	width := max(20, widthForFooter(m.width))
	for _, candidate := range []string{
		wrapFooter(helpText, width),
		wrapFooter(shortHelpText, width),
	} {
		if rows := budget - modulePaneChromeLines - lipgloss.Height(candidate); rows >= minModuleRows {
			return candidate, rows
		}
	}
	return "", max(1, budget-modulePaneChromeLines)
}

// modulePaneCompact reports whether the pane has to use its short header block.
func (m *model) modulePaneCompact() bool {
	return m.modulePaneHeight()-2 < modulePaneChromeLines+minModuleRows
}

// minModulePaneHeight is what the module pane needs to show its chrome and a few
// module rows: two borders, the chrome lines, and the minimum rows.
const minModulePaneHeight = 2 + modulePaneChromeLines + minModuleRows

// minOutputPaneHeight keeps the output pane usable - two borders, a header, and
// one line of output - on a terminal too short to satisfy both panes.
const minOutputPaneHeight = 5

// layoutHeights divides the terminal between the navigation pane, the module
// pane, and the output pane. The output pane keeps its configured share, except
// where that would leave the module list too short to navigate: the list the
// operator works in wins over the pane they read from.
func (m *model) layoutHeights() (navigation, modulePane, outputPane int) {
	navigation = lipgloss.Height(m.navigationView())
	remaining := max(3, m.height-navigation)
	outputPane = remaining * outputPaneHeightPercent / 100
	if outputPane < minOutputPaneHeight {
		outputPane = minOutputPaneHeight
	}
	if maxOutput := remaining - minModulePaneHeight; outputPane > maxOutput {
		outputPane = max(minOutputPaneHeight, maxOutput)
	}
	if outputPane > remaining-1 {
		outputPane = max(1, remaining-1)
	}
	modulePane = max(1, remaining-outputPane)
	return navigation, modulePane, outputPane
}

// modulePaneHeight is the total height, borders included, the module pane may
// occupy at the current terminal size.
func (m *model) modulePaneHeight() int {
	_, modulePane, _ := m.layoutHeights()
	return modulePane
}

// moduleWindow returns the first visible module index and the number of rows the
// pane shows. The offset is clamped here - against the list length and the
// cursor - so the caller cannot render a window that hides the selection, even
// if a resize or a scope change happened since the offset was set.
func (m *model) moduleWindow() (top, rows int) {
	rows = m.moduleViewportRows()
	m.moduleRows = rows
	m.clampModuleScroll(rows)
	return m.moduleTop, rows
}

// clampModuleScroll keeps the offset inside the list and the cursor inside the
// window. It is the single place the invariant is enforced: cursor in
// [moduleTop, moduleTop+rows).
func (m *model) clampModuleScroll(rows int) {
	if rows < 1 {
		rows = 1
	}
	if len(m.modules) == 0 {
		m.moduleTop, m.cursor = 0, 0
		return
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor > len(m.modules)-1 {
		m.cursor = len(m.modules) - 1
	}
	if m.moduleTop > m.cursor {
		m.moduleTop = m.cursor
	}
	if m.cursor >= m.moduleTop+rows {
		m.moduleTop = m.cursor - rows + 1
	}
	if limit := len(m.modules) - rows; m.moduleTop > limit {
		m.moduleTop = limit
	}
	if m.moduleTop < 0 {
		m.moduleTop = 0
	}
}

// scrollModuleList recomputes the window after something changed the list, the
// cursor, or the terminal size.
func (m *model) scrollModuleList() { m.clampModuleScroll(m.moduleViewportRows()) }

// moveModuleCursor moves the highlight by one row, which scrolls the window when
// the highlight reaches an edge.
func (m *model) moveModuleCursor(delta int) {
	if len(m.modules) == 0 {
		return
	}
	m.cursor += delta
	m.clampModuleScroll(m.moduleViewportRows())
}

// pageModuleCursor moves the highlight by one window, keeping the cursor's
// position inside the window so paging feels the same as scrolling by hand.
func (m *model) pageModuleCursor(delta int) {
	if len(m.modules) == 0 {
		return
	}
	rows := max(1, m.moduleViewportRows())
	offset := m.cursor - m.moduleTop
	m.cursor += delta * rows
	m.clampModuleScroll(rows)
	if m.cursor >= m.moduleTop && m.cursor < m.moduleTop+rows {
		m.moduleTop = m.cursor - offset
		if m.moduleTop < 0 {
			m.moduleTop = 0
		}
		if limit := len(m.modules) - rows; m.moduleTop > limit {
			m.moduleTop = max(0, limit)
		}
	}
	m.clampModuleScroll(rows)
}

// goModuleEdge moves the highlight to the first or last module.
func (m *model) goModuleEdge(last bool) {
	if len(m.modules) == 0 {
		return
	}
	if last {
		m.cursor = len(m.modules) - 1
	} else {
		m.cursor = 0
	}
	m.clampModuleScroll(m.moduleViewportRows())
}
