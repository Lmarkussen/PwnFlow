package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/viewport"
	"github.com/pwnflow/pwnflow/internal/runner"
)

const outputPaneHeightPercent = 30

func (m *model) currentBuffer() *runner.Buffer {
	return m.bufferFor(m.cursor)
}

func (m *model) bufferFor(index int) *runner.Buffer {
	if index >= 0 && index < len(m.moduleKeys) {
		index = m.moduleKeys[index]
	}
	if buffer := m.outputBuffers[index]; buffer != nil {
		return buffer
	}
	return nil
}

func (m *model) resizeOutput() {
	width := m.width - 4
	if width < 1 {
		width = 1
	}
	// The output pane contains a header, a separating newline, and a two-row
	// border in addition to the viewport itself.
	height := m.height*outputPaneHeightPercent/100 - 4
	if height < 3 {
		height = 3
	}
	wasAtBottom := m.outputViewport.AtBottom()
	m.outputViewport.Width, m.outputViewport.Height = width, height
	m.outputWidth = 0
	if m.outputFollow || wasAtBottom {
		m.outputViewport.GotoBottom()
	}
	m.refreshOutput()
}

func (m *model) refreshOutput() {
	buffer := m.currentBuffer()
	if buffer == nil {
		m.outputModule = m.cursor
		m.outputContent = "No output yet. Press Enter to run this module."
		m.outputViewport.SetContent(m.outputContent)
		return
	}
	changed := buffer.Changed()
	if changed.Equal(m.outputRawChange) && m.outputWidth == m.outputViewport.Width && m.outputModule == m.cursor {
		if m.outputFollow {
			m.outputViewport.GotoBottom()
		}
		return
	}
	m.outputRawChange, m.outputWidth = changed, m.outputViewport.Width
	m.outputModule = m.cursor
	m.outputContent = displayOutput(string(buffer.Snapshot()), m.outputViewport.Width)
	m.outputViewport.SetContent(m.outputContent)
	if m.outputFollow {
		m.outputViewport.GotoBottom()
	}
}

func (m *model) outputView() string {
	m.refreshOutput()
	if len(m.modules) == 0 {
		return paneStyle(m.focus == focusOutput).Render(paneHeader("OUTPUT // INACTIVE CATEGORY", m.focus == focusOutput, m.outputViewport.Width) + "\nNo modules available.")
	}
	module := m.modules[m.cursor]
	state := m.status
	if state == "" {
		state = "READY"
	}
	follow := "SCROLL"
	if m.outputFollow {
		follow = "FOLLOW"
	}
	header := fmt.Sprintf("OUTPUT // %s // %s // %s", module.Name(), state, follow)
	return paneStyle(m.focus == focusOutput).Render(paneHeader(header, m.focus == focusOutput, m.outputViewport.Width) + "\n" + m.outputViewport.View())
}

func newOutputViewport() viewport.Model { return viewport.New(1, 1) }
