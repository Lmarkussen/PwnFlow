package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// Interactive input for modules that need a value only the operator can supply.
//
// The value is collected before the batch starts, never while it runs, and it is
// held for the current assessment only: the model - and therefore the values - is
// rebuilt for every PwnFlow invocation, so a value entered for one assessment
// cannot appear in another. Values supplied on the command line with
// --module-options are still honoured, and an entered value takes precedence for
// the rest of the session.

// advanceInput opens the prompt for the next value in the queue, skipping modules
// whose values have already been supplied, and continues the plan when the queue
// is empty.
func (m *model) advanceInput() tea.Cmd {
	runtime := m.moduleRuntime()
	for len(m.inputQueue) > 0 {
		request := m.inputQueue[0]
		requester, ok := request.module.(modules.InputRequester)
		if !ok {
			m.inputQueue = m.inputQueue[1:]
			continue
		}
		fields := requester.MissingInputs(runtime)
		if len(fields) == 0 {
			m.inputQueue = m.inputQueue[1:]
			continue
		}
		m.openInput(request, fields[0])
		return nil
	}
	m.inputPrompt = false
	return m.continuePlan()
}

// openInput puts one field in front of the operator.
func (m *model) openInput(request inputRequest, field modules.InputField) {
	m.inputPrompt = true
	m.inputRequest = request
	m.inputField = field
	m.textInput.SetValue("")
	m.textInput.CursorEnd()
	m.textInput.Focus()
	m.status = fmt.Sprintf("%s needs %s: %s", request.module.Name(), field.Key, field.Prompt)
}

// acceptInput stores what the operator typed and moves to the next value. An
// empty value is refused here rather than passed on to a module that would reject
// it on the target.
func (m *model) acceptInput() tea.Cmd {
	value := strings.TrimSpace(m.textInput.Value())
	if value == "" {
		m.status = fmt.Sprintf("%s is required; type a value and press Enter, or Esc to skip %s", m.inputField.Key, m.inputRequest.module.Name())
		return nil
	}
	m.setModuleInput(m.inputRequest.module.ID(), m.inputField.Key, value)
	m.inputPrompt = false
	m.status = fmt.Sprintf("%s %s stored for this assessment", m.inputRequest.module.Name(), m.inputField.Key)
	return m.advanceInput()
}

// skipInput drops the module whose value the operator declined to supply and
// continues with the rest of the plan.
func (m *model) skipInput() tea.Cmd {
	skipped := m.inputRequest.module
	remaining := make([]inputRequest, 0, len(m.inputQueue))
	for _, request := range m.inputQueue {
		if request.module.ID() != skipped.ID() {
			remaining = append(remaining, request)
		}
	}
	m.inputQueue = remaining
	m.inputPrompt = false
	m.pending = m.pending.withoutIndices([]int{m.inputRequest.index})
	m.pending.skipped = append(m.pending.skipped, skipped.Name()+" (no input supplied)")
	command := m.advanceInput()
	// The status is set after the plan continues, because starting a batch
	// reports "running" and the skip would otherwise be lost.
	m.status = fmt.Sprintf("skipped %s: its required value was not supplied; running the rest of the plan", skipped.Name())
	return command
}

// cancelPlan abandons the whole pending run, which is what Ctrl+C means while a
// prompt is open.
func (m *model) cancelPlan() {
	m.inputPrompt = false
	m.inputQueue = nil
	m.approvalPrompt = false
	m.approvalIndices = nil
	m.pending = plan{}
	m.status = "cancelled"
}

// setModuleInput stores a value for the rest of this assessment.
func (m *model) setModuleInput(moduleID, key, value string) {
	if m.moduleInputs == nil {
		m.moduleInputs = make(map[string]map[string]string)
	}
	if m.moduleInputs[moduleID] == nil {
		m.moduleInputs[moduleID] = make(map[string]string)
	}
	m.moduleInputs[moduleID][key] = value
}

// approvePlan keeps the credential-access modules in the pending plan.
func (m *model) approvePlan() tea.Cmd {
	m.approvalPrompt = false
	m.approvalIndices = nil
	m.pending.approvals = nil
	return m.continuePlan()
}

// declinePlan drops the credential-access modules and continues with the rest.
func (m *model) declinePlan() tea.Cmd {
	dropped := m.pending.approvalIndices()
	m.approvalPrompt = false
	m.approvalIndices = nil
	m.pending = m.pending.withoutIndices(dropped)
	m.pending.approvals = nil
	m.pending.skipped = append(m.pending.skipped, "credential-access modules (not approved)")
	command := m.continuePlan()
	m.status = "the modules that needed your decision were skipped; running the rest of the plan"
	return command
}

// inputPromptView renders the interactive question in the output pane, so the
// module list and Module Information stay visible while the operator types.
func (m *model) inputPromptView() string {
	header := paneHeader(fmt.Sprintf("INPUT // %s // %s", m.inputRequest.module.Name(), m.inputField.Key), m.focus == focusOutput, m.outputViewport.Width)
	var body strings.Builder
	if m.planLine != "" {
		body.WriteString(dim.Render(m.planLine) + "\n\n")
	}
	body.WriteString(warn.Render(m.inputField.Prompt) + "\n\n")
	body.WriteString(m.textInput.View() + "\n\n")
	if m.inputField.Example != "" {
		body.WriteString(dim.Render("for example: "+m.inputField.Example) + "\n")
	}
	body.WriteString(dim.Render(fmt.Sprintf("Enter stores the value for this assessment   Esc skips %s   Ctrl+C cancels the whole run", m.inputRequest.module.Name())))
	if len(m.inputQueue) > 1 {
		body.WriteString("\n" + dim.Render(fmt.Sprintf("%d module(s) in this plan still need input", len(m.inputQueue))))
	}
	return paneStyle(m.focus == focusOutput).Render(header + "\n" + body.String())
}

// approvalPromptView names the modules the plan will not start without a decision.
func (m *model) approvalPromptView() string {
	header := paneHeader("APPROVAL // MODULES THAT NEED YOUR DECISION", m.focus == focusOutput, m.outputViewport.Width)
	var body strings.Builder
	if m.planLine != "" {
		body.WriteString(dim.Render(m.planLine) + "\n\n")
	}
	body.WriteString(warn.Render("This plan includes operations that are not plain enumeration:") + "\n\n")
	for _, item := range m.pending.approvals {
		if item.index < 0 || item.index >= len(m.allModules) {
			continue
		}
		module := m.allModules[item.index]
		body.WriteString(fmt.Sprintf("  %s (%s, %s)\n    %s\n", module.Name(), module.Category(), module.Protocol(), item.reason))
	}
	body.WriteString("\n" + dim.Render("Y runs them with the rest of the plan   N skips them and runs the rest   Ctrl+C cancels the plan"))
	return paneStyle(m.focus == focusOutput).Render(header + "\n" + body.String())
}
