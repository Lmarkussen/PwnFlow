package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func TestPrimaryShortcutsOpenFindingsAndWatcher(t *testing.T) {
	log := &executionLog{}
	m := yoloModel(t, log)

	m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlF})
	if !m.findingsView {
		t.Fatal("Ctrl+F did not open Findings")
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlW})
	if !m.watcher {
		t.Fatal("Ctrl+W did not open Watcher")
	}
}

func TestPrimaryRunShortcutsRemainSafeInInputPrompt(t *testing.T) {
	log := &executionLog{}
	m, _, _ := inputModel(t, log)

	press(t, m, "enter")
	if !m.inputPrompt {
		t.Fatal("test module did not open its input prompt")
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlA})
	m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlR})
	m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlF})
	if !m.inputPrompt || m.running {
		t.Fatalf("global shortcuts escaped the input prompt: prompt=%v running=%v", m.inputPrompt, m.running)
	}
}

func TestNavigationHelpUsesBoundedCompactShortcuts(t *testing.T) {
	for _, width := range []int{20, 32, 48, 76} {
		wrapped := wrapFooter(helpText, width)
		for _, line := range strings.Split(wrapped, "\n") {
			if ansi.StringWidth(line) > width {
				t.Fatalf("help line exceeds width %d: %q", width, line)
			}
		}
	}
	if shortHelpText == helpText {
		t.Fatal("narrow help fallback is not compact")
	}
}
