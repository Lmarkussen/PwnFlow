package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
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

func TestPrompt112QIsSafeForTextInput(t *testing.T) {
	m := &model{inputPrompt: true, textInput: newTextInput()}
	m.textInput.Focus()
	m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if m.textInput.Value() != "q" {
		t.Fatalf("q was intercepted while text input was focused: %q", m.textInput.Value())
	}
}
