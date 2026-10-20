package tui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
)

func easterModel(t *testing.T) *model {
	t.Helper()
	m := newModel(context.Background(), config.Config{}, nil, []modules.Module{viewTestModule{}}, []int64{1}, 1, "test")
	m.width, m.height = 420, 70
	m.resizeOutput()
	return m
}

func TestEasterEggOpensWithBubbleTeaControlRepresentation(t *testing.T) {
	m := easterModel(t)
	m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlCloseBracket})
	if !m.easterEgg {
		t.Fatal("Bubble Tea control-byte representation did not open Easter egg")
	}
	if m.running || !strings.Contains(easterArtwork, "Boobs as requested @TS") {
		t.Fatal("Easter egg changed execution state or embedded artwork is missing")
	}
	view := m.View()
	if !strings.Contains(ansi.Strip(view), "Boobs as requested @TS") {
		t.Fatal("rendered Easter egg does not contain the embedded artwork")
	}
	if !strings.Contains(ansi.Strip(view), "╭") {
		t.Fatal("Easter egg is missing the existing bordered view")
	}
}

func TestEasterEggAcceptsNamedCtrlEqualsAndQOnlyClosesIt(t *testing.T) {
	for _, closeKey := range []rune{'q', 'Q'} {
		m := easterModel(t)
		m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("ctrl+=")})
		if !m.easterEgg {
			t.Fatal("named ctrl+= representation did not open Easter egg")
		}
		updated, command := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{closeKey}})
		if command != nil || updated.(*model).easterEgg {
			t.Fatalf("%q did not close Easter egg without a quit command", closeKey)
		}
	}
}

func TestEasterEggDoesNotOpenDuringEnumeration(t *testing.T) {
	m := easterModel(t)
	m.running = true
	m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlCloseBracket})
	if m.easterEgg {
		t.Fatal("Easter egg opened during active enumeration")
	}
}

func TestEasterEggResizesSafely(t *testing.T) {
	m := easterModel(t)
	m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlCloseBracket})
	for _, size := range []struct{ width, height int }{{16, 6}, {40, 10}, {120, 24}} {
		m.Update(tea.WindowSizeMsg{Width: size.width, Height: size.height})
		if strings.TrimSpace(ansi.Strip(m.View())) == "" {
			t.Fatalf("empty Easter egg view at %dx%d", size.width, size.height)
		}
	}
}

func TestNormalQStillUsesQuitPathOutsideEasterEgg(t *testing.T) {
	m := easterModel(t)
	_, command := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if command == nil {
		t.Fatal("normal q no longer uses the quit path outside Easter egg")
	}
}
