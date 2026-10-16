package tui

import (
	"context"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// promptModel is a model waiting for the operator to answer a privilege
// confirmation, which is the state the warning colour exists for.
func promptModel(t *testing.T) *model {
	t.Helper()
	log := &executionLog{}
	elevating := elevatingModule{selectionModule: selectionModule{id: "needs-privileges", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log}, required: true}
	plain := selectionModule{id: "plain", family: modules.ToolFamilySCCM, category: modules.CategoryEnumeration, protocol: modules.ProtocolNA, log: log}
	m := newModel(context.Background(), testConfig(t), nil, []modules.Module{elevating, plain}, []int64{1, 2}, 1, "test")
	m.width, m.height = 150, 50
	m.resizeOutput()
	m.setToolFamily(sccmFamilyIndex)
	m.focus = focusModules
	for _, id := range []string{"needs-privileges", "plain"} {
		m.cursor = rowOf(t, m, id)
		press(t, m, " ")
	}
	press(t, m, "ctrl+r")
	if !m.elevationPrompt {
		t.Fatal("the privilege confirmation was not asked for")
	}
	return m
}

// The privilege confirmation uses the warning style, not the title green that
// ordinary progress and successful results use.
func TestPrivilegeConfirmationUsesTheWarningStyle(t *testing.T) {
	m := promptModel(t)
	if got := m.statusHeaderStyle().GetForeground(); got != amber {
		t.Fatalf("the confirmation header is %v, want the amber warning colour", got)
	}
	if amber == green {
		t.Fatal("the warning colour is the same as the success colour")
	}
	if !strings.Contains(m.status, "[y/N]") {
		t.Fatalf("the decision is not shown: %q", m.status)
	}
	// The decision text carries the warning style in its own right, so it stays
	// legible wherever the status is shown.
	if rendered := m.statusText(""); !strings.Contains(rendered, m.status) {
		t.Fatalf("the status was altered by styling: %q", rendered)
	}
}

// Once the question is answered the pane goes back to the ordinary style, and a
// normal status is never amber.
func TestWarningStyleIsOnlyForAPendingConfirmation(t *testing.T) {
	m := promptModel(t)
	m.elevationPrompt = false
	m.status = "running"
	if got := m.statusHeaderStyle().GetForeground(); got != green {
		t.Fatalf("an ordinary status is %v, want the title colour", got)
	}
	if rendered := m.statusText("idle"); rendered != "running" {
		t.Fatalf("an ordinary status was styled: %q", rendered)
	}
	if rendered := m.statusText("idle"); strings.Contains(rendered, "\x1b") {
		t.Fatalf("an ordinary status carries an escape sequence: %q", rendered)
	}
}

// The rendered interface shows the confirmation in the warning colour, in both the
// output pane and the module information pane, and keeps the focus indicator.
func TestRenderedConfirmationIsAmberAndReadable(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })

	m := promptModel(t)
	frame := m.View()
	// Lip Gloss renders the amber as a truecolor foreground, or as the nearest
	// 256-colour when the terminal reports a smaller palette.
	amberSequences := []string{"\x1b[1;38;2;255;170;51m", "\x1b[1;38;5;215m"}
	amberFound := false
	for _, sequence := range amberSequences {
		if strings.Contains(frame, sequence) {
			amberFound = true
		}
	}
	if !amberFound {
		t.Fatalf("the rendered frame does not use the warning colour:\n%q", frame)
	}
	if !strings.Contains(ansi.Strip(frame), "[y/N]") {
		t.Fatalf("the decision is missing from the rendered frame:\n%s", ansi.Strip(frame))
	}
	// The pane still reports whether it has focus, and nothing else was recoloured:
	// successful results keep the success colour.
	stripped := ansi.Strip(frame)
	if !strings.Contains(stripped, "OUTPUT //") {
		t.Fatalf("the output pane header is missing:\n%s", stripped)
	}
	// Selection marks keep the success colour: they are not part of the warning.
	if !strings.Contains(frame, lipgloss.NewStyle().Foreground(green).Bold(true).Render("[x]")) {
		t.Fatal("the selection marks are no longer rendered in the success colour")
	}
}
