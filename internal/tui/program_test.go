package tui

import (
	"bytes"
	"context"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
)

func TestBubbleTeaProgramStopsOnQWithoutRenderer(t *testing.T) {
	model := newModel(context.Background(), config.Config{}, nil, []modules.Module{viewTestModule{}}, []int64{1}, 1, "test")
	input := bytes.NewBufferString("q")
	program := tea.NewProgram(model, tea.WithInput(input), tea.WithOutput(&bytes.Buffer{}), tea.WithoutRenderer(), tea.WithoutSignals())
	if _, err := program.Run(); err != nil {
		t.Fatalf("program did not shut down cleanly: %v", err)
	}
}
