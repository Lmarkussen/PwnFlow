package tui

import (
	"context"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/runner"
)

func TestWrapWatcherOutputPreservesLongLines(t *testing.T) {
	input := "LDAP  10.1.10.40  389  DC  [+] sccm.lab\\snablr-lab-admin: [REDACTED] (Pwn3d!)"
	wrapped := wrapWatcherOutput(input, 24)
	if strings.ReplaceAll(wrapped, "\n", "") != input {
		t.Fatalf("wrapped output lost characters: %q", wrapped)
	}
	for _, line := range strings.Split(wrapped, "\n") {
		if ansi.StringWidthWc(line) > 24 {
			t.Fatalf("line exceeds width: %q", line)
		}
	}
}

func TestWatcherRetainsAndNavigatesFullBatchHistory(t *testing.T) {
	all := make([]modules.Module, 30)
	items := make([]runner.BatchItem, 30)
	for index := range all {
		all[index] = viewTestModule{}
		items[index] = runner.BatchItem{Index: index, Module: all[index], Buffer: runner.NewBuffer(128)}
	}
	m := newModel(context.Background(), config.Config{}, nil, all, make([]int64, 30), 1, "test")
	m.modules = all
	m.moduleKeys = make([]int, 30)
	for index := range m.moduleKeys {
		m.moduleKeys[index] = index
	}
	m.batch = runner.NewBatchRun(items)
	m.width, m.height = 120, 30
	m.watcherListViewport = newWatcherViewport()
	m.watcherViewport = newWatcherViewport()
	m.resizeWatcher()
	m.setWatcherSelection(0, true)
	if !strings.Contains(m.watcherListViewport.View(), "View Module") {
		t.Fatal("first batch module is not visible")
	}
	m.setWatcherSelection(15, true)
	if m.watcherSelected != 15 {
		t.Fatalf("middle selection = %d", m.watcherSelected)
	}
	m.setWatcherSelection(29, true)
	if m.watcherListCursor != 29 || m.watcherSelected != 29 {
		t.Fatal("last batch module is not selectable")
	}
}

func TestWrapWatcherOutputHandlesANSIUnicodeAndNarrowWidths(t *testing.T) {
	input := "\x1b[32m界界界界界界\x1b[0m café café\n第二行"
	wrapped := wrapWatcherOutput(input, 2)
	if ansi.Strip(strings.ReplaceAll(wrapped, "\n", "")) != ansi.Strip(strings.ReplaceAll(input, "\n", "")) {
		t.Fatalf("ANSI/Unicode content changed: %q", wrapped)
	}
	for _, line := range strings.Split(wrapped, "\n") {
		if ansi.StringWidthWc(line) > 2 {
			t.Fatalf("narrow line exceeds width: %q", line)
		}
	}
}

func TestWrapWatcherOutputPreservesMultipleLines(t *testing.T) {
	input := "first very long line with words\nsecond very long line with words\nthird"
	wrapped := wrapWatcherOutput(input, 10)
	if strings.ReplaceAll(wrapped, "\n", "") != strings.ReplaceAll(input, "\n", "") {
		t.Fatalf("multiple lines changed: %q", wrapped)
	}
}
