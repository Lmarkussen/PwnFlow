package tui

import (
	"testing"

	"github.com/charmbracelet/bubbles/viewport"
	"github.com/pwnflow/pwnflow/internal/runner"
)

func TestWatcherViewportFollowAndResize(t *testing.T) {
	buffer := runner.NewBuffer(1024)
	_, _ = buffer.Write([]byte("one\ntwo\nthree\nfour\nfive\nsix"))
	m := &model{buffer: buffer, watcherViewport: newWatcherViewport(), watcherFollow: true, width: 20, height: 12}
	m.resizeWatcher()
	if !m.watcherViewport.AtBottom() {
		t.Fatal("watcher did not follow the newest output")
	}

	m.watcherFollow = false
	m.watcherViewport.GotoTop()
	previousOffset := m.watcherViewport.YOffset
	m.width = 12
	m.height = 8
	m.resizeWatcher()
	if m.watcherViewport.YOffset != previousOffset {
		t.Fatalf("scroll position changed from %d to %d", previousOffset, m.watcherViewport.YOffset)
	}

	m.watcherFollow = true
	m.refreshWatcher()
	if !m.watcherViewport.AtBottom() {
		t.Fatal("End/follow mode did not return to the newest output")
	}
}

func newWatcherViewport() viewport.Model { return viewport.New(1, 1) }
