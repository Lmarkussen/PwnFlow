package tui

import (
	"strings"
	"testing"
)

func TestWrapPaneTextBreaksLongCommaListsAtBoundaries(t *testing.T) {
	value := "21,22,23,25,53,80,110,111,135,139,389,443,445,593,623,636"
	wrapped := wrapPaneText(value, 20)
	for _, line := range strings.Split(wrapped, "\n") {
		if len(line) > 20 {
			t.Fatalf("wrapped line exceeds width: %q", line)
		}
	}
	if !strings.Contains(wrapped, "593,623") {
		t.Fatalf("port pair was split away from its comma boundary: %q", wrapped)
	}
}
