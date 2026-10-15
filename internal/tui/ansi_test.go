package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestSafeANSIKeepsSGRAndDropsControlSequences(t *testing.T) {
	input := "\x1b[38;5;45m[+] ok\x1b[0m\x1b]0;unsafe title\a\x1b[2J"
	got := safeANSI(input)
	if !strings.Contains(got, "\x1b[38;5;45m") || !strings.Contains(got, "\x1b[0m") {
		t.Fatalf("safe SGR removed: %q", got)
	}
	if strings.Contains(got, "unsafe title") || strings.Contains(got, "[2J") {
		t.Fatalf("unsafe escape survived: %q", got)
	}
}

func TestDisplayOutputFallbackHighlightsWithoutChangingText(t *testing.T) {
	input := "[*] info\n[+] success\n[-] error"
	got := displayOutput(input, 80)
	if ansi.Strip(strings.ReplaceAll(got, "\n", "")) != strings.ReplaceAll(input, "\n", "") {
		t.Fatalf("fallback changed output: %q", got)
	}
}
