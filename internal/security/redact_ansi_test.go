package security

import "testing"

func TestRedactANSIInterleavedSecret(t *testing.T) {
	input := "user \x1b[31ms\x1b[0mecret value"
	got := RedactString(input, "secret")
	if got != "user \x1b[31m[REDACTED] value" {
		t.Fatalf("got %q", got)
	}
}

func TestStripANSI(t *testing.T) {
	input := "\x1b[32mgreen\x1b[0m\x1b]0;unsafe\a text"
	if got := StripANSI(input); got != "greentext" && got != "green text" {
		t.Fatalf("got %q", got)
	}
}
