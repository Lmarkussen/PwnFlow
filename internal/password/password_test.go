package password

import (
	"bytes"
	"errors"
	"testing"
)

func TestReadMaskedEditing(t *testing.T) {
	var output bytes.Buffer
	got, err := ReadMasked(bytes.NewBufferString("ab\bcd\r"), &output)
	if err != nil {
		t.Fatal(err)
	}
	if got != "acd" {
		t.Fatalf("got %q", got)
	}
	if output.String() != "**\b \b**\r\n" {
		t.Fatalf("mask output %q", output.String())
	}
}

func TestReadMaskedCancellation(t *testing.T) {
	var output bytes.Buffer
	_, err := ReadMasked(bytes.NewBuffer([]byte{'a', 3}), &output)
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("got %v", err)
	}
	if output.String() != "*^C\r\n" {
		t.Fatalf("output %q", output.String())
	}
}

func TestReadMaskedRejectsEmpty(t *testing.T) {
	_, err := ReadMasked(bytes.NewBufferString("\r"), &bytes.Buffer{})
	if err == nil || err.Error() != "password cannot be empty" {
		t.Fatalf("got %v", err)
	}
}
