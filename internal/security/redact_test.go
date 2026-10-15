package security

import "testing"

func TestSplitChunkRedaction(t *testing.T) {
	r := NewRedactor("secret")
	a, _ := r.Write([]byte("pass se"))
	b, _ := r.Write([]byte("cret value"))
	got := string(append(a, b...)) + string(r.Flush())
	if got != "pass [REDACTED] value" {
		t.Fatalf("%q", got)
	}
}
