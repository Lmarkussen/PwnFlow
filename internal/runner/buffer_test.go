package runner

import "testing"

func TestBufferBounded(t *testing.T) {
	b := NewBuffer(5)
	_, _ = b.Write([]byte("123456789"))
	if got := string(b.Snapshot()); got != "56789" {
		t.Fatalf("got %q", got)
	}
}
