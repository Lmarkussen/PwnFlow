package runner

import (
	"bytes"
	"sync"
	"time"
)

type Buffer struct {
	mu      sync.Mutex
	data    []byte
	limit   int
	changed time.Time
}

func NewBuffer(limit int) *Buffer { return &Buffer{limit: limit} }
func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = append(b.data, p...)
	if len(b.data) > b.limit {
		b.data = append([]byte(nil), b.data[len(b.data)-b.limit:]...)
	}
	b.changed = time.Now()
	return len(p), nil
}
func (b *Buffer) Snapshot() []byte   { b.mu.Lock(); defer b.mu.Unlock(); return bytes.Clone(b.data) }
func (b *Buffer) Changed() time.Time { b.mu.Lock(); defer b.mu.Unlock(); return b.changed }
