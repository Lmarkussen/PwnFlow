package security

import (
	"bytes"
	"strings"
	"sync"
)

const replacement = "[REDACTED]"

type Redactor struct {
	secrets []string
	pending []byte
	mu      sync.Mutex
}

func NewRedactor(secrets ...string) *Redactor {
	r := &Redactor{}
	for _, s := range secrets {
		if s != "" {
			r.secrets = append(r.secrets, s)
		}
	}
	return r
}

func (r *Redactor) transform(in []byte) []byte {
	out := append([]byte(nil), in...)
	for _, secret := range r.secrets {
		out = redactANSI(out, []byte(secret))
	}
	return out
}

func (r *Redactor) Write(p []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending = append(r.pending, p...)
	keep := r.maxSecretLen() - 1
	if keep < 0 {
		keep = 0
	}
	if len(r.pending) <= keep {
		return nil, nil
	}
	cut := len(r.pending) - keep
	out := r.transform(r.pending[:cut])
	r.pending = append([]byte(nil), r.pending[cut:]...)
	return out, nil
}

func (r *Redactor) Flush() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.transform(r.pending)
	r.pending = nil
	return out
}

func (r *Redactor) maxSecretLen() int {
	n := 0
	for _, s := range r.secrets {
		if len(s) > n {
			n = len(s)
		}
	}
	return n
}

func RedactString(value string, secrets ...string) string {
	return string(NewRedactor(secrets...).transform([]byte(value)))
}
func ContainsSecret(value string, secrets ...string) bool {
	for _, secret := range secrets {
		if secret != "" && strings.Contains(value, secret) {
			return true
		}
	}
	return false
}

func redactANSI(input, secret []byte) []byte {
	visible, ranges := visibleBytes(input)
	start := bytes.Index(visible, secret)
	if start < 0 {
		return input
	}
	end := start + len(secret)
	if end > len(ranges) {
		return input
	}
	rawStart, rawEnd := ranges[start][0], ranges[end-1][1]
	out := make([]byte, 0, len(input)-rawEnd+rawStart+len(replacement))
	out = append(out, input[:rawStart]...)
	out = append(out, replacement...)
	out = append(out, input[rawEnd:]...)
	return redactANSI(out, secret)
}

func visibleBytes(input []byte) ([]byte, [][2]int) {
	visible := make([]byte, 0, len(input))
	ranges := make([][2]int, 0, len(input))
	for i := 0; i < len(input); {
		if input[i] != 0x1b {
			visible = append(visible, input[i])
			ranges = append(ranges, [2]int{i, i + 1})
			i++
			continue
		}
		i = escapeEnd(input, i)
	}
	return visible, ranges
}

func StripANSI(value string) string {
	input := []byte(value)
	var out strings.Builder
	for i := 0; i < len(input); {
		if input[i] == 0x1b {
			i = escapeEnd(input, i)
			continue
		}
		if input[i] == '\n' || input[i] == '\r' || input[i] == '\t' || input[i] >= 0x20 {
			out.WriteByte(input[i])
		}
		i++
	}
	return out.String()
}

func escapeEnd(input []byte, start int) int {
	if start+1 >= len(input) {
		return len(input)
	}
	if input[start+1] == '[' {
		i := start + 2
		for i < len(input) && (input[i] < 0x40 || input[i] > 0x7e) {
			i++
		}
		if i < len(input) {
			return i + 1
		}
		return len(input)
	}
	if input[start+1] == ']' {
		i := start + 2
		for i < len(input) {
			if input[i] == 0x07 {
				return i + 1
			}
			if input[i] == 0x1b && i+1 < len(input) && input[i+1] == '\\' {
				return i + 2
			}
			i++
		}
		return len(input)
	}
	return start + 2
}
