package tui

import (
	"github.com/pwnflow/pwnflow/internal/storage"
	"testing"
)

func TestExtractKerberosInlineParsesASREPPrincipal(t *testing.T) {
	lines := []string{"$krb5asrep$23$user@example.test:REDACTED"}
	got := extractKerberosInline(lines, map[string]any{"material_type": "asrep", "principal": "user@example.test", "record_line_numbers": []any{float64(1)}}, storage.Finding{})
	if len(got) != 1 || got[0] != lines[0] {
		t.Fatalf("AS-REP evidence was not matched to its principal: %v", got)
	}
}
