package findings

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBloodyADDetailPreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bloodyad.log")
	os.WriteFile(path, []byte("distinguishedName: CN=Lab,DC=example,DC=test\nobjectClass: user\nservicePrincipalName: WRITE\ndn: WRITE_DAC\n"), 0600)
	rows, err := AnalyzeBloodyADWritable(context.Background(), path, 1, 2, time.Now())
	if err != nil || len(rows) != 1 {
		t.Fatalf("%+v %v", rows, err)
	}
	if rows[0].Severity != "informational" || !strings.Contains(rows[0].EvidenceJSON, "servicePrincipalName") {
		t.Fatal(rows[0])
	}
	os.WriteFile(path, []byte("access denied"), 0600)
	rows, err = AnalyzeBloodyADWritable(context.Background(), path, 1, 2, time.Now())
	if err != nil || len(rows) != 0 {
		t.Fatalf("%+v %v", rows, err)
	}
}
