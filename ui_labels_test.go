package pwnflow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The module list reports an available module by saying nothing about it. The
// retired "READY" suffix must not come back through a source file, a template, or
// documentation; the label is assembled here so this check does not match itself.
func TestRepositoryCarriesNoReadyLabel(t *testing.T) {
	label := "REA" + "DY"
	for _, path := range trackedFiles(t) {
		if path == "ui_labels_test.go" {
			continue
		}
		switch filepath.Ext(path) {
		case ".go", ".md", ".sh":
		default:
			continue
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if strings.Contains(string(contents), label) {
			t.Errorf("%s still carries the %s label; an available module must carry no suffix", path, label)
		}
	}
}
