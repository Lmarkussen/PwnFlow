package pwntools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
)

func TestADWritableObjectsDeclaresRustHoundBatchPrerequisite(t *testing.T) {
	module := ADWritableObjects{}
	if got := module.BatchPrerequisites(); len(got) != 1 || got[0] != "rusthound-ce" {
		t.Fatalf("batch prerequisites = %#v, want rusthound-ce", got)
	}
	if got := module.DependencyKey(); got != "rusthound-ce" {
		t.Fatalf("dependency key = %q, want rusthound-ce", got)
	}
	if got := module.Status(&modules.Runtime{}); got != modules.StatusAvailable {
		t.Fatalf("runtime artifact absence made module unavailable at plan time: %v", got)
	}
	if details := strings.Join(module.DetailLines(&modules.Runtime{}), "\n"); !strings.Contains(details, "Requirement: RUSTHOUND-REQ") || !strings.Contains(details, "Prerequisite: REQUIRES RUSTHOUND") {
		t.Fatalf("missing prerequisite metadata: %s", details)
	}
	ready := &modules.Runtime{BatchArtifacts: map[string]string{"rusthound-ce": "/current-run"}}
	if details := strings.Join(module.DetailLines(ready), "\n"); !strings.Contains(details, "Prerequisite: "+"REA"+"DY") {
		t.Fatalf("current-batch artifact was not reflected as ready: %s", details)
	}
}

func TestADWritableObjectsPrefersExplicitArtifactOverBatchArtifact(t *testing.T) {
	runtime := &modules.Runtime{
		BatchArtifacts: map[string]string{"rusthound-ce": "/batch"},
		ModuleOptions: map[string]map[string]string{
			adWritableID: {rustHoundOption: "/explicit"},
		},
	}
	if got := writableArtifact(runtime); got != "/explicit" {
		t.Fatalf("artifact = %q, want explicit path", got)
	}
}

func TestHasRustHoundJSONRequiresEvidenceFile(t *testing.T) {
	root := t.TempDir()
	if hasRustHoundJSON(root) {
		t.Fatal("empty RustHound directory was treated as usable")
	}
	if err := os.WriteFile(filepath.Join(root, "users.json"), []byte(`{"data":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if !hasRustHoundJSON(root) {
		t.Fatal("RustHound JSON evidence was not detected")
	}
}
