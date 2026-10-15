package networkhound

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/runner"
)

// The live check is opt-in and offline by default. It runs the directory
// collection - the registration that reads the domain controller over LDAP and
// resolves names through it - against an authorized target supplied through the
// environment:
//
//	PWNFLOW_LIVE_TARGET=198.51.100.10 \
//	PWNFLOW_LIVE_DOMAIN=corp.example \
//	PWNFLOW_LIVE_USER=audituser \
//	PWNFLOW_LIVE_PASSWORD=... \
//	go test ./internal/modules/networkhound -run TestLiveLabTopologyCollection -v
//
// The scoped network scan is never part of this check: it needs a scope the
// operator authorizes per run, and the live check has no way to grant one.
func TestLiveLabTopologyCollection(t *testing.T) {
	target := os.Getenv("PWNFLOW_LIVE_TARGET")
	if target == "" {
		t.Skip("set PWNFLOW_LIVE_TARGET (and PWNFLOW_LIVE_DOMAIN/USER/PASSWORD) to run the live collection")
	}
	domain := os.Getenv("PWNFLOW_LIVE_DOMAIN")
	user := os.Getenv("PWNFLOW_LIVE_USER")
	password := os.Getenv("PWNFLOW_LIVE_PASSWORD")
	if domain == "" || user == "" || password == "" {
		t.Fatal("PWNFLOW_LIVE_DOMAIN, PWNFLOW_LIVE_USER, and PWNFLOW_LIVE_PASSWORD are required")
	}
	root := t.TempDir()
	runtime := &modules.Runtime{Target: target, Domain: domain, Username: user, Password: password, ResultsRoot: root}
	entry := module(t, "networkhound-topology")
	result := (runner.Runner{Secrets: []string{password}, BufferLimit: 512 * 1024}).
		Execute(context.Background(), entry, runtime, root)
	if result.Status != "completed" {
		t.Fatalf("the collection did not complete: %s (%v)", result.Status, result.Err)
	}
	// The OpenGraph JSON is the artifact: it has to exist, parse, and describe the
	// domain it was collected from. It is found by searching the assessment tree
	// for this run's file, so the check does not depend on the run's timestamp.
	pattern := filepath.Join(root, artifactRel, "*", topologyOutput)
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		t.Fatalf("the collection wrote no OpenGraph JSON (looked for %s): %v", pattern, err)
	}
	path := matches[len(matches)-1]
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the collection wrote no OpenGraph JSON: %v", err)
	}
	var document struct {
		Graph struct {
			Nodes []map[string]any `json:"nodes"`
			Edges []map[string]any `json:"edges"`
		} `json:"graph"`
	}
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatalf("the OpenGraph JSON does not parse: %v", err)
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm()&0007 != 0 {
		t.Fatalf("the artifact is world-accessible: %o", info.Mode().Perm())
	}
	if len(document.Graph.Nodes) == 0 {
		t.Fatalf("the OpenGraph JSON describes no nodes")
	}
	t.Logf("collection: %d node(s), %d edge(s), %d bytes in %s",
		len(document.Graph.Nodes), len(document.Graph.Edges), len(contents), path)
	// The scope statement is what the operator reads before running it.
	details := strings.Join(entry.DetailLines(runtime), "\n")
	if !strings.Contains(details, "does not connect") && !strings.Contains(details, "Not requested") {
		t.Fatalf("Module Information does not state the collection scope:\n%s", details)
	}
}
