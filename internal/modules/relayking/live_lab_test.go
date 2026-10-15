package relayking

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
	"github.com/pwnflow/pwnflow/internal/runner"
)

// The live check is opt-in and offline by default. It runs the *targeted*
// assessment - the profile that stays on the single host the operator configured -
// against an authorized target supplied through the environment:
//
//	PWNFLOW_LIVE_TARGET=198.51.100.10 \
//	PWNFLOW_LIVE_DOMAIN=corp.example \
//	PWNFLOW_LIVE_USER=lowpriv \
//	PWNFLOW_LIVE_PASSWORD=... \
//	go test ./internal/modules/relayking -run TestLiveLabTargetedAssessment -v
//
// The domain-wide audit is never part of this check: it contacts every computer
// RelayKing enumerates, which is a decision only the operator can make for a
// specific engagement.
func TestLiveLabTargetedAssessment(t *testing.T) {
	target := os.Getenv("PWNFLOW_LIVE_TARGET")
	if target == "" {
		t.Skip("set PWNFLOW_LIVE_TARGET (and PWNFLOW_LIVE_DOMAIN/USER/PASSWORD) to run the live assessment")
	}
	domain := os.Getenv("PWNFLOW_LIVE_DOMAIN")
	user := os.Getenv("PWNFLOW_LIVE_USER")
	password := os.Getenv("PWNFLOW_LIVE_PASSWORD")
	if domain == "" || user == "" || password == "" {
		t.Fatal("PWNFLOW_LIVE_DOMAIN, PWNFLOW_LIVE_USER, and PWNFLOW_LIVE_PASSWORD are required")
	}
	root := t.TempDir()
	runtime := &modules.Runtime{Target: target, Domain: domain, Username: user, Password: password, ResultsRoot: root}
	entry := module(t, "relayking-target-assessment")
	result := (runner.Runner{Secrets: []string{password}, BufferLimit: 512 * 1024}).
		Execute(context.Background(), entry, runtime, root)
	if result.Status != "completed" {
		t.Fatalf("the assessment did not complete: %s (%v)", result.Status, result.Err)
	}
	// Both reports and the relay target list belong to this run.
	pattern := filepath.Join(root, artifactRel, "*", "relayking-scan.json")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		t.Fatalf("the assessment wrote no JSON report (looked for %s): %v", pattern, err)
	}
	path := matches[len(matches)-1]
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Targets  []string       `json:"targets"`
		Hosts    map[string]any `json:"host_results"`
		Paths    []any          `json:"relay_paths"`
		Duration float64        `json:"scan_duration"`
	}
	if err := json.Unmarshal(contents, &report); err != nil {
		t.Fatalf("the JSON report does not parse: %v", err)
	}
	// The scan stays on the host the operator named.
	if len(report.Targets) != 1 || report.Targets[0] != target {
		t.Fatalf("the assessment did not stay on the configured target: %v", report.Targets)
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm()&0007 != 0 {
		t.Fatalf("the report is world-accessible: %o", info.Mode().Perm())
	}
	list := filepath.Join(filepath.Dir(path), "relaytargets.txt")
	listInfo, listErr := os.Stat(list)
	if listErr != nil {
		t.Fatalf("the relay target list was not written: %v", listErr)
	}
	if listInfo.Mode().Perm()&0007 != 0 {
		t.Fatalf("the relay target list is world-accessible: %o", listInfo.Mode().Perm())
	}
	t.Logf("targeted assessment: %d host result(s), %d relay path(s), %.1fs, %d bytes in %s",
		len(report.Hosts), len(report.Paths), report.Duration, len(contents), path)
}
