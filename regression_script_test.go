package pwnflow

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestRegressionScriptParses(t *testing.T) {
	if output, err := exec.Command("bash", "-n", "scripts/regression.sh").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, output)
	}
}

func TestRegressionScriptCheck(t *testing.T) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 is not installed")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "enumeration.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE targets (id INTEGER PRIMARY KEY, domain TEXT, target_address TEXT, created_at TEXT)`,
		`CREATE TABLE findings (id INTEGER PRIMARY KEY, assessment_id INTEGER, finding_type TEXT, title TEXT, affected_object_name TEXT, last_seen TEXT)`,
		`CREATE TABLE executions (id INTEGER PRIMARY KEY, target_id INTEGER, started_at TEXT, status TEXT)`,
		`CREATE TABLE analysis_jobs (id INTEGER PRIMARY KEY, assessment_id INTEGER, updated_at TEXT, status TEXT)`,
		`INSERT INTO targets VALUES (1, 'corp.example', '192.0.2.10', '2026-06-01T00:00:00Z')`,
		// Observed in this run, with fractional seconds in the same second as --since.
		`INSERT INTO findings VALUES (1, 1, 'smb_spooler_service_running', 'Print Spooler reachable: DC01', 'DC01', '2026-06-01T10:00:00.5Z')`,
		// Left over from an earlier run.
		`INSERT INTO findings VALUES (2, 1, 'netexec_cve_check', 'old', 'DC01', '2026-05-01T10:00:00Z')`,
		`INSERT INTO executions VALUES (1, 1, '2026-06-01T10:00:01Z', 'completed')`,
		`INSERT INTO analysis_jobs VALUES (1, 1, '2026-06-01T10:00:02Z', 'COMPLETE')`,
	} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	run := func(expectations string) (string, error) {
		path := filepath.Join(dir, "expect.txt")
		if err := os.WriteFile(path, []byte(expectations), 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command("bash", "scripts/regression.sh", "check", "--db", dbPath, "--domain", "corp.example", "--expect", path, "--since", "2026-06-01T10:00:00Z").CombinedOutput()
		return string(output), err
	}
	output, err := run("# coercion\npresent smb_spooler_service_running DC01\nabsent netexec_cve_check\nabsent smb_webclient_service_running\n")
	if err != nil || !strings.Contains(output, "all checks passed") {
		t.Fatalf("expected a pass: %v\n%s", err, output)
	}
	output, err = run("present smb_webclient_service_running\nabsent smb_spooler_service_running\n")
	if err == nil || !strings.Contains(output, "FAIL present smb_webclient_service_running") || !strings.Contains(output, "FAIL absent  smb_spooler_service_running") {
		t.Fatalf("expected failures: %v\n%s", err, output)
	}
}
