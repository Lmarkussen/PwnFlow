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

func TestRegressionScriptTrend(t *testing.T) {
	dir := t.TempDir()
	header := "time,duration_s,findings,high,medium,low,informational,failed_checks,status\n"
	stable := "2026-06-01T01:00:00Z,80,110,7,32,7,64,0,0\n2026-06-02T01:00:00Z,85,111,7,32,7,65,0,0\n2026-06-03T01:00:00Z,82,110,7,32,7,64,0,0\n"
	run := func(lines string) (string, error) {
		path := filepath.Join(dir, "history.csv")
		if err := os.WriteFile(path, []byte(header+lines), 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command("bash", "scripts/regression.sh", "trend", "--history", path).CombinedOutput()
		return string(output), err
	}
	if output, err := run(stable); err != nil || !strings.Contains(output, "in line with history") {
		t.Fatalf("stable history flagged: %v\n%s", err, output)
	}
	for name, latest := range map[string]string{
		"failed checks rose": "2026-06-04T01:00:00Z,84,110,7,32,7,64,2,1\n",
		"duration":           "2026-06-04T01:00:00Z,200,110,7,32,7,64,0,0\n",
		"Finding count":      "2026-06-04T01:00:00Z,84,80,7,20,7,46,0,0\n",
	} {
		output, err := run(stable + latest)
		if err == nil || !strings.Contains(output, name) {
			t.Fatalf("%s not flagged: %v\n%s", name, err, output)
		}
	}
}

// path expectations are checked against the attack paths of a report the
// PwnFlow binary next to the database writes; the report is removed again.
func TestRegressionScriptPathExpectations(t *testing.T) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 is not installed")
	}
	root := t.TempDir()
	results := filepath.Join(root, "results", "corp.example")
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(results, 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(results, "enumeration.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE targets (id INTEGER PRIMARY KEY, domain TEXT)`,
		`CREATE TABLE findings (id INTEGER PRIMARY KEY, assessment_id INTEGER, finding_type TEXT, title TEXT, affected_object_name TEXT, last_seen TEXT)`,
		`CREATE TABLE executions (id INTEGER PRIMARY KEY, target_id INTEGER, started_at TEXT, status TEXT)`,
		`CREATE TABLE analysis_jobs (id INTEGER PRIMARY KEY, assessment_id INTEGER, updated_at TEXT, status TEXT)`,
		`INSERT INTO targets VALUES (1, 'corp.example')`,
	} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	report := filepath.Join(results, "report.md")
	fake := "#!/bin/sh\n[ \"$1\" = --report ] || exit 9\nprintf '%s\\n' '- **Attack path: Spoof a name through ADIDNS and relay the authentication it attracts — CORP.EXAMPLE**' > " + report + "\necho \"Report written: " + report + "\"\n"
	if err := os.WriteFile(filepath.Join(root, "bin", "pwnflow"), []byte(fake), 0o700); err != nil {
		t.Fatal(err)
	}
	expect := filepath.Join(root, "expect.txt")
	run := func(expectations string) (string, error) {
		if err := os.WriteFile(expect, []byte(expectations), 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command("bash", "scripts/regression.sh", "check", "--db", dbPath, "--domain", "corp.example", "--expect", expect).CombinedOutput()
		return string(output), err
	}
	output, err := run("path ADIDNS\npath relay the authentication\n")
	if err != nil || !strings.Contains(output, "PASS path    ADIDNS") || !strings.Contains(output, "all checks passed") {
		t.Fatalf("expected the path to pass: %v\n%s", err, output)
	}
	if _, statErr := os.Stat(report); !os.IsNotExist(statErr) {
		t.Fatal("the generated report was not removed")
	}
	output, err = run("path unconstrained\n")
	if err == nil || !strings.Contains(output, "FAIL path    unconstrained") {
		t.Fatalf("expected the path to fail: %v\n%s", err, output)
	}
}

// --notify receives a summary when a run fails, here one that cannot start.
func TestRegressionScriptNotifiesOnFailure(t *testing.T) {
	dir := t.TempDir()
	notified := filepath.Join(dir, "notified")
	output, err := exec.Command("bash", "scripts/regression.sh", "run", "--env", filepath.Join(dir, "missing.env"), "--expect", filepath.Join(dir, "missing.txt"), "--notify", "cat > "+notified).CombinedOutput()
	if err == nil {
		t.Fatalf("a run without its files succeeded:\n%s", output)
	}
	summary, readErr := os.ReadFile(notified)
	if readErr != nil || !strings.Contains(string(summary), "run exit 2") {
		t.Fatalf("no failure summary: %v %q\n%s", readErr, summary, output)
	}
}
