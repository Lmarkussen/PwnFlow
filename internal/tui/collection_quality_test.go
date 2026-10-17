package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAssessCollectionQualitySeparatesExecutionAndCollection(t *testing.T) {
	root := t.TempDir()
	completePath := filepath.Join(root, "trust.json")
	if err := os.WriteFile(completePath, []byte(`{"collection":{"status":"complete","object_count":0}}`), 0600); err != nil {
		t.Fatal(err)
	}
	partialPath := filepath.Join(root, "partial.log")
	if err := os.WriteFile(partialPath, []byte("partial evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	emptyPath := filepath.Join(root, "empty.txt")
	if err := os.WriteFile(emptyPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, module, tool, status, path, wantExecution, wantCollection, wantConfidence string
	}{
		{"complete zero", "Active Directory Trust Inventory", "LDAP", "completed", completePath, "completed", "complete", "explicit"},
		{"generic success", "RustHound-CE", "RustHound", "completed", partialPath, "completed", "unknown", "inferred"},
		{"invalid structured output", "NetworkHound", "NetworkHound", "completed", filepath.Join(root, "invalid.json"), "completed", "partial", "explicit"},
		{"timeout partial", "LDAP query", "NetExec", "timeout", partialPath, "timeout", "partial", "explicit"},
		{"failed", "LDAP query", "NetExec", "failed", filepath.Join(root, "missing"), "failed", "failed", "explicit"},
		{"permission denied", "LDAP query", "NetExec", "failed", filepath.Join(root, "missing"), "failed", "permission_denied", "explicit"},
		{"internal timeout", "LDAP query", "NetExec", "failed", filepath.Join(root, "missing"), "failed", "timeout", "explicit"},
		{"empty FTP result", "FTP Authentication Check", "NetExec (nxc)", "completed", emptyPath, "completed", "unknown", "unknown"},
		{"explicit FTP failure", "FTP Authentication Check", "NetExec (nxc)", "completed", emptyPath, "completed", "failed", "explicit"},
		{"aborted no evidence", "NetworkHound", "NetworkHound", "aborted", filepath.Join(root, "missing"), "aborted", "unknown", "explicit"},
		{"aborted partial", "NetworkHound", "NetworkHound", "aborted", partialPath, "aborted", "partial", "explicit"},
		{"aborted failure", "NetworkHound", "NetworkHound", "aborted", filepath.Join(root, "missing"), "aborted", "failed", "explicit"},
		{"unsupported", "Unsupported", "Tool", "unsupported", "", "unsupported", "unsupported", "explicit"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			errorText := ""
			if test.name == "permission denied" {
				errorText = "LDAP permission denied"
			}
			if test.name == "internal timeout" {
				errorText = "operation timed out"
			}
			if test.name == "explicit FTP failure" {
				errorText = "FTP connection failed"
			}
			if test.name == "aborted failure" {
				errorText = "collection failed before completion"
			}
			if test.name == "invalid structured output" {
				if err := os.WriteFile(test.path, []byte("not-json"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			row := assessCollectionQuality(collectionQualityExecution{ID: 1, Module: test.module, Tool: test.tool, Status: test.status, OutputPath: test.path, Error: errorText, Finished: time.Unix(1, 0)}, root)
			if row.Execution != test.wantExecution || row.Collection != test.wantCollection || row.Confidence != test.wantConfidence {
				t.Fatalf("got execution=%q collection=%q confidence=%q, want %q/%q/%q", row.Execution, row.Collection, row.Confidence, test.wantExecution, test.wantCollection, test.wantConfidence)
			}
		})
	}
}

func TestCollectionQualityReportReconcilesAbortedExecutions(t *testing.T) {
	report := formatCollectionQuality("example.test", collectionQualityReport{
		GeneratedAt: time.Unix(1, 0),
		Rows: []collectionQualityRow{
			{ExecutionID: 1, Module: "FTP Authentication Check", Tool: "NetExec", Execution: "completed", Collection: "unknown", Confidence: "unknown", Reason: "no usable output recorded"},
			{ExecutionID: 2, Module: "NetworkHound", Tool: "NetworkHound", Execution: "aborted", Collection: "unknown", Confidence: "explicit", Reason: "execution was aborted; collection coverage could not be established"},
		},
	})
	for _, want := range []string{"Executions completed:             1", "Executions aborted:                1", "Unknown:", "COMPLETED WITH COLLECTION LIMITATIONS"} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
}

func TestCollectionQualityReportIsRunScopedAndSanitized(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, assessment, execution := summaryFixtureDB(t, root, "example.test", "completed")
	defer db.Close()
	if err := os.WriteFile(filepath.Join(root, "synthetic.log"), []byte("valid output"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeCollectionQuality(ctx, db, root, "example.test", assessment, []int64{execution}, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "collection_completeness.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	report := string(data)
	for _, want := range []string{"PWNFLOW COLLECTION QUALITY REPORT", "Synthetic Module", "Unknown:", "synthetic.log"} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
	for _, secret := range []string{"password: hidden", "synthetic-secret", "hash: deadbeef"} {
		if strings.Contains(report, secret) {
			t.Fatalf("report leaked %q", secret)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("report permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestCollectionQualityAtomicFailurePreservesPreviousReport(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "collection_completeness.txt")
	if err := os.WriteFile(path, []byte("previous"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteSummary(path, "replacement"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "replacement" {
		t.Fatalf("atomic replacement failed: %q", data)
	}
}
