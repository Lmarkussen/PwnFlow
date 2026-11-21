package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestCollectionGapsFromLatestExecutions(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	results := filepath.Join(root, "results", "corp.example")
	db, err := storage.Open(filepath.Join(results, "enumeration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.UpsertTarget(ctx, "corp.example", "192.0.2.10")
	target, _ := db.TargetID(ctx, "corp.example", "192.0.2.10")
	write := func(rel, content string) string {
		path := filepath.Join(results, rel)
		os.MkdirAll(filepath.Dir(path), 0o700)
		os.WriteFile(path, []byte(content), 0o600)
		return path
	}
	at := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	run := func(name, tool, status, output, errorSummary string, started time.Time, job string) {
		module, _ := db.RegisterModule(ctx, name, tool, "SMB", "", filepath.Base(output))
		id, err := db.RecordExecutionID(ctx, target, module, started, started.Add(time.Minute), status, 0, output, errorSummary)
		if err != nil {
			t.Fatal(err)
		}
		if job != "" {
			key := name + started.String()
			db.QueueAnalysis(ctx, key, target, id, tool, output)
			db.SetAnalysisStatus(ctx, key, job, "v1", "parser exploded")
		}
	}
	ok := write("Enumeration/NetExec/SMB_spooler.txt", "SMB  192.0.2.10  445  DC01  [+] corp.example\\auditor:x\nSPOOLER  192.0.2.10  445  DC01  Spooler service enabled\n")
	refused := write("Enumeration/NetExec/LDAP_machine_account_quota.txt", "LDAPS  192.0.2.10  636  DC01  [*] Windows (name:DC01) (domain:corp.example)\nLDAPS  192.0.2.10  636  DC01  [-] corp.example\\auditor:[REDACTED] \n")
	null := write("Enumeration/NetExec/SMB_null_session.txt", "SMB  192.0.2.10  445  DC01  [-] corp.example\\: STATUS_ACCESS_DENIED\n")
	write("Enumeration/ActiveDirectory/AD_directory_settings.json", `{"schema_version":1,"ds_heuristics":{"status":"error"},"errors":["root DSE: refused"]}`)
	settings := write("Enumeration/ActiveDirectory/AD_directory_settings.txt", "AD DIRECTORY SETTINGS\n")
	bloody := write("Enumeration/Specialized/bloodyad-writable.log", "Traceback ... invalidCredentials\n")
	rh := write("Enumeration/RustHound/rusthound.log", "ok\n")

	run("Check Print Spooler", "NetExec (nxc)", "failed", ok, "Reason: old failure", at.Add(-time.Hour), "")
	run("Check Print Spooler", "NetExec (nxc)", "completed", ok, "", at, storage.AnalysisComplete)
	run("Check Machine Account Quota", "NetExec (nxc)", "completed", refused, "", at, storage.AnalysisComplete)
	run("SMB Null Session Enumeration", "NetExec (nxc)", "completed", null, "", at, storage.AnalysisComplete)
	run("AD Directory Settings", "AD Directory Settings", "completed", settings, "", at, storage.AnalysisComplete)
	run("BloodyAD Writable Object Detail", "BloodyAD", "failed", bloody, "Stage: execution\nReason: BloodyAD writable enumeration failed: exit status 1\n", at, "")
	run("RustHound-CE Collection", "RustHound-CE", "completed", rh, "", at, storage.AnalysisFailed)
	run("FTP Authentication Check", "NetExec (nxc)", "failed", ok, "Reason: no FTP service", at, "")
	run("FTP Anonymous Access", "PwnFlow FTP Probe", "skipped", "", "Reason: no endpoint", at, "")
	// An aborted batch: the queued module is recorded as cancelled without
	// output (never attempted), the running one as cancelled with output.
	gppOutput := write("CredentialDumping/NetExec/SMB_gpp_autologin.txt", "SMB  192.0.2.10  445  DC01  [+] corp.example\\auditor:x\n")
	run("GPP Autologin Credentials", "NetExec (nxc)", "completed", gppOutput, "", at, storage.AnalysisComplete)
	run("GPP Autologin Credentials", "NetExec (nxc)", "cancelled", gppOutput, "context canceled", at.Add(time.Hour), "")
	run("Check WebClient Service", "NetExec (nxc)", "completed", ok, "", at, storage.AnalysisComplete)
	run("Check WebClient Service", "NetExec (nxc)", "cancelled", "", "context canceled", at.Add(time.Hour), "")

	gaps, err := loadCollectionGaps(ctx, db, target, results, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]collectionGap{}
	for _, gap := range gaps {
		got[gap.Module] = gap
	}
	expect := map[string]string{
		"Check Machine Account Quota":     "partial",
		"AD Directory Settings":           "partial",
		"BloodyAD Writable Object Detail": "failed",
		"RustHound-CE Collection":         "analysis failed",
		"GPP Autologin Credentials":       "aborted",
	}
	for module, status := range expect {
		if got[module].Status != status {
			t.Fatalf("%s gap %+v, want status %s (all %+v)", module, got[module], status, gaps)
		}
	}
	if len(got) != len(expect) {
		t.Fatalf("unexpected gaps: %+v", gaps)
	}
	if !strings.Contains(got["BloodyAD Writable Object Detail"].Reason, "BloodyAD writable enumeration failed") {
		t.Fatalf("reason line not extracted: %q", got["BloodyAD Writable Object Detail"].Reason)
	}
	if strings.Join(got["BloodyAD Writable Object Detail"].Categories, ",") != "acl" {
		t.Fatalf("static categories %v", got["BloodyAD Writable Object Detail"].Categories)
	}

	m := &model{ctx: ctx, findingsView: true, findingCategoryView: true, width: 140, height: 50, collectionGaps: gaps}
	m.setFindingRows([]storage.Finding{{FindingInput: storage.FindingInput{FindingType: "ad_acl_genericall", Title: "ACL", Severity: "medium", EvidenceJSON: "{}"}}})
	frame := m.View()
	if !strings.Contains(frame, "COLLECTION GAPS: 5 module(s)") || !strings.Contains(frame, "Active Directory ACLs · incomplete") {
		t.Fatalf("gap notice or category marker missing:\n%s", frame)
	}
	report := RenderReport(nil, gaps, "corp.example", "192.0.2.10", results, at)
	if !strings.Contains(report, "## Collection gaps (5)") || !strings.Contains(report, "Affects: Active Directory ACLs.") {
		t.Fatalf("report gap section missing:\n%s", report)
	}
}
