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

func reportFixture(assessment int64, root string) []storage.FindingInput {
	at := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	base := func(key, source, typ, title, severity, evidence string) storage.FindingInput {
		return storage.FindingInput{FindingKey: key, AssessmentID: assessment, SourceTool: source, FindingType: typ, Title: title,
			Description: "Description for " + title, Severity: severity, Confidence: "fixture", AffectedObjectID: "obj", AffectedObject: "OBJECT",
			EvidenceJSON: evidence, ArtifactPath: filepath.Join(root, "NetExec", "artifact.txt"), ArtifactRef: "line:1", ObservedAt: at, Status: "open", ParserVersion: "fixture"}
	}
	return []storage.FindingInput{
		base("gpp", "NetExec (nxc)", "netexec_gpp_password_exposure", "Recoverable Password Stored in Group Policy Preferences", "high", `{"password":"Fixture-Recovered-Secret","account":"corp\\svc"}`),
		base("pw", "NetExec (nxc)", "ad_account_password_attribute_readable", "userPassword readable: svc-legacy", "high", `{"account":"svc-legacy","attribute":"userPassword","read_by":"corp.example\\auditor"}`),
		base("stale", "RustHound-CE", "ad_account_stale_enabled_users", "Stale enabled user accounts | <script>", "low", `{"affected_objects":["ALICE@CORP.EXAMPLE","BOB@CORP.EXAMPLE"]}`),
		base("smb", "NetExec (nxc)", "smb_signing_not_required", "SMB Signing Not Required", "medium", `{"target":"192.0.2.11","signing_required":false}`),
	}
}

func TestReportRendersCategoriesCriticalAndWithholdsSecrets(t *testing.T) {
	root := t.TempDir()
	db, err := storage.Open(filepath.Join(root, "enumeration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertTarget(ctx, "corp.example", "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	id, err := db.TargetID(ctx, "corp.example", "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.IngestFindings(ctx, reportFixture(id, root)); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 2, 9, 30, 0, 0, time.UTC)
	path, err := WriteReport(ctx, db, id, "corp.example", "192.0.2.10", root, now)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "reports", "PwnFlow_report_20260602-093000Z.md"); path != want {
		t.Fatalf("report path %s, want %s", path, want)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("report mode %v", info.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	report := string(data)
	for _, want := range []string{
		"# PwnFlow assessment report: corp.example", "| HIGH | 2 |", "## Critical findings", "### Confirmed critical (1)",
		"userPassword readable: svc-legacy", "### Credentials", "### Active Directory", "#### Account Security",
		"Objects: ALICE@CORP.EXAMPLE; BOB@CORP.EXAMPLE", "`NetExec/artifact.txt` line:1", "Stale enabled user accounts \\| &lt;script&gt;",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, "Fixture-Recovered-Secret") {
		t.Fatal("report reproduced a recovered secret")
	}
	if strings.Contains(report, root) {
		t.Fatal("report exposes the absolute results path")
	}
	if _, err := WriteReport(ctx, db, id, "corp.example", "192.0.2.10", root, now); err == nil {
		t.Fatal("an existing report was overwritten")
	}
}

func TestReportMovesNotReobservedFindingsToAppendix(t *testing.T) {
	current := storage.Finding{FindingInput: storage.FindingInput{FindingType: "smb_spooler_service_running", Title: "Print Spooler reachable: DC01", Severity: "medium", SourceTool: "NetExec (nxc)", ArtifactPath: "a.txt", ArtifactRef: "line:1", EvidenceJSON: "{}"}}
	stale := storage.Finding{FindingInput: storage.FindingInput{FindingType: "netexec_cve_check", Title: "Old CVE observation", Severity: "high", SourceTool: "NetExec (nxc)", ArtifactPath: "b.txt", ArtifactRef: "line:2", EvidenceJSON: "{}"}, NotReobserved: true, LastSeen: time.Date(2026, 5, 1, 8, 0, 0, 0, time.UTC)}
	report := RenderReport([]storage.Finding{current, stale}, "corp.example", "192.0.2.10", "", time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	appendix := strings.Index(report, "## Appendix: not re-observed (1)")
	if appendix < 0 || !strings.Contains(report[appendix:], "Old CVE observation") || !strings.Contains(report[appendix:], "last seen 2026-05-01 08:00 UTC") {
		t.Fatalf("appendix missing:\n%s", report)
	}
	if strings.Contains(report[:appendix], "Old CVE observation") || strings.Contains(report, "| HIGH |") {
		t.Fatalf("not re-observed Finding leaked into the main report:\n%s", report)
	}
	if !strings.Contains(report, "1 further Finding(s) were not re-observed") {
		t.Fatalf("summary note missing:\n%s", report)
	}
}

func TestFindingsViewReportKeyWritesReport(t *testing.T) {
	root := t.TempDir()
	db, err := storage.Open(filepath.Join(root, "enumeration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.UpsertTarget(ctx, "corp.example", "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	id, _ := db.TargetID(ctx, "corp.example", "192.0.2.10")
	if err := db.IngestFindings(ctx, reportFixture(id, filepath.Join(root, "results", "corp.example"))); err != nil {
		t.Fatal(err)
	}
	m := &model{ctx: ctx, db: db, targetID: id, findingsView: true, findingCategoryView: true, width: 120, height: 40}
	m.cfg.Root, m.cfg.Domain, m.cfg.Target = root, "corp.example", "192.0.2.10"
	_, cmd := m.handleFindingsKey("R")
	if cmd == nil || !m.reportWriting {
		t.Fatal("R did not start writing a report")
	}
	if _, again := m.handleFindingsKey("R"); again != nil {
		t.Fatal("a second report started while one is being written")
	}
	msg, ok := cmd().(reportWrittenMsg)
	if !ok || msg.err != nil {
		t.Fatalf("report command result %#v", msg)
	}
	if !strings.HasPrefix(msg.path, filepath.Join(root, "results", "corp.example", "reports")) {
		t.Fatalf("report written to %s", msg.path)
	}
	m.Update(msg)
	if m.reportWriting || !strings.Contains(m.status, "report written: "+msg.path) {
		t.Fatalf("status %q", m.status)
	}
}
