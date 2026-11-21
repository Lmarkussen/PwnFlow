package tui

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/storage"
)

func searchFixture() []storage.Finding {
	return []storage.Finding{
		{ID: 1, FindingInput: storage.FindingInput{FindingType: "smb_spooler_service_running", Title: "Print Spooler reachable: MECM", AffectedObject: "MECM", Severity: "medium", SourceTool: "NetExec (nxc)", EvidenceJSON: "{}"}},
		{ID: 2, FindingInput: storage.FindingInput{FindingType: "ad_account_laps_not_observed", Title: "Computers without observed LAPS (CORP.EXAMPLE)", AffectedObject: "CORP.EXAMPLE", Severity: "medium", SourceTool: "RustHound-CE", EvidenceJSON: `{"affected_objects":["MECM.CORP.EXAMPLE","WS01.CORP.EXAMPLE"]}`}},
		{ID: 3, FindingInput: storage.FindingInput{FindingType: "rbcd_observed", Title: "Resource-based delegation configured: WS01", AffectedObject: "WS01.CORP.EXAMPLE", RelatedObject: "MECM$", Severity: "medium", SourceTool: "RustHound-CE", EvidenceJSON: "{}"}},
		{ID: 4, FindingInput: storage.FindingInput{FindingType: "netexec_gpp_password_exposure", Title: "Recoverable Password Stored in Group Policy Preferences", AffectedObject: "CORP\\svc-backup", Severity: "high", SourceTool: "NetExec (nxc)", EvidenceJSON: `{"password":"Fixture-Secret-7","account":"CORP\\svc-backup"}`}},
	}
}

func TestSearchFindingsMatchesWordsButNotSecrets(t *testing.T) {
	rows := searchFixture()
	if got := searchFindings(rows, "spooler mecm"); len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("multi-word search %+v", got)
	}
	if got := searchFindings(rows, "ws01"); len(got) != 2 {
		t.Fatalf("evidence object names not searched: %+v", got)
	}
	if got := searchFindings(rows, "Fixture-Secret-7"); len(got) != 0 {
		t.Fatal("a recovered secret is searchable")
	}
}

func TestFindingsAboutObjectNormalizesNames(t *testing.T) {
	for _, form := range []string{"MECM", "mecm.corp.example", "MECM$", "CORP\\MECM", "mecm@CORP.EXAMPLE"} {
		if key := normalizeObjectName(form); key != "mecm" {
			t.Fatalf("%q normalizes to %q", form, key)
		}
	}
	if normalizeObjectName("192.0.2.10") != "192.0.2.10" {
		t.Fatal("an address was truncated")
	}
	got := findingsAboutObject(searchFixture(), "MECM")
	ids := map[int64]bool{}
	for _, row := range got {
		ids[row.ID] = true
	}
	if len(got) != 3 || !ids[1] || !ids[2] || !ids[3] {
		t.Fatalf("object view %+v", got)
	}
}

func TestSearchAndObjectKeys(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "enumeration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m := &model{ctx: context.Background(), db: db, findingsView: true, findingCategoryView: true, width: 140, height: 40}
	m.setFindingRows(searchFixture())
	m.findingsLoaded = true
	m.handleFindingsKey("/")
	for _, key := range []string{"s", "p", "o", "o", "l", "e", "r"} {
		m.handleFindingsKey(key)
	}
	if !strings.Contains(m.View(), "Search: spooler▌") {
		t.Fatalf("search line not shown:\n%s", m.View())
	}
	m.handleFindingsKey("enter")
	if m.findingCategory != "results" || len(m.findingRows) != 1 || !strings.Contains(m.View(), `Search "spooler" — 1 Finding(s)`) {
		t.Fatalf("search results: category=%q rows=%d", m.findingCategory, len(m.findingRows))
	}
	m.handleFindingsKey("O")
	if !strings.HasPrefix(m.findingResultsTitle, "Everything about MECM") || len(m.findingRows) != 3 {
		t.Fatalf("object view: %q rows=%d", m.findingResultsTitle, len(m.findingRows))
	}
	m.handleFindingsKey("esc")
	if m.findingCategory != "" || !m.findingCategoryView {
		t.Fatal("Esc did not return to the categories")
	}
	m.handleFindingsKey("/")
	m.handleFindingsKey("x")
	m.handleFindingsKey("esc")
	if m.findingSearchActive || m.findingCategory != "" {
		t.Fatal("Esc did not cancel the search line")
	}
}
