package tui

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

func TestRunDiffClassifiesChanges(t *testing.T) {
	baseline := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	latest := baseline.Add(24 * time.Hour)
	history := runHistory{
		Runs: []storage.Run{
			{ID: 3, Started: latest.Add(time.Hour), Status: "aborted"}, // ignored as a comparison point
			{ID: 2, Started: latest, Status: "completed"},
			{ID: 1, Started: baseline, Status: "completed"},
			{ID: 0, Started: baseline.Add(-48 * time.Hour), Status: "completed"},
		},
		Changes: []storage.SeverityChange{{FindingID: 6, Observed: latest.Add(time.Minute), Old: "low", New: "medium"}},
	}
	row := func(id int64, typ, title string, first, last time.Time, notReobserved bool) storage.Finding {
		return storage.Finding{ID: id, FindingInput: storage.FindingInput{FindingType: typ, Title: title, AffectedObject: "DC01", Severity: "medium"}, FirstSeen: first, LastSeen: last, NotReobserved: notReobserved}
	}
	retired := row(4, "netexec_cve_check", "old CVE", baseline, baseline.Add(time.Minute), true)
	retired.SourceModuleRetired = true
	rows := []storage.Finding{
		row(1, "smb_webclient_service_running", "WebClient running", latest.Add(time.Minute), latest.Add(time.Minute), false),
		row(2, "smb_spooler_service_running", "Spooler", baseline.Add(time.Minute), latest.Add(time.Minute), false),
		row(3, "smb_v1_enabled", "SMBv1", baseline.Add(time.Minute), baseline.Add(time.Minute), true),
		retired,
		row(5, "ad_acl_evidence_inventory", "AD ACL Evidence Inventory", baseline.Add(time.Minute), baseline.Add(time.Minute), true),
		row(50, "ad_acl_evidence_inventory", "AD ACL Evidence Inventory", latest.Add(time.Minute), latest.Add(time.Minute), false),
		row(6, "ldap_signing_not_enforced", "LDAP signing", baseline.Add(time.Minute), latest.Add(time.Minute), false),
		row(7, "smb_guest_session_mapped", "Guest", baseline.Add(-47*time.Hour), baseline.Add(-47*time.Hour), true),
		// An overview whose affected object changes per run: same type and
		// title on both sides is a superseded copy, not a change.
		{ID: 8, FindingInput: storage.FindingInput{FindingType: "ad_privileged_acl_evidence_inventory", Title: "AD Privileged ACL Evidence Inventory", AffectedObject: "run-1", Severity: "informational"}, FirstSeen: baseline.Add(time.Minute), LastSeen: baseline.Add(time.Minute), NotReobserved: true},
		{ID: 80, FindingInput: storage.FindingInput{FindingType: "ad_privileged_acl_evidence_inventory", Title: "AD Privileged ACL Evidence Inventory", AffectedObject: "run-2", Severity: "informational"}, FirstSeen: latest.Add(time.Minute), LastSeen: latest.Add(time.Minute)},
	}
	diff, ok := computeRunDiff(rows, history)
	if !ok {
		t.Fatal("diff not computed")
	}
	ids := func(list []storage.Finding) []int64 {
		var out []int64
		for _, item := range list {
			out = append(out, item.ID)
		}
		return out
	}
	if got := ids(diff.New); len(got) != 1 || got[0] != 1 {
		t.Fatalf("new %v", got)
	}
	if got := ids(diff.Resolved); len(got) != 1 || got[0] != 3 {
		t.Fatalf("resolved %v", got)
	}
	if len(diff.Changed) != 1 || diff.Changed[0].ID != 6 || diff.Changed[0].ChangeNote != "severity low → medium" {
		t.Fatalf("changed %+v", diff.Changed)
	}
	if !strings.Contains(diff.summary(), "1 new · 1 resolved · 1 severity changed") {
		t.Fatalf("summary %q", diff.summary())
	}
	if displayFindingTitle(diff.New[0]) != "WebClient running · new" || displayFindingTitle(diff.Resolved[0]) != "SMBv1 · resolved" {
		t.Fatalf("markers %q / %q", displayFindingTitle(diff.New[0]), displayFindingTitle(diff.Resolved[0]))
	}
	if _, ok := computeRunDiff(rows, runHistory{Runs: history.Runs[:2]}); ok {
		t.Fatal("a diff needs two completed runs")
	}

	db, err := storage.Open(filepath.Join(t.TempDir(), "enumeration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m := &model{ctx: context.Background(), db: db, findingsView: true, findingCategoryView: true, width: 140, height: 40, runHistory: history}
	m.setFindingRows(rows)
	m.findingsLoaded = true
	frame := m.View()
	if !strings.Contains(frame, "1 new · 1 resolved · 1 severity changed; D lists them.") {
		t.Fatalf("summary line missing:\n%s", frame)
	}
	m.handleFindingsKey("D")
	if m.findingCategory != "changes" || len(m.findingRows) != 3 {
		t.Fatalf("D did not open the change list: category=%q rows=%d", m.findingCategory, len(m.findingRows))
	}
	m.handleFindingsKey("esc")
	if m.findingCategory != "" || !m.findingCategoryView {
		t.Fatal("Esc did not return to the categories")
	}
	report := renderReport(rows, nil, diff, true, "corp.example", "192.0.2.10", "", latest)
	for _, want := range []string{"## Changes since the previous run", "### New (1)", "### Severity changed (1)", "(severity low → medium)", "### Resolved (not re-observed) (1)"} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
}
