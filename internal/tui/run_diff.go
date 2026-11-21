package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/runner"
	"github.com/pwnflow/pwnflow/internal/storage"
)

// runDiff compares the latest completed Default Enumeration run with the one
// before it.
type runDiff struct {
	Latest, Baseline storage.Run
	New              []storage.Finding
	Resolved         []storage.Finding
	Changed          []storage.Finding
}

func (d runDiff) empty() bool { return len(d.New)+len(d.Resolved)+len(d.Changed) == 0 }

// rows returns the changes as one list for the Findings view, each marked.
func (d runDiff) rows() []storage.Finding {
	var rows []storage.Finding
	rows = append(rows, d.New...)
	rows = append(rows, d.Changed...)
	rows = append(rows, d.Resolved...)
	return rows
}

// runHistory is what the diff is computed from, loaded with the Findings.
type runHistory struct {
	Runs    []storage.Run
	Changes []storage.SeverityChange
}

func loadRunHistory(ctx context.Context, db *storage.DB, assessmentID int64) runHistory {
	if db == nil {
		return runHistory{}
	}
	runs, err := db.Runs(ctx, assessmentID)
	if err != nil {
		return runHistory{}
	}
	history := runHistory{Runs: runs}
	if latest, _, ok := latestCompletedRuns(runs); ok {
		history.Changes, _ = db.SeverityChanges(ctx, assessmentID, latest.Started)
	}
	return history
}

func latestCompletedRuns(runs []storage.Run) (latest, baseline storage.Run, ok bool) {
	var completed []storage.Run
	for _, run := range runs {
		if strings.EqualFold(run.Status, "completed") {
			completed = append(completed, run)
		}
	}
	if len(completed) < 2 {
		return storage.Run{}, storage.Run{}, false
	}
	return completed[0], completed[1], true
}

// diffIdentity matches a condition across runs. Finding keys are not enough:
// some overview Findings are keyed per execution, so every run creates a new
// row for the same condition.
func diffIdentity(finding storage.Finding) string {
	object := strings.ToLower(strings.TrimSpace(fallbackText(finding.AffectedObjectID, finding.AffectedObject)))
	return strings.ToLower(finding.FindingType) + "\x00" + object + "\x00" + strings.ToLower(strings.TrimSpace(finding.Title))
}

// computeRunDiff needs the loaded rows with not-re-observed and retired
// sources already marked. A condition is new when its row first appeared in
// the latest run and nothing equivalent existed in the previous one;
// resolved when it was seen in the previous run, the latest run did not
// re-observe it and no equivalent is current; changed when its severity
// changed during the latest run.
func computeRunDiff(rows []storage.Finding, history runHistory) (runDiff, bool) {
	latest, baseline, ok := latestCompletedRuns(history.Runs)
	if !ok {
		return runDiff{}, false
	}
	diff := runDiff{Latest: latest, Baseline: baseline}
	current := map[string]bool{}
	previous := map[string]bool{}
	for _, row := range rows {
		identity := diffIdentity(row)
		if !row.NotReobserved {
			current[identity] = true
		}
		if row.FirstSeen.Before(latest.Started) && !row.LastSeen.Before(baseline.Started) {
			previous[identity] = true
		}
	}
	changes := map[int64]storage.SeverityChange{}
	for _, change := range history.Changes {
		if !change.Observed.Before(latest.Started) {
			changes[change.FindingID] = change
		}
	}
	for _, row := range rows {
		identity := diffIdentity(row)
		switch {
		case !row.NotReobserved && !row.FirstSeen.Before(latest.Started) && !previous[identity]:
			row.ChangeNote = "new"
			diff.New = append(diff.New, row)
		case row.NotReobserved && !row.SourceModuleRetired && !row.LastSeen.Before(baseline.Started) && row.LastSeen.Before(latest.Started) && !current[identity]:
			row.ChangeNote = "resolved"
			diff.Resolved = append(diff.Resolved, row)
		case !row.NotReobserved:
			if change, ok := changes[row.ID]; ok {
				row.ChangeNote = fmt.Sprintf("severity %s → %s", strings.ToLower(change.Old), strings.ToLower(change.New))
				diff.Changed = append(diff.Changed, row)
			}
		}
	}
	diff.New, diff.Resolved = dropSupersededPairs(diff.New, diff.Resolved)
	for _, list := range [][]storage.Finding{diff.New, diff.Changed, diff.Resolved} {
		sortReportFindings(list)
	}
	return diff, true
}

// dropSupersededPairs removes a new and a resolved Finding of the same type
// and title: that is one condition reported again under a new row (overview
// Findings whose affected-object or key carries per-run detail), not a
// change. Titles name the affected object, so distinct conditions differ.
func dropSupersededPairs(added, resolved []storage.Finding) ([]storage.Finding, []storage.Finding) {
	key := func(finding storage.Finding) string {
		return strings.ToLower(finding.FindingType) + "\x00" + strings.ToLower(strings.TrimSpace(finding.Title))
	}
	resolvedKeys := map[string]int{}
	for _, finding := range resolved {
		resolvedKeys[key(finding)]++
	}
	paired := map[string]int{}
	keptNew := make([]storage.Finding, 0, len(added))
	for _, finding := range added {
		if resolvedKeys[key(finding)] > paired[key(finding)] {
			paired[key(finding)]++
			continue
		}
		keptNew = append(keptNew, finding)
	}
	keptResolved := make([]storage.Finding, 0, len(resolved))
	for _, finding := range resolved {
		if paired[key(finding)] > 0 {
			paired[key(finding)]--
			continue
		}
		keptResolved = append(keptResolved, finding)
	}
	return keptNew, keptResolved
}

func (d runDiff) summary() string {
	return fmt.Sprintf("Since the previous run (%s): %d new · %d resolved · %d severity changed",
		d.Baseline.Started.UTC().Format("2006-01-02 15:04 UTC"), len(d.New), len(d.Resolved), len(d.Changed))
}

// recordDefaultEnumerationRun stores one Default Enumeration batch in runs, so
// later runs can be compared with it. A batch with an interrupted module is
// recorded as aborted and is not used as a comparison point.
func recordDefaultEnumerationRun(ctx context.Context, db *storage.DB, targetID int64, states []runner.BatchState, finished time.Time) error {
	var started time.Time
	status := "completed"
	for _, state := range states {
		if !state.Result.Started.IsZero() && (started.IsZero() || state.Result.Started.Before(started)) {
			started = state.Result.Started
		}
		switch strings.ToLower(state.Status) {
		case "cancelled", "canceled", "aborted", "timeout":
			status = "aborted"
		}
	}
	if started.IsZero() {
		return nil
	}
	if finished.IsZero() {
		finished = time.Now()
	}
	_, err := db.RecordRun(ctx, targetID, started, finished, status)
	return err
}
