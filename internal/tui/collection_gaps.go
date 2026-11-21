package tui

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

// collectionGap is a module whose latest execution did not produce complete
// evidence, so Findings it normally feeds may be missing.
type collectionGap struct {
	Module     string
	Tool       string
	Status     string // failed, partial, timeout, aborted, analysis failed
	Reason     string
	Started    time.Time
	Categories []string // Finding category keys the module has fed
}

// netExecLoginRefused matches a NetExec login line that failed for a named
// account. Null-session refusals ("DOMAIN\:") are expected and do not match.
var netExecLoginRefused = regexp.MustCompile(`^\s*\S+\s+\S+\s+\d+\s+\S+\s+\[-\]\s+[^\\\s]*\\[^:\s]+:`)

// staticModuleCategories covers modules that have not produced a Finding yet
// in this assessment, so their gap still names what may be missing.
var staticModuleCategories = map[string][]string{
	"rusthound-ce":                  {"active_directory", "acl", "kerberos", "delegation"},
	"certipy":                       {"adcs"},
	"bloodyad":                      {"acl"},
	"ad writable object assessment": {"acl"},
	"pwnflow / rusthound analysis":  {"acl"},
	"ad directory settings":         {"active_directory"},
	"sccmhunter":                    {"credentials"},
	"pxethief":                      {"credentials"},
	"relayking":                     {"network"},
	"networkhound":                  {"network"},
	"gpoparser":                     {"active_directory", "network"},
	"ghostspn":                      {"active_directory"},
}

// loadCollectionGaps assesses the latest execution of every module that has
// run in the assessment.
func loadCollectionGaps(ctx context.Context, db *storage.DB, assessmentID int64, resultsRoot string, findings []storage.Finding) ([]collectionGap, error) {
	if db == nil || assessmentID <= 0 {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `SELECT e.id,m.name,m.tool,e.status,COALESCE(e.exit_code,-1),COALESCE(e.output_path,''),COALESCE(e.error_summary,''),e.started_at,COALESCE(e.finished_at,''),
		COALESCE((SELECT upper(a.status) FROM analysis_jobs a WHERE a.execution_id = e.id ORDER BY a.id DESC LIMIT 1),''),
		COALESCE((SELECT a.error_summary FROM analysis_jobs a WHERE a.execution_id = e.id ORDER BY a.id DESC LIMIT 1),'')
		FROM executions e JOIN modules m ON m.id = e.module_id
		WHERE e.target_id = ? AND e.id IN (
			SELECT max(x.id) FROM executions x JOIN modules xm ON xm.id = x.module_id
			WHERE x.target_id = ?
			  -- A batch that is aborted records its queued modules as cancelled
			  -- without output; they were never attempted, so the module's
			  -- previous run still stands.
			  AND NOT (lower(x.status) IN ('cancelled', 'canceled') AND COALESCE(x.output_path, '') = '')
			GROUP BY xm.name, xm.tool)
		ORDER BY m.name`, assessmentID, assessmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	categories := moduleFindingCategories(findings)
	var gaps []collectionGap
	for rows.Next() {
		var execution collectionQualityExecution
		var started, finished, jobStatus, jobError string
		if err := rows.Scan(&execution.ID, &execution.Module, &execution.Tool, &execution.Status, &execution.ExitCode, &execution.OutputPath, &execution.Error, &started, &finished, &jobStatus, &jobError); err != nil {
			return nil, err
		}
		execution.Started, _ = time.Parse(time.RFC3339Nano, started)
		if finished != "" {
			execution.Finished, _ = time.Parse(time.RFC3339Nano, finished)
		}
		gap, ok := assessCollectionGap(execution, resultsRoot, jobStatus, jobError)
		if !ok {
			continue
		}
		gap.Categories = categories[execution.Module+"\x00"+execution.Tool]
		if len(gap.Categories) == 0 {
			gap.Categories = staticModuleCategories[strings.ToLower(execution.Tool)]
		}
		gaps = append(gaps, gap)
	}
	return gaps, rows.Err()
}

// assessCollectionGap decides whether one latest execution is a gap.
// Skipped and unsupported modules are not gaps: nothing was attempted. The
// optional per-protocol authentication checks fail whenever a service is
// absent, so only an explicit failure of another kind counts for them.
func assessCollectionGap(execution collectionQualityExecution, resultsRoot, jobStatus, jobError string) (collectionGap, bool) {
	gap := collectionGap{Module: execution.Module, Tool: execution.Tool, Started: execution.Started}
	row := assessCollectionQuality(execution, resultsRoot)
	switch {
	case row.Execution == "not_assessed" || row.Collection == "unsupported" || row.Collection == "not_assessed":
		return gap, false
	case isOptionalAuthenticationCheck(execution.Module):
		return gap, false
	case row.Execution == "timeout" || row.Execution == "aborted":
		gap.Status, gap.Reason = row.Execution, firstReasonLine(fallbackText(execution.Error, row.Reason))
		return gap, true
	case row.Execution == "failed" || row.Collection == "failed":
		gap.Status, gap.Reason = "failed", firstReasonLine(fallbackText(execution.Error, row.Reason))
		return gap, true
	}
	if reason := artifactCollectionProblem(execution, resultsRoot); reason != "" {
		gap.Status, gap.Reason = "partial", reason
		return gap, true
	}
	if row.Collection == "partial" {
		gap.Status, gap.Reason = "partial", firstReasonLine(row.Reason)
		return gap, true
	}
	if jobStatus == storage.AnalysisFailed {
		gap.Status, gap.Reason = "analysis failed", firstReasonLine(fallbackText(jobError, "the Findings analysis of this execution failed"))
		return gap, true
	}
	return gap, false
}

// artifactCollectionProblem finds failures a completed execution hides in its
// own output: a refused NetExec login, or collection errors recorded in the AD
// Directory Settings report.
func artifactCollectionProblem(execution collectionQualityExecution, resultsRoot string) string {
	tool := strings.ToLower(execution.Tool)
	switch {
	case strings.HasPrefix(tool, "netexec"):
		for _, path := range collectionEvidencePaths(execution, resultsRoot) {
			if refusedNetExecLogin(path) {
				return "the target refused the assessment account's login, so the module collected nothing"
			}
		}
	case tool == "ad directory settings":
		for _, path := range collectionEvidencePaths(execution, resultsRoot) {
			if !strings.HasSuffix(strings.ToLower(path), ".json") {
				path = strings.TrimSuffix(path, ".txt") + ".json"
			}
			if problem := directorySettingsProblem(path); problem != "" {
				return problem
			}
		}
	}
	return ""
}

func refusedNetExecLogin(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for lines := 0; scanner.Scan() && lines < 200; lines++ {
		line := ansiPattern.ReplaceAllString(scanner.Text(), "")
		if netExecLoginRefused.MatchString(line) {
			return true
		}
		if strings.Contains(line, "[+]") && strings.Contains(line, "\\") {
			return false
		}
	}
	return false
}

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func directorySettingsProblem(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var report struct {
		DSHeuristics struct {
			Status string `json:"status"`
		} `json:"ds_heuristics"`
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(data, &report) != nil {
		return ""
	}
	var problems []string
	if report.DSHeuristics.Status == "error" {
		problems = append(problems, "dSHeuristics could not be read")
	}
	if len(report.Errors) > 0 {
		problems = append(problems, fmt.Sprintf("%d directory read(s) failed", len(report.Errors)))
	}
	return strings.Join(problems, "; ")
}

// moduleFindingCategories maps each module (name and tool) to the categories
// of the Findings it has produced.
func moduleFindingCategories(findings []storage.Finding) map[string][]string {
	sets := map[string]map[string]bool{}
	for _, finding := range findings {
		if finding.SourceModule == "" {
			continue
		}
		key := finding.SourceModule + "\x00" + finding.SourceModuleTool
		if sets[key] == nil {
			sets[key] = map[string]bool{}
		}
		sets[key][findingCategoryKey(finding)] = true
	}
	result := map[string][]string{}
	for key, set := range sets {
		for category := range set {
			result[key] = append(result[key], category)
		}
		sort.Strings(result[key])
	}
	return result
}

// firstReasonLine keeps the most useful line of a stored error summary: its
// "Reason:" line when there is one.
func firstReasonLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "Reason:") {
			return safeQualityText(strings.TrimSpace(strings.TrimPrefix(trimmed, "Reason:")))
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return safeQualityText(trimmed)
		}
	}
	return ""
}

// categoryName returns the display name of a Finding category key.
func categoryName(key string) string {
	for _, category := range findingCategoryOrder {
		if category.Key == key {
			return category.Name
		}
	}
	return key
}
