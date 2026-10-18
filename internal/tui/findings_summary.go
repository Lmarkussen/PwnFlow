package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/pwnflow/pwnflow/internal/storage"
)

var summarySecretPattern = regexp.MustCompile(`(?i)(?:password|passwd|passphrase|secret|token|hash|private\s+key|ticket)\s*[:=]\s*[^\s,;]+|\$krb5[^\s]+|-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----|\b[0-9a-f]{32,}\b`)

type summaryExecution struct {
	ID, Module string
	Status     string
	Error      string
}

type summaryFinding struct {
	Finding      storage.Finding
	EvidencePath string
}

func (m *model) exportDefaultEnumerationSummary() {
	if m.batchSummaryExported {
		return
	}
	m.batchSummaryExported = true
	if m.db == nil || len(m.batchExecutionIDs) == 0 {
		m.status += " · findings summary unavailable: no recorded execution IDs"
		return
	}
	if err := writeFindingsSummary(m.ctx, m.db, m.cfg.ResultsRoot(), m.cfg.Domain, m.targetID, m.batchExecutionIDs, time.Now().UTC()); err != nil {
		m.status += " · findings summary export failed: " + summarySafeText(err.Error())
		return
	}
	m.status += " · findings summary written"
}

func writeFindingsSummary(ctx context.Context, db *storage.DB, resultsRoot, domain string, assessmentID int64, executionIDs []int64, generatedAt time.Time) error {
	if db == nil || assessmentID <= 0 || len(executionIDs) == 0 {
		return fmt.Errorf("summary requires a database, assessment, and execution IDs")
	}
	executionIDs = uniqueInt64Values(executionIDs)
	executions, err := loadSummaryExecutions(ctx, db, assessmentID, executionIDs)
	if err != nil {
		return err
	}
	if len(executions) != uniqueInt64Count(executionIDs) {
		return fmt.Errorf("summary execution provenance is incomplete")
	}
	jobs, err := loadSummaryAnalysisJobs(ctx, db, assessmentID, executionIDs)
	if err != nil {
		return err
	}
	for _, job := range jobs {
		if job == storage.AnalysisPending || job == storage.AnalysisAnalyzing {
			return fmt.Errorf("findings analysis is still %s", strings.ToLower(job))
		}
	}
	findings, err := loadSummaryFindings(ctx, db, assessmentID, executionIDs)
	if err != nil {
		return err
	}
	report := formatFindingsSummary(resultsRoot, domain, generatedAt, executions, jobs, findings)
	return atomicWriteSummary(filepath.Join(resultsRoot, "findings_summary.txt"), report)
}

func loadSummaryExecutions(ctx context.Context, db *storage.DB, assessmentID int64, executionIDs []int64) ([]summaryExecution, error) {
	args := []any{assessmentID}
	args = appendInt64Args(args, executionIDs)
	rows, err := db.QueryContext(ctx, `SELECT e.id,m.name,e.status,COALESCE(e.error_summary,'') FROM executions e JOIN modules m ON m.id=e.module_id WHERE e.target_id=? AND e.id IN (`+placeholders(len(executionIDs))+`) ORDER BY e.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []summaryExecution
	for rows.Next() {
		var execution summaryExecution
		if err := rows.Scan(&execution.ID, &execution.Module, &execution.Status, &execution.Error); err != nil {
			return nil, err
		}
		result = append(result, execution)
	}
	return result, rows.Err()
}

func loadSummaryAnalysisJobs(ctx context.Context, db *storage.DB, assessmentID int64, executionIDs []int64) ([]string, error) {
	args := []any{assessmentID}
	args = appendInt64Args(args, executionIDs)
	rows, err := db.QueryContext(ctx, `SELECT status FROM analysis_jobs WHERE assessment_id=? AND execution_id IN (`+placeholders(len(executionIDs))+`) ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var status string
		if err := rows.Scan(&status); err != nil {
			return nil, err
		}
		result = append(result, status)
	}
	return result, rows.Err()
}

func loadSummaryFindings(ctx context.Context, db *storage.DB, assessmentID int64, executionIDs []int64) ([]summaryFinding, error) {
	args := []any{assessmentID}
	args = appendInt64Args(args, executionIDs)
	rows, err := db.QueryContext(ctx, `SELECT fe.finding_id,fe.artifact_path FROM finding_evidence fe JOIN findings f ON f.id=fe.finding_id WHERE f.assessment_id=? AND fe.source_execution_id IN (`+placeholders(len(executionIDs))+`) ORDER BY fe.finding_id,fe.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	paths := make(map[int64]string)
	for rows.Next() {
		var id int64
		var path string
		if err := rows.Scan(&id, &path); err != nil {
			return nil, err
		}
		if _, exists := paths[id]; !exists {
			paths[id] = path
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	all, err := db.ListFindings(ctx, assessmentID)
	if err != nil {
		return nil, err
	}
	result := make([]summaryFinding, 0, len(paths))
	for _, finding := range all {
		if path, ok := paths[finding.ID]; ok {
			if path == "" {
				path = finding.ArtifactPath
			}
			result = append(result, summaryFinding{Finding: finding, EvidencePath: path})
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		left, right := result[i].Finding, result[j].Finding
		if severityRank(left.Severity) != severityRank(right.Severity) {
			return severityRank(left.Severity) > severityRank(right.Severity)
		}
		if strings.ToLower(left.Title) != strings.ToLower(right.Title) {
			return strings.ToLower(left.Title) < strings.ToLower(right.Title)
		}
		return left.ID < right.ID
	})
	return result, nil
}

func formatFindingsSummary(resultsRoot, domain string, generatedAt time.Time, executions []summaryExecution, jobs []string, findings []summaryFinding) string {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
	for _, item := range findings {
		severity := strings.ToLower(item.Finding.Severity)
		if severity == "info" {
			severity = "informational"
		}
		if _, ok := counts[severity]; ok {
			counts[severity]++
		}
	}
	completed, failed, unsupported := 0, 0, 0
	for _, execution := range executions {
		switch strings.ToLower(strings.TrimSpace(execution.Status)) {
		case "completed", "complete", "success", "succeeded":
			completed++
		case "unsupported", "not supported":
			unsupported++
		default:
			failed++
		}
	}
	status := "COMPLETED"
	if failed > 0 || unsupported > 0 {
		status = "PARTIAL"
	}
	for _, job := range jobs {
		if job != storage.AnalysisComplete {
			status = "PARTIAL"
		}
	}

	var report strings.Builder
	report.WriteString("======================================================================\n")
	report.WriteString("                         PWNFLOW SECURITY SUMMARY\n")
	report.WriteString("======================================================================\n\n")
	executionScope := make([]string, 0, len(executions))
	for _, execution := range executions {
		executionScope = append(executionScope, fmt.Sprintf("%s (%s)", execution.ID, summarySafeText(execution.Module)))
	}
	fmt.Fprintf(&report, "DOMAIN:        %s\nASSESSMENT:    Default Enumeration\nGENERATED:     %s\nSTATUS:        %s\nEXECUTIONS:    %s\nCOUNT SCOPE:   stored findings linked to these execution IDs; one row per retained finding ID; historical/unlinked assessment rows are excluded\n\n", summarySafeText(domain), generatedAt.Format("2006-01-02 15:04:05 MST"), status, strings.Join(executionScope, ", "))
	report.WriteString("----------------------------------------------------------------------\nOVERVIEW\n----------------------------------------------------------------------\n\n")
	fmt.Fprintf(&report, "Critical findings:          %d\nHigh findings:              %d\nMedium findings:            %d\nLow findings:               %d\nInformational observations: %d\n\nTotal security findings:    %d\n\nModules completed:          %d\nModules failed:             %d\nModules unsupported:        %d\n\n", counts["critical"], counts["high"], counts["medium"], counts["low"], counts["informational"], counts["critical"]+counts["high"]+counts["medium"]+counts["low"], completed, failed, unsupported)

	report.WriteString("----------------------------------------------------------------------\nIMPORTANT FINDINGS\n----------------------------------------------------------------------\n\n")
	important := false
	for _, item := range findings {
		if !summaryImportantFinding(item.Finding) {
			continue
		}
		important = true
		writeSummaryFinding(&report, item, resultsRoot)
	}
	if !important {
		report.WriteString("None recorded for this batch.\n")
	}

	report.WriteString("\n----------------------------------------------------------------------\nFINDINGS BY CATEGORY\n----------------------------------------------------------------------\n\n")
	for _, category := range findingCategoryOrder {
		var categoryFindings []summaryFinding
		for _, item := range findings {
			if findingCategoryKey(item.Finding) == category.Key {
				categoryFindings = append(categoryFindings, item)
			}
		}
		if len(categoryFindings) == 0 {
			continue
		}
		fmt.Fprintf(&report, "%s\n", category.Name)
		for _, item := range categoryFindings {
			fmt.Fprintf(&report, "  [%s] %s", summarySeverity(item.Finding.Severity), summarySafeText(item.Finding.Title))
			if object := summaryFindingObject(item.Finding); object != "" {
				fmt.Fprintf(&report, " — %s", object)
			}
			if subcategory := findingSubcategoryKey(item.Finding); subcategory != "" {
				fmt.Fprintf(&report, " (subcategory: %s)", summarySafeText(subcategory))
			}
			report.WriteByte('\n')
		}
		report.WriteByte('\n')
	}

	report.WriteString("----------------------------------------------------------------------\nOBSERVATIONS\n----------------------------------------------------------------------\n\n")
	hasObservation := false
	for _, item := range findings {
		if strings.EqualFold(item.Finding.Severity, "informational") || strings.EqualFold(item.Finding.Severity, "info") {
			hasObservation = true
			fmt.Fprintf(&report, "[INFO] %s\n", summarySafeText(item.Finding.Title))
		}
	}
	if !hasObservation {
		report.WriteString("None recorded for this batch.\n")
	}

	report.WriteString("\n----------------------------------------------------------------------\nEXECUTION HEALTH\n----------------------------------------------------------------------\n\n")
	fmt.Fprintf(&report, "Completed:     %d\nFailed:        %d\nUnsupported:   %d\n\n", completed, failed, unsupported)
	for _, execution := range executions {
		if strings.EqualFold(execution.Status, "completed") || strings.EqualFold(execution.Status, "complete") {
			continue
		}
		fmt.Fprintf(&report, "- %s: %s", summarySafeText(execution.Module), summarySeverity(execution.Status))
		if execution.Error != "" {
			fmt.Fprintf(&report, " — %s", summarySafeText(execution.Error))
		}
		report.WriteByte('\n')
	}
	report.WriteString("\n----------------------------------------------------------------------\nREPORT NOTES\n----------------------------------------------------------------------\n\n")
	report.WriteString("- Findings are derived from saved tool evidence linked to this Default Enumeration batch.\n")
	report.WriteString("- Sensitive values are intentionally omitted; original protected artifacts remain authoritative.\n")
	report.WriteString("- Unassessed, failed, unsupported, or partial checks do not imply the absence of vulnerabilities.\n")
	report.WriteString("\n======================================================================\n                         END OF PWNFLOW SUMMARY\n======================================================================\n")
	return report.String()
}

func writeSummaryFinding(report *strings.Builder, item summaryFinding, resultsRoot string) {
	finding := item.Finding
	fmt.Fprintf(report, "[%s] %s\n", summarySeverity(finding.Severity), summarySafeText(finding.Title))
	if object := summaryFindingObject(finding); object != "" {
		fmt.Fprintf(report, "  Object:    %s\n", object)
	}
	fmt.Fprintf(report, "  Source:    %s\n  Evidence:  %s\n\n", summarySafeText(finding.SourceTool), summaryEvidencePath(item.EvidencePath, resultsRoot))
}

func summaryImportantFinding(finding storage.Finding) bool {
	if severityRank(finding.Severity) >= 3 {
		return true
	}
	typ := strings.ToLower(finding.FindingType + " " + finding.Title)
	for _, marker := range []string{"pwn3d", "privileged", "credential", "password", "hash", "private", "token", "adcs_", "kerberos", "kerberoast", "asrep"} {
		if strings.Contains(typ, marker) && severityRank(finding.Severity) >= 2 {
			return true
		}
	}
	return false
}

func summaryFindingObject(finding storage.Finding) string {
	object := finding.AffectedObject
	if object == "" {
		object = finding.AffectedObjectID
	}
	if finding.RelatedObject != "" && finding.RelatedObject != object {
		object += " / " + finding.RelatedObject
	}
	return summarySafeText(object)
}

func summarySeverity(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return "INFO"
	}
	if value == "NOT SUPPORTED" {
		return "UNSUPPORTED"
	}
	return value
}

func summarySafeText(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	value = strings.TrimSpace(summarySecretPattern.ReplaceAllString(value, "[REDACTED]"))
	if len(value) > 240 {
		value = value[:237] + "..."
	}
	return value
}

func summaryEvidencePath(path, resultsRoot string) string {
	if path == "" {
		return "[source path unavailable]"
	}
	if filepath.IsAbs(path) {
		relative, err := filepath.Rel(resultsRoot, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return "[external artifact]"
		}
		return summarySafeText(filepath.ToSlash(relative))
	}
	clean := filepath.Clean(path)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "[external artifact]"
	}
	return summarySafeText(filepath.ToSlash(clean))
}

func atomicWriteSummary(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".findings_summary-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.WriteString(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func placeholders(count int) string {
	values := make([]string, count)
	for index := range values {
		values[index] = "?"
	}
	return strings.Join(values, ",")
}

func appendInt64Args(args []any, values []int64) []any {
	seen := make(map[int64]bool)
	for _, value := range values {
		if value > 0 && !seen[value] {
			args = append(args, value)
			seen[value] = true
		}
	}
	return args
}

func uniqueInt64Count(values []int64) int {
	return len(uniqueInt64Values(values))
}

func uniqueInt64Values(values []int64) []int64 {
	seen := make(map[int64]bool)
	result := make([]int64, 0, len(values))
	for _, value := range values {
		if value > 0 {
			if !seen[value] {
				seen[value] = true
				result = append(result, value)
			}
		}
	}
	return result
}
