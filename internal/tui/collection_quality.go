package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	findingengine "github.com/pwnflow/pwnflow/internal/findings"
	"github.com/pwnflow/pwnflow/internal/storage"
)

type collectionQualityExecution struct {
	ID         int64
	Module     string
	Tool       string
	Status     string
	ExitCode   int
	OutputPath string
	Error      string
	Started    time.Time
	Finished   time.Time
}

type collectionQualityRow struct {
	ExecutionID   int64
	Module        string
	Tool          string
	Started       time.Time
	Finished      time.Time
	Execution     string
	Collection    string
	Confidence    string
	Reason        string
	Scope         string
	Records       string
	EvidencePaths []string
}

type collectionQualityReport struct {
	Rows        []collectionQualityRow
	GeneratedAt time.Time
}

type trustCollectionEnvelope struct {
	Collection struct {
		Status      string `json:"status"`
		ObjectCount int    `json:"object_count"`
		Detail      string `json:"detail"`
	} `json:"collection"`
}

func (m *model) exportCollectionQuality() {
	if m.collectionQualityExported {
		return
	}
	m.collectionQualityExported = true
	if m.db == nil || len(m.batchExecutionIDs) == 0 {
		m.status += " · collection quality unavailable: no recorded execution IDs"
		return
	}
	if err := writeCollectionQuality(m.ctx, m.db, m.cfg.ResultsRoot(), m.cfg.Domain, m.targetID, m.batchExecutionIDs, time.Now().UTC()); err != nil {
		m.status += " · collection quality export failed: " + summarySafeText(err.Error())
		return
	}
	m.status += " · collection quality written"
}

func writeCollectionQuality(ctx context.Context, db *storage.DB, resultsRoot, domain string, assessmentID int64, executionIDs []int64, generatedAt time.Time) error {
	if db == nil || assessmentID <= 0 || len(executionIDs) == 0 {
		return fmt.Errorf("collection quality requires a database, assessment, and execution IDs")
	}
	ids := uniqueInt64Values(executionIDs)
	executions, err := loadCollectionQualityExecutions(ctx, db, assessmentID, ids)
	if err != nil {
		return err
	}
	if len(executions) != len(ids) {
		return fmt.Errorf("collection quality execution provenance is incomplete")
	}
	report := collectionQualityReport{GeneratedAt: generatedAt}
	for _, execution := range executions {
		report.Rows = append(report.Rows, assessCollectionQuality(execution, resultsRoot))
	}
	return atomicWriteSummary(filepath.Join(resultsRoot, "collection_completeness.txt"), formatCollectionQuality(domain, report))
}

func loadCollectionQualityExecutions(ctx context.Context, db *storage.DB, assessmentID int64, ids []int64) ([]collectionQualityExecution, error) {
	args := []any{assessmentID}
	args = appendInt64Args(args, ids)
	rows, err := db.QueryContext(ctx, `SELECT e.id,m.name,m.tool,e.status,COALESCE(e.exit_code,-1),COALESCE(e.output_path,''),COALESCE(e.error_summary,''),e.started_at,COALESCE(e.finished_at,'') FROM executions e JOIN modules m ON m.id=e.module_id WHERE e.target_id=? AND e.id IN (`+placeholders(len(ids))+`) ORDER BY e.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]collectionQualityExecution, 0, len(ids))
	for rows.Next() {
		var item collectionQualityExecution
		var started, finished string
		if err := rows.Scan(&item.ID, &item.Module, &item.Tool, &item.Status, &item.ExitCode, &item.OutputPath, &item.Error, &started, &finished); err != nil {
			return nil, err
		}
		item.Started, err = time.Parse(time.RFC3339Nano, started)
		if err != nil {
			return nil, err
		}
		if finished != "" {
			item.Finished, err = time.Parse(time.RFC3339Nano, finished)
			if err != nil {
				return nil, err
			}
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func assessCollectionQuality(execution collectionQualityExecution, resultsRoot string) collectionQualityRow {
	row := collectionQualityRow{
		ExecutionID: execution.ID,
		Module:      execution.Module,
		Tool:        execution.Tool,
		Started:     execution.Started,
		Finished:    execution.Finished,
		Execution:   normalizeExecutionStatus(execution.Status),
		Collection:  "unknown",
		Confidence:  "unknown",
		Scope:       "declared module operation",
	}
	paths := collectionEvidencePaths(execution, resultsRoot)
	row.EvidencePaths = relativeEvidencePaths(paths, resultsRoot)
	usable, empty := artifactState(paths)
	lowerStatus := strings.ToLower(strings.TrimSpace(execution.Status))
	switch lowerStatus {
	case "unsupported", "not supported":
		row.Collection, row.Confidence, row.Reason = "unsupported", "explicit", "the module reported that the requested operation is unsupported"
		return row
	case "skipped", "not assessed":
		row.Execution = "not_assessed"
		row.Collection, row.Confidence, row.Reason = "not_assessed", "explicit", "the module was not assessed in this batch"
		return row
	case "cancelled", "canceled", "timeout", "timed out":
		if lowerStatus == "cancelled" || lowerStatus == "canceled" {
			row.Execution = "aborted"
			row.Collection, row.Confidence = collectionFromAborted(usable, execution.Error), "explicit"
			row.Reason = abortedReason(execution.Error, usable)
		} else {
			row.Execution = "timeout"
			row.Collection, row.Confidence = collectionFromInterrupted(usable, empty), "explicit"
			row.Reason = interruptedReason(execution.Error, usable, empty)
		}
		return row
	case "aborted":
		row.Execution = "aborted"
		row.Collection, row.Confidence = collectionFromAborted(usable, execution.Error), "explicit"
		row.Reason = abortedReason(execution.Error, usable)
		return row
	case "failed", "error":
		row.Execution = "failed"
		if specific := explicitFailureCollectionStatus(execution.Error); specific != "" {
			row.Collection, row.Confidence = specific, "explicit"
			row.Reason = safeQualityText(execution.Error)
			if row.Reason == "" {
				row.Reason = "the execution recorded this collection failure"
			}
			return row
		}
		if usable {
			row.Collection = "partial"
			row.Reason = "execution failed after usable evidence was written"
		} else {
			row.Collection = "failed"
			row.Reason = "execution failed before usable evidence was established"
		}
		row.Confidence = "explicit"
		return row
	}

	if lowerStatus != "completed" && lowerStatus != "complete" && lowerStatus != "success" && lowerStatus != "succeeded" {
		row.Collection, row.Confidence, row.Reason = "unknown", "unknown", "execution status did not establish a recognized terminal result"
		return row
	}
	if !usable {
		if isOptionalAuthenticationCheck(execution.Module) && execution.Error == "" {
			row.Collection, row.Confidence, row.Reason = "unknown", "unknown", "no usable output recorded; the available evidence does not establish the collection outcome"
			return row
		}
		row.Collection, row.Confidence = "failed", "explicit"
		if empty {
			row.Reason = "execution completed but its expected output artifact is empty"
		} else {
			row.Reason = "execution completed but its expected output artifact is missing"
		}
		return row
	}
	if reason := knownArtifactQualityIssue(execution, paths); reason != "" {
		row.Collection, row.Confidence, row.Reason = "partial", "explicit", reason
		return row
	}

	if strings.EqualFold(execution.Module, "Active Directory Trust Inventory") {
		for _, path := range paths {
			if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
				return assessTrustInventory(row, path)
			}
		}
		return row
	}
	row.Collection, row.Confidence = "unknown", "inferred"
	row.Reason = "usable evidence exists, but this module has no authoritative completeness indicator"
	if isKnownStructuredCollector(execution.Tool) {
		row.Reason = "structured evidence is valid, but validity does not prove exhaustive collection"
	}
	if specific := explicitFailureCollectionStatus(execution.Error); specific != "" {
		row.Collection, row.Confidence, row.Reason = specific, "explicit", safeQualityText(execution.Error)
		return row
	}
	if isOptionalAuthenticationCheck(execution.Module) && hasExplicitError(execution.Error) {
		row.Collection, row.Confidence, row.Reason = "failed", "explicit", safeQualityText(execution.Error)
		return row
	}
	if hasExplicitError(execution.Error) {
		row.Collection, row.Confidence, row.Reason = "partial", "explicit", "the execution recorded an internal collection error"
	}
	return row
}

func knownArtifactQualityIssue(execution collectionQualityExecution, paths []string) string {
	tool := strings.ToLower(strings.TrimSpace(execution.Tool))
	if tool != "rusthound" && tool != "rusthound-ce" && tool != "networkhound" {
		return ""
	}
	for _, path := range paths {
		if !strings.EqualFold(filepath.Ext(path), ".json") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "structured artifact could not be read"
		}
		var value json.RawMessage
		if err := json.Unmarshal(data, &value); err != nil {
			return "structured artifact is not valid JSON"
		}
		return ""
	}
	return ""
}

func assessTrustInventory(row collectionQualityRow, path string) collectionQualityRow {
	data, err := os.ReadFile(path)
	if err != nil {
		row.Collection, row.Confidence, row.Reason = "partial", "explicit", "the trust inventory artifact could not be read"
		return row
	}
	var envelope trustCollectionEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		row.Collection, row.Confidence, row.Reason = "partial", "explicit", "the trust inventory artifact is not valid JSON"
		return row
	}
	row.Records = fmt.Sprintf("%d", envelope.Collection.ObjectCount)
	row.Scope = "trusted-domain objects in the queried naming context"
	switch envelope.Collection.Status {
	case "complete":
		row.Collection, row.Confidence, row.Reason = "complete", "explicit", "LDAP search completed successfully for the declared scope"
	case "partial", "permission_denied", "timeout", "unsupported", "failed", "unknown":
		row.Collection, row.Confidence = envelope.Collection.Status, "explicit"
		row.Reason = safeQualityText(envelope.Collection.Detail)
		if row.Reason == "" {
			row.Reason = "the trust inventory recorded a non-complete collection status"
		}
	default:
		row.Collection, row.Confidence, row.Reason = "unknown", "unknown", "the artifact contained an unrecognized collection status"
	}
	return row
}

func collectionEvidencePaths(execution collectionQualityExecution, resultsRoot string) []string {
	paths := []string{}
	add := func(path string) {
		if path == "" {
			return
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(resultsRoot, path)
		}
		for _, existing := range paths {
			if existing == path {
				return
			}
		}
		if withinRoot(path, resultsRoot) {
			paths = append(paths, path)
		}
	}
	add(execution.OutputPath)
	add(findingengine.DiscoverArtifact(execution.Tool, execution.OutputPath))
	return paths
}

func relativeEvidencePaths(paths []string, root string) []string {
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		rel, err := filepath.Rel(root, path)
		if err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." {
			result = append(result, filepath.ToSlash(rel))
		}
	}
	return result
}

func artifactState(paths []string) (usable, empty bool) {
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if info.Size() > 0 {
			return true, false
		}
		empty = true
	}
	return false, empty
}

func isKnownStructuredCollector(tool string) bool {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "rusthound", "rusthound-ce", "networkhound", "certipy", "gpoparser", "ldap", "netexec", "netexec (nxc)":
		return true
	default:
		return false
	}
}

func hasExplicitError(value string) bool {
	text := strings.ToLower(strings.TrimSpace(value))
	return text != "" && (strings.Contains(text, "permission") || strings.Contains(text, "denied") || strings.Contains(text, "timeout") || strings.Contains(text, "timed out") || strings.Contains(text, "partial") || strings.Contains(text, "incomplete") || strings.Contains(text, "error") || strings.Contains(text, "failed"))
}

func explicitFailureCollectionStatus(value string) string {
	text := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(text, "permission"), strings.Contains(text, "access denied"), strings.Contains(text, "insufficient access"):
		return "permission_denied"
	case strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return "timeout"
	default:
		return ""
	}
}

func collectionFromInterrupted(usable, empty bool) string {
	if usable {
		return "partial"
	}
	if empty {
		return "partial"
	}
	return "timeout"
}

func collectionFromAborted(usable bool, err string) string {
	if usable {
		return "partial"
	}
	if explicitFailureCollectionStatus(err) != "" || hasExplicitError(err) {
		return "failed"
	}
	return "unknown"
}

func abortedReason(err string, usable bool) string {
	if usable {
		return "execution was aborted after usable evidence was written; collection coverage could not be established"
	}
	if safe := safeQualityText(err); safe != "" {
		return safe
	}
	return "execution was aborted; collection coverage could not be established"
}

func interruptedReason(err string, usable, empty bool) string {
	if usable {
		return "execution ended before completion after partial evidence was written"
	}
	if empty {
		return "execution ended before completion and left an empty artifact"
	}
	if safe := safeQualityText(err); safe != "" {
		return safe
	}
	return "execution ended before the declared operation completed"
}

func normalizeExecutionStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed", "complete", "success", "succeeded":
		return "completed"
	case "cancelled", "canceled":
		return "aborted"
	case "timeout", "timed out":
		return "timeout"
	case "skipped", "not assessed":
		return "not_assessed"
	default:
		return strings.ToLower(strings.TrimSpace(status))
	}
}

func isOptionalAuthenticationCheck(module string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(module)), " authentication check")
}

func safeQualityText(value string) string {
	text := summarySafeText(value)
	text = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, text)
	return strings.Join(strings.Fields(text), " ")
}

func formatCollectionQuality(domain string, report collectionQualityReport) string {
	counts := map[string]int{}
	for _, row := range report.Rows {
		counts[row.Collection]++
	}
	status := "COMPLETED"
	if counts["partial"] > 0 || counts["unknown"] > 0 || counts["failed"] > 0 || counts["timeout"] > 0 || counts["permission_denied"] > 0 || counts["unsupported"] > 0 || counts["not_assessed"] > 0 {
		status = "COMPLETED WITH COLLECTION LIMITATIONS"
	}
	var b strings.Builder
	b.WriteString("======================================================================\n                  PWNFLOW COLLECTION QUALITY REPORT\n======================================================================\n\n")
	fmt.Fprintf(&b, "DOMAIN:      %s\nASSESSMENT:  Default Enumeration\nGENERATED:   %s\nSTATUS:      %s\n\n", safeQualityText(domain), report.GeneratedAt.Format("2006-01-02 15:04:05 MST"), status)
	b.WriteString("----------------------------------------------------------------------\nEXECUTION OVERVIEW\n----------------------------------------------------------------------\n\n")
	executionCounts := map[string]int{}
	for _, row := range report.Rows {
		executionCounts[row.Execution]++
	}
	otherTerminal := len(report.Rows) - executionCounts["completed"] - executionCounts["failed"] - executionCounts["timeout"] - executionCounts["aborted"]
	if otherTerminal < 0 {
		otherTerminal = 0
	}
	fmt.Fprintf(&b, "Modules selected:                  %d\nExecutions completed:             %d\nExecutions failed:                 %d\nExecutions timed out:              %d\nExecutions aborted:                %d\nOther terminal states:            %d\n\n", len(report.Rows), executionCounts["completed"], executionCounts["failed"], executionCounts["timeout"], executionCounts["aborted"], otherTerminal)
	b.WriteString("----------------------------------------------------------------------\nCOLLECTION QUALITY\n----------------------------------------------------------------------\n\n")
	for _, statusName := range []string{"complete", "partial", "unknown", "permission_denied", "timeout", "unsupported", "failed", "not_assessed"} {
		fmt.Fprintf(&b, "%-34s %d\n", strings.Title(strings.ReplaceAll(statusName, "_", " "))+":", counts[statusName])
	}
	b.WriteString("\n----------------------------------------------------------------------\nMODULE DETAILS\n----------------------------------------------------------------------\n\n")
	rows := append([]collectionQualityRow(nil), report.Rows...)
	sort.SliceStable(rows, func(i, j int) bool {
		if strings.ToLower(rows[i].Module) != strings.ToLower(rows[j].Module) {
			return strings.ToLower(rows[i].Module) < strings.ToLower(rows[j].Module)
		}
		return rows[i].ExecutionID < rows[j].ExecutionID
	})
	for _, row := range rows {
		fmt.Fprintf(&b, "[%s] %s (execution %d)\n", strings.ToUpper(row.Collection), safeQualityText(row.Module), row.ExecutionID)
		fmt.Fprintf(&b, "  Tool:        %s\n  Execution:   %s\n  Confidence:  %s\n  Observed:    %s\n  Reason:      %s\n  Scope:       %s\n", safeQualityText(row.Tool), safeQualityText(row.Execution), safeQualityText(row.Confidence), row.Finished.Format(time.RFC3339), safeQualityText(row.Reason), safeQualityText(row.Scope))
		if row.Records != "" {
			fmt.Fprintf(&b, "  Records:     %s\n", row.Records)
		}
		if len(row.EvidencePaths) > 0 {
			b.WriteString("  Evidence:\n")
			for _, path := range row.EvidencePaths {
				fmt.Fprintf(&b, "    - %s\n", safeQualityText(path))
			}
		} else {
			b.WriteString("  Evidence:    unavailable\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("----------------------------------------------------------------------\nIMPORTANT LIMITATIONS\n----------------------------------------------------------------------\n\n- Successful execution does not always prove complete collection.\n- Missing findings do not establish the absence of vulnerabilities.\n- Directory objects do not establish host reachability.\n- Effective GPO applicability may require additional evidence.\n\n======================================================================\n")
	return b.String()
}
