package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	findingengine "github.com/pwnflow/pwnflow/internal/findings"
	"github.com/pwnflow/pwnflow/internal/storage"
)

// maxReportObjects bounds the affected-object list printed per Finding.
const maxReportObjects = 25

var reportSeverityOrder = []string{"critical", "high", "medium", "low", "informational"}

// WriteReport renders the assessment's persisted Findings as a Markdown
// report under <results>/reports and returns its path. It reads the
// database only, never starts a module, and never copies evidence JSON:
// recovered secrets stay in the evidence store and the original artifacts.
// An existing report is never overwritten.
func WriteReport(ctx context.Context, db *storage.DB, assessmentID int64, domain, target, resultsRoot string, now time.Time) (string, error) {
	return WriteReportFormat(ctx, db, assessmentID, domain, target, resultsRoot, now, "md")
}

// WriteReportFormat writes the report as Markdown ("md") or as one
// self-contained HTML page ("html").
func WriteReportFormat(ctx context.Context, db *storage.DB, assessmentID int64, domain, target, resultsRoot string, now time.Time, format string) (string, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "md"
	}
	if format != "md" && format != "html" {
		return "", fmt.Errorf("unsupported report format %q (use md or html)", format)
	}
	rows, err := db.ListFindings(ctx, assessmentID)
	if err != nil {
		return "", err
	}
	gaps, err := loadCollectionGaps(ctx, db, assessmentID, resultsRoot, rows)
	if err != nil {
		return "", err
	}
	marked := markRetiredSources(append([]storage.Finding(nil), rows...))
	diff, known := computeRunDiff(marked, loadRunHistory(ctx, db, assessmentID))
	content := renderReport(rows, gaps, diff, known, domain, target, resultsRoot, now)
	if format == "html" {
		content = reportHTML(content, "PwnFlow assessment report: "+domain)
	}
	dir := filepath.Join(resultsRoot, "reports")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "PwnFlow_report_"+now.UTC().Format("20060102-150405")+"Z."+format)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := file.WriteString(content); err != nil {
		file.Close()
		return "", err
	}
	return path, file.Close()
}

// RenderReport builds the Markdown report from Finding rows. Findings the
// latest run of their module did not re-observe are listed in an appendix
// and kept out of the summary, the Critical paths and the categories.
func RenderReport(all []storage.Finding, gaps []collectionGap, domain, target, resultsRoot string, now time.Time) string {
	return renderReport(all, gaps, runDiff{}, false, domain, target, resultsRoot, now)
}

func renderReport(all []storage.Finding, gaps []collectionGap, diff runDiff, diffKnown bool, domain, target, resultsRoot string, now time.Time) string {
	var rows, stale []storage.Finding
	for _, row := range markRetiredSources(append([]storage.Finding(nil), all...)) {
		if row.NotReobserved {
			stale = append(stale, row)
		} else {
			rows = append(rows, row)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# PwnFlow assessment report: %s\n\n", reportText(domain))
	fmt.Fprintf(&b, "- Generated: %s\n- Domain controller: %s\n- Findings: %d\n\n", now.UTC().Format(time.RFC3339), reportText(target), len(rows))

	counts := map[string]int{}
	for _, row := range rows {
		counts[strings.ToLower(row.Severity)]++
	}
	b.WriteString("| Severity | Findings |\n|---|---|\n")
	for _, severity := range reportSeverityOrder {
		if counts[severity] > 0 {
			fmt.Fprintf(&b, "| %s | %d |\n", strings.ToUpper(severity), counts[severity])
		}
	}
	if len(stale) > 0 {
		fmt.Fprintf(&b, "\n%d further Finding(s) were not re-observed by the latest run of their module and are listed in the appendix.\n", len(stale))
	}
	b.WriteString("\nFindings are evidence-backed observations. Each one states what was observed and what was not verified; ")
	b.WriteString("recovered secrets are not reproduced here and remain in the restricted original artifacts.\n\n")

	if len(gaps) > 0 {
		fmt.Fprintf(&b, "## Collection gaps (%d)\n\n", len(gaps))
		b.WriteString("These modules did not collect completely in their latest run, so Findings they feed may be missing from this report. An absent Finding in an affected category is not evidence that the condition is absent.\n\n")
		for _, gap := range gaps {
			var affected []string
			for _, category := range gap.Categories {
				affected = append(affected, categoryName(category))
			}
			fmt.Fprintf(&b, "- **%s** (%s): %s", reportText(gap.Module), reportText(gap.Status), reportText(gap.Reason))
			if len(affected) > 0 {
				fmt.Fprintf(&b, " Affects: %s.", reportText(strings.Join(affected, ", ")))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if diffKnown {
		fmt.Fprintf(&b, "## Changes since the previous run\n\n%s.\n\n", reportText(diff.summary()))
		for _, group := range []struct {
			heading string
			rows    []storage.Finding
		}{{"New", diff.New}, {"Severity changed", diff.Changed}, {"Resolved (not re-observed)", diff.Resolved}} {
			if len(group.rows) == 0 {
				continue
			}
			fmt.Fprintf(&b, "### %s (%d)\n\n", group.heading, len(group.rows))
			for _, finding := range group.rows {
				line := fmt.Sprintf("- **[%s] %s**", strings.ToUpper(fallbackText(finding.Severity, "informational")), reportText(finding.Title))
				if finding.ChangeNote != "new" && finding.ChangeNote != "resolved" {
					line += " (" + reportText(finding.ChangeNote) + ")"
				}
				b.WriteString(line + "\n")
			}
			b.WriteString("\n")
		}
	}
	projection := findingengine.ProjectCritical(rows)
	b.WriteString("## Critical findings\n\n")
	if len(projection.Confirmed)+len(projection.Potential) == 0 {
		b.WriteString("No Finding qualified for the Critical projection.\n\n")
	}
	writeCriticalSection(&b, "Confirmed critical", projection.Confirmed, resultsRoot)
	writeCriticalSection(&b, "Potential critical (not verified)", projection.Potential, resultsRoot)

	b.WriteString("## Findings by category\n\n")
	byCategory := map[string][]storage.Finding{}
	for _, row := range rows {
		byCategory[findingCategoryKey(row)] = append(byCategory[findingCategoryKey(row)], row)
	}
	for _, category := range findingCategoryOrder {
		findings := byCategory[category.Key]
		if len(findings) == 0 {
			continue
		}
		fmt.Fprintf(&b, "### %s (%d)\n\n", category.Name, len(findings))
		bySubcategory := map[string][]storage.Finding{}
		var order []string
		for _, definition := range findingSubcategoryOrder[category.Key] {
			order = append(order, definition.Key)
		}
		for _, finding := range findings {
			key := findingSubcategoryKey(finding)
			if !containsKey(order, key) {
				key = ""
			}
			bySubcategory[key] = append(bySubcategory[key], finding)
		}
		for _, key := range append(order, "") {
			group := bySubcategory[key]
			if len(group) == 0 {
				continue
			}
			if key != "" {
				fmt.Fprintf(&b, "#### %s\n\n", reportText(subcategoryName(category.Key, key)))
			} else if len(order) > 0 {
				b.WriteString("#### Other\n\n")
			}
			sortReportFindings(group)
			for _, finding := range group {
				writeReportFinding(&b, finding, resultsRoot)
			}
		}
	}
	if len(stale) > 0 {
		fmt.Fprintf(&b, "## Appendix: not re-observed (%d)\n\n", len(stale))
		b.WriteString("The module that reported each of these either ran again later, completed and was analyzed without reporting it, or is no longer part of PwnFlow. They may describe an earlier state of the target.\n\n")
		sortReportFindings(stale)
		for _, finding := range stale {
			fmt.Fprintf(&b, "- **[%s] %s** (last seen %s)\n", strings.ToUpper(fallbackText(finding.Severity, "informational")), reportText(finding.Title), finding.LastSeen.UTC().Format("2006-01-02 15:04 UTC"))
			source := finding.SourceTool
			if finding.SourceModuleRetired {
				source += " (module " + finding.SourceModule + " is no longer part of PwnFlow)"
			}
			fmt.Fprintf(&b, "  - Source: %s · Evidence: %s\n", reportText(source), reportEvidence(finding.ArtifactPath, finding.ArtifactRef, resultsRoot))
		}
	}
	return b.String()
}

func writeCriticalSection(b *strings.Builder, heading string, paths []findingengine.CriticalPath, resultsRoot string) {
	if len(paths) == 0 {
		return
	}
	fmt.Fprintf(b, "### %s (%d)\n\n", heading, len(paths))
	for _, path := range paths {
		title := path.Finding.Title
		if strings.TrimSpace(title) == "" {
			title = path.Title
		}
		fmt.Fprintf(b, "- **%s** (%s)\n", reportText(title), reportText(pathGroupName(path.Family)))
		if path.Reason != "" {
			fmt.Fprintf(b, "  - Why: %s\n", reportText(path.Reason))
		}
		if path.Target != "" {
			fmt.Fprintf(b, "  - Target: %s\n", reportText(path.Target))
		}
		for _, item := range path.ConfirmedPrereqs {
			if item != path.Reason {
				fmt.Fprintf(b, "  - Observed: %s\n", reportText(item))
			}
		}
		for _, item := range path.UnverifiedPrereqs {
			fmt.Fprintf(b, "  - Not verified: %s\n", reportText(item))
		}
		for _, evidence := range path.Evidence {
			fmt.Fprintf(b, "  - Evidence: %s\n", reportEvidence(evidence.ArtifactPath, evidence.ArtifactRef, resultsRoot))
		}
	}
	b.WriteString("\n")
}

func writeReportFinding(b *strings.Builder, finding storage.Finding, resultsRoot string) {
	fmt.Fprintf(b, "- **[%s] %s**\n", strings.ToUpper(fallbackText(finding.Severity, "informational")), reportText(finding.Title))
	if finding.Description != "" {
		fmt.Fprintf(b, "  - %s\n", reportText(finding.Description))
	}
	if affected := displayFindingObject(finding.AffectedObject, finding.AffectedObjectID); affected != "" {
		fmt.Fprintf(b, "  - Affected: %s\n", reportText(affected))
	}
	if related := displayFindingObject(finding.RelatedObject, finding.RelatedObjectID); related != "" {
		fmt.Fprintf(b, "  - Related: %s\n", reportText(related))
	}
	// Only object names are taken from the evidence; every other evidence
	// field, including any recovered value, stays out of the report.
	if names := metadataStringSlice(findingMetadata(finding), "affected_objects"); len(names) > 0 {
		shown := names
		if len(shown) > maxReportObjects {
			shown = shown[:maxReportObjects]
		}
		line := strings.Join(shown, "; ")
		if len(names) > len(shown) {
			line += fmt.Sprintf("; … and %d more", len(names)-len(shown))
		}
		fmt.Fprintf(b, "  - Objects: %s\n", reportText(line))
	}
	fmt.Fprintf(b, "  - Source: %s · %s\n", reportText(finding.SourceTool), reportText(finding.Confidence))
	writeTechniqueLines(b, findingTechniqueReference(finding))
	fmt.Fprintf(b, "  - Evidence: %s\n", reportEvidence(finding.ArtifactPath, finding.ArtifactRef, resultsRoot))
}

func reportEvidence(path, ref, resultsRoot string) string {
	if resultsRoot != "" {
		if relative, err := filepath.Rel(resultsRoot, path); err == nil && !strings.HasPrefix(relative, "..") {
			path = relative
		}
	}
	text := "`" + strings.ReplaceAll(path, "`", "'") + "`"
	if ref != "" {
		text += " " + reportText(ref)
	}
	return text
}

// reportText keeps a value on one line and stops it from opening Markdown
// structure of its own.
func reportText(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	return strings.NewReplacer("|", "\\|", "<", "&lt;", ">", "&gt;").Replace(value)
}

func sortReportFindings(findings []storage.Finding) {
	rank := map[string]int{}
	for index, severity := range reportSeverityOrder {
		rank[severity] = index
	}
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := rank[strings.ToLower(findings[i].Severity)], rank[strings.ToLower(findings[j].Severity)]
		if left != right {
			return left < right
		}
		return strings.ToLower(findings[i].Title) < strings.ToLower(findings[j].Title)
	})
}

func subcategoryName(category, key string) string {
	for _, definition := range findingSubcategoryOrder[category] {
		if definition.Key == key {
			return definition.Name
		}
	}
	return key
}

func containsKey(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// writeReportCmd writes the assessment report from the Findings view without
// blocking the interface. The report reads the database, as --report does.
func (m *model) writeReportCmd() tea.Cmd {
	if m.db == nil || m.reportWriting {
		return nil
	}
	m.reportWriting = true
	m.status = "writing report…"
	db, ctx, targetID, cfg := m.db, m.ctx, m.targetID, m.cfg
	return func() tea.Msg {
		path, err := WriteReport(ctx, db, targetID, cfg.Domain, cfg.Target, cfg.ResultsRoot(), time.Now())
		return reportWrittenMsg{path: path, err: err}
	}
}

// writeTechniqueLines lists a Finding's technique references - write-ups,
// tools and ATT&CK entries for how the condition is abused - as links.
func writeTechniqueLines(b *strings.Builder, reference string) {
	lines := strings.Split(strings.TrimSpace(reference), "\n")
	for index := 0; index+1 < len(lines); index += 2 {
		label, url := strings.TrimSpace(lines[index]), strings.TrimSpace(lines[index+1])
		if strings.HasPrefix(url, "https://") {
			fmt.Fprintf(b, "  - Technique: [%s](%s)\n", reportText(label), url)
		}
	}
}
