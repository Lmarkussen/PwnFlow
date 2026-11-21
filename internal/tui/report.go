package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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
	rows, err := db.ListFindings(ctx, assessmentID)
	if err != nil {
		return "", err
	}
	content := RenderReport(rows, domain, target, resultsRoot, now)
	dir := filepath.Join(resultsRoot, "reports")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "PwnFlow_report_"+now.UTC().Format("20060102-150405")+"Z.md")
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

// RenderReport builds the Markdown report from Finding rows.
func RenderReport(rows []storage.Finding, domain, target, resultsRoot string, now time.Time) string {
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
	b.WriteString("\nFindings are evidence-backed observations. Each one states what was observed and what was not verified; ")
	b.WriteString("recovered secrets are not reproduced here and remain in the restricted original artifacts.\n\n")

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
