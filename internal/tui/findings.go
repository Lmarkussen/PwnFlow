package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func (m *model) refreshFindings() {
	if !m.findingsView || m.db == nil {
		return
	}
	rows, err := m.db.ListFindings(m.ctx, m.targetID)
	if err != nil {
		m.status = "findings unavailable: " + err.Error()
		return
	}
	search := strings.ToLower(strings.TrimSpace(m.findingSearch))
	filtered := rows[:0]
	for _, finding := range rows {
		if m.findingSeverity != "" && !strings.EqualFold(finding.Severity, m.findingSeverity) {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(strings.Join([]string{finding.Title, finding.AffectedObject, finding.RelatedObject, finding.SourceTool, finding.FindingType}, " ")), search) {
			continue
		}
		filtered = append(filtered, finding)
	}
	sort.SliceStable(filtered, func(i, j int) bool { return severityRank(filtered[i].Severity) > severityRank(filtered[j].Severity) })
	m.findingRows = append(m.findingRows[:0], filtered...)
	if m.findingCursor >= len(m.findingRows) {
		m.findingCursor = max(0, len(m.findingRows)-1)
	}
}

func severityRank(value string) int {
	switch strings.ToLower(value) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func (m *model) findingsViewRender() string {
	width := max(40, m.width-4)
	var content strings.Builder
	content.WriteString(title.Render("PwnFlow // FINDINGS") + "\n")
	if m.findingSearch != "" {
		content.WriteString(dim.Render("Search: "+m.findingSearch) + "\n")
	}
	if m.findingSeverity != "" {
		content.WriteString(dim.Render("Severity: "+strings.ToUpper(m.findingSeverity)) + "\n")
	}
	content.WriteString("\n")
	if m.findingDetail && len(m.findingRows) > 0 {
		finding := m.findingRows[m.findingCursor]
		content.WriteString(lipgloss.NewStyle().Bold(true).Render(finding.Title) + "\n\n")
		content.WriteString(fmt.Sprintf("Severity: %s    Confidence: %s\n", strings.ToUpper(finding.Severity), finding.Confidence))
		content.WriteString(fmt.Sprintf("Affected: %s\n", displayFindingObject(finding.AffectedObject, finding.AffectedObjectID)))
		if finding.RelatedObject != "" || finding.RelatedObjectID != "" {
			content.WriteString(fmt.Sprintf("Principal/related: %s\n", displayFindingObject(finding.RelatedObject, finding.RelatedObjectID)))
		}
		content.WriteString(fmt.Sprintf("Source: %s  Execution: %d\n", finding.SourceTool, finding.SourceExecution))
		content.WriteString(fmt.Sprintf("Evidence: %s %s\n", finding.ArtifactPath, finding.ArtifactRef))
		content.WriteString(fmt.Sprintf("\n%s\n\nRemediation/review: %s\n", wrapPaneText(finding.Description, width-4), wrapPaneText(finding.Description, width-4)))
		content.WriteString(dim.Render("Esc Back   Up/Down Change finding"))
		return paneStyle(false).Width(width).Render(content.String())
	}
	if len(m.findingRows) == 0 {
		content.WriteString("No findings match the current filters.\n\n")
	} else {
		for index, finding := range m.findingRows {
			prefix := "  "
			if index == m.findingCursor {
				prefix = "> "
			}
			object := displayFindingObject(finding.AffectedObject, finding.AffectedObjectID)
			line := fmt.Sprintf("%s%-11s %-42s %s", prefix, strings.ToUpper(finding.Severity), truncateFinding(finding.Title, 42), truncateFinding(object, 28))
			if index == m.findingCursor {
				line = lipgloss.NewStyle().Bold(true).Render(line)
			}
			content.WriteString(line + "\n")
		}
	}
	content.WriteString(fmt.Sprintf("\n%d findings", len(m.findingRows)))
	if m.findingSearchMode {
		content.WriteString("\nSearch text: " + m.findingSearch + "_")
	}
	content.WriteString(dim.Render("\n\nEnter Detail   / Search   P Reanalyze PXE   1 High   2 Medium   3 Info   0 All   Esc Close"))
	return paneStyle(false).Width(width).Render(content.String())
}

func displayFindingObject(name, id string) string {
	if name != "" {
		return name
	}
	if id != "" {
		return id
	}
	return "(unspecified)"
}
func truncateFinding(value string, width int) string {
	if len(value) <= width {
		return value
	}
	if width < 4 {
		return value[:width]
	}
	return value[:width-3] + "..."
}
