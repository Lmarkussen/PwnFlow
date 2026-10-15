package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/pwnflow/pwnflow/internal/storage"
)

type findingCategory struct {
	Key          string
	Name         string
	Description  string
	Findings     int
	Observations int
	Highest      string
}

var findingCategoryOrder = []struct {
	Key, Name, Description string
}{
	{"credentials", "Credentials & SCCM", "Recovered credentials and SCCM security conditions"},
	{"kerberos", "Kerberos", "Kerberoasting, AS-REP and Kerberos material"},
	{"acl", "Active Directory ACLs", "Direct control relationships and object permissions"},
	{"adcs", "AD CS", "Certificate template and CA security conditions"},
	{"delegation", "Delegation", "Delegation configuration and related exposure"},
	{"network", "Network & Protocols", "SMB, LDAP and relay security conditions"},
	{"other", "Other / Unclassified", "Security records without a safer category"},
}

func findingCategoryKey(finding storage.Finding) string {
	typ := strings.ToLower(finding.FindingType + " " + finding.Title + " " + finding.SourceTool)
	switch {
	case strings.Contains(typ, "pxethief"), strings.Contains(typ, "sccm"), strings.Contains(typ, "credential"):
		return "credentials"
	case strings.Contains(typ, "kerberoast"), strings.Contains(typ, "asrep"), strings.Contains(typ, "as-rep"), strings.Contains(typ, "kerberos"):
		return "kerberos"
	case strings.HasPrefix(typ, "ad_acl_"), strings.Contains(typ, "acl"):
		return "acl"
	case strings.Contains(typ, "adcs"), strings.Contains(typ, "certipy"), strings.Contains(typ, "certificate"):
		return "adcs"
	case strings.Contains(typ, "delegation"), strings.Contains(typ, "allowedtoact"):
		return "delegation"
	case strings.Contains(typ, "relay"), strings.Contains(typ, "smb"), strings.Contains(typ, "ldap"), strings.Contains(typ, "signing"):
		return "network"
	default:
		return "other"
	}
}

func buildFindingCategories(rows []storage.Finding) []findingCategory {
	categories := make([]findingCategory, 0, len(findingCategoryOrder))
	for _, definition := range findingCategoryOrder {
		categories = append(categories, findingCategory{Key: definition.Key, Name: definition.Name, Description: definition.Description, Highest: "NOT ASSESSED"})
	}
	for _, finding := range rows {
		key := findingCategoryKey(finding)
		for index := range categories {
			if categories[index].Key != key {
				continue
			}
			if actionableFinding(finding) {
				categories[index].Findings++
			} else {
				categories[index].Observations++
			}
			if categories[index].Highest == "NOT ASSESSED" || severityRank(finding.Severity) > severityRank(categories[index].Highest) {
				categories[index].Highest = strings.ToUpper(finding.Severity)
			}
		}
	}
	return categories
}

func (m *model) refreshFindings() {
	if !m.findingsView || m.db == nil {
		return
	}
	rows, err := m.db.ListFindings(m.ctx, m.targetID)
	if err != nil {
		m.status = "findings unavailable: " + err.Error()
		return
	}
	m.findingAllRows = append(m.findingAllRows[:0], rows...)
	m.findingCategories = buildFindingCategories(rows)
	search := strings.ToLower(strings.TrimSpace(m.findingSearch))
	filtered := rows[:0]
	for _, finding := range rows {
		if m.findingViewMode == "" {
			m.findingViewMode = "findings"
		}
		if m.findingViewMode == "findings" && !actionableFinding(finding) {
			continue
		}
		if m.findingViewMode == "observations" && actionableFinding(finding) {
			continue
		}
		if m.findingSeverity != "" && !strings.EqualFold(finding.Severity, m.findingSeverity) {
			continue
		}
		if m.findingCategory != "" && findingCategoryKey(finding) != m.findingCategory {
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
	m.keepFindingVisible()
}

func actionableFinding(finding storage.Finding) bool {
	if strings.HasPrefix(finding.FindingType, "ad_acl_") {
		return finding.Severity == "high" || strings.Contains(strings.ToLower(finding.Title), "privileged")
	}
	return finding.Severity != "informational"
}

func (m *model) findingPageSize() int {
	return max(1, m.height-8)
}

func (m *model) keepFindingVisible() {
	page := m.findingPageSize()
	if m.findingCursor < m.findingTop {
		m.findingTop = m.findingCursor
	}
	if m.findingCursor >= m.findingTop+page {
		m.findingTop = m.findingCursor - page + 1
	}
	maxTop := max(0, len(m.findingRows)-page)
	if m.findingTop > maxTop {
		m.findingTop = maxTop
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
	if m.findingCategoryView {
		return m.findingCategoryOverview(width)
	}
	var content strings.Builder
	content.WriteString(title.Render("PwnFlow // FINDINGS") + "\n")
	if m.findingSearch != "" {
		content.WriteString(dim.Render("Search: "+m.findingSearch) + "\n")
	}
	content.WriteString(dim.Render("View: "+strings.Title(m.findingViewMode)+"   f Findings   o Observations   a All") + "\n")
	if m.findingSeverity != "" {
		content.WriteString(dim.Render("Severity: "+strings.ToUpper(m.findingSeverity)) + "\n")
	}
	content.WriteString("\n")
	m.keepFindingVisible()
	end := min(len(m.findingRows), m.findingTop+m.findingPageSize())
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
		for index := m.findingTop; index < end; index++ {
			finding := m.findingRows[index]
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
	content.WriteString(fmt.Sprintf("\n%d visible records (total database results are filtered)  rows %d-%d", len(m.findingRows), min(m.findingTop+1, len(m.findingRows)), min(end, len(m.findingRows))))
	if m.findingSearchMode {
		content.WriteString("\nSearch text: " + m.findingSearch + "_")
	}
	content.WriteString(dim.Render("\n\nEnter Detail   / Search   P Reanalyze PXE   1 High   2 Medium   3 Info   0 All   Esc Close"))
	return paneStyle(false).Width(width).Render(content.String())
}

func (m *model) findingCategoryOverview(width int) string {
	var content strings.Builder
	content.WriteString(title.Render("PwnFlow // FINDINGS") + "\n")
	content.WriteString(dim.Render("Choose a category. Original detection records and evidence remain available.") + "\n\n")
	for index, category := range m.findingCategories {
		prefix := "  "
		if index == m.findingCursor {
			prefix = "> "
		}
		line := fmt.Sprintf("%s%-27s %8d findings  %8d observations  %-12s", prefix, category.Name, category.Findings, category.Observations, category.Highest)
		if index == m.findingCursor {
			line = lipgloss.NewStyle().Bold(true).Render(line)
		}
		content.WriteString(line + "\n")
		content.WriteString("   " + dim.Render(wrapPaneText(category.Description, max(20, width-7))) + "\n")
	}
	if len(m.findingCategories) == 0 {
		content.WriteString("No findings categories are available.\n")
	}
	content.WriteString(dim.Render("\nEnter Open Category   / Search   f Findings   o Observations   a All   Esc Close"))
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
