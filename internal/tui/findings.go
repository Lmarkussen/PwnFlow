package tui

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/pwnflow/pwnflow/internal/storage"
)

var explicitCertipyESC = regexp.MustCompile(`(?i)\bESC[0-9]+\b`)

type findingCategory struct {
	Key          string
	Name         string
	Description  string
	Findings     int
	Observations int
	Highest      string
}

type findingSubcategory struct {
	Key, Name, Description string
	Findings, Observations int
}

var findingSubcategoryOrder = map[string][]struct{ Key, Name, Description string }{
	"credentials": {{"credentials", "Exposed Credentials", "Task-sequence and other confirmed credential exposures"}},
	"kerberos": {
		{"kerberoastable", "Kerberoastable Users", "Accounts with directly evidenced service principals"},
		{"asrep", "AS-REP Roastable Users", "Accounts with preauthentication disabled where evidenced"},
		{"kerberos_material", "Collected Kerberos Material", "Explicitly collected ticket or AS-REP material"},
	},
	"acl":        {{"acl", "Vulnerable ACLs", "Grouped principal-to-target control relationships"}},
	"adcs":       {{"adcs", "Vulnerable Templates", "Explicit ESC conditions reported by Certipy"}},
	"delegation": {{"delegation", "Delegation", "Delegation configurations and related observations"}},
	"active_directory": {
		{"gpo", "Group Policy", "Evidence-backed Group Policy configuration conditions"},
		{"spn", "SPN Hygiene", "Explicitly reported stale or orphaned service principals"},
		{"user_descriptions", "Exposed Credentials / User Descriptions", "Credential-like values recovered from NetExec user attributes"},
	},
	"network": {
		{"smb", "SMB Signing", "SMB signing conditions"},
		{"ldap", "LDAP Security", "LDAP signing and channel-binding conditions"},
		{"relay", "Relay Exposure", "Explicit relay-path evidence"},
		{"mssql", "MSSQL Security", "MSSQL configuration and relationship observations"},
		{"port_discovery", "Port Discovery", "Masscan open-port observations"},
	},
}

var findingCategoryOrder = []struct {
	Key, Name, Description string
}{
	{"credentials", "Credentials & SCCM", "Recovered credentials and SCCM security conditions"},
	{"kerberos", "Kerberos", "Kerberoasting, AS-REP and Kerberos material"},
	{"active_directory", "Active Directory", "Group Policy and SPN configuration conditions"},
	{"acl", "Active Directory ACLs", "Direct control relationships and object permissions"},
	{"adcs", "AD CS", "Certificate template and CA security conditions"},
	{"delegation", "Delegation", "Delegation configuration and related exposure"},
	{"network", "Network & Protocols", "SMB, LDAP and relay security conditions"},
	{"other", "Other / Unclassified", "Security records without a safer category"},
}

func findingCategoryKey(finding storage.Finding) string {
	typ := strings.ToLower(strings.TrimSpace(finding.FindingType))
	title := strings.ToLower(finding.Title)
	source := strings.ToLower(finding.SourceTool)
	switch {
	case strings.HasPrefix(typ, "ad_user_description_"):
		return "active_directory"
	case strings.HasPrefix(typ, "ad_acl_"):
		return "acl"
	case strings.HasPrefix(typ, "kerberoast"), strings.HasPrefix(typ, "asrep_"), strings.HasPrefix(typ, "kerberos_"):
		return "kerberos"
	case strings.HasPrefix(typ, "adcs_"):
		return "adcs"
	case strings.HasPrefix(typ, "unconstrained_delegation"), strings.HasPrefix(typ, "constrained_delegation"), strings.HasPrefix(typ, "rbcd_"), strings.HasPrefix(typ, "delegation_"):
		return "delegation"
	case strings.HasPrefix(typ, "gpo_"), strings.HasPrefix(typ, "ghostspn_"):
		return "active_directory"
	case strings.HasPrefix(typ, "sccm_"), strings.EqualFold(source, "pxethief"):
		return "credentials"
	case strings.HasPrefix(typ, "mssql_") || strings.EqualFold(source, "mssqlrelay") || strings.EqualFold(source, "mssqlpwner"):
		return "network"
	case strings.HasPrefix(typ, "masscan_") || strings.EqualFold(source, "masscan"):
		return "network"
	case strings.HasPrefix(typ, "relay_") || strings.EqualFold(source, "relayking"), strings.HasPrefix(typ, "smb_"), strings.HasPrefix(typ, "ldap_"):
		return "network"
	case strings.EqualFold(source, "certipy") && strings.HasPrefix(typ, "certificate_"):
		return "adcs"
	case strings.Contains(title, "pxethief") || strings.Contains(title, "sccm task-sequence"):
		return "credentials"
	default:
		return "other"
	}
}

func findingSubcategoryKey(finding storage.Finding) string {
	typ := strings.ToLower(finding.FindingType + " " + finding.Title)
	switch {
	case strings.HasPrefix(typ, "ad_user_description_"):
		return "user_descriptions"
	case strings.Contains(typ, "asrep"), strings.Contains(typ, "as-rep"):
		return "asrep"
	case strings.Contains(typ, "kerberoast"):
		return "kerberoastable"
	case strings.Contains(typ, "kerberos") || strings.Contains(typ, "krb5"):
		return "kerberos_material"
	case strings.Contains(typ, "smb"):
		return "smb"
	case strings.Contains(typ, "ldap") || strings.Contains(typ, "channel"):
		return "ldap"
	case strings.Contains(typ, "relay"):
		return "relay"
	case strings.Contains(typ, "gpo"):
		return "gpo"
	case strings.Contains(typ, "ghostspn") || strings.Contains(typ, "spn"):
		return "spn"
	case strings.Contains(typ, "mssql"):
		return "mssql"
	case strings.Contains(typ, "masscan") || strings.Contains(typ, "port"):
		return "port_discovery"
	default:
		return findingCategoryKey(finding)
	}
}

func buildFindingSubcategories(category string, rows []storage.Finding) []findingSubcategory {
	definitions := findingSubcategoryOrder[category]
	result := make([]findingSubcategory, 0, len(definitions))
	for _, definition := range definitions {
		result = append(result, findingSubcategory{Key: definition.Key, Name: definition.Name, Description: definition.Description})
	}
	for _, finding := range rows {
		if findingCategoryKey(finding) != category {
			continue
		}
		key := findingSubcategoryKey(finding)
		for index := range result {
			if result[index].Key != key {
				continue
			}
			if actionableFinding(finding) {
				result[index].Findings++
			} else {
				result[index].Observations++
			}
		}
	}
	return result
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
		if m.findingSubcategory != "" && findingSubcategoryKey(finding) != m.findingSubcategory {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(strings.Join([]string{finding.Title, finding.AffectedObject, finding.RelatedObject, finding.SourceTool, finding.FindingType}, " ")), search) {
			continue
		}
		filtered = append(filtered, finding)
	}
	sort.SliceStable(filtered, func(i, j int) bool { return severityRank(filtered[i].Severity) > severityRank(filtered[j].Severity) })
	if m.findingCategory == "acl" || m.findingCategory == "" {
		filtered = groupVisibleFindings(filtered)
	}
	sort.SliceStable(filtered, func(i, j int) bool { return severityRank(filtered[i].Severity) > severityRank(filtered[j].Severity) })
	m.findingRows = append(m.findingRows[:0], filtered...)
	if m.findingCursor >= len(m.findingRows) {
		m.findingCursor = max(0, len(m.findingRows)-1)
	}
	m.keepFindingVisible()
}

func groupVisibleFindings(rows []storage.Finding) []storage.Finding {
	acl := make([]storage.Finding, 0)
	other := make([]storage.Finding, 0)
	for _, finding := range rows {
		if strings.HasPrefix(strings.ToLower(finding.FindingType), "ad_acl_") {
			acl = append(acl, finding)
		} else {
			other = append(other, finding)
		}
	}
	return append(groupACLFindings(acl), other...)
}

func groupACLFindings(rows []storage.Finding) []storage.Finding {
	type group struct {
		finding storage.Finding
		rights  []string
		seen    map[string]bool
	}
	groups := make(map[string]*group)
	order := make([]string, 0, len(rows))
	for _, finding := range rows {
		key := finding.RelatedObjectID + "|" + finding.RelatedObject + "->" + finding.AffectedObjectID + "|" + finding.AffectedObject
		entry := groups[key]
		if entry == nil {
			entry = &group{finding: finding, seen: make(map[string]bool)}
			groups[key] = entry
			order = append(order, key)
		}
		right := strings.TrimSpace(strings.TrimPrefix(finding.FindingType, "ad_acl_"))
		if right == "" {
			right = finding.Title
		}
		if !entry.seen[right] {
			entry.seen[right] = true
			entry.rights = append(entry.rights, right)
		}
		if severityRank(finding.Severity) > severityRank(entry.finding.Severity) {
			entry.finding.Severity = finding.Severity
		}
	}
	result := make([]storage.Finding, 0, len(order))
	for _, key := range order {
		entry := groups[key]
		finding := entry.finding
		principal := displayFindingObject(finding.RelatedObject, finding.RelatedObjectID)
		target := displayFindingObject(finding.AffectedObject, finding.AffectedObjectID)
		finding.Title = fmt.Sprintf("AD control: %s → %s", principal, target)
		finding.Description = fmt.Sprintf("Direct ACL relationship. Observed rights: %s. Grouped %d stored ACE record(s); this presentation does not establish effective access or an attack path.", strings.Join(entry.rights, ", "), len(entry.rights))
		finding.FindingType = "ad_acl_group"
		result = append(result, finding)
	}
	return result
}

func actionableFinding(finding storage.Finding) bool {
	if strings.EqualFold(finding.SourceTool, "Certipy") && strings.HasPrefix(strings.ToLower(finding.FindingType), "adcs_") && !explicitCertipyESC.MatchString(finding.Title) {
		return false
	}
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
	if m.evidenceView {
		return m.evidenceViewRender(width)
	}
	if m.findingCategoryView {
		if m.findingSubcategoryView {
			return m.findingSubcategoryOverview(width)
		}
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
		if m.inlineEvidenceLoading {
			content.WriteString("\n" + dim.Render("Loading recovered evidence…") + "\n")
		} else if m.inlineEvidence.section != "" {
			content.WriteString("\n" + lipgloss.NewStyle().Bold(true).Render(m.inlineEvidence.section) + "\n")
			content.WriteString(dim.Render("────────────────────────────────────────────") + "\n")
			if m.inlineEvidence.error != "" {
				content.WriteString(warn.Render(m.inlineEvidence.error) + "\n")
			} else {
				page := max(1, m.findingPageSize()-10)
				endEvidence := min(len(m.inlineEvidence.lines), m.inlineEvidenceTop+page)
				for index := m.inlineEvidenceTop; index < endEvidence; index++ {
					content.WriteString(m.inlineEvidence.lines[index] + "\n")
				}
				content.WriteString(dim.Render(fmt.Sprintf("Evidence lines %d-%d of %d\n", min(m.inlineEvidenceTop+1, len(m.inlineEvidence.lines)), endEvidence, len(m.inlineEvidence.lines))))
			}
		}
		content.WriteString(fmt.Sprintf("\nCondition: %s\n\nImpact: %s\n\nRemediation: %s\n\nConfidence/limitations: %s\n", wrapPaneText(finding.Description, width-4), wrapPaneText(findingImpact(finding), width-4), wrapPaneText(findingRemediation(finding), width-4), wrapPaneText(finding.Confidence, width-4)))
		content.WriteString(dim.Render("E View Original Evidence   Esc Back   Up/Down Change finding"))
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
	content.WriteString(dim.Render("\n\nEnter Detail   / Search   P Reanalyze Certipy   1 High   2 Medium   3 Info   0 All   Esc Close"))
	return paneStyle(false).Width(width).Render(content.String())
}

func (m *model) evidenceViewRender(width int) string {
	var content strings.Builder
	content.WriteString(title.Render("PwnFlow // ORIGINAL EVIDENCE") + "\n")
	content.WriteString(dim.Render("Unmodified local artifact: "+m.evidencePath) + "\n\n")
	if m.evidenceError != "" {
		content.WriteString(warn.Render(m.evidenceError) + "\n")
	} else {
		page := max(1, m.findingPageSize())
		end := min(len(m.evidenceLines), m.evidenceTop+page)
		for index := m.evidenceTop; index < end; index++ {
			content.WriteString(fmt.Sprintf("%6d  %s\n", index+1, m.evidenceLines[index]))
		}
		content.WriteString(fmt.Sprintf("\nLines %d-%d of %d", min(m.evidenceTop+1, len(m.evidenceLines)), end, len(m.evidenceLines)))
	}
	content.WriteString(dim.Render("\n\nUp/Down PageUp/PageDown   Esc Back to Finding"))
	return paneStyle(false).Width(width).Render(content.String())
}

func findingImpact(finding storage.Finding) string {
	typ := strings.ToLower(finding.FindingType)
	switch {
	case strings.Contains(typ, "asrep"):
		return "The account may be exposed to offline AS-REP password guessing; collected material does not prove the password was cracked."
	case strings.Contains(typ, "kerberoast"):
		return "The service account may be targeted for ticket-based offline password guessing; this does not prove compromise."
	case strings.HasPrefix(typ, "adcs_esc_"):
		return "Certipy reported a potential AD CS misconfiguration; exploitation and all prerequisites remain unverified."
	case strings.Contains(typ, "pxethief"), strings.Contains(typ, "credential"):
		return "A credential-bearing deployment value was recovered and should be treated as exposed."
	case strings.HasPrefix(typ, "ad_acl_"):
		return "The named principal has a directly observed permission relationship; effective access and abuse paths require separate review."
	default:
		return "The source evidence records a security-relevant condition requiring operator review."
	}
}

func findingRemediation(finding storage.Finding) string {
	typ := strings.ToLower(finding.FindingType)
	switch {
	case strings.Contains(typ, "asrep"):
		return "Enable Kerberos preauthentication where appropriate, use a strong managed secret, and review the account's purpose."
	case strings.Contains(typ, "kerberoast"):
		return "Review the SPN, remove unnecessary service principals, reduce privilege, and use a strong managed service-account secret where supported."
	case strings.HasPrefix(typ, "adcs_esc_"):
		return "Review the exact ESC condition, restrict enrollment or template administration as applicable, and remove unnecessary issuance paths."
	case strings.Contains(typ, "pxethief"), strings.Contains(typ, "credential"):
		return "Rotate exposed credentials, restrict task-sequence access, and remove secrets from deployment content where possible."
	case strings.HasPrefix(typ, "ad_acl_"):
		return "Review and restrict the named principal's direct permissions on the affected object."
	default:
		return "Review the affected configuration and apply the source tool's recommended hardening."
	}
}

func (m *model) findingSubcategoryOverview(width int) string {
	var content strings.Builder
	content.WriteString(title.Render("PwnFlow // FINDINGS") + "\n")
	content.WriteString(dim.Render("Select a security condition group; evidence remains in its findings.") + "\n\n")
	for index, subcategory := range m.findingSubcategories {
		prefix := "  "
		if index == m.findingCursor {
			prefix = "> "
		}
		line := fmt.Sprintf("%s%-30s %8d findings  %8d observations", prefix, subcategory.Name, subcategory.Findings, subcategory.Observations)
		if index == m.findingCursor {
			line = lipgloss.NewStyle().Bold(true).Render(line)
		}
		content.WriteString(line + "\n   " + dim.Render(wrapPaneText(subcategory.Description, max(20, width-7))) + "\n")
	}
	if len(m.findingSubcategories) == 0 || (m.findingSubcategories[m.findingCursor].Findings == 0 && m.findingSubcategories[m.findingCursor].Observations == 0) {
		content.WriteString(warn.Render("No records in this category. Analysis status: NOT ASSESSED.") + "\n")
	}
	content.WriteString(dim.Render("\nEnter Open Group   Esc Back"))
	return paneStyle(false).Width(width).Render(content.String())
}

func (m *model) findingCategoryOverview(width int) string {
	if strings.TrimSpace(m.findingSearch) != "" {
		return m.findingSearchResults(width)
	}
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

func (m *model) findingSearchResults(width int) string {
	var content strings.Builder
	content.WriteString(title.Render("PwnFlow // FINDINGS SEARCH") + "\n")
	content.WriteString(dim.Render("Search: "+m.findingSearch+"   Results span all categories") + "\n\n")
	m.keepFindingVisible()
	end := min(len(m.findingRows), m.findingTop+m.findingPageSize())
	for index := m.findingTop; index < end; index++ {
		finding := m.findingRows[index]
		prefix := "  "
		if index == m.findingCursor {
			prefix = "> "
		}
		category := findingCategoryKey(finding)
		line := fmt.Sprintf("%s%-10s %-18s %-42s %s", prefix, strings.ToUpper(finding.Severity), category, truncateFinding(finding.Title, 42), truncateFinding(displayFindingObject(finding.AffectedObject, finding.AffectedObjectID), 24))
		if index == m.findingCursor {
			line = lipgloss.NewStyle().Bold(true).Render(line)
		}
		content.WriteString(line + "\n")
	}
	if len(m.findingRows) == 0 {
		content.WriteString("No findings match across any category.\n")
	}
	content.WriteString(fmt.Sprintf("\n%d cross-category results  rows %d-%d", len(m.findingRows), min(m.findingTop+1, len(m.findingRows)), min(end, len(m.findingRows))))
	content.WriteString(dim.Render("\n\nEnter Detail   / Edit Search   Esc Categories"))
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
