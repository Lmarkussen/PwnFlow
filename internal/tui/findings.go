package tui

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
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
	"acl": {
		{"acl", "Vulnerable ACLs", "Grouped principal-to-target control relationships"},
		{"acl_inventory", "ACL Evidence Inventory", "Informational direct ACL evidence and collection limitations"},
	},
	"adcs": {
		{"adcs_ca", "Vulnerable Certificate Authorities", "Explicit ESC conditions reported for certificate authorities"},
		{"adcs_template", "Vulnerable Templates", "Explicit ESC conditions reported for certificate templates"},
		{"adcs_other", "Other AD CS Findings", "AD CS findings whose persisted object type is unavailable"},
	},
	"delegation": {{"delegation", "Delegation", "Delegation configurations and related observations"}},
	"active_directory": {
		{"gpo", "Group Policy", "Evidence-backed Group Policy configuration conditions"},
		{"domain_security_policy", "Domain Security Policy", "Domain-default password and machine-account policy observations"},
		{"spn", "SPN Hygiene", "Explicitly reported stale or orphaned service principals"},
		{"account_security", "Account Security", "Evidence-backed account-control and credential-lifecycle conditions"},
		{"user_descriptions", "User Descriptions & Notes", "Credential-related values and keyword observations from NetExec user attributes"},
	},
	"network": {
		{"smb", "SMB Signing", "SMB signing conditions"},
		{"ldap", "LDAP Security", "LDAP signing and channel-binding conditions"},
		{"relay", "Relay Exposure", "Explicit relay-path evidence"},
		{"mssql", "MSSQL Security", "MSSQL configuration and relationship observations"},
		{"port_discovery", "Port Discovery", "Masscan open-port observations"},
	},
	"authentication": {
		{"successful_authentication", "Successful Authentication", "Verified successful protocol authentications"},
		{"privileged_access", "Privileged Access", "Explicit NetExec elevated-access indicators"},
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
	{"authentication", "Authentication & Privileged Access", "Verified authentication and protocol-specific elevated access"},
	{"network", "Network & Protocols", "SMB, LDAP and relay security conditions"},
	{"other", "Other / Unclassified", "Security records without a safer category"},
}

func findingCategoryKey(finding storage.Finding) string {
	typ := strings.ToLower(strings.TrimSpace(finding.FindingType))
	title := strings.ToLower(finding.Title)
	source := strings.ToLower(finding.SourceTool)
	switch {
	case strings.HasPrefix(typ, "ad_privileged_acl_"):
		return "acl"
	case strings.HasPrefix(typ, "ad_user_description_"):
		return "active_directory"
	case strings.HasPrefix(typ, "ad_account_"):
		return "active_directory"
	case strings.HasPrefix(typ, "ad_domain_policy_"):
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
	case strings.HasPrefix(typ, "netexec_auth_"), strings.HasPrefix(typ, "netexec_privileged_"):
		return "authentication"
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
	case strings.HasPrefix(typ, "ad_privileged_acl_"):
		return "acl_inventory"
	case strings.HasPrefix(typ, "adcs_"):
		if strings.Contains(strings.ToLower(finding.EvidenceJSON), `"object_type":"ca"`) {
			return "adcs_ca"
		}
		if strings.Contains(strings.ToLower(finding.EvidenceJSON), `"object_type":"template"`) {
			return "adcs_template"
		}
		return "adcs_other"
	case strings.HasPrefix(typ, "ad_user_description_"):
		return "user_descriptions"
	case strings.Contains(typ, "asrep"), strings.Contains(typ, "as-rep"):
		return "asrep"
	case strings.Contains(typ, "kerberoast"):
		return "kerberoastable"
	case strings.Contains(typ, "kerberos") || strings.Contains(typ, "krb5"):
		return "kerberos_material"
	case strings.HasPrefix(typ, "netexec_auth_"):
		return "successful_authentication"
	case strings.HasPrefix(typ, "netexec_privileged_"):
		return "privileged_access"
	case strings.Contains(typ, "smb"):
		return "smb"
	case strings.Contains(typ, "ldap") || strings.Contains(typ, "channel"):
		return "ldap"
	case strings.Contains(typ, "relay"):
		return "relay"
	case strings.Contains(typ, "gpo"):
		return "gpo"
	case strings.Contains(typ, "passwd_notreqd"), strings.Contains(typ, "dont_expire_password"):
		return "account_security"
	case strings.HasPrefix(typ, "ad_domain_policy_"):
		return "domain_security_policy"
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
	if !m.findingsLoaded {
		rows, err := m.db.ListFindings(m.ctx, m.targetID)
		if err != nil {
			m.status = "findings unavailable: " + err.Error()
			return
		}
		m.findingAllRows = append(m.findingAllRows[:0], rows...)
		m.findingCategories = buildFindingCategories(m.findingAllRows)
		m.findingsLoaded = true
	}
	if m.findingCategories == nil {
		m.findingCategories = buildFindingCategories(m.findingAllRows)
	}
	rows := m.findingAllRows
	m.findingViewMode = "all"
	m.findingSearch = ""
	m.findingSeverity = ""
	filtered := make([]storage.Finding, 0, len(rows))
	for _, finding := range rows {
		if m.findingCategory != "" && findingCategoryKey(finding) != m.findingCategory {
			continue
		}
		if m.findingSubcategory != "" && findingSubcategoryKey(finding) != m.findingSubcategory {
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
	if m.findingCategoryView {
		limit := len(m.findingCategories)
		if m.findingSubcategoryView {
			limit = len(m.findingSubcategories)
		}
		if m.findingCursor >= limit {
			m.findingCursor = max(0, limit-1)
		}
	} else if m.findingCursor >= len(m.findingRows) {
		m.findingCursor = max(0, len(m.findingRows)-1)
	}
	if !m.findingCategoryView {
		m.keepFindingVisible()
	}
}

func (m *model) ensureFindingNavigationMemory() {
	if m.findingSubcategorySelections == nil {
		m.findingSubcategorySelections = make(map[string]string)
	}
	if m.findingSubcategoryTops == nil {
		m.findingSubcategoryTops = make(map[string]int)
	}
	if m.findingRowSelections == nil {
		m.findingRowSelections = make(map[string]string)
	}
	if m.findingRowTops == nil {
		m.findingRowTops = make(map[string]int)
	}
}

func findingRowIdentity(finding storage.Finding) string {
	if finding.ID > 0 {
		return fmt.Sprintf("id:%d", finding.ID)
	}
	if finding.FindingKey != "" {
		return "key:" + finding.FindingKey
	}
	return strings.Join([]string{finding.FindingType, fmt.Sprint(finding.SourceExecution), finding.ArtifactPath, finding.ArtifactRef, finding.AffectedObjectID, finding.AffectedObject}, "\x00")
}

func findingSubcategoryPath(category, subcategory string) string {
	return category + "\x00" + subcategory
}

func (m *model) restoreFindingCategorySelection() {
	if m.findingCategorySelection != "" {
		for index, category := range m.findingCategories {
			if category.Key == m.findingCategorySelection {
				m.findingCursor = index
				return
			}
		}
	}
	m.findingCursor = min(max(0, m.findingCursor), max(0, len(m.findingCategories)-1))
}

func (m *model) restoreFindingSubcategorySelection() {
	m.ensureFindingNavigationMemory()
	selection := m.findingSubcategorySelections[m.findingCategory]
	if selection != "" {
		for index, subcategory := range m.findingSubcategories {
			if subcategory.Key == selection {
				m.findingCursor = index
				m.findingTop = m.findingSubcategoryTops[m.findingCategory]
				return
			}
		}
	}
	m.findingCursor = min(max(0, m.findingCursor), max(0, len(m.findingSubcategories)-1))
}

func (m *model) restoreFindingRowSelection() {
	m.ensureFindingNavigationMemory()
	selection := m.findingRowSelections[findingSubcategoryPath(m.findingCategory, m.findingSubcategory)]
	if selection != "" {
		for index, finding := range m.findingRows {
			if findingRowIdentity(finding) == selection {
				m.findingCursor = index
				m.findingTop = m.findingRowTops[findingSubcategoryPath(m.findingCategory, m.findingSubcategory)]
				return
			}
		}
	}
	m.findingCursor = min(max(0, m.findingCursor), max(0, len(m.findingRows)-1))
}

func (m *model) rememberFindingSubcategorySelection() {
	m.ensureFindingNavigationMemory()
	if m.findingCategory == "" || len(m.findingSubcategories) == 0 || m.findingCursor < 0 || m.findingCursor >= len(m.findingSubcategories) {
		return
	}
	m.findingSubcategorySelections[m.findingCategory] = m.findingSubcategories[m.findingCursor].Key
	m.findingSubcategoryTops[m.findingCategory] = m.findingTop
}

func (m *model) rememberFindingRowSelection() {
	m.ensureFindingNavigationMemory()
	if m.findingCategory == "" || m.findingSubcategory == "" || len(m.findingRows) == 0 || m.findingCursor < 0 || m.findingCursor >= len(m.findingRows) {
		return
	}
	path := findingSubcategoryPath(m.findingCategory, m.findingSubcategory)
	m.findingRowSelections[path] = findingRowIdentity(m.findingRows[m.findingCursor])
	m.findingRowTops[path] = m.findingTop
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
	if m.searchMode && m.searchKind == "findings" {
		return m.searchViewRender(width)
	}
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
	content.WriteString("\n")
	m.keepFindingVisible()
	end := min(len(m.findingRows), m.findingTop+m.findingPageSize())
	if m.findingDetail && len(m.findingRows) > 0 {
		finding := m.hydrateHistoricalACLInventory(m.findingRows[m.findingCursor])
		content.WriteString(findingDetailHeader(finding, width-4) + "\n\n")
		content.WriteString(wrapPaneText(findingCondition(finding), width-4) + "\n\n")
		content.WriteString(findingAttributes(finding, width-4))
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
		content.WriteString("\n" + findingSection("SECURITY IMPACT", findingImpact(finding), width-4))
		content.WriteString(findingSection("RECOMMENDED ACTION", findingRemediation(finding), width-4))
		content.WriteString(findingSection("EVIDENCE", findingEvidenceSummary(finding), width-4))
		content.WriteString(findingSection("LIMITATIONS", findingLimitations(finding), width-4))
		content.WriteString(dim.Render("E View Original Evidence   Esc Back   Up/Down Change finding"))
		return paneStyle(false).Width(width).Render(content.String())
	}
	if len(m.findingRows) == 0 {
		content.WriteString("No findings match the current filters.\n\n")
	} else {
		for index := m.findingTop; index < end; index++ {
			finding := m.findingRows[index]
			selected := index == m.findingCursor
			object := displayFindingObject(finding.AffectedObject, finding.AffectedObjectID)
			titleWidth := max(12, min(42, width-40))
			objectWidth := max(12, width-titleWidth-22)
			severityText := strings.ToUpper(finding.Severity)
			severityField := severityStyle(finding.Severity).Render(severityText) + strings.Repeat(" ", max(1, 11-ansi.StringWidthWc(severityText)))
			line := fmt.Sprintf("%s%s %-*s %s", selectionPrefix(selected), severityField, titleWidth, selectionLabel(truncateFinding(finding.Title, titleWidth), selected), truncateFinding(object, objectWidth))
			content.WriteString(line + "\n")
		}
	}
	content.WriteString(fmt.Sprintf("\n%d visible records (total database results are filtered)  rows %d-%d", len(m.findingRows), min(m.findingTop+1, len(m.findingRows)), min(end, len(m.findingRows))))
	content.WriteString(dim.Render("\n\nEnter = Open    Ctrl+S = Search    Esc = Back"))
	return paneStyle(false).Width(width).Render(content.String())
}

func (m *model) startSearch(kind string) {
	m.searchMode = true
	m.searchKind = kind
	m.searchCursor = 0
	m.searchFindingReturn = false
	m.searchInput = newSearchInput()
	m.searchInput.Focus()
	if kind == "findings" {
		if !m.findingsLoaded && m.db != nil {
			m.refreshFindings()
		}
		m.searchFindingRows = append([]storage.Finding(nil), m.findingRows...)
		m.searchFindingCursor = m.findingCursor
		m.searchFindingTop = m.findingTop
		m.searchFindingCategoryView = m.findingCategoryView
		m.searchFindingSubcategoryView = m.findingSubcategoryView
		m.searchFindingCategory = m.findingCategory
		m.searchFindingSubcategory = m.findingSubcategory
		m.searchFindingCategories = append([]findingCategory(nil), m.findingCategories...)
		m.searchFindingSubcategories = append([]findingSubcategory(nil), m.findingSubcategories...)
		m.searchFindingSource = append([]storage.Finding(nil), m.findingAllRows...)
		if len(m.searchFindingSource) == 0 {
			m.searchFindingSource = append([]storage.Finding(nil), m.findingRows...)
		}
		m.searchFindingResults = append([]storage.Finding(nil), m.searchFindingSource...)
	}
	m.refreshSearchResults()
}

func (m *model) refreshSearchResults() {
	query := strings.ToLower(strings.TrimSpace(m.searchInput.Value()))
	if m.searchKind == "modules" {
		m.searchModuleResults = m.searchModuleResults[:0]
		for index, module := range m.modules {
			text := strings.ToLower(strings.Join([]string{module.Name(), module.ID(), string(module.Category()), module.Description()}, "\x00"))
			if query == "" || strings.Contains(text, query) {
				m.searchModuleResults = append(m.searchModuleResults, index)
			}
		}
		m.searchCursor = min(max(0, m.searchCursor), max(0, len(m.searchModuleResults)-1))
		return
	}
	m.searchFindingResults = filterFindingSearchResults(m.searchFindingSource, query)
	m.searchCursor = min(max(0, m.searchCursor), max(0, len(m.searchFindingResults)-1))
}

func filterFindingSearchResults(rows []storage.Finding, query string) []storage.Finding {
	if query == "" {
		return append([]storage.Finding(nil), rows...)
	}
	result := make([]storage.Finding, 0, len(rows))
	for _, finding := range rows {
		text := strings.ToLower(strings.Join([]string{
			finding.Title, finding.FindingType, finding.SourceTool,
			finding.AffectedObject, finding.AffectedObjectID,
			finding.RelatedObject, finding.RelatedObjectID,
			findingCategoryKey(finding), findingSubcategoryKey(finding),
		}, "\x00"))
		if strings.Contains(text, query) {
			result = append(result, finding)
		}
	}
	return result
}

func (m *model) restoreSearchFindingContext() {
	m.findingRows = append([]storage.Finding(nil), m.searchFindingRows...)
	m.findingCursor = m.searchFindingCursor
	m.findingTop = m.searchFindingTop
	m.findingCategoryView = m.searchFindingCategoryView
	m.findingSubcategoryView = m.searchFindingSubcategoryView
	m.findingCategory = m.searchFindingCategory
	m.findingSubcategory = m.searchFindingSubcategory
	m.findingCategories = append([]findingCategory(nil), m.searchFindingCategories...)
	m.findingSubcategories = append([]findingSubcategory(nil), m.searchFindingSubcategories...)
	m.searchFindingRows = nil
	m.searchFindingResults = nil
	m.searchFindingSource = nil
	m.searchFindingCategories = nil
	m.searchFindingSubcategories = nil
}

func (m *model) closeSearch() {
	if m.searchKind == "findings" {
		m.restoreSearchFindingContext()
	}
	m.searchMode = false
	m.searchKind = ""
	m.searchCursor = 0
	m.searchModuleResults = nil
	m.searchFindingReturn = false
}

func (m *model) searchViewRender(width int) string {
	var content strings.Builder
	content.WriteString(title.Render("PwnFlow // SEARCH") + "\n\n")
	content.WriteString(m.searchInput.View() + "\n")
	content.WriteString(dim.Render("Enter open/select   Esc cancel   Up/Down move") + "\n\n")
	if m.searchKind == "modules" {
		if len(m.searchModuleResults) == 0 {
			content.WriteString(warn.Render("No matching modules.") + "\n")
		} else {
			for resultIndex, moduleIndex := range m.searchModuleResults {
				selected := resultIndex == m.searchCursor
				module := m.modules[moduleIndex]
				content.WriteString(fmt.Sprintf("%s%s  %s\n", selectionPrefix(selected), selectionLabel(module.Name(), selected), dim.Render(string(module.Category()))))
			}
		}
	} else if len(m.searchFindingResults) == 0 {
		content.WriteString(warn.Render("No matching findings.") + "\n")
	} else {
		limit := max(1, m.findingPageSize())
		start := 0
		if m.searchCursor >= limit {
			start = m.searchCursor - limit + 1
		}
		end := min(len(m.searchFindingResults), start+limit)
		for index := start; index < end; index++ {
			finding := m.searchFindingResults[index]
			selected := index == m.searchCursor
			object := displayFindingObject(finding.AffectedObject, finding.AffectedObjectID)
			severityText := strings.ToUpper(finding.Severity)
			severityField := severityStyle(finding.Severity).Render(severityText) + strings.Repeat(" ", max(1, 9-ansi.StringWidthWc(severityText)))
			content.WriteString(fmt.Sprintf("%s%s  %s  %s\n", selectionPrefix(selected), severityField, selectionLabel(truncateFinding(finding.Title, max(20, width-65)), selected), dim.Render(truncateFinding(object, 28))))
		}
	}
	return paneStyle(false).Width(width).Render(content.String())
}

func findingDetailHeader(finding storage.Finding, width int) string {
	titleText := strings.ToUpper(finding.Title)
	severity := strings.ToUpper(finding.Severity)
	severityDisplayStyle := severityStyle(finding.Severity)
	if width < 1 {
		width = 1
	}
	line := titleText + "  " + severityDisplayStyle.Render(severity)
	if ansi.StringWidthWc(line) <= width {
		return lipgloss.NewStyle().Bold(true).Render(titleText) + "  " + severityDisplayStyle.Render(severity)
	}
	return lipgloss.NewStyle().Bold(true).Render(wrapPaneText(titleText, width)) + "\n" + severityDisplayStyle.Render(severity)
}

func findingCondition(finding storage.Finding) string {
	typ := strings.ToLower(finding.FindingType)
	if typ == "ad_privileged_acl_evidence_inventory" {
		return formatACLInventoryOverview(finding)
	}
	metadata := findingMetadata(finding)
	if condition := specificFindingCondition(finding, metadata); condition != "" {
		return condition
	}
	protocol := metadataString(metadata, "protocol")
	if protocol == "" {
		protocol = protocolFromFindingTitle(finding.Title)
	}
	switch {
	case strings.HasPrefix(typ, "netexec_privileged_"):
		return "NetExec reported privileged access through " + fallbackText(protocol, "the reported protocol") + "."
	case strings.HasPrefix(typ, "netexec_auth_"):
		return "NetExec reported successful authentication through " + fallbackText(protocol, "the reported protocol") + "."
	case typ == "smb_signing_not_required":
		return "The SMB service does not require message signing."
	case typ == "ad_account_passwd_notreqd":
		return "This account has the PASSWD_NOTREQD flag set."
	case typ == "ad_account_dont_expire_password":
		return "This account has the DONT_EXPIRE_PASSWORD flag set."
	case strings.HasPrefix(typ, "adcs_esc_"):
		return "Certipy reported an explicit certificate-services vulnerability condition."
	case strings.Contains(typ, "credential") || strings.Contains(typ, "secret") || strings.Contains(typ, "material"):
		return "Security-sensitive authentication material or credential exposure was identified."
	default:
		return finding.Description
	}
}

func findingAttributes(finding storage.Finding, width int) string {
	metadata := findingMetadata(finding)
	var lines []string
	add := func(label, value string) {
		if strings.TrimSpace(value) != "" {
			lines = append(lines, fmt.Sprintf("  %-12s %s", label, value))
		}
	}
	if target := metadataString(metadata, "target"); target != "" {
		if port := metadataString(metadata, "port"); port != "" {
			target += ":" + port
		}
		add("TARGET", target)
	} else if strings.HasPrefix(strings.ToLower(finding.FindingType), "adcs_esc_") {
		objectType := strings.ToLower(metadataString(metadata, "object_type"))
		label := "TEMPLATE"
		if objectType == "ca" || objectType == "certificate_authority" {
			label = "CA"
		}
		add(label, displayFindingObject(finding.AffectedObject, finding.AffectedObjectID))
		add("ESC", certipyESCType(finding, metadata))
	} else if finding.AffectedObject != "" || finding.AffectedObjectID != "" {
		add("AFFECTED", displayFindingObject(finding.AffectedObject, finding.AffectedObjectID))
	}
	if finding.RelatedObject != "" || finding.RelatedObjectID != "" {
		add("ACCOUNT", displayFindingObject(finding.RelatedObject, finding.RelatedObjectID))
	}
	add("PROTOCOL", metadataString(metadata, "protocol"))
	add("HOST", metadataString(metadata, "host"))
	add("INDICATOR", findingIndicator(finding))
	add("OBJECT", metadataString(metadata, "object_name"))
	add("CONDITION", explicitCondition(finding))
	if uac := metadataString(metadata, "user_account_control"); uac != "" {
		add("UAC FLAG", metadataString(metadata, "flag")+" ("+uac+")")
	}
	if len(lines) == 0 {
		return ""
	}
	var content strings.Builder
	content.WriteString(infoBlueStyle().Bold(true).Render("AFFECTED ASSETS") + "\n")
	content.WriteString(wrapPaneText(strings.Join(lines, "\n"), width) + "\n")
	return content.String()
}

func findingSection(name, value string, width int) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return "\n" + findingSectionStyle(name).Render(name) + "\n" + wrapPaneText(value, width) + "\n"
}

func infoBlueStyle() lipgloss.Style { return lipgloss.NewStyle().Foreground(infoBlue).Bold(true) }

func findingSectionStyle(name string) lipgloss.Style {
	switch name {
	case "SECURITY IMPACT":
		return severityMediumStyle
	case "RECOMMENDED ACTION":
		return lipgloss.NewStyle().Foreground(green).Bold(true)
	case "LIMITATIONS":
		return lipgloss.NewStyle().Foreground(amber).Bold(true)
	default:
		return infoBlueStyle()
	}
}

func findingEvidenceSummary(finding storage.Finding) string {
	if strings.HasPrefix(strings.ToLower(finding.FindingType), "adcs_esc_") {
		return fmt.Sprintf("Certipy · Execution %d\nOriginal artifact: %s\nSource reference: %s", finding.SourceExecution, fallbackText(finding.ArtifactPath, "source artifact unavailable"), fallbackText(finding.ArtifactRef, "source reference unavailable"))
	}
	if strings.EqualFold(finding.FindingType, "ad_privileged_acl_evidence_inventory") {
		metadata := findingMetadata(finding)
		return fmt.Sprintf("%s · Execution %d\nFull report: %s\nStructured inventory: %s\nOriginal RustHound source: %s", finding.SourceTool, finding.SourceExecution, metadataString(metadata, "human_report"), fallbackText(finding.ArtifactPath, metadataString(metadata, "structured_artifact")), metadataString(metadata, "source_artifact"))
	}
	if strings.EqualFold(finding.FindingType, "gpo_evidence_inventory") {
		metadata := findingMetadata(finding)
		lines := []string{"Configured GPO links are evidence of directory configuration, not proof of effective client-side application."}
		if failures := metadataInt(metadata, "file_failures"); failures > 0 {
			lines = append(lines, fmt.Sprintf("SYSVOL retrieval failures: %d.", failures))
		}
		if limits := metadataInt(metadata, "file_limits"); limits > 0 {
			lines = append(lines, fmt.Sprintf("SYSVOL records limited by collection bounds: %d.", limits))
		}
		if limitations := metadataStringSlice(metadata, "limitations"); len(limitations) > 0 {
			lines = append(lines, "Collection limitations: "+strings.Join(limitations, "; "))
		}
		return strings.Join(lines, "\n")
	}
	return fmt.Sprintf("%s · Execution %d\n%s %s", finding.SourceTool, finding.SourceExecution, finding.ArtifactPath, finding.ArtifactRef)
}

func findingLimitations(finding storage.Finding) string {
	if strings.HasPrefix(strings.ToLower(finding.FindingType), "adcs_esc_") {
		metadata := findingMetadata(finding)
		lines := []string{"Certipy reported the ESC classification from the preserved source artifact; PwnFlow did not request a certificate or test exploitation."}
		if metadataString(metadata, "object_type") == "" {
			lines = append(lines, "CA/template object type is unavailable in this historical record.")
		}
		lines = append(lines, "Effective permissions, certificate issuance, authentication, impersonation and attack-path prerequisites were not independently verified.")
		return strings.Join(lines, "\n")
	}
	if strings.EqualFold(finding.FindingType, "ad_privileged_acl_evidence_inventory") {
		metadata := findingMetadata(finding)
		var lines []string
		if status := metadataString(metadata, "status"); status != "" {
			lines = append(lines, "ACL evidence status: "+status+".")
		}
		if count := metadataInt(metadata, "unsupported_relationships"); count > 0 {
			lines = append(lines, fmt.Sprintf("Unsupported ACL forms were encountered (%d records); they were not generalized into permissions.", count))
		}
		if count := metadataInt(metadata, "unresolved_principals"); count > 0 {
			lines = append(lines, fmt.Sprintf("%d principal or target references remain unresolved.", count))
		}
		if count := metadataInt(metadata, "omitted_relationships"); count > 0 {
			lines = append(lines, fmt.Sprintf("%d normalized relationships were omitted by the analyzer's processing bound.", count))
		}
		if count := metadataInt(metadata, "malformed_entries"); count > 0 {
			lines = append(lines, fmt.Sprintf("%d malformed source entries were not normalized.", count))
		}
		lines = append(lines, "Effective permissions, group-derived rights, deny precedence and exploitability were not evaluated.")
		return strings.Join(lines, "\n")
	}
	if strings.TrimSpace(finding.Confidence) == "" {
		return "Source limitations were not recorded."
	}
	return finding.Confidence
}

func metadataInt(metadata map[string]any, key string) int {
	value, ok := metadata[key]
	if !ok {
		return 0
	}
	switch number := value.(type) {
	case float64:
		return int(number)
	case int:
		return number
	default:
		return 0
	}
}

func formatACLInventoryOverview(finding storage.Finding) string {
	metadata := findingMetadata(finding)
	var b strings.Builder
	fmt.Fprintf(&b, "RustHound execution %d contains observed direct ACL relationships affecting high-value Active Directory objects.\nStatus: %s\nHigh-value targets: %d\nObserved relationships: %d\n", finding.SourceExecution, fallbackText(metadataString(metadata, "status"), "unknown"), metadataInt(metadata, "high_value_targets"), metadataInt(metadata, "normalized_relationships"))
	relationships, _ := metadata["relationship_overview"].([]any)
	if len(relationships) == 0 {
		b.WriteString("\nNo bounded relationship overview is available; inspect the full report for retained evidence.")
		return b.String()
	}
	additional := metadataInt(metadata, "normalized_relationships") - len(relationships)
	if additional < 0 {
		additional = 0
	}
	fmt.Fprintf(&b, "\nObserved relationships (showing %d; %d additional in the full report):\n", len(relationships), additional)
	for _, raw := range relationships {
		relation, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		principal := fallbackText(metadataString(relation, "principal_name"), "(unresolved principal)")
		principalID := metadataString(relation, "principal_id")
		target := fallbackText(metadataString(relation, "target_name"), "(unnamed target)")
		targetID := metadataString(relation, "target_id")
		fmt.Fprintf(&b, "- %s [%s] -> %s -> %s [%s] (%s)\n  Decision: %s | Inheritance: %s", principal, principalID, metadataString(relation, "permission"), target, targetID, metadataString(relation, "target_type"), fallbackText(metadataString(relation, "decision"), "unknown"), fallbackText(metadataString(relation, "inheritance"), "unknown"))
		if restriction := metadataString(relation, "object_type"); restriction != "" || metadataString(relation, "inherited_object_type") != "" {
			fmt.Fprintf(&b, " | Object restriction: %s/%s", restriction, metadataString(relation, "inherited_object_type"))
		}
		fmt.Fprintf(&b, "\n  Source: %s#%s\n", metadataString(relation, "artifact"), metadataString(relation, "artifact_ref"))
	}
	return b.String()
}

func specificFindingCondition(finding storage.Finding, metadata map[string]any) string {
	typ := strings.ToLower(finding.FindingType)
	switch {
	case typ == "netexec_privileged_access" || typ == "netexec_auth_success":
		protocol := fallbackText(metadataString(metadata, "protocol"), "unknown protocol")
		target := fallbackText(metadataString(metadata, "target"), fallbackText(finding.AffectedObject, "target identity unavailable in source evidence"))
		principal := fallbackText(metadataString(metadata, "principal"), fallbackText(finding.RelatedObject, "principal identity unavailable in source evidence"))
		port := metadataString(metadata, "port")
		if port != "" {
			target += ":" + port
		}
		if typ == "netexec_privileged_access" {
			return fmt.Sprintf("NetExec reported its administrative-access indicator for %s authentication by %s against %s. The indicator is scoped to this tested protocol and target.", protocol, principal, target)
		}
		return fmt.Sprintf("NetExec reported successful %s authentication by %s against %s.", protocol, principal, target)
	case typ == "unconstrained_delegation_configured" || typ == "constrained_delegation_configured":
		delegationType := fallbackText(metadataString(metadata, "delegation_type"), strings.TrimSuffix(strings.TrimPrefix(typ, "configured"), "_"))
		object := fallbackText(metadataString(metadata, "object_name"), fallbackText(finding.AffectedObject, "object identity unavailable in source evidence"))
		condition := fmt.Sprintf("RustHound observed %s delegation configured on %s.", delegationType, object)
		if services := metadataStringSlice(metadata, "allowed_to_delegate"); len(services) > 0 {
			condition += " Allowed service targets: " + strings.Join(services, ", ") + "."
		}
		return condition
	case typ == "relay_exposure_observed":
		protocol := fallbackText(metadataString(metadata, "protocol"), "protocol unavailable")
		destination := fallbackText(metadataString(metadata, "destination"), fallbackText(finding.AffectedObject, "destination unavailable"))
		level := metadataString(metadata, "level")
		impact := metadataString(metadata, "impact")
		condition := fmt.Sprintf("RelayKing reported an explicit relay-related path for %s toward %s.", protocol, destination)
		if level != "" || impact != "" {
			condition += fmt.Sprintf(" Tool classification: level=%s impact=%s.", fallbackText(level, "unknown"), fallbackText(impact, "unknown"))
		}
		return condition
	case typ == "smb_signing_not_required":
		protocol := fallbackText(metadataString(metadata, "protocol"), "SMB")
		target := fallbackText(metadataString(metadata, "target"), fallbackText(finding.AffectedObject, "target identity unavailable in source evidence"))
		return fmt.Sprintf("NetExec reported that %s message signing is not required by %s.", protocol, target)
	case strings.HasPrefix(typ, "ad_domain_policy_"):
		domain := fallbackText(metadataString(metadata, "domain"), fallbackText(finding.AffectedObject, "domain identity unavailable in source evidence"))
		scope := fallbackText(metadataString(metadata, "policy_scope"), "domain policy")
		value := domainPolicyDisplayValue(typ, metadata)
		if value == "" {
			value = "configured value unavailable in source evidence"
		}
		return fmt.Sprintf("NetExec observed %s on %s: %s.", scope, domain, value)
	case typ == "asrep_material_collected" || typ == "kerberos_ticket_material_collected":
		kind := fallbackText(metadataString(metadata, "material_type"), "Kerberos material")
		principal := fallbackText(metadataString(metadata, "principal"), fallbackText(finding.AffectedObject, "principal identity unavailable in source evidence"))
		return fmt.Sprintf("NetExec recorded %s associated with %s. Secret material is intentionally not displayed.", kind, principal)
	case typ == "ad_user_description_keyword_observed":
		principal := fallbackText(metadataString(metadata, "principal"), fallbackText(finding.AffectedObject, "principal identity unavailable in source evidence"))
		attribute := fallbackText(metadataString(metadata, "attribute"), "account information")
		keyword := fallbackText(metadataString(metadata, "keyword"), "credential-related language")
		return fmt.Sprintf("NetExec observed the keyword %q in the %s attribute for %s. The keyword is not proof that a credential was disclosed.", keyword, attribute, principal)
	case strings.HasPrefix(typ, "adcs_esc_"):
		return formatCertipyESCCondition(finding, metadata)
	case typ == "gpo_evidence_inventory":
		return formatGPOEvidenceCondition(metadata, finding)
	}
	return ""
}

func specificFindingImpact(finding storage.Finding) string {
	typ := strings.ToLower(finding.FindingType)
	metadata := findingMetadata(finding)
	switch {
	case typ == "netexec_privileged_access":
		return "The result indicates tool-reported administrative access in this protocol context; broader privileges, local administrator membership and domain-wide access were not independently verified."
	case typ == "netexec_auth_success":
		return "The tested service accepted the authentication attempt. This does not establish elevated privileges, local administrator membership, privilege escalation or domain-wide access."
	case typ == "unconstrained_delegation_configured":
		return "Unconstrained delegation is an observed directory configuration that can broaden credential-delegation exposure for the affected object. Credential capture or Kerberos abuse was not observed or verified."
	case typ == "constrained_delegation_configured":
		services := metadataStringSlice(metadata, "allowed_to_delegate")
		if len(services) > 0 {
			return "Constrained delegation is configured toward the listed service targets. The configuration and trust boundary matter for review; ticket abuse or exploitability was not verified."
		}
		return "Constrained-delegation properties were observed, but the allowed service targets were not available in this record. Exploitability was not verified."
	case typ == "relay_exposure_observed":
		return "RelayKing classified a relay-related path in the supplied assessment evidence. This does not prove that an NTLM relay succeeded; signing, channel binding, authentication behavior and destination prerequisites require separate validation."
	case typ == "smb_signing_not_required":
		return "SMB signing is not required on the reported service, which can increase relay exposure when other relay prerequisites are present. No relay success is established by this observation."
	case strings.HasPrefix(typ, "ad_domain_policy_"):
		return "The reported value is a domain-default policy observation. It may be overridden by fine-grained or endpoint-specific policy; it does not by itself prove weak credentials, compromise or effective policy for every account."
	case typ == "asrep_material_collected" || typ == "kerberos_ticket_material_collected":
		return "The source artifact contains roast material associated with the identified principal. The material is protected and not displayed; collection does not prove that it was cracked or used."
	case typ == "ad_user_description_keyword_observed":
		return "A credential-related term was observed in directory metadata. This is an indicator to inspect the account information safely, not confirmed credential exposure."
	case typ == "gpo_evidence_inventory":
		return "The collector preserved GPO metadata, configured-link evidence and bounded SYSVOL files. Configured links do not prove effective client-side policy application."
	case strings.HasPrefix(typ, "adcs_esc_"):
		return certipyESCImpact(finding, metadata)
	}
	return ""
}

func specificFindingRemediation(finding storage.Finding) string {
	typ := strings.ToLower(finding.FindingType)
	metadata := findingMetadata(finding)
	switch {
	case typ == "netexec_privileged_access":
		return "Verify whether the identified account is intended to have administrative access to the named host over the tested protocol. Confirm the administrative scope using approved controls; do not infer domain-wide privilege from this record."
	case typ == "netexec_auth_success":
		return "Verify whether this account is expected to authenticate to the identified host using the tested protocol. If unexpected, review account permissions, credential exposure and permitted access paths."
	case typ == "unconstrained_delegation_configured":
		return "Review the affected account or computer's delegation configuration and business need. Restrict or remove unconstrained delegation where operationally appropriate, then validate dependent services."
	case typ == "constrained_delegation_configured":
		return "Review the allowed service targets and trust boundary for the affected object. Restrict delegation to the minimum necessary service scope where operationally appropriate."
	case typ == "relay_exposure_observed":
		return "Validate the reported source, destination and protocol conditions using approved configuration review. Require appropriate signing and channel binding protections; do not disable protections to reproduce the path."
	case typ == "smb_signing_not_required":
		return "Verify the signing policy on the named SMB service and require signing where compatible. Review relay prerequisites separately; this record does not justify an attack attempt."
	case strings.HasPrefix(typ, "ad_domain_policy_"):
		return "Verify the named domain-default setting in directory policy and review whether fine-grained policies or business requirements override it. Apply a targeted policy change only after confirming the affected accounts and services."
	case typ == "asrep_material_collected" || typ == "kerberos_ticket_material_collected":
		return "Treat the protected artifact as sensitive evidence. Verify the principal and collection scope, restrict unnecessary access, and rotate affected credentials through the approved process if exposure is confirmed."
	case typ == "ad_user_description_keyword_observed":
		return "Verify whether the identified account's directory attribute contains sensitive operational or credential information. Remove sensitive metadata and review access if disclosure is confirmed; do not treat the keyword alone as a recovered credential."
	case typ == "gpo_evidence_inventory":
		return "Review the listed GPO metadata, links and preserved SYSVOL files using the referenced evidence. Validate security filtering and client-side application separately before changing policy."
	case strings.HasPrefix(typ, "adcs_esc_"):
		return certipyESCRemediation(finding, metadata)
	}
	return ""
}

func formatGPOEvidenceCondition(metadata map[string]any, finding storage.Finding) string {
	discovered := metadataInt(metadata, "gpos_discovered")
	complete := metadataInt(metadata, "gpos_complete")
	partial := metadataInt(metadata, "gpos_partial")
	files := metadataInt(metadata, "sysvol_files")
	links := metadataInt(metadata, "configured_relationships")
	condition := fmt.Sprintf("AD GPO Evidence preserved %d GPOs (%d complete, %d partial), %d SYSVOL file records and %d configured link relationships.", discovered, complete, partial, files, links)
	if names := metadataStringSlice(metadata, "gpo_names"); len(names) > 0 {
		condition += " GPOs: " + strings.Join(names, "; ") + "."
	}
	if finding.SourceExecution > 0 {
		condition += fmt.Sprintf(" Producing execution: %d.", finding.SourceExecution)
	}
	return condition
}

func certipyESCType(finding storage.Finding, metadata map[string]any) string {
	if value := strings.ToUpper(strings.TrimSpace(metadataString(metadata, "esc"))); value != "" {
		return value
	}
	if match := explicitCertipyESC.FindString(finding.FindingType + " " + finding.Title); match != "" {
		return strings.ToUpper(match)
	}
	return "ESC classification unavailable"
}

func certipyObjectLabel(finding storage.Finding, metadata map[string]any) string {
	objectType := strings.ToLower(metadataString(metadata, "object_type"))
	label := "certificate template"
	if objectType == "ca" || objectType == "certificate_authority" {
		label = "certificate authority"
	}
	name := fallbackText(finding.AffectedObject, metadataString(metadata, "object_name"))
	return label + " " + fallbackText(name, "identity unavailable in source evidence")
}

func certipyVulnerabilityReason(metadata map[string]any, esc string) string {
	value, ok := metadata["vulnerability"]
	if !ok || value == nil {
		return ""
	}
	if values, ok := value.(map[string]any); ok {
		for key, item := range values {
			if strings.EqualFold(key, esc) {
				if text, ok := item.(string); ok {
					return summarySafeText(text)
				}
			}
		}
	}
	if text, ok := value.(string); ok {
		return summarySafeText(text)
	}
	return ""
}

func certipyConfigurationSummary(metadata map[string]any) string {
	parts := make([]string, 0, 4)
	if value, present := metadata["enabled"]; present && value != nil {
		parts = append(parts, fmt.Sprintf("Enabled=%v", value))
	}
	if value, present := metadata["manager_approval"]; present && value != nil {
		parts = append(parts, fmt.Sprintf("Manager approval=%v", value))
	}
	if value, present := metadata["authorized_signatures"]; present && value != nil {
		parts = append(parts, fmt.Sprintf("Authorized signatures=%v", value))
	}
	if owner := metadataString(metadata, "owner"); owner != "" {
		parts = append(parts, "Owner="+summarySafeText(owner))
	}
	return strings.Join(parts, "; ")
}

func formatCertipyESCCondition(finding storage.Finding, metadata map[string]any) string {
	esc := certipyESCType(finding, metadata)
	condition := fmt.Sprintf("Certipy reported %s for %s.", esc, certipyObjectLabel(finding, metadata))
	if reason := certipyVulnerabilityReason(metadata, esc); reason != "" {
		condition += " Tool-reported condition: " + reason
	}
	if configuration := certipyConfigurationSummary(metadata); configuration != "" {
		condition += " Observed configuration: " + configuration + "."
	}
	if finding.SourceExecution > 0 {
		condition += fmt.Sprintf(" Producing execution: %d.", finding.SourceExecution)
	}
	return condition
}

func certipyESCImpact(finding storage.Finding, metadata map[string]any) string {
	esc := certipyESCType(finding, metadata)
	object := certipyObjectLabel(finding, metadata)
	switch esc {
	case "ESC1":
		return fmt.Sprintf("The %s may allow an enrollee to influence certificate subject or SAN data when the reported client-authentication and enrollment conditions are satisfied. Certificate issuance, impersonation and authentication were not verified.", object)
	case "ESC2":
		return fmt.Sprintf("The %s was reported with a broad certificate purpose that may increase issuance risk when enrollment rights permit use. Certificate issuance or privilege escalation was not verified.", object)
	case "ESC3":
		return fmt.Sprintf("The %s was reported with enrollment-agent capability. This may enable requests on behalf of another subject when the required enrollment permissions and target-template conditions are satisfied; impersonation was not verified.", object)
	case "ESC4":
		return fmt.Sprintf("Certipy reported potentially dangerous control of %s. Effective ACL rights, group membership and template modification were not independently verified.", object)
	case "ESC6":
		return fmt.Sprintf("The %s was reported with a CA-wide subject/SAN-related configuration that may affect certificate identity handling. A vulnerable template combination and successful issuance were not verified.", object)
	case "ESC7":
		return fmt.Sprintf("Certipy reported potentially dangerous CA permissions on %s. The responsible principal's effective rights and any certificate-management action were not verified.", object)
	case "ESC8":
		return fmt.Sprintf("Certipy reported HTTP enrollment exposure on %s. This may increase relay risk when NTLM authentication and destination prerequisites are present; no relay or certificate issuance succeeded in this evidence.", object)
	case "ESC15":
		return fmt.Sprintf("The %s was reported with enrollee-controlled subject data and a schema-version condition associated with ESC15. The relevant issuance and application-policy prerequisites were not independently verified.", object)
	case "ESC17":
		return fmt.Sprintf("The %s was reported with enrollee-controlled subject data and server-authentication capability. A suitable enrollment path and successful server impersonation were not verified.", object)
	default:
		return fmt.Sprintf("Certipy reported %s for %s. The tool-reported configuration may present a certificate-services risk, but the required prerequisites and exploitation were not verified.", esc, object)
	}
}

func certipyESCRemediation(finding storage.Finding, metadata map[string]any) string {
	esc := certipyESCType(finding, metadata)
	object := certipyObjectLabel(finding, metadata)
	switch esc {
	case "ESC1":
		return fmt.Sprintf("Review subject/SAN supply, client-authentication EKUs, publication and enrollment permissions for %s. Require manager approval or authorized signatures where appropriate; do not infer impersonation from this record.", object)
	case "ESC2":
		return fmt.Sprintf("Review the certificate purpose/EKU and enrollment permissions for %s. Remove broad issuance capability where it is not required and validate dependent workflows.", object)
	case "ESC3":
		return fmt.Sprintf("Review enrollment-agent EKUs and permissions for %s and restrict enrollment-agent use to approved principals and target templates.", object)
	case "ESC4":
		return fmt.Sprintf("Review template owner and ACLs for %s, including unresolved group membership and deny entries. Remove unnecessary template-control permissions.", object)
	case "ESC6":
		return fmt.Sprintf("Review the CA-wide subject/SAN configuration affecting %s and restrict it to an approved operational need. Validate the associated templates separately.", object)
	case "ESC7":
		return fmt.Sprintf("Review CA management permissions affecting %s and remove unnecessary control rights from non-administrative principals.", object)
	case "ESC8":
		return fmt.Sprintf("Review HTTP enrollment protection for %s, require appropriate channel and authentication protections, and reduce unnecessary NTLM exposure without disabling safeguards.", object)
	case "ESC15":
		return fmt.Sprintf("Review schema version, subject/SAN supply and application-policy behavior for %s. Restrict enrollment and identity control to the minimum required.", object)
	case "ESC17":
		return fmt.Sprintf("Review subject/SAN supply and server-authentication EKUs for %s, then restrict enrollment permissions and publication where the configuration is not required.", object)
	default:
		return fmt.Sprintf("Review the Certipy-reported %s configuration for %s and restrict the relevant enrollment or administration permission after validating operational dependencies.", esc, object)
	}
}

func metadataStringSlice(metadata map[string]any, key string) []string {
	value, ok := metadata[key]
	if !ok {
		return nil
	}
	values, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
			result = append(result, text)
		}
	}
	return result
}

func domainPolicyDisplayValue(typ string, metadata map[string]any) string {
	switch {
	case strings.HasSuffix(typ, "weak_minimum_password_length"):
		if value := metadataInt(metadata, "minimum_password_length"); value > 0 {
			return fmt.Sprintf("minimum password length=%d", value)
		}
	case strings.HasSuffix(typ, "password_expiration_not_enforced"):
		return "maximum password age=" + fallbackText(metadataString(metadata, "maximum_password_age"), "unknown")
	case strings.HasSuffix(typ, "machine_account_creation_quota"):
		return fmt.Sprintf("machine account quota=%d", metadataInt(metadata, "machine_account_quota"))
	}
	return ""
}

func findingIndicator(finding storage.Finding) string {
	typ := strings.ToLower(finding.FindingType)
	if strings.HasPrefix(typ, "netexec_privileged_") || strings.Contains(strings.ToLower(finding.Title), "pwn3d!") {
		return warn.Render("Pwn3d!")
	}
	if strings.HasPrefix(typ, "adcs_esc_") {
		if esc := explicitCertipyESC.FindString(finding.Title + " " + finding.Description); esc != "" {
			return warn.Render(strings.ToUpper(esc))
		}
	}
	if sensitiveFindingType(typ) {
		return warn.Render("SENSITIVE EVIDENCE")
	}
	return ""
}

// sensitiveFindingType identifies detector-backed records whose existing detail
// presentation describes authentication material. It is deliberately based on
// stable finding types, not secret-looking text, so styling cannot expose or
// classify arbitrary metadata as a credential.
func sensitiveFindingType(findingType string) bool {
	typ := strings.ToLower(strings.TrimSpace(findingType))
	for _, marker := range []string{"credential", "secret", "material", "private_key", "token", "hash", "ticket"} {
		if strings.Contains(typ, marker) {
			return true
		}
	}
	return false
}

func explicitCondition(finding storage.Finding) string {
	typ := strings.ToLower(finding.FindingType)
	switch {
	case typ == "ad_account_passwd_notreqd":
		return "PASSWD_NOTREQD"
	case typ == "ad_account_dont_expire_password":
		return "DONT_EXPIRE_PASSWORD"
	case typ == "smb_signing_not_required":
		return "signing:False"
	default:
		return ""
	}
}

func findingMetadata(finding storage.Finding) map[string]any {
	metadata := make(map[string]any)
	if finding.EvidenceJSON != "" {
		_ = json.Unmarshal([]byte(finding.EvidenceJSON), &metadata)
	}
	return metadata
}

func metadataString(metadata map[string]any, key string) string {
	value, ok := metadata[key]
	if !ok {
		return ""
	}
	text, _ := value.(string)
	return text
}

func fallbackText(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func protocolFromFindingTitle(title string) string {
	for _, protocol := range []string{"SMB", "LDAP", "WINRM", "RDP", "SSH", "WMI", "FTP", "VNC", "MSSQL", "NFS"} {
		if strings.Contains(strings.ToUpper(title), protocol) {
			return protocol
		}
	}
	return ""
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
	if impact := specificFindingImpact(finding); impact != "" {
		return impact
	}
	switch {
	case typ == "ad_privileged_acl_evidence_inventory":
		return "RustHound observed direct ACL relationships affecting high-value Active Directory objects. These are configured permission relationships, not verified effective access or exploitable attack paths."
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
	if remediation := specificFindingRemediation(finding); remediation != "" {
		return remediation
	}
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
	content.WriteString(dim.Render("Select a security condition group; evidence remains in its findings.") + "\n")
	if width >= 80 {
		content.WriteString(dim.Render(fmt.Sprintf("%-34s %8s  %8s", "SUBCATEGORY", "FINDINGS", "OBSERVED")) + "\n\n")
	} else {
		content.WriteString(dim.Render("SUBCATEGORY                         F/O") + "\n\n")
	}
	for index, subcategory := range m.findingSubcategories {
		selected := index == m.findingCursor
		var line string
		if width >= 80 {
			line = fmt.Sprintf("%s%-30s %8d findings  %8d observations", selectionPrefix(selected), selectionLabel(subcategory.Name, selected), subcategory.Findings, subcategory.Observations)
		} else {
			nameWidth := max(12, width-18)
			line = fmt.Sprintf("%s%-*s %d/%d", selectionPrefix(selected), nameWidth, selectionLabel(truncateFinding(subcategory.Name, nameWidth), selected), subcategory.Findings, subcategory.Observations)
		}
		content.WriteString(line + "\n   " + dim.Render(wrapPaneText(subcategory.Description, max(20, width-7))) + "\n")
	}
	empty := len(m.findingSubcategories) == 0
	if !empty {
		index := min(max(0, m.findingCursor), len(m.findingSubcategories)-1)
		empty = m.findingSubcategories[index].Findings == 0 && m.findingSubcategories[index].Observations == 0
	}
	if empty {
		message := "No records in this category. Analysis status: NOT ASSESSED."
		if m.findingCategory == "kerberos" && len(m.findingSubcategories) > 0 && m.findingCursor < len(m.findingSubcategories) && m.findingSubcategories[m.findingCursor].Key == "kerberos_material" {
			message = "No collected Kerberos-material records are associated with this assessment. This does not establish that no material exists; the relevant collector may not have run or may have produced no qualifying records."
		}
		content.WriteString(warn.Render(message) + "\n")
	}
	content.WriteString(dim.Render("\nEnter = Open    Ctrl+S = Search    Esc = Back"))
	return paneStyle(false).Width(width).Render(content.String())
}

func (m *model) findingCategoryOverview(width int) string {
	var content strings.Builder
	content.WriteString(title.Render("PwnFlow // FINDINGS") + "\n")
	content.WriteString(dim.Render("Choose a category. Original detection records and evidence remain available.") + "\n")
	if width >= 80 {
		content.WriteString(dim.Render(fmt.Sprintf("%-31s %8s  %8s  %-12s", "CATEGORY", "FINDINGS", "OBSERVED", "HIGHEST")) + "\n")
		content.WriteString(dim.Render("────────────────────────────────────────────────────────────────────────") + "\n\n")
	} else {
		content.WriteString(dim.Render("CATEGORY                         F/O  HIGH") + "\n\n")
	}
	for index, category := range m.findingCategories {
		selected := index == m.findingCursor
		var line string
		if width >= 80 {
			line = fmt.Sprintf("%s%-27s %8d findings  %8d observations  %s", selectionPrefix(selected), selectionLabel(category.Name, selected), category.Findings, category.Observations, severityStyle(category.Highest).Render(fmt.Sprintf("%-12s", category.Highest)))
		} else {
			nameWidth := max(12, width-18)
			line = fmt.Sprintf("%s%-*s %d/%d %s", selectionPrefix(selected), nameWidth, selectionLabel(truncateFinding(category.Name, nameWidth), selected), category.Findings, category.Observations, severityStyle(category.Highest).Render(category.Highest))
		}
		content.WriteString(line + "\n")
		content.WriteString("   " + dim.Render(wrapPaneText(category.Description, max(20, width-7))) + "\n")
	}
	if len(m.findingCategories) == 0 {
		content.WriteString("No findings categories are available.\n")
	}
	content.WriteString(dim.Render("\nEnter = Open Category    Esc = Close    Ctrl+S = Search"))
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
