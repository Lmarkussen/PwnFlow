package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
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
		{"acl_replication_rights", "Replication Rights Evidence", "Observed domain-root replication-right relationships and completeness"},
	},
	"adcs": {
		{"adcs_ca", "Vulnerable Certificate Authorities", "Explicit ESC conditions reported for certificate authorities"},
		{"adcs_template", "Vulnerable Templates", "Explicit ESC conditions reported for certificate templates"},
		{"adcs_other", "Other AD CS Findings", "AD CS findings whose persisted object type is unavailable"},
	},
	"delegation": {{"delegation", "Delegation", "Delegation configurations and related observations"}},
	"active_directory": {
		{"protected_accounts", "Protected Accounts", "Observed adminCount and protected-group membership context"},
		{"tiering", "Administrative Tiering", "Conceptual Tier 0, Tier 1 and Tier 2 evidence scopes"},
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
	case strings.HasPrefix(typ, "ad_privileged_acl_"), strings.HasPrefix(typ, "ad_replication_rights_"):
		return "acl"
	case strings.HasPrefix(typ, "ad_protected_accounts_"):
		return "active_directory"
	case strings.HasPrefix(typ, "ad_tier0_"):
		return "active_directory"
	case strings.HasPrefix(typ, "ad_tier1_"), strings.HasPrefix(typ, "ad_tier2_"):
		return "active_directory"
	case strings.HasPrefix(typ, "ad_gpo_privilege_"):
		return "active_directory"
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
	case strings.HasPrefix(typ, "ad_protected_accounts_"):
		return "protected_accounts"
	case strings.HasPrefix(typ, "ad_tier0_"):
		return "tier0_context"
	case strings.HasPrefix(typ, "ad_tier1_"):
		return "tier1_context"
	case strings.HasPrefix(typ, "ad_tier2_"):
		return "tier2_context"
	case strings.HasPrefix(typ, "ad_privileged_acl_"):
		return "acl_inventory"
	case strings.HasPrefix(typ, "ad_replication_rights_"):
		return "acl_replication_rights"
	case strings.HasPrefix(typ, "ad_acl_") && strings.EqualFold(finding.Severity, "informational"):
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
		for index := range result {
			if !findingBelongsToSubcategory(category, result[index].Key, finding) {
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

func findingBelongsToSubcategory(category, subcategory string, finding storage.Finding) bool {
	if category == "active_directory" && subcategory == "tiering" {
		scope := findingTierScopeKey(finding)
		return scope == "tier0_context" || scope == "tier1_context" || scope == "tier2_context"
	}
	return findingSubcategoryKey(finding) == subcategory
}

func findingTierScopeKey(finding storage.Finding) string {
	typ := strings.ToLower(strings.TrimSpace(finding.FindingType))
	switch {
	case strings.HasPrefix(typ, "ad_tier0_"):
		return "tier0_context"
	case strings.HasPrefix(typ, "ad_tier1_"):
		return "tier1_context"
	case strings.HasPrefix(typ, "ad_tier2_"):
		return "tier2_context"
	default:
		return ""
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
	if !m.findingsLoaded {
		rows, err := m.db.ListFindings(m.ctx, m.targetID)
		if err != nil {
			m.status = "findings unavailable: " + err.Error()
			return
		}
		m.findingAllRows = append(m.findingAllRows[:0], rows...)
		m.findingCategories = buildFindingCategories(m.findingAllRows)
		m.findingsAnalysisStatus = findingsStatusLabel(m.db, m.ctx, m.targetID)
		m.findingsLoaded = true
	}
	if m.findingCategories == nil {
		m.findingCategories = buildFindingCategories(m.findingAllRows)
	}
	rows := m.findingAllRows
	m.findingViewMode = "all"
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
		if strings.HasPrefix(strings.ToLower(finding.FindingType), "ad_acl_") && !isGeneralACLInventory(finding) {
			acl = append(acl, finding)
		} else {
			other = append(other, finding)
		}
	}
	return append(groupACLFindings(acl), other...)
}

func isGeneralACLInventory(finding storage.Finding) bool {
	return strings.EqualFold(finding.FindingType, "ad_acl_evidence_inventory")
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
		finding.Title = fmt.Sprintf("AD ACL: %s → %s (%s)", principal, target, strings.Join(entry.rights, ", "))
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
		if m.findingTieringView {
			return m.findingTieringOverview(width)
		}
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
		var detail strings.Builder
		detail.WriteString(findingDetailHeader(finding, width-4) + "\n\n")
		detail.WriteString(wrapPaneText(findingCondition(finding), width-4) + "\n\n")
		detail.WriteString(findingAttributes(finding, width-4))
		if m.inlineEvidenceLoading {
			detail.WriteString("\n" + dim.Render("Loading recovered evidence…") + "\n")
		} else if m.inlineEvidence.section != "" {
			detail.WriteString("\n" + lipgloss.NewStyle().Bold(true).Render(m.inlineEvidence.section) + "\n")
			detail.WriteString(dim.Render("────────────────────────────────────────────") + "\n")
			if m.inlineEvidence.error != "" {
				detail.WriteString(warn.Render(m.inlineEvidence.error) + "\n")
			} else {
				page := max(1, m.findingPageSize()-10)
				endEvidence := min(len(m.inlineEvidence.lines), m.inlineEvidenceTop+page)
				for index := m.inlineEvidenceTop; index < endEvidence; index++ {
					detail.WriteString(m.inlineEvidence.lines[index] + "\n")
				}
				detail.WriteString(dim.Render(fmt.Sprintf("Evidence lines %d-%d of %d\n", min(m.inlineEvidenceTop+1, len(m.inlineEvidence.lines)), endEvidence, len(m.inlineEvidence.lines))))
			}
		}
		detail.WriteString("\n" + findingSection("SECURITY IMPACT", findingImpact(finding), width-4))
		detail.WriteString(findingSection("RECOMMENDED ACTION", findingRemediation(finding), width-4))
		detail.WriteString(findingSection("EVIDENCE", findingEvidenceSummary(finding), width-4))
		detail.WriteString(findingSection("LIMITATIONS", findingLimitations(finding), width-4))
		detailLines := strings.Split(detail.String(), "\n")
		detailPageSize := max(1, m.findingPageSize()-4)
		maxDetailTop := max(0, len(detailLines)-detailPageSize)
		m.findingDetailTop = min(max(0, m.findingDetailTop), maxDetailTop)
		endDetail := min(len(detailLines), m.findingDetailTop+detailPageSize)
		content.WriteString(strings.Join(detailLines[m.findingDetailTop:endDetail], "\n"))
		content.WriteString(dim.Render("\n↑/↓ Scroll    PgUp/PgDn Change Finding    ←/Esc Back    E Evidence    Q Quit"))
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
			title := truncateFinding(finding.Title, titleWidth)
			titleField := selectionLabel(title, selected) + strings.Repeat(" ", max(0, titleWidth-ansi.StringWidthWc(title)))
			objectField := truncateFinding(object, objectWidth)
			line := fmt.Sprintf("%s%s %s %s", selectionPrefix(selected), severityField, titleField, objectField)
			content.WriteString(line + "\n")
		}
	}
	content.WriteString(fmt.Sprintf("\n%d visible records (total database results are filtered)  rows %d-%d", len(m.findingRows), min(m.findingTop+1, len(m.findingRows)), min(end, len(m.findingRows))))
	content.WriteString(dim.Render("\n\n→/Enter Open    ←/Esc Back    Q Quit"))
	return paneStyle(false).Width(width).Render(content.String())
}

func (m *model) findingTieringOverview(width int) string {
	counts := map[string]int{"tier0_context": 0, "tier1_context": 0, "tier2_context": 0}
	for _, finding := range m.findingAllRows {
		if findingCategoryKey(finding) == "active_directory" {
			if scope := findingTierScopeKey(finding); scope != "" {
				counts[scope]++
			}
		}
	}
	rows := []struct {
		name, description, status string
		count                     int
	}{
		{"Tier 0 — Identity Control Plane", "Source-backed identity-control plane context", "", counts["tier0_context"]},
		{"Tier 1 — Server Administration", "Declared server-administration evidence scope", "", counts["tier1_context"]},
		{"Tier 2 — Workstation Administration", "Declared workstation-administration evidence scope", "", counts["tier2_context"]},
	}
	for index := range rows {
		if rows[index].count > 0 {
			rows[index].status = "INFORMATIONAL"
		} else {
			rows[index].status = "NOT ASSESSED"
		}
	}
	var content strings.Builder
	content.WriteString(title.Render("PwnFlow // ADMINISTRATIVE TIERING") + "\n")
	content.WriteString(dim.Render("Conceptual tier scopes; organization-specific policy is not inferred.") + "\n\n")
	for index, row := range rows {
		selected := index == m.findingCursor
		label := selectionLabel(row.name, selected)
		prefix := selectionPrefix(selected)
		if width >= 80 {
			content.WriteString(fmt.Sprintf("%s%-40s %10s %s\n", prefix, label, row.status, fmt.Sprintf("%d", row.count)))
		} else {
			content.WriteString(fmt.Sprintf("%s%s  %s\n", prefix, label, row.status))
		}
		content.WriteString("   " + dim.Render(wrapPaneText(row.description, max(20, width-7))) + "\n")
	}
	content.WriteString(dim.Render("\n→/Enter Open Tier    ←/Esc Back    Q Quit"))
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
	if isGeneralACLInventory(finding) {
		return formatGeneralACLInventoryOverview(finding)
	}
	if typ == "ad_privileged_acl_evidence_inventory" {
		return formatACLInventoryOverview(finding)
	}
	if typ == "ad_replication_rights_evidence_overview" {
		return formatReplicationRightsOverview(finding)
	}
	metadata := protectedFindingMetadata(finding)
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
	if isGeneralACLInventory(finding) {
		add("SCOPE", fallbackText(finding.AffectedObject, finding.AffectedObjectID))
	} else if target := metadataString(metadata, "target"); target != "" {
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
	if strings.EqualFold(finding.FindingType, "ad_replication_rights_evidence_overview") {
		metadata := findingMetadata(finding)
		return fmt.Sprintf("%s — Execution %d\nFull report: %s\nStructured evidence: %s", finding.SourceTool, finding.SourceExecution, shortEvidencePath(finding.ArtifactPath), fallbackText(metadataString(metadata, "structured_artifact"), "execution-associated replication-rights JSON"))
	}
	if strings.EqualFold(finding.FindingType, "ad_privileged_acl_evidence_inventory") {
		metadata := findingMetadata(finding)
		structured := metadataString(metadata, "structured_artifact")
		if strings.Contains(structured, "<execution-id>") {
			structured = ""
		}
		if structured == "" {
			structured = shortEvidencePath(finding.ArtifactPath)
			if strings.EqualFold(structured, shortEvidencePath(metadataString(metadata, "source_artifact"))) {
				structured = ""
			}
		}
		return fmt.Sprintf("%s — Execution %d\nSource artifacts: %s\nFull report: %s\nStructured inventory: %s", finding.SourceTool, finding.SourceExecution, aclEvidenceNames(metadata), fallbackText(metadataString(metadata, "human_report"), "AD_PRIVILEGED_ACL_EVIDENCE.txt"), fallbackText(structured, "execution-associated ACL inventory JSON"))
	}
	if isGeneralACLInventory(finding) {
		metadata := findingMetadata(finding)
		return fmt.Sprintf("%s — Execution %d\nFull report: %s\nStructured inventory: %s", fallbackText(finding.SourceTool, "RustHound-CE"), finding.SourceExecution, fallbackText(shortEvidencePath(metadataString(metadata, "human_report")), shortEvidencePath(finding.ArtifactPath)), fallbackText(shortEvidencePath(metadataString(metadata, "structured_artifact")), "execution-associated ACL inventory JSON"))
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
	if strings.EqualFold(finding.FindingType, "ad_gpo_privilege_relationship_evidence") {
		metadata := findingMetadata(finding)
		return fmt.Sprintf("%s — Execution %d\nFull report: %s\nStructured evidence: %s", finding.SourceTool, finding.SourceExecution, shortEvidencePath(finding.ArtifactPath), fallbackText(metadataString(metadata, "structured_artifact"), "execution-associated GPO privilege JSON"))
	}
	if strings.EqualFold(finding.FindingType, "ad_protected_accounts_admincount_evidence") {
		metadata := findingMetadata(finding)
		return fmt.Sprintf("%s — Execution %d\nFull report: %s\nStructured evidence: %s", finding.SourceTool, finding.SourceExecution, shortEvidencePath(finding.ArtifactPath), fallbackText(metadataString(metadata, "structured_artifact"), "execution-associated protected-accounts JSON"))
	}
	return fmt.Sprintf("%s · Execution %d\n%s %s", finding.SourceTool, finding.SourceExecution, finding.ArtifactPath, finding.ArtifactRef)
}

func shortEvidencePath(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.LastIndexAny(value, "/\\"); index >= 0 {
		return value[index+1:]
	}
	return value
}

func aclEvidenceNames(metadata map[string]any) string {
	seen := map[string]bool{}
	var names []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if index := strings.LastIndexAny(value, "/\\"); index >= 0 {
			value = value[index+1:]
		}
		if !seen[value] {
			seen[value] = true
			names = append(names, value)
		}
	}
	add(metadataString(metadata, "source_artifact"))
	for _, key := range []string{"relationship_overview", "membership_context"} {
		values, _ := metadata[key].([]any)
		for _, raw := range values {
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			add(metadataString(item, "artifact"))
			add(metadataString(item, "acl_artifact"))
			for _, artifact := range metadataStringSlice(item, "membership_artifacts") {
				add(artifact)
			}
		}
	}
	if len(names) == 0 {
		return "source artifact unavailable"
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
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
	if strings.EqualFold(finding.FindingType, "ad_protected_accounts_admincount_evidence") {
		return "adminCount is an observed attribute and does not prove current protected membership. Membership context and AdminSDHolder identity are source-backed observations; effective protection, complete security descriptors and SDProp application were not verified."
	}
	if strings.EqualFold(finding.FindingType, "ad_replication_rights_evidence_overview") {
		return "Effective replication authorization and DCSync capability were not evaluated. NOT OBSERVED means no matching supported relationship was found in the inspected evidence; it does not mean denied or absent. Allow/deny precedence, inheritance applicability, object-specific restrictions, group scope, SIDHistory, cross-domain authorization and token semantics remain unknown."
	}
	if strings.EqualFold(finding.FindingType, "ad_gpo_privilege_relationship_evidence") {
		metadata := findingMetadata(finding)
		lines := []string{"Effective GPO authorization, GPC/SYSVOL write access and client-side policy application were not evaluated."}
		if mismatch, ok := metadata["snapshot_mismatch"].(bool); ok && mismatch {
			lines = append(lines, "ACL and configured-link evidence are cross-snapshot identity context, not proof of temporal consistency.")
		}
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
		if coverage := metadataString(metadata, "membership_coverage"); coverage != "" {
			lines = append(lines, "Membership context coverage: "+coverage+".")
		}
		if count := metadataInt(metadata, "unresolved_membership_paths"); count > 0 {
			lines = append(lines, fmt.Sprintf("%d membership paths contain unresolved identities.", count))
		}
		if count := metadataInt(metadata, "omitted_membership_paths"); count > 0 {
			lines = append(lines, fmt.Sprintf("%d membership paths were omitted by bounded processing.", count))
			lines = append(lines, "The retained preview and report are bounded; omitted paths are not verified permissions.")
		}
		lines = append(lines, "Effective permissions, group-derived rights, deny precedence and exploitability were not evaluated.")
		if limitations := metadataStringSlice(metadata, "membership_limitations"); len(limitations) > 0 {
			lines = append(lines, "Membership limitations: "+strings.Join(limitations, "; "))
		}
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

func formatReplicationRightsOverview(finding storage.Finding) string {
	metadata := findingMetadata(finding)
	var b strings.Builder
	fmt.Fprintf(&b, "RustHound execution %d recorded replication-related ACL relationships.\nCoverage: %s\nDistinct membership paths shown: %d\nMembership evidence records retained: %d\nMembership paths omitted before materialization: %d\nEffective replication authorization: NOT VERIFIED\n", finding.SourceExecution, fallbackText(metadataString(metadata, "coverage"), "unknown"), metadataInt(metadata, "membership_paths_shown"), metadataInt(metadata, "membership_evidence_records"), metadataInt(metadata, "membership_paths_omitted"))
	roots, _ := metadata["domain_roots"].([]any)
	if len(roots) == 0 {
		return b.String() + "\nNo authoritative domain-root replication-right relationships were observed in this execution."
	}
	for _, rawRoot := range roots {
		root, ok := rawRoot.(map[string]any)
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "\nDOMAIN ROOT\n%s [%s]\n", fallbackText(metadataString(root, "name"), metadataString(root, "id")), metadataString(root, "id"))
		principals, _ := root["principals"].([]any)
		for _, rawPrincipal := range principals {
			principal, ok := rawPrincipal.(map[string]any)
			if !ok {
				continue
			}
			fmt.Fprintf(&b, "\nPrincipal: %s [%s] (%s)\n", fallbackText(metadataString(principal, "name"), metadataString(principal, "id")), metadataString(principal, "id"), fallbackText(metadataString(principal, "type"), "unknown"))
			rights, _ := principal["rights"].([]any)
			for _, rawRight := range rights {
				right, ok := rawRight.(map[string]any)
				if !ok {
					continue
				}
				fmt.Fprintf(&b, "  %-28s %s\n", metadataString(right, "right"), strings.ToUpper(metadataString(right, "status")))
			}
			members, _ := principal["membership_context"].([]any)
			if len(members) == 0 {
				b.WriteString("  Membership context: No membership context observed in this execution.\n")
			} else {
				b.WriteString("  Membership context:\n")
				for _, rawMember := range members {
					member, ok := rawMember.(map[string]any)
					if !ok {
						continue
					}
					b.WriteString("    - " + fallbackText(metadataString(member, "member_name"), metadataString(member, "member_id")) + " → MemberOf: " + metadataString(member, "acl_principal_name") + "\n")
				}
			}
		}
	}
	b.WriteString("\nLIMITATIONS\nEffective rights were not calculated. NOT OBSERVED does not mean denied or absent. Membership context is informational.\n")
	return b.String()
}

func formatACLInventoryOverview(finding storage.Finding) string {
	metadata := findingMetadata(finding)
	var b strings.Builder
	fmt.Fprintf(&b, "RustHound execution %d contains observed direct ACL relationships affecting high-value Active Directory objects.\nStatus: %s\nHigh-value targets: %d\nObserved relationships: %d\nMembership edges: %d\nDirect membership paths: %d\nNested membership paths: %d\nMembership coverage: %s\n", finding.SourceExecution, fallbackText(metadataString(metadata, "status"), "unknown"), metadataInt(metadata, "high_value_targets"), metadataInt(metadata, "normalized_relationships"), metadataInt(metadata, "membership_edges"), metadataInt(metadata, "direct_membership_paths"), metadataInt(metadata, "nested_membership_paths"), fallbackText(metadataString(metadata, "membership_coverage"), "unknown"))
	relationships, _ := metadata["relationship_overview"].([]any)
	if len(relationships) == 0 {
		b.WriteString("\nNo bounded relationship overview is available; inspect the full report for retained evidence.")
	} else {
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
	}
	membership, _ := metadata["membership_context"].([]any)
	if len(membership) == 0 {
		b.WriteString("\nNo membership context observed in this collection.")
		return b.String()
	}
	type membershipGroup struct {
		targetName, targetID, targetClass      string
		permission, principalName, principalID string
		paths                                  []map[string]any
	}
	groups := make(map[string]*membershipGroup)
	for _, raw := range membership {
		context, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		key := strings.Join([]string{metadataString(context, "target_id"), metadataString(context, "permission"), metadataString(context, "acl_principal_id")}, "\x00")
		group := groups[key]
		if group == nil {
			group = &membershipGroup{targetName: metadataString(context, "target_name"), targetID: metadataString(context, "target_id"), targetClass: metadataString(context, "target_class"), permission: metadataString(context, "permission"), principalName: metadataString(context, "acl_principal_name"), principalID: metadataString(context, "acl_principal_id")}
			groups[key] = group
		}
		group.paths = append(group.paths, context)
	}
	ordered := make([]*membershipGroup, 0, len(groups))
	for _, group := range groups {
		ordered = append(ordered, group)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		left, right := ordered[i], ordered[j]
		for _, pair := range [][2]string{{left.targetName, right.targetName}, {left.targetID, right.targetID}, {left.permission, right.permission}, {left.principalName, right.principalName}, {left.principalID, right.principalID}} {
			if pair[0] != pair[1] {
				return pair[0] < pair[1]
			}
		}
		return false
	})
	totalMembershipPaths := metadataInt(metadata, "direct_membership_paths") + metadataInt(metadata, "nested_membership_paths")
	omittedMembershipPaths := metadataInt(metadata, "omitted_membership_paths")
	membershipAdditional := totalMembershipPaths - omittedMembershipPaths - len(membership)
	if membershipAdditional < 0 {
		membershipAdditional = 0
	}
	fmt.Fprintf(&b, "\nOBSERVED MEMBERSHIP CONTEXT\nShowing %d grouped relationships; %d additional retained paths remain in the full report.\n", len(ordered), membershipAdditional)
	if omittedMembershipPaths > 0 {
		fmt.Fprintf(&b, "Bounded processing omitted %d paths before materialization; those paths are not available in the report.\n", omittedMembershipPaths)
	}
	for _, group := range ordered {
		fmt.Fprintf(&b, "\nTarget: %s [%s]\n", fallbackText(group.targetName, group.targetID), group.targetID)
		if group.targetClass != "" {
			fmt.Fprintf(&b, "Type/classification: %s\n", group.targetClass)
		}
		fmt.Fprintf(&b, "  Permission: %s\n  ACL principal: %s [%s]\n  Observed members:\n", group.permission, fallbackText(group.principalName, group.principalID), group.principalID)
		for _, context := range group.paths {
			fmt.Fprintf(&b, "    - %s\n      Path: %s\n      Classification: %s\n", fallbackText(metadataString(context, "member_name"), metadataString(context, "member_id")), formatMembershipContextPath(context), fallbackText(metadataString(context, "classification"), "observed_membership_context"))
		}
		fmt.Fprintf(&b, "  Interpretation: Observed membership paths connect the listed principals to the group named in this ACL.\n  Effective permission: NOT VERIFIED\n")
	}
	return b.String()
}

func formatGeneralACLInventoryOverview(finding storage.Finding) string {
	metadata := findingMetadata(finding)
	var b strings.Builder
	fmt.Fprintf(&b, "RustHound execution %d recorded an aggregate Active Directory ACL evidence inventory.\n\nSUMMARY\nObserved ACL records: %s\nRetained records: %s\nExplicit ACEs: %s\nInherited ACEs: %s\nUnknown decisions: %s\n", finding.SourceExecution, metadataCount(metadata, "source_supported_ace_count"), metadataCount(metadata, "retained_ace_count"), metadataCount(metadata, "explicit_count"), metadataCount(metadata, "inherited_count"), metadataCount(metadata, "unknown_decision_count"))
	b.WriteString("\nINTERPRETATION\nThe inventory preserves observed Active Directory ACL relationships. These records do not independently establish effective authorization, misconfiguration or exploitable attack paths.\n")
	if examples, ok := metadata["examples"].([]any); ok && len(examples) > 0 {
		b.WriteString("\nREPRESENTATIVE OBSERVED RELATIONSHIPS\n")
		for index, raw := range examples {
			if index >= 12 {
				break
			}
			record, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			principal := fallbackText(metadataString(record, "principal_name"), metadataString(record, "principal_id"))
			target := fallbackText(metadataString(record, "target_name"), metadataString(record, "target_id"))
			permission := fallbackText(metadataString(record, "permission"), "UNKNOWN")
			fmt.Fprintf(&b, "  %s → %s → %s\n", principal, permission, target)
		}
		if retained, ok := metadata["retained_ace_count"].(float64); ok && int(retained) > len(examples) {
			fmt.Fprintf(&b, "  Additional retained relationships are available in the full report (%d more).\n", int(retained)-len(examples))
		}
	} else {
		b.WriteString("\nNo representative relationships were retained in the bounded preview.\n")
	}
	return b.String()
}

func metadataCount(metadata map[string]any, key string) string {
	if _, ok := metadata[key]; !ok {
		return "UNKNOWN"
	}
	return strconv.Itoa(metadataInt(metadata, key))
}

func formatMembershipContextPath(context map[string]any) string {
	parts := []string{fallbackText(metadataString(context, "member_name"), metadataString(context, "member_id"))}
	path, _ := context["group_path"].([]any)
	for _, raw := range path {
		hop, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		parts = append(parts, "MemberOf: "+fallbackText(metadataString(hop, "name"), metadataString(hop, "id")))
	}
	return strings.Join(parts, " -> ")
}

func formatMembershipContextEvidence(context map[string]any) string {
	refs := metadataStringSlice(context, "membership_refs")
	artifacts := metadataStringSlice(context, "membership_artifacts")
	values := make([]string, 0, len(refs))
	for index, ref := range refs {
		if index < len(artifacts) && artifacts[index] != "" {
			values = append(values, artifacts[index]+"#"+ref)
		} else {
			values = append(values, ref)
		}
	}
	return strings.Join(values, ", ")
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
		count := metadataInt(metadata, "record_count")
		scope := "The original evidence artifact may contain additional qualifying records."
		if count > 0 {
			return fmt.Sprintf("NetExec recorded %s associated with %s (%d source record(s) for this principal). This Finding represents one principal; %s Secret material is intentionally not displayed.", kind, principal, count, scope)
		}
		return fmt.Sprintf("NetExec recorded %s associated with %s. %s Secret material is intentionally not displayed.", kind, principal, scope)
	case typ == "ad_user_description_keyword_observed":
		principal := fallbackText(metadataString(metadata, "principal"), fallbackText(finding.AffectedObject, "principal identity unavailable in source evidence"))
		attribute := fallbackText(metadataString(metadata, "attribute"), "account information")
		keyword := fallbackText(metadataString(metadata, "keyword"), "credential-related language")
		return fmt.Sprintf("NetExec observed the keyword %q in the %s attribute for %s. The keyword is not proof that a credential was disclosed.", keyword, attribute, principal)
	case strings.HasPrefix(typ, "adcs_esc_"):
		return formatCertipyESCCondition(finding, metadata)
	case typ == "gpo_evidence_inventory":
		return formatGPOEvidenceCondition(metadata, finding)
	case typ == "ad_gpo_privilege_relationship_evidence":
		return formatGPOPrivilegeCondition(metadata, finding)
	case typ == "ad_protected_accounts_admincount_evidence":
		return formatProtectedAccountsCondition(metadata, finding)
	case typ == "ad_tier0_context_evidence":
		return formatTier0ContextCondition(metadata, finding)
	case typ == "ad_tier1_context_evidence" || typ == "ad_tier2_context_evidence":
		return formatTierContextCondition(finding)
	}
	return ""
}

func formatProtectedAccountsCondition(metadata map[string]any, finding storage.Finding) string {
	lines := []string{"ADMINCOUNT OBSERVATIONS"}
	if execution := finding.SourceExecution; execution > 0 {
		lines = append(lines, fmt.Sprintf("RustHound execution: %d", execution))
	}
	if value := metadataInt(metadata, "admincount_users"); value >= 0 {
		lines = append(lines, fmt.Sprintf("Users with adminCount=true: %d", value))
	}
	if value := metadataInt(metadata, "admincount_groups"); value >= 0 {
		lines = append(lines, fmt.Sprintf("Groups with adminCount=true: %d", value))
	}
	if value := metadataInt(metadata, "membership_paths"); value >= 0 {
		lines = append(lines, fmt.Sprintf("Observed membership paths retained: %d", value))
	}
	appendProtectedPreview(&lines, "Users with adminCount=true", metadata["admincount_user_examples"])
	appendProtectedPreview(&lines, "Groups with adminCount=true", metadata["admincount_group_examples"])
	if paths, ok := metadata["membership_examples"].([]any); ok && len(paths) > 0 {
		lines = append(lines, "PROTECTED-GROUP MEMBERSHIP")
		for index, raw := range paths {
			if index >= 8 {
				lines = append(lines, "  Additional paths are available through E.")
				break
			}
			path, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			values, _ := path["path"].([]any)
			names := make([]string, 0, len(values))
			for _, value := range values {
				if name, ok := value.(string); ok {
					names = append(names, name)
				}
			}
			classification := fallbackText(stringValue(path["classification"]), "observed")
			if len(names) > 0 {
				lines = append(lines, fmt.Sprintf("  %s (%s)", strings.Join(names, " → "), classification))
			}
		}
	}
	if differences, ok := metadata["attribute_membership_differences"].([]any); ok && len(differences) > 0 {
		lines = append(lines, "ATTRIBUTE / MEMBERSHIP DIFFERENCES")
		for index, raw := range differences {
			if index >= 6 {
				lines = append(lines, "  Additional differences are available through E.")
				break
			}
			object, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			lines = append(lines, fmt.Sprintf("  %s — adminCount=%s; membership=%s (not a protection conclusion)", fallbackText(stringValue(object["name"]), stringValue(object["id"])), fallbackText(stringValue(object["admin_count"]), "unknown"), fallbackText(stringValue(object["membership"]), "unknown")))
		}
	}
	if holder, ok := metadata["admin_sdholder"].(map[string]any); ok {
		lines = append(lines, "ADMINSDHOLDER")
		lines = append(lines, "  Object: "+fallbackText(stringValue(holder["distinguished_name"]), fallbackText(stringValue(holder["name"]), stringValue(holder["id"]))))
		if aces, ok := holder["aces"].([]any); ok {
			lines = append(lines, fmt.Sprintf("  Observed ACEs: %d", len(aces)))
			for index, raw := range aces {
				if index >= 3 {
					lines = append(lines, "  Additional ACEs are available through E.")
					break
				}
				ace, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				lines = append(lines, fmt.Sprintf("    %s → %s", fallbackText(stringValue(ace["principal"]), stringValue(ace["principal_id"])), fallbackText(stringValue(ace["rights"]), "right unavailable")))
			}
		}
		lines = append(lines, "  Complete security descriptor: NOT VERIFIED", "  SDProp application: NOT VERIFIED")
	}
	if unavailable := metadataString(metadata, "identity_preview_unavailable"); unavailable != "" {
		lines = append(lines, "Identity preview unavailable: "+unavailable+". Full evidence remains available through E.")
	}
	if value := metadataInt(metadata, "omitted_membership_paths"); value > 0 {
		lines = append(lines, fmt.Sprintf("Membership paths omitted by bounds: %d", value))
	}
	lines = append(lines, "Effective protection: NOT VERIFIED", "AdminSDHolder descriptor completeness and SDProp application: NOT VERIFIED")
	return strings.Join(lines, "\n")
}

func formatTier0ContextCondition(metadata map[string]any, finding storage.Finding) string {
	lines := []string{"TIER 0 ADMINISTRATIVE CONTEXT EVIDENCE OVERVIEW", "INFORMATIONAL"}
	if finding.SourceExecution > 0 {
		lines = append(lines, fmt.Sprintf("SOURCE: RustHound-CE — Execution %d", finding.SourceExecution))
	}
	if domain := metadataString(metadata, "domain"); domain != "" {
		lines = append(lines, "DOMAIN CONTROL CONTEXT", "  Domain: "+domain)
	}
	if controllers, ok := metadata["domain_controllers"].([]any); ok && len(controllers) > 0 {
		lines = append(lines, "  Domain Controllers:")
		for _, raw := range controllers {
			controller, ok := raw.(map[string]any)
			if ok {
				lines = append(lines, "    "+fallbackText(stringValue(controller["name"]), stringValue(controller["id"])))
			}
		}
	}
	if groups, ok := metadata["tier0_groups"].([]any); ok && len(groups) > 0 {
		lines = append(lines, "TIER 0-ASSOCIATED GROUPS")
		for index, raw := range groups {
			if index >= 12 {
				lines = append(lines, "  Additional Tier 0 groups are available through E.")
				break
			}
			group, ok := raw.(map[string]any)
			if ok {
				lines = append(lines, "  "+fallbackText(stringValue(group["name"]), stringValue(group["id"]))+" ("+fallbackText(stringValue(group["role"]), "validated identity-control role")+")")
			}
		}
	}
	if paths, ok := metadata["membership_paths"].([]any); ok && len(paths) > 0 {
		lines = append(lines, "OBSERVED MEMBERSHIP")
		for index, raw := range paths {
			if index >= 12 {
				lines = append(lines, "  Additional membership paths are available through E.")
				break
			}
			path, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			values, _ := path["path"].([]any)
			names := make([]string, 0, len(values))
			for _, value := range values {
				if name, ok := value.(string); ok {
					names = append(names, name)
				}
			}
			if len(names) > 0 {
				lines = append(lines, "  "+strings.Join(names, " → ")+" ("+fallbackText(stringValue(path["classification"]), "observed")+")")
			}
		}
	}
	if acls, ok := metadata["acl_relationships"].([]any); ok && len(acls) > 0 {
		lines = append(lines, "ACL CONFIGURATION CONTEXT")
		for index, raw := range acls {
			if index >= 8 {
				lines = append(lines, "  Additional ACL relationships are available through E.")
				break
			}
			acl, ok := raw.(map[string]any)
			if ok {
				lines = append(lines, fmt.Sprintf("  %s → %s → %s", fallbackText(stringValue(acl["principal_name"]), stringValue(acl["principal_id"])), stringValue(acl["permission"]), fallbackText(stringValue(acl["target_name"]), stringValue(acl["target_id"]))))
			}
		}
		lines = append(lines, "  Effective authorization: NOT VERIFIED")
	}
	if roots, ok := metadata["replication_rights"].([]any); ok && len(roots) > 0 {
		lines = append(lines, "REPLICATION RIGHTS")
		shown := 0
		for _, rawRoot := range roots {
			root, ok := rawRoot.(map[string]any)
			if !ok {
				continue
			}
			principals, _ := root["principals"].([]any)
			for _, rawPrincipal := range principals {
				principal, ok := rawPrincipal.(map[string]any)
				if !ok {
					continue
				}
				rights, _ := principal["rights"].([]any)
				for _, rawRight := range rights {
					if shown >= 8 {
						break
					}
					right, ok := rawRight.(map[string]any)
					if ok {
						lines = append(lines, fmt.Sprintf("  %s — %s: %s", fallbackText(stringValue(principal["name"]), stringValue(principal["id"])), stringValue(right["right"]), strings.ToUpper(stringValue(right["status"]))))
						shown++
					}
				}
			}
		}
		lines = append(lines, "  DCSync capability: NOT VERIFIED")
	}
	if users, ok := metadata["admincount_users"].([]any); ok && len(users) > 0 {
		lines = append(lines, "ADMINCOUNT / ADMINSDHOLDER")
		lines = append(lines, fmt.Sprintf("  Tier 0-associated adminCount=true users: %d", len(users)))
	}
	if holder, ok := metadata["admin_sd_holder"].(map[string]any); ok {
		lines = append(lines, "  AdminSDHolder: "+fallbackText(stringValue(holder["distinguished_name"]), stringValue(holder["id"])))
		if aces, ok := holder["aces"].([]any); ok {
			lines = append(lines, fmt.Sprintf("  Observed ACEs: %d", len(aces)))
		}
	}
	lines = append(lines, "LIMITATIONS", "  Tier 1/2 authority: NOT ASSESSED", "  Cross-tier violations: NOT ESTABLISHED", "  Effective administrative rights: NOT VERIFIED")
	return strings.Join(lines, "\n")
}

func formatTierContextCondition(finding storage.Finding) string {
	var metadata map[string]any
	if json.Unmarshal([]byte(finding.EvidenceJSON), &metadata) != nil {
		return "Administrative tier evidence is unavailable in the stored observation. See E for the source report."
	}
	tier := metadataInt(metadata, "tier")
	if tier == 0 {
		if strings.Contains(strings.ToLower(finding.FindingType), "tier2") {
			tier = 2
		} else {
			tier = 1
		}
	}
	lines := []string{fmt.Sprintf("TIER %d ADMINISTRATIVE CONTEXT EVIDENCE OVERVIEW", tier), "INFORMATIONAL"}
	if finding.SourceExecution > 0 {
		lines = append(lines, "SOURCE", fmt.Sprintf("  RustHound-CE — Execution %d", finding.SourceExecution))
	}
	if policy := stringValue(metadata["policy_id"]); policy != "" {
		lines = append(lines, "TIER POLICY", "  Policy: "+policy, "  Status: DECLARED / EXTERNALLY DOCUMENTED")
	}
	if groups, ok := metadata["declared_groups"].([]any); ok && len(groups) > 0 {
		lines = append(lines, "OBSERVED DIRECTORY IDENTITIES")
		for i, raw := range groups {
			if i >= 12 {
				lines = append(lines, "  Additional groups are available through E.")
				break
			}
			if g, ok := raw.(map[string]any); ok {
				lines = append(lines, "  Group: "+fallbackText(stringValue(g["name"]), stringValue(g["id"])))
			}
		}
	}
	if paths, ok := metadata["membership_paths"].([]any); ok && len(paths) > 0 {
		lines = append(lines, "OBSERVED MEMBERSHIP")
		for i, raw := range paths {
			if i >= 16 {
				lines = append(lines, "  Additional membership paths are available through E.")
				break
			}
			if p, ok := raw.(map[string]any); ok {
				vals, _ := p["path"].([]any)
				names := make([]string, 0, len(vals))
				for _, v := range vals {
					if s, ok := v.(string); ok {
						names = append(names, s)
					}
				}
				if len(names) > 0 {
					lines = append(lines, "  "+strings.Join(names, " → ")+" ("+fallbackText(stringValue(p["classification"]), "observed")+")")
				}
			}
		}
	}
	if targets, ok := metadata["targets"].([]any); ok && len(targets) > 0 {
		lines = append(lines, "DECLARED ADMINISTRATIVE SCOPE")
		for _, raw := range targets {
			if t, ok := raw.(map[string]any); ok {
				d, _ := t["declared"].(map[string]any)
				lines = append(lines, "  Target: "+fallbackText(stringValue(d["name"]), stringValue(d["ip"]))+" ("+fallbackText(stringValue(t["status"]), "unresolved")+")")
			}
		}
	}
	lines = append(lines, "ADMINISTRATIVE ACCESS VERIFICATION", "  Host-local Administrators membership: NOT VERIFIED", "  Effective administrative authorization: NOT VERIFIED", "LIMITATIONS", "  Declared tier is not verified host authority.", "  Cross-tier policy violation: NOT ESTABLISHED.")
	return strings.Join(lines, "\n")
}

func appendProtectedPreview(lines *[]string, heading string, value any) {
	objects, ok := value.([]any)
	if !ok || len(objects) == 0 {
		return
	}
	*lines = append(*lines, heading)
	for index, raw := range objects {
		if index >= 8 {
			*lines = append(*lines, "  Additional entries are available through E.")
			break
		}
		object, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		*lines = append(*lines, "  "+fallbackText(stringValue(object["name"]), stringValue(object["id"])))
	}
}

func formatGPOPrivilegeCondition(metadata map[string]any, finding storage.Finding) string {
	lines := []string{"Observed GPO ACL and configured-link context:"}
	if status := metadataString(metadata, "status"); status != "" {
		lines = append(lines, "Status: "+status)
	}
	if mismatch, ok := metadata["snapshot_mismatch"].(bool); ok && mismatch {
		lines = append(lines, "Snapshot caveat: ACL and GPO link evidence came from separate snapshots.")
	}
	if gpos, ok := metadata["gpos"].([]any); ok {
		for index, raw := range gpos {
			if index >= 8 {
				lines = append(lines, "Additional GPO relationships are available in the full report.")
				break
			}
			gpo, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			name := fallbackText(stringValue(gpo["display_name"]), "GPO identity unavailable")
			guid := stringValue(gpo["gpo_guid"])
			lines = append(lines, fmt.Sprintf("GPO: %s [%s]", name, guid))
			if acls, ok := gpo["observed_acl_relationships"].([]any); ok {
				for j, rawACL := range acls {
					if j >= 6 {
						lines = append(lines, "  Additional ACL relationships are in the full report.")
						break
					}
					acl, ok := rawACL.(map[string]any)
					if !ok {
						continue
					}
					lines = append(lines, fmt.Sprintf("  Principal: %s | Permission: %s | Effective permission: NOT VERIFIED", fallbackText(stringValue(acl["principal_name"]), stringValue(acl["principal_id"])), stringValue(acl["permission"])))
				}
			}
			if links, ok := gpo["configured_links"].([]any); ok {
				for _, rawLink := range links {
					link, ok := rawLink.(map[string]any)
					if !ok {
						continue
					}
					lines = append(lines, "  Configured link: "+fallbackText(stringValue(link["target_container_dn"]), stringValue(link["source_dn"])))
				}
			}
		}
	}
	if len(lines) == 1 {
		lines = append(lines, fallbackText(finding.Description, "No bounded GPO relationship details were retained."))
	}
	lines = append(lines, "Policy application: NOT VERIFIED.")
	return strings.Join(lines, "\n")
}

func stringValue(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func specificFindingImpact(finding storage.Finding) string {
	typ := strings.ToLower(finding.FindingType)
	metadata := findingMetadata(finding)
	switch {
	case typ == "ad_privileged_acl_evidence_inventory":
		return "RustHound observed ACL entries referencing groups with collected member relationships. These observations identify principals and objects that warrant permission review, but do not establish effective authorization or exploitability."
	case typ == "ad_replication_rights_evidence_overview":
		return "RustHound recorded ACL relationships corresponding to Active Directory replication-related rights on the identified domain object. These observations identify principals and permissions that warrant authorization review, but do not establish effective replication access or DCSync capability."
	case typ == "ad_gpo_privilege_relationship_evidence":
		return "RustHound observed supported ACL relationships for the identified GPOs, while separately collected policy metadata supplied configured-link context. The GUID correlation is evidence context only; effective GPO authorization, SYSVOL access and policy application were not verified."
	case typ == "ad_protected_accounts_admincount_evidence":
		return "The collected adminCount attributes and protected-group membership relationships identify accounts and groups that warrant administrative protection review. Differences may reflect historical membership or incomplete collection, but do not establish current SDProp protection or misconfiguration."
	case typ == "ad_tier0_context_evidence":
		return "The collected directory evidence identifies accounts, groups and configured relationships associated with Active Directory's identity-control plane. These relationships support privilege-boundary review but do not establish effective administrative authorization, compromise or tier-policy violations."
	case typ == "ad_tier1_context_evidence" || typ == "ad_tier2_context_evidence":
		return "The collected directory memberships and declared administrative scope identify server or workstation administration context for review. They do not establish host-local administrator membership, effective authorization or a tier-policy violation."
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
	case typ == "ad_privileged_acl_evidence_inventory":
		return "Review the listed ACL principals and permissions on the identified AD objects. Confirm whether each group should hold the observed rights, then validate effective permissions with approved AD administration tools before changing access controls."
	case typ == "ad_replication_rights_evidence_overview":
		return "Review the observed replication-related permissions on the identified domain root. Confirm which principals require those rights, validate effective permissions using approved AD administration methods, and remove unnecessary grants only after verifying their operational purpose."
	case typ == "ad_gpo_privilege_relationship_evidence":
		return "Review the observed GPO ACL principal/right combinations and configured links. Validate effective GPC and SYSVOL permissions, intended policy scope and actual processing with approved AD administration tools before changing policy access."
	case typ == "ad_protected_accounts_admincount_evidence":
		return "Review the observed adminCount values, protected-group membership paths and AdminSDHolder evidence. Validate current membership, complete security descriptors and SDProp behavior with approved AD administration tools before making access-control changes."
	case typ == "ad_tier0_context_evidence":
		return "Review the listed Tier 0-associated identities, membership paths, ACL relationships and replication-right configuration. Validate intended administrative roles and effective permissions with approved AD administration methods before drawing security conclusions or changing privileges."
	case typ == "ad_tier1_context_evidence" || typ == "ad_tier2_context_evidence":
		return "Review the declared tier assignments and observed membership paths. Validate host-local Administrators membership and effective access with approved administration methods before changing privileges."
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

func protectedFindingMetadata(finding storage.Finding) map[string]any {
	metadata := findingMetadata(finding)
	if strings.ToLower(finding.FindingType) != "ad_protected_accounts_admincount_evidence" || metadata["admincount_user_examples"] != nil {
		return metadata
	}
	path := metadataString(metadata, "structured_artifact")
	if path == "" {
		metadata["identity_preview_unavailable"] = "structured artifact reference is missing"
		return metadata
	}
	data, err := os.ReadFile(path)
	if err != nil {
		metadata["identity_preview_unavailable"] = "referenced structured artifact is unavailable"
		return metadata
	}
	var report map[string]any
	if err := json.Unmarshal(data, &report); err != nil {
		metadata["identity_preview_unavailable"] = "referenced structured artifact is invalid"
		return metadata
	}
	sourceExecution, ok := report["source_execution_id"].(float64)
	if !ok || int64(sourceExecution) != finding.SourceExecution {
		metadata["identity_preview_unavailable"] = "structured artifact execution does not match the Finding execution"
		return metadata
	}
	users := protectedMetadataAdminExamples(report["users"])
	groups := protectedMetadataAdminExamples(report["groups"])
	metadata["admincount_user_examples"] = users
	metadata["admincount_group_examples"] = groups
	metadata["membership_examples"] = report["membership_paths"]
	metadata["attribute_membership_differences"] = protectedMetadataDifferences(report)
	if holder, ok := report["admin_sd_holder"]; ok {
		metadata["admin_sdholder"] = holder
	}
	metadata["identity_preview_source"] = path
	return metadata
}

func protectedMetadataAdminExamples(value any) []any {
	objects, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]any, 0, len(objects))
	for _, raw := range objects {
		object, ok := raw.(map[string]any)
		if ok && stringValue(object["admin_count"]) == "true" {
			result = append(result, object)
		}
	}
	return result
}

func protectedMetadataDifferences(report map[string]any) []any {
	var result []any
	for _, key := range []string{"users", "groups"} {
		objects, ok := report[key].([]any)
		if !ok {
			continue
		}
		for _, raw := range objects {
			object, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			adminCount := stringValue(object["admin_count"])
			membership := stringValue(object["membership"])
			if adminCount == "true" && membership == "not_observed" || adminCount == "false" && membership == "observed" || adminCount == "unknown" {
				result = append(result, object)
			}
		}
	}
	return result
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
	content.WriteString(dim.Render("\n\nUp/Down PageUp/PageDown   ←/Esc Back to Finding   Q Quit"))
	return paneStyle(false).Width(width).Render(content.String())
}

func findingImpact(finding storage.Finding) string {
	typ := strings.ToLower(finding.FindingType)
	if impact := specificFindingImpact(finding); impact != "" {
		return impact
	}
	switch {
	case isGeneralACLInventory(finding):
		return "RustHound collected Active Directory ACL relationships describing configured permissions between principals and directory objects. These relationships provide evidence for administrative review but do not, by themselves, establish effective access, misconfiguration or exploitability."
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
	case isGeneralACLInventory(finding):
		return "Review the collected ACL relationships in the full evidence report, prioritize sensitive objects and unexpected principals, and validate effective permissions and operational requirements before making any access-control changes."
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
		content.WriteString(dim.Render(fmt.Sprintf("%-34s %10s", "SUBCATEGORY", "FINDINGS")) + "\n\n")
	} else {
		content.WriteString(dim.Render("SUBCATEGORY                    FINDINGS") + "\n\n")
	}
	for index, subcategory := range m.findingSubcategories {
		selected := index == m.findingCursor
		var line string
		count := subcategory.Findings + subcategory.Observations
		if width >= 80 {
			name := truncateFinding(subcategory.Name, 34)
			nameField := selectionLabel(name, selected) + strings.Repeat(" ", max(0, 34-ansi.StringWidthWc(name)))
			line = fmt.Sprintf("%s%s %10d", selectionPrefix(selected), nameField, count)
		} else {
			nameWidth := max(12, width-14)
			name := truncateFinding(subcategory.Name, nameWidth)
			line = fmt.Sprintf("%s%-*s %d", selectionPrefix(selected), nameWidth, selectionLabel(name, selected)+strings.Repeat(" ", max(0, nameWidth-ansi.StringWidthWc(name))), count)
		}
		content.WriteString(line + "\n   " + dim.Render(wrapPaneText(subcategory.Description, max(20, width-7))) + "\n")
	}
	empty := len(m.findingSubcategories) == 0
	selectedSubcategory := ""
	if !empty {
		index := min(max(0, m.findingCursor), len(m.findingSubcategories)-1)
		selectedSubcategory = m.findingSubcategories[index].Key
		empty = m.findingSubcategories[index].Findings == 0 && m.findingSubcategories[index].Observations == 0
	}
	if empty {
		message := "No records in this category. Analysis status: " + m.findingSubcategoryAssessmentStatus(selectedSubcategory) + "."
		if m.findingCategory == "kerberos" && len(m.findingSubcategories) > 0 && m.findingCursor < len(m.findingSubcategories) && m.findingSubcategories[m.findingCursor].Key == "kerberos_material" {
			message = m.kerberosMaterialEmptyMessage()
		}
		content.WriteString(warn.Render(message) + "\n")
	}
	content.WriteString(dim.Render("\n→/Enter Open    ←/Esc Back    Q Quit"))
	return paneStyle(false).Width(width).Render(content.String())
}

func (m *model) kerberosMaterialEmptyMessage() string {
	for _, finding := range m.findingAllRows {
		typ := strings.ToLower(finding.FindingType)
		if strings.HasPrefix(typ, "kerberoastable_account") || strings.HasPrefix(typ, "asrep_roastable_account") {
			return "No normalized Kerberos-material records are associated with this assessment, although related roastability evidence exists. This does not establish that material was absent; inspect the producing execution and original artifact."
		}
	}
	return "No collected Kerberos-material records are associated with this assessment. This does not establish that no material exists; the relevant collector may not have run or may have produced no qualifying records."
}

func (m *model) findingSubcategoryAssessmentStatus(subcategory string) string {
	if m.db == nil || m.targetID <= 0 {
		return fallbackText(m.findingsAnalysisStatus, "NOT ASSESSED")
	}
	tool := ""
	matcher := func(string) bool { return false }
	switch subcategory {
	case "kerberos_material", "kerberoastable", "asrep":
		tool = "NetExec (nxc)"
		matcher = func(name string) bool {
			n := strings.ToLower(name)
			return strings.Contains(n, "kerberoast") || strings.Contains(n, "as-rep")
		}
	case "domain_security_policy":
		tool = "NetExec (nxc)"
		matcher = func(name string) bool {
			n := strings.ToLower(name)
			return strings.Contains(n, "password policy") || strings.Contains(n, "machine account quota") || strings.Contains(n, "fine-grained password policy")
		}
	case "spn":
		tool = "ghostSPN"
		matcher = func(string) bool { return true }
	case "acl", "acl_inventory", "acl_replication_rights":
		tool = "RustHound-CE"
		matcher = func(string) bool { return true }
	default:
		return fallbackText(m.findingsAnalysisStatus, "NOT ASSESSED")
	}
	executions, err := m.db.ExecutionsForTool(m.ctx, m.targetID, tool)
	if err != nil {
		return fallbackText(m.findingsAnalysisStatus, "NOT ASSESSED")
	}
	matched := false
	for _, execution := range executions {
		if matcher(execution.ModuleName) {
			matched = true
			break
		}
	}
	if !matched {
		return "NOT ASSESSED"
	}
	return "ASSESSED — NO QUALIFYING EVIDENCE"
}

func findingsStatusLabel(db *storage.DB, ctx context.Context, assessmentID int64) string {
	jobs, err := db.ListAnalysisJobs(ctx, assessmentID)
	if err != nil || len(jobs) == 0 {
		return "NOT ASSESSED"
	}
	for _, job := range jobs {
		switch job.Status {
		case storage.AnalysisPending, storage.AnalysisAnalyzing:
			return "ANALYSIS PENDING"
		case storage.AnalysisFailed:
			return "ANALYSIS FAILED"
		case storage.AnalysisPartial:
			return "PARTIAL"
		}
	}
	return "ASSESSED; NO QUALIFYING EVIDENCE"
}

func (m *model) findingCategoryOverview(width int) string {
	var content strings.Builder
	content.WriteString(title.Render("PwnFlow // FINDINGS") + "\n")
	content.WriteString(dim.Render("Choose a category. Original detection records and evidence remain available.") + "\n")
	// The category row includes the two-cell selection prefix, two inter-column
	// gaps, and a severity field wide enough for INFORMATIONAL. The surrounding
	// pane consumes its border and horizontal padding, so calculate from the
	// actual inner width rather than the nominal pane width.
	innerWidth := max(1, width-4)
	countWidth := 10
	severityWidth := 12
	categoryWidth := max(16, innerWidth-2-1-countWidth-2-severityWidth)
	if width >= 80 {
		content.WriteString(dim.Render(fmt.Sprintf("  %-*s %*s  %*s", categoryWidth, "CATEGORY", countWidth, "FINDINGS", severityWidth, "SEVERITY")) + "\n")
		content.WriteString(dim.Render("────────────────────────────────────────────────────────────────────────") + "\n\n")
	} else {
		countWidth = 6
		categoryWidth = max(16, innerWidth-2-1-countWidth-2-severityWidth)
		content.WriteString(dim.Render(fmt.Sprintf("  %-*s %*s  %*s", categoryWidth, "CATEGORY", countWidth, "COUNT", severityWidth, "SEV")) + "\n\n")
	}
	for index, category := range m.findingCategories {
		selected := index == m.findingCursor
		var line string
		count := category.Findings + category.Observations
		severityText := strings.ToUpper(strings.TrimSpace(category.Highest))
		if width >= 80 {
			name := truncateFinding(category.Name, categoryWidth)
			nameField := selectionLabel(name, selected) + strings.Repeat(" ", max(0, categoryWidth-ansi.StringWidthWc(name)))
			line = fmt.Sprintf("%s%s %10d  %s", selectionPrefix(selected), nameField, count, severityStyle(category.Highest).Render(fmt.Sprintf("%12s", severityText)))
		} else {
			name := truncateFinding(category.Name, categoryWidth)
			nameField := selectionLabel(name, selected) + strings.Repeat(" ", max(0, categoryWidth-ansi.StringWidthWc(name)))
			line = fmt.Sprintf("%s%s %6d  %s", selectionPrefix(selected), nameField, count, severityStyle(category.Highest).Render(fmt.Sprintf("%12s", severityText)))
		}
		content.WriteString(line + "\n")
		content.WriteString("   " + dim.Render(wrapPaneText(category.Description, max(10, categoryWidth-3))) + "\n")
	}
	if len(m.findingCategories) == 0 {
		content.WriteString("No findings categories are available.\n")
	}
	content.WriteString(dim.Render("\n→/Enter Open Category    ←/Esc Close    Q Quit"))
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
