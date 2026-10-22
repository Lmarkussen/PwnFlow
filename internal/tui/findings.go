package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	findingengine "github.com/pwnflow/pwnflow/internal/findings"
	"github.com/pwnflow/pwnflow/internal/storage"
)

var explicitCertipyESC = regexp.MustCompile(`(?i)\bESC[0-9]+\b`)

const criticalFindingsNotice = "This classification is under active development and is not exhaustive. Review all Findings categories for additional security risks and attack paths."

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
	Highest                string
}

var findingSubcategoryOrder = map[string][]struct{ Key, Name, Description string }{
	"credentials": {
		{"sccm", "SCCM", "Recovered SCCM task-sequence credential material"},
		{"gpp", "GPP", "Recovered Group Policy Preferences credentials"},
	},
	"kerberos": {
		{"kerberoastable", "Kerberoastable Users", "Accounts with directly evidenced service principals"},
		{"asrep", "AS-REP Roastable Users", "Accounts with preauthentication disabled where evidenced"},
	},
	"acl": {
		{"acl", "Vulnerable ACLs", "Grouped principal-to-target control relationships"},
		{"acl_inventory", "ACL Evidence Inventory", "Informational direct ACL evidence and collection limitations"},
		{"acl_replication_rights", "Replication Rights Evidence", "Observed domain-root replication-right relationships and completeness"},
		{"ad_writable_objects", "AD Writable Objects", "Source-backed write-capable relationships for the assessed identity"},
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
	"pwntools": {
		{"ftp_anonymous_access", "FTP Anonymous Access", "Confirmed anonymous FTP authentication"},
	},
	"authentication": {
		{"successful_authentication", "Successful Authentication", "Verified successful protocol authentications"},
		{"privileged_access", "Privileged Access", "Explicit NetExec elevated-access indicators"},
	},
	"other": {{"other", "Informational", "Evidence-backed domain and assessment information"}},
}

var findingCategoryOrder = []struct {
	Key, Name, Description string
}{
	{"credentials", "Credentials", "Recovered credentials and SCCM security conditions"},
	{"kerberos", "Kerberos", "Kerberoasting, AS-REP and Kerberos material"},
	{"active_directory", "Active Directory", "Group Policy and SPN configuration conditions"},
	{"acl", "Active Directory ACLs", "Direct control relationships and object permissions"},
	{"adcs", "AD CS", "Certificate template and CA security conditions"},
	{"delegation", "Delegation", "Delegation configuration and related exposure"},
	{"authentication", "Authentication & Privileged Access", "Verified authentication and protocol-specific elevated access"},
	{"network", "Network & Protocols", "SMB, LDAP and relay security conditions"},
	{"pwntools", "PwnTools", "Explicitly designated PwnTools security observations"},
	{"other", "Informational", "Evidence-backed domain and assessment information"},
	{"critical", "CRITICAL FINDINGS", "Verified paths to domain compromise or Tier Zero control"},
}

func findingCategoryKey(finding storage.Finding) string {
	typ := strings.ToLower(strings.TrimSpace(finding.FindingType))
	title := strings.ToLower(finding.Title)
	source := strings.ToLower(finding.SourceTool)
	switch {
	case strings.HasPrefix(typ, "ad_writable_object_"):
		return "acl"
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
	case typ == "netexec_gpp_password_exposure":
		return "credentials"
	case strings.HasPrefix(typ, "mssql_") || strings.EqualFold(source, "mssqlrelay") || strings.EqualFold(source, "mssqlpwner"):
		return "network"
	case strings.HasPrefix(typ, "masscan_") || strings.EqualFold(source, "masscan"):
		return "network"
	case strings.HasPrefix(typ, "pwntools_ftp_anonymous_"):
		return "pwntools"
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
	case strings.HasPrefix(typ, "ad_writable_object_"):
		return "ad_writable_objects"
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
	case strings.Contains(typ, "kerberoast"), strings.Contains(typ, "kerberos_ticket_material"):
		return "kerberoastable"
	case strings.Contains(typ, "kerberos") || strings.Contains(typ, "krb5"):
		return "kerberoastable"
	case strings.HasPrefix(typ, "netexec_auth_"):
		return "successful_authentication"
	case strings.HasPrefix(typ, "netexec_privileged_"):
		return "privileged_access"
	case strings.HasPrefix(typ, "pwntools_ftp_anonymous_"):
		return "ftp_anonymous_access"
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
		result = append(result, findingSubcategory{Key: definition.Key, Name: definition.Name, Description: definition.Description, Highest: "NOT ASSESSED"})
	}
	for _, finding := range rows {
		if category != "critical" && findingCategoryKey(finding) != category {
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
			if result[index].Highest == "NOT ASSESSED" || severityRank(findingSeverityForDisplay(finding)) > severityRank(result[index].Highest) {
				result[index].Highest = strings.ToUpper(findingSeverityForDisplay(finding))
			}
		}
	}
	return result
}

func findingBelongsToSubcategory(category, subcategory string, finding storage.Finding) bool {
	if category == "credentials" && subcategory == "sccm" {
		return findingCategoryKey(finding) == "credentials" && !strings.EqualFold(finding.FindingType, "netexec_gpp_password_exposure")
	}
	if category == "credentials" && subcategory == "gpp" {
		return strings.EqualFold(finding.FindingType, "netexec_gpp_password_exposure")
	}
	if category == "critical" && subcategory == "critical" {
		_, ok := findingengine.ClassifyCritical(finding)
		return ok
	}
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

func (m *model) findingAtRoot() bool {
	return m.findingCategory == "" && !m.findingDetail && !m.findingTieringView && !m.evidenceView
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
			if categories[index].Highest == "NOT ASSESSED" || severityRank(findingSeverityForDisplay(finding)) > severityRank(categories[index].Highest) {
				categories[index].Highest = strings.ToUpper(findingSeverityForDisplay(finding))
			}
		}
	}
	projection := findingengine.ProjectCritical(rows)
	for index := range categories {
		if categories[index].Key != "critical" {
			continue
		}
		categories[index].Findings = len(projection.Confirmed) + len(projection.Potential)
		if len(projection.Confirmed) > 0 {
			categories[index].Highest = "CRITICAL"
		} else if len(projection.Potential) > 0 {
			categories[index].Highest = "HIGH"
		}
	}
	return categories
}

func (m *model) setFindingRows(rows []storage.Finding) {
	rows = append(rows, findingengine.DeriveInformationalFindings(m.ctx, rows)...)
	m.criticalProjection = findingengine.ProjectCritical(rows)
	rows = m.consolidatePresentationFindings(rows)
	m.findingAllRows = append(m.findingAllRows[:0], rows...)
	m.findingCategories = buildFindingCategories(rows)
	for index := range m.findingCategories {
		if m.findingCategories[index].Key != "critical" {
			continue
		}
		m.findingCategories[index].Findings = len(m.criticalProjection.Confirmed) + len(m.criticalProjection.Potential)
		if len(m.criticalProjection.Confirmed) > 0 {
			m.findingCategories[index].Highest = "CRITICAL"
		} else if len(m.criticalProjection.Potential) > 0 {
			m.findingCategories[index].Highest = "HIGH"
		}
	}
}

func (m *model) refreshFindings() {
	if !m.findingsView || m.db == nil {
		return
	}
	if !m.findingsLoaded {
		if m.findingsAsync {
			if !m.findingsLoading {
				m.status = "loading findings…"
			}
			return
		}
		rows, err := m.db.ListFindings(m.ctx, m.targetID)
		if err != nil {
			m.status = "findings unavailable: " + err.Error()
			return
		}
		m.setFindingRows(rows)
		m.findingsAnalysisStatus = findingsStatusLabel(m.db, m.ctx, m.targetID)
		m.findingsLoaded = true
	}
	if m.findingCategories == nil {
		m.findingCategories = buildFindingCategories(m.findingAllRows)
	}
	rows := m.findingAllRows
	if m.findingCategory == "critical" {
		if len(m.criticalProjection.Confirmed) == 0 && len(m.criticalProjection.Potential) == 0 && len(rows) > 0 {
			m.criticalProjection = findingengine.ProjectCritical(rows)
		}
		rows = criticalProjectionRows(m.criticalProjection)
	}
	m.findingViewMode = "all"
	m.findingSeverity = ""
	filtered := make([]storage.Finding, 0, len(rows))
	for _, finding := range rows {
		if m.findingCategory != "critical" && m.findingCategory != "" && findingCategoryKey(finding) != m.findingCategory {
			continue
		}
		if m.findingCategory == "critical" && !m.findingCategoryView {
			if m.criticalState != "" && findingengine.CriticalStateOf(finding) != m.criticalState {
				continue
			}
			if m.criticalFamily != "" && criticalDisplayGroup(finding) != m.criticalFamily {
				continue
			}
		}
		if m.findingSubcategory != "" && m.findingCategory != "critical" && !findingBelongsToSubcategory(m.findingCategory, m.findingSubcategory, finding) {
			continue
		}
		filtered = append(filtered, finding)
	}
	if m.findingCategory == "critical" {
		sort.SliceStable(filtered, func(i, j int) bool {
			leftState := findingengine.CriticalStateOf(filtered[i])
			rightState := findingengine.CriticalStateOf(filtered[j])
			if leftState != rightState {
				return leftState == findingengine.CriticalConfirmed
			}
			leftGroup := criticalDisplayGroup(filtered[i])
			rightGroup := criticalDisplayGroup(filtered[j])
			if leftGroup != rightGroup {
				return criticalDisplayGroupRank(leftGroup) < criticalDisplayGroupRank(rightGroup)
			}
			left := strings.ToLower(strings.TrimSpace(displayFindingTitle(filtered[i])))
			right := strings.ToLower(strings.TrimSpace(displayFindingTitle(filtered[j])))
			if left != right {
				return left < right
			}
			return findingRowIdentity(filtered[i]) < findingRowIdentity(filtered[j])
		})
	} else {
		sort.SliceStable(filtered, func(i, j int) bool {
			return severityRank(findingSeverityForDisplay(filtered[i])) > severityRank(findingSeverityForDisplay(filtered[j]))
		})
	}
	if m.findingCategory == "acl" || m.findingCategory == "" {
		filtered = groupVisibleFindings(filtered)
	}
	if m.findingCategory != "critical" {
		sort.SliceStable(filtered, func(i, j int) bool {
			return severityRank(findingSeverityForDisplay(filtered[i])) > severityRank(findingSeverityForDisplay(filtered[j]))
		})
	}
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

func criticalProjectionRows(projection findingengine.CriticalProjection) []storage.Finding {
	rows := make([]storage.Finding, 0, len(projection.Confirmed)+len(projection.Potential))
	for _, path := range projection.Confirmed {
		rows = append(rows, path.Finding)
	}
	for _, path := range projection.Potential {
		rows = append(rows, path.Finding)
	}
	return rows
}

var criticalDisplayGroupOrder = []string{
	"AD CS",
	"AD Privileged",
	"SCCM / MECM",
	"Delegation",
	"NTLM Relay / Infrastructure",
	"Credentials / Secrets",
}

func criticalDisplayGroup(finding storage.Finding) string {
	family := strings.ToLower(metadataString(findingMetadata(finding), "family"))
	switch {
	case strings.HasPrefix(family, "adcs_"):
		return "AD CS"
	case family == "privileged_access", family == "acl_control", family == "dcsync":
		return "AD Privileged"
	case family == "credential_disclosure":
		return "SCCM / MECM"
	case family == "delegation":
		return "Delegation"
	case family == "ntlm_relay":
		return "NTLM Relay / Infrastructure"
	default:
		return "Credentials / Secrets"
	}
}

func criticalDisplayGroupRank(group string) int {
	for index, value := range criticalDisplayGroupOrder {
		if value == group {
			return index
		}
	}
	return len(criticalDisplayGroupOrder)
}

func criticalStateSubcategories(projection findingengine.CriticalProjection) []findingSubcategory {
	result := make([]findingSubcategory, 0, 2)
	if len(projection.Confirmed) > 0 {
		result = append(result, findingSubcategory{Key: string(findingengine.CriticalConfirmed), Name: "Confirmed Critical", Findings: len(projection.Confirmed), Highest: "CRITICAL"})
	}
	if len(projection.Potential) > 0 {
		result = append(result, findingSubcategory{Key: string(findingengine.CriticalPotential), Name: "Potential Critical — Not Verified", Findings: len(projection.Potential), Highest: "HIGH"})
	}
	return result
}

func criticalFamilySubcategories(projection findingengine.CriticalProjection, state findingengine.CriticalState) []findingSubcategory {
	counts := make(map[string]int)
	paths := projection.Confirmed
	if state == findingengine.CriticalPotential {
		paths = projection.Potential
	}
	for _, path := range paths {
		counts[pathGroupName(path.Family)]++
	}
	result := make([]findingSubcategory, 0, len(counts))
	for _, group := range criticalDisplayGroupOrder {
		if count := counts[group]; count > 0 {
			result = append(result, findingSubcategory{Key: group, Name: group, Findings: count, Highest: criticalStateHighest(state)})
		}
	}
	return result
}

func pathGroupName(family string) string {
	switch {
	case strings.HasPrefix(strings.ToLower(family), "adcs_"):
		return "AD CS"
	case family == "privileged_access", family == "acl_control", family == "dcsync":
		return "AD Privileged"
	case family == "credential_disclosure":
		return "SCCM / MECM"
	case family == "delegation":
		return "Delegation"
	case family == "ntlm_relay":
		return "NTLM Relay / Infrastructure"
	default:
		return "Credentials / Secrets"
	}
}

func criticalStateHighest(state findingengine.CriticalState) string {
	if state == findingengine.CriticalConfirmed {
		return "CRITICAL"
	}
	return "HIGH"
}

func (m *model) consolidatePresentationFindings(rows []storage.Finding) []storage.Finding {
	return m.consolidateACLInventoryFindings(m.consolidateDelegationFindings(m.consolidateCertipyFindings(m.consolidateWritableObjectFindings(m.consolidatePasswordPolicyFindings(m.consolidateGPOFindings(m.consolidateTierFindings(m.consolidateProtectedAccountFindings(m.consolidateKerberosFindings(m.consolidatePXEFindings(rows))))))))))
}

func (m *model) consolidateDelegationFindings(rows []storage.Finding) []storage.Finding {
	groups := make(map[string]*storage.Finding)
	order := make([]string, 0)
	result := make([]storage.Finding, 0, len(rows))
	for _, finding := range rows {
		typ := strings.ToLower(strings.TrimSpace(finding.FindingType))
		if typ != "unconstrained_delegation_configured" && typ != "constrained_delegation_configured" && typ != "rbcd_observed" {
			result = append(result, finding)
			continue
		}
		metadata := protectedFindingMetadata(finding)
		identity := strings.ToLower(strings.TrimSpace(firstNonEmpty(metadataString(metadata, "object_id"), finding.AffectedObjectID, finding.AffectedObject)))
		targets := strings.Join(metadataStringSlice(metadata, "allowed_to_delegate"), "\x00")
		key := strings.Join([]string{typ, identity, strings.ToLower(targets)}, "\x00")
		if entry := groups[key]; entry != nil {
			merged := findingMetadata(*entry)
			records, _ := merged["source_records"].([]any)
			merged["source_records"] = appendUniqueJSONObjects(records, delegationSourceRecord(finding))
			if encoded, err := json.Marshal(merged); err == nil {
				entry.EvidenceJSON = string(encoded)
			}
			continue
		}
		copy := finding
		merged := protectedFindingMetadata(copy)
		if typ == "unconstrained_delegation_configured" {
			if isDC, ok := merged["domain_controller"].(bool); ok && isDC {
				copy.Severity = "informational"
			}
		}
		merged["source_records"] = appendUniqueJSONObjects(nil, delegationSourceRecord(finding))
		if encoded, err := json.Marshal(merged); err == nil {
			copy.EvidenceJSON = string(encoded)
		}
		groups[key] = &copy
		order = append(order, key)
	}
	for _, key := range order {
		result = append(result, *groups[key])
	}
	return result
}

func delegationSourceRecord(finding storage.Finding) map[string]any {
	return map[string]any{"execution": finding.SourceExecution, "artifact": finding.ArtifactPath, "reference": finding.ArtifactRef}
}

func (m *model) consolidateCertipyFindings(rows []storage.Finding) []storage.Finding {
	groups := make(map[string]*storage.Finding)
	order := make([]string, 0)
	result := make([]storage.Finding, 0, len(rows))
	for _, finding := range rows {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(finding.FindingType)), "adcs_esc_") {
			result = append(result, finding)
			continue
		}
		metadata := findingMetadata(finding)
		key := strings.Join([]string{
			strings.ToLower(strings.TrimSpace(finding.FindingType)),
			strings.ToLower(strings.TrimSpace(firstNonEmpty(finding.AffectedObjectID, finding.AffectedObject))),
			strings.ToLower(strings.TrimSpace(certipyVulnerabilityReason(metadata, certipyESCType(finding, metadata)))),
		}, "\x00")
		entry := groups[key]
		if entry == nil {
			copy := finding
			merged := findingMetadata(copy)
			merged["source_records"] = appendUniqueJSONObjects(nil, certipySourceRecord(finding))
			if encoded, err := json.Marshal(merged); err == nil {
				copy.EvidenceJSON = string(encoded)
			}
			groups[key] = &copy
			order = append(order, key)
			continue
		}
		mergeCertipyMetadata(entry, finding)
	}
	for _, key := range order {
		result = append(result, *groups[key])
	}
	return result
}

func certipySourceRecord(finding storage.Finding) map[string]any {
	return map[string]any{"execution": finding.SourceExecution, "artifact": finding.ArtifactPath, "reference": finding.ArtifactRef}
}

func mergeCertipyMetadata(target *storage.Finding, source storage.Finding) {
	metadata := findingMetadata(*target)
	records, _ := metadata["source_records"].([]any)
	metadata["source_records"] = appendUniqueJSONObjects(records, certipySourceRecord(source))
	if encoded, err := json.Marshal(metadata); err == nil {
		target.EvidenceJSON = string(encoded)
	}
}

func (m *model) consolidateACLInventoryFindings(rows []storage.Finding) []storage.Finding {
	groups := make(map[string]*storage.Finding)
	order := make([]string, 0)
	result := make([]storage.Finding, 0, len(rows))
	for _, finding := range rows {
		typ := strings.ToLower(strings.TrimSpace(finding.FindingType))
		if typ != "ad_acl_evidence_inventory" && typ != "ad_privileged_acl_evidence_inventory" && typ != "ad_replication_rights_evidence_overview" {
			result = append(result, finding)
			continue
		}
		metadata := findingMetadata(finding)
		key := typ + "\x00" + strings.ToLower(strings.TrimSpace(firstNonEmpty(metadataString(metadata, "domain"), finding.AffectedObject, finding.AffectedObjectID)))
		entry := groups[key]
		if entry == nil {
			copy := finding
			merged := findingMetadata(copy)
			merged["source_records"] = appendUniqueJSONObjects(nil, aclSourceRecord(finding))
			if encoded, err := json.Marshal(merged); err == nil {
				copy.EvidenceJSON = string(encoded)
			}
			groups[key] = &copy
			order = append(order, key)
			continue
		}
		mergeACLInventoryMetadata(entry, finding)
	}
	for _, key := range order {
		result = append(result, *groups[key])
	}
	return result
}

func aclSourceRecord(finding storage.Finding) map[string]any {
	return map[string]any{"execution": finding.SourceExecution, "artifact": finding.ArtifactPath, "reference": finding.ArtifactRef}
}

func mergeACLInventoryMetadata(target *storage.Finding, source storage.Finding) {
	metadata := findingMetadata(*target)
	incoming := findingMetadata(source)
	records, _ := metadata["source_records"].([]any)
	metadata["source_records"] = appendUniqueJSONObjects(records, aclSourceRecord(source))
	for _, key := range []string{"examples", "relationship_overview", "domain_roots"} {
		existing, _ := metadata[key].([]any)
		additions, _ := incoming[key].([]any)
		if len(additions) == 0 {
			continue
		}
		metadata[key] = mergeACLRecords(existing, additions)
	}
	for _, key := range []string{"source_supported_ace_count", "retained_ace_count", "explicit_count", "inherited_count", "unknown_decision_count", "normalized_relationships", "high_value_targets", "membership_edges", "direct_membership_paths", "nested_membership_paths", "membership_paths_shown", "membership_evidence_records"} {
		if metadataInt(incoming, key) > metadataInt(metadata, key) {
			metadata[key] = incoming[key]
		}
	}
	if encoded, err := json.Marshal(metadata); err == nil {
		target.EvidenceJSON = string(encoded)
	}
}

func mergeACLRecords(existing, additions []any) []any {
	seen := make(map[string]bool, len(existing))
	for _, raw := range existing {
		seen[aclRecordIdentity(raw)] = true
	}
	for _, raw := range additions {
		key := aclRecordIdentity(raw)
		if key != "" && seen[key] {
			continue
		}
		existing = append(existing, raw)
		seen[key] = true
	}
	return existing
}

func aclRecordIdentity(raw any) string {
	record, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	return strings.ToLower(strings.Join([]string{
		stringValue(record["principal_id"]), stringValue(record["principal_name"]),
		stringValue(record["target_id"]), stringValue(record["target_name"]),
		stringValue(record["permission"]), stringValue(record["right"]),
		stringValue(record["decision"]), stringValue(record["inheritance"]),
	}, "\x00"))
}

func (m *model) consolidateWritableObjectFindings(rows []storage.Finding) []storage.Finding {
	groups := make(map[string]*storage.Finding)
	order := make([]string, 0)
	result := make([]storage.Finding, 0, len(rows))
	for _, finding := range rows {
		if !strings.EqualFold(finding.FindingType, "ad_writable_object_assessment") {
			result = append(result, finding)
			continue
		}
		metadata := findingMetadata(finding)
		identity := strings.ToLower(strings.TrimSpace(metadataString(metadata, "authenticated_user")))
		if identity == "" {
			identity = strings.ToLower(strings.TrimSpace(fallbackText(finding.AffectedObjectID, finding.AffectedObject)))
		}
		domain := strings.ToLower(strings.TrimSpace(metadataString(metadata, "domain")))
		key := identity + "\x00" + domain
		entry := groups[key]
		if entry == nil {
			copy := finding
			merged := findingMetadata(copy)
			merged["source_records"] = appendUniqueJSONObjects(nil, writableObjectSourceRecord(finding))
			if encoded, err := json.Marshal(merged); err == nil {
				copy.EvidenceJSON = string(encoded)
			}
			groups[key] = &copy
			order = append(order, key)
			continue
		}
		mergeWritableObjectMetadata(entry, finding)
	}
	for _, key := range order {
		result = append(result, *groups[key])
	}
	return result
}

func writableObjectSourceRecord(finding storage.Finding) map[string]any {
	return map[string]any{"execution": finding.SourceExecution, "artifact": finding.ArtifactPath, "reference": finding.ArtifactRef}
}

func mergeWritableObjectMetadata(target *storage.Finding, source storage.Finding) {
	metadata := findingMetadata(*target)
	sourceMetadata := findingMetadata(source)
	records, _ := metadata["source_records"].([]any)
	metadata["source_records"] = appendUniqueJSONObjects(records, writableObjectSourceRecord(source))
	existing, _ := metadata["relationships"].([]any)
	incoming, _ := sourceMetadata["relationships"].([]any)
	seen := make(map[string]bool, len(existing))
	for _, raw := range existing {
		seen[writableRelationshipKey(raw)] = true
	}
	for _, raw := range incoming {
		key := writableRelationshipKey(raw)
		if key != "" && seen[key] {
			continue
		}
		existing = append(existing, raw)
		seen[key] = true
	}
	metadata["relationships"] = existing
	if encoded, err := json.Marshal(metadata); err == nil {
		target.EvidenceJSON = string(encoded)
	}
}

func writableRelationshipKey(raw any) string {
	relationship, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(stringValue(relationship["principal_id"]))),
		strings.ToLower(strings.TrimSpace(stringValue(relationship["target_id"]))),
		strings.ToLower(strings.TrimSpace(stringValue(relationship["permission"]))),
		strings.ToLower(strings.TrimSpace(stringValue(relationship["decision"]))),
		strings.ToLower(strings.TrimSpace(stringValue(relationship["inheritance"]))),
	}, "\x00")
}

func (m *model) consolidatePasswordPolicyFindings(rows []storage.Finding) []storage.Finding {
	var weak *storage.Finding
	var snapshot *storage.Finding
	result := make([]storage.Finding, 0, len(rows))
	for _, finding := range rows {
		switch strings.ToLower(strings.TrimSpace(finding.FindingType)) {
		case "ad_domain_policy_weak_minimum_password_length":
			copy := finding
			weak = &copy
		case "ad_domain_policy_password_policy_snapshot":
			copy := finding
			snapshot = &copy
		default:
			result = append(result, finding)
		}
	}
	if weak == nil {
		if snapshot != nil {
			result = append(result, *snapshot)
		}
		return result
	}
	metadata := findingMetadata(*weak)
	metadata["source_records"] = appendUniqueJSONObjects(nil, passwordPolicySourceRecord(*weak))
	if snapshot != nil && samePasswordPolicyScope(*weak, *snapshot) {
		mergePasswordPolicyMetadata(metadata, *snapshot)
	} else if snapshot != nil {
		result = append(result, *snapshot)
	}
	if encoded, err := json.Marshal(metadata); err == nil {
		weak.EvidenceJSON = string(encoded)
	}
	result = append(result, *weak)
	return result
}

func samePasswordPolicyScope(left, right storage.Finding) bool {
	leftMetadata, rightMetadata := findingMetadata(left), findingMetadata(right)
	leftDomain := firstNonEmpty(metadataString(leftMetadata, "domain"), left.AffectedObject, left.AffectedObjectID)
	rightDomain := firstNonEmpty(metadataString(rightMetadata, "domain"), right.AffectedObject, right.AffectedObjectID)
	leftScope := firstNonEmpty(metadataString(leftMetadata, "policy_scope"), "domain default policy")
	rightScope := firstNonEmpty(metadataString(rightMetadata, "policy_scope"), "domain default policy")
	return strings.EqualFold(strings.TrimSpace(leftDomain), strings.TrimSpace(rightDomain)) && strings.EqualFold(strings.TrimSpace(leftScope), strings.TrimSpace(rightScope))
}

func passwordPolicySourceRecord(finding storage.Finding) map[string]any {
	return map[string]any{"type": finding.FindingType, "title": finding.Title, "execution": finding.SourceExecution, "artifact": finding.ArtifactPath, "reference": finding.ArtifactRef}
}

func mergePasswordPolicyMetadata(target map[string]any, finding storage.Finding) {
	source := findingMetadata(finding)
	records, _ := target["source_records"].([]any)
	target["source_records"] = appendUniqueJSONObjects(records, passwordPolicySourceRecord(finding))
	fields, _ := target["fields"].(map[string]any)
	if fields == nil {
		fields = make(map[string]any)
	}
	if sourceFields, ok := source["fields"].(map[string]any); ok {
		for key, value := range sourceFields {
			fields[key] = value
		}
	}
	if minimum := metadataInt(source, "minimum_password_length"); minimum > 0 {
		if _, exists := fields["minimum_password_length"]; !exists {
			fields["minimum_password_length"] = map[string]any{"numeric": minimum, "raw": strconv.Itoa(minimum), "state": "observed"}
		}
	}
	target["fields"] = fields
	for _, key := range []string{"domain", "policy_scope", "fine_grained_policy_limitation"} {
		if metadataString(target, key) == "" && metadataString(source, key) != "" {
			target[key] = source[key]
		}
	}
}

func (m *model) consolidateGPOFindings(rows []storage.Finding) []storage.Finding {
	var consolidated *storage.Finding
	var metadata map[string]any
	result := make([]storage.Finding, 0, len(rows))
	for _, finding := range rows {
		if !strings.EqualFold(finding.FindingType, "ad_gpo_privilege_relationship_evidence") {
			result = append(result, finding)
			continue
		}
		if consolidated == nil {
			copy := finding
			consolidated = &copy
			metadata = findingMetadata(finding)
			metadata["source_records"] = appendUniqueJSONObjects(nil, protectedSourceRecord(finding))
		} else {
			mergeGPOMetadata(metadata, finding)
		}
	}
	if consolidated != nil {
		if encoded, err := json.Marshal(metadata); err == nil {
			consolidated.EvidenceJSON = string(encoded)
		}
		result = append(result, *consolidated)
	}
	return result
}

func mergeGPOMetadata(target map[string]any, finding storage.Finding) {
	source := findingMetadata(finding)
	records, _ := target["source_records"].([]any)
	target["source_records"] = appendUniqueJSONObjects(records, protectedSourceRecord(finding))
	for _, key := range []string{"source_artifacts", "source_hashes", "unresolved_joins", "limitations"} {
		values := metadataStringSlice(target, key)
		values = appendUniqueStrings(values, metadataStringSlice(source, key)...)
		if len(values) > 0 {
			target[key] = values
		}
	}
	if metadataBool(source, "snapshot_mismatch") {
		target["snapshot_mismatch"] = true
	}
	values, _ := target["gpos"].([]any)
	incoming, _ := source["gpos"].([]any)
	target["gpos"] = mergeGPOObjects(values, incoming...)
}

func mergeGPOObjects(values []any, additions ...any) []any {
	for _, addition := range additions {
		incoming, ok := addition.(map[string]any)
		if !ok {
			values = appendUniqueJSONValues(values, addition)
			continue
		}
		key := gpoObjectKey(incoming)
		matched := false
		for index, existingRaw := range values {
			existing, ok := existingRaw.(map[string]any)
			if !ok || gpoObjectKey(existing) != key {
				continue
			}
			mergeGPOObject(existing, incoming)
			values[index] = existing
			matched = true
			break
		}
		if !matched {
			values = append(values, incoming)
		}
	}
	return values
}

func gpoObjectKey(gpo map[string]any) string {
	guid := strings.ToLower(strings.Trim(strings.TrimSpace(stringValue(gpo["gpo_guid"])), "{}"))
	if guid != "" {
		return "guid\x00" + guid
	}
	return "identity\x00" + strings.ToLower(strings.Join([]string{stringValue(gpo["display_name"]), stringValue(gpo["distinguished_name"])}, "\x00"))
}

func mergeGPOObject(target, source map[string]any) {
	for _, key := range []string{"observed_acl_relationships", "configured_links", "membership_context"} {
		values, _ := target[key].([]any)
		incoming, _ := source[key].([]any)
		target[key] = mergeGPOObservations(values, incoming...)
	}
	for _, key := range []string{"gpo_source_execution_id", "snapshot_caveat", "configured_applicability", "distinguished_name", "display_name", "object_guid"} {
		if strings.TrimSpace(stringValue(target[key])) == "" && strings.TrimSpace(stringValue(source[key])) != "" {
			target[key] = source[key]
		}
	}
}

func mergeGPOObservations(values []any, additions ...any) []any {
	for _, addition := range additions {
		incoming, ok := addition.(map[string]any)
		if !ok {
			values = appendUniqueJSONValues(values, addition)
			continue
		}
		key := gpoObservationKey(incoming)
		matched := false
		for index, existingRaw := range values {
			existing, ok := existingRaw.(map[string]any)
			if !ok || gpoObservationKey(existing) != key {
				continue
			}
			mergeGPOEvidenceProvenance(existing, incoming)
			mergeProtectedObservationProvenance(existing, incoming)
			values[index] = existing
			matched = true
			break
		}
		if !matched {
			values = append(values, incoming)
		}
	}
	return values
}

func mergeGPOEvidenceProvenance(target, source map[string]any) {
	refs := metadataStringSlice(target, "evidence_refs")
	for _, item := range []map[string]any{target, source} {
		artifact := stringValue(item["artifact"])
		reference := stringValue(item["artifact_ref"])
		if artifact != "" || reference != "" {
			refs = appendUniqueStrings(refs, strings.TrimSpace(artifact+"#"+reference))
		}
	}
	if len(refs) > 0 {
		target["evidence_refs"] = refs
	}
}

func gpoObservationKey(observation map[string]any) string {
	parts := []string{
		stringValue(observation["principal_id"]), stringValue(observation["principal_name"]),
		stringValue(observation["permission"]), stringValue(observation["decision"]),
		stringValue(observation["inheritance"]), stringValue(observation["object_type"]),
		stringValue(observation["source_dn"]), stringValue(observation["target_container_dn"]),
		stringValue(observation["classification"]), stringValue(observation["applicability"]),
	}
	return strings.ToLower(strings.Join(parts, "\x00"))
}

func (m *model) consolidateTierFindings(rows []storage.Finding) []storage.Finding {
	groups := make(map[string]*storage.Finding)
	order := make([]string, 0)
	for _, finding := range rows {
		if !isTierContextFinding(finding) {
			key := "row:" + findingRowIdentity(finding)
			copy := finding
			order = append(order, key)
			groups[key] = &copy
			continue
		}
		key := strings.ToLower(strings.TrimSpace(finding.FindingType))
		current := groups[key]
		if current == nil {
			copy := finding
			metadata := findingMetadata(finding)
			metadata["source_records"] = appendUniqueJSONObjects(nil, protectedSourceRecord(finding))
			if encoded, err := json.Marshal(metadata); err == nil {
				copy.EvidenceJSON = string(encoded)
			}
			groups[key] = &copy
			order = append(order, key)
			continue
		}
		metadata := findingMetadata(*current)
		mergeTierMetadata(metadata, finding)
		if encoded, err := json.Marshal(metadata); err == nil {
			current.EvidenceJSON = string(encoded)
		}
	}
	result := make([]storage.Finding, 0, len(order))
	for _, key := range order {
		result = append(result, *groups[key])
	}
	return result
}

func isTierContextFinding(finding storage.Finding) bool {
	typ := strings.ToLower(strings.TrimSpace(finding.FindingType))
	return typ == "ad_tier0_context_evidence" || typ == "ad_tier1_context_evidence" || typ == "ad_tier2_context_evidence"
}

func mergeTierMetadata(target map[string]any, finding storage.Finding) {
	source := findingMetadata(finding)
	records, _ := target["source_records"].([]any)
	target["source_records"] = appendUniqueJSONObjects(records, protectedSourceRecord(finding))
	for _, key := range []string{"domain_controllers", "tier0_groups", "tier0_principals", "membership_paths", "acl_relationships", "replication_rights", "admincount_users", "admincount_groups", "declared_groups", "targets"} {
		values, _ := target[key].([]any)
		incoming, _ := source[key].([]any)
		if key == "targets" {
			target[key] = mergeTierTargets(values, incoming...)
		} else {
			target[key] = mergeProtectedObservations(values, incoming...)
		}
	}
	for _, key := range []string{"source_artifacts", "source_hashes"} {
		values := metadataStringSlice(target, key)
		values = appendUniqueStrings(values, metadataStringSlice(source, key)...)
		if len(values) > 0 {
			target[key] = values
		}
	}
	for _, key := range []string{"omitted_acl_relationships", "omitted_membership_paths"} {
		if value := metadataInt(source, key); value > metadataInt(target, key) {
			target[key] = value
		}
	}
}

func mergeTierTargets(values []any, additions ...any) []any {
	for _, addition := range additions {
		observation, ok := addition.(map[string]any)
		if !ok {
			values = appendUniqueJSONValues(values, addition)
			continue
		}
		key := tierTargetKey(observation)
		matched := false
		for index, existingRaw := range values {
			existing, ok := existingRaw.(map[string]any)
			if !ok || tierTargetKey(existing) != key {
				continue
			}
			mergeProtectedObservationProvenance(existing, observation)
			values[index] = existing
			matched = true
			break
		}
		if !matched {
			values = append(values, observation)
		}
	}
	return values
}

func tierTargetKey(target map[string]any) string {
	declared, _ := target["declared"].(map[string]any)
	return strings.ToLower(strings.TrimSpace(strings.Join([]string{
		stringValue(declared["name"]),
		stringValue(declared["ip"]),
		stringValue(target["status"]),
	}, "\x00")))
}

func (m *model) consolidateProtectedAccountFindings(rows []storage.Finding) []storage.Finding {
	var consolidated *storage.Finding
	var metadata map[string]any
	result := make([]storage.Finding, 0, len(rows))
	for _, finding := range rows {
		if !strings.EqualFold(finding.FindingType, "ad_protected_accounts_admincount_evidence") {
			result = append(result, finding)
			continue
		}
		if consolidated == nil {
			copy := finding
			consolidated = &copy
			metadata = findingMetadata(finding)
			metadata["source_records"] = appendUniqueJSONObjects(nil, protectedSourceRecord(finding))
		} else {
			mergeProtectedMetadata(metadata, finding)
		}
	}
	if consolidated != nil {
		if encoded, err := json.Marshal(metadata); err == nil {
			consolidated.EvidenceJSON = string(encoded)
		}
		result = append(result, *consolidated)
	}
	return result
}

func mergeProtectedMetadata(target map[string]any, finding storage.Finding) {
	source := findingMetadata(finding)
	records, _ := target["source_records"].([]any)
	records = appendUniqueJSONObjects(records, protectedSourceRecord(finding))
	target["source_records"] = records
	for _, key := range []string{"admincount_user_examples", "admincount_group_examples", "membership_examples", "attribute_membership_differences", "membership_paths"} {
		values, _ := target[key].([]any)
		incoming, _ := source[key].([]any)
		target[key] = mergeProtectedObservations(values, incoming...)
	}
	for _, key := range []string{"structured_artifact"} {
		values := []string{}
		if value := metadataString(target, key); value != "" {
			values = append(values, value)
		}
		if value := metadataString(source, key); value != "" {
			values = appendUniqueStrings(values, value)
		}
		if len(values) > 0 {
			target[key+"s"] = values
		}
	}
	for _, key := range []string{"admincount_users", "admincount_groups", "membership_paths", "omitted_membership_paths"} {
		if value := metadataInt(source, key); value > metadataInt(target, key) {
			target[key] = value
		}
	}
	if holder, ok := source["admin_sdholder"].(map[string]any); ok {
		if existing, ok := target["admin_sdholder"].(map[string]any); ok {
			mergeProtectedAdminSDHolder(existing, holder)
		} else {
			target["admin_sdholder"] = holder
		}
	}
}

func protectedSourceRecord(finding storage.Finding) map[string]any {
	return map[string]any{
		"execution":   finding.SourceExecution,
		"artifact":    finding.ArtifactPath,
		"reference":   finding.ArtifactRef,
		"observed_at": finding.ObservedAt.UTC().Format(time.RFC3339),
	}
}

func mergeProtectedAdminSDHolder(target, source map[string]any) {
	targetACEs, _ := target["aces"].([]any)
	sourceACEs, _ := source["aces"].([]any)
	target["aces"] = mergeProtectedObservations(targetACEs, sourceACEs...)
}

func mergeProtectedObservations(values []any, additions ...any) []any {
	for _, addition := range additions {
		observation, ok := addition.(map[string]any)
		if !ok {
			values = appendUniqueJSONValues(values, addition)
			continue
		}
		key := protectedObservationKey(observation)
		matched := false
		for index, existingRaw := range values {
			existing, ok := existingRaw.(map[string]any)
			if !ok || protectedObservationKey(existing) != key {
				continue
			}
			mergeProtectedObservationProvenance(existing, observation)
			values[index] = existing
			matched = true
			break
		}
		if !matched {
			values = append(values, observation)
		}
	}
	return values
}

func protectedObservationKey(observation map[string]any) string {
	copy := make(map[string]any, len(observation))
	for key, value := range observation {
		switch key {
		case "source_ref", "source_refs", "source_artifact", "source_artifacts", "membership_artifacts":
			continue
		default:
			copy[key] = value
		}
	}
	encoded, _ := json.Marshal(copy)
	return string(encoded)
}

func mergeProtectedObservationProvenance(target, source map[string]any) {
	refs := metadataStringSlice(target, "source_refs")
	refs = appendUniqueStrings(refs, metadataString(source, "source_ref"))
	refs = appendUniqueStrings(refs, metadataStringSlice(source, "source_refs")...)
	if value := metadataString(target, "source_ref"); value != "" {
		refs = appendUniqueStrings(refs, value)
	}
	if len(refs) > 0 {
		target["source_refs"] = refs
	}
	artifacts := metadataStringSlice(target, "source_artifacts")
	artifacts = appendUniqueStrings(artifacts, metadataString(target, "source_artifact"), metadataString(source, "source_artifact"))
	artifacts = appendUniqueStrings(artifacts, metadataStringSlice(source, "source_artifacts")...)
	if len(artifacts) > 0 {
		target["source_artifacts"] = artifacts
	}
}

func appendUniqueJSONValues(values []any, additions ...any) []any {
	seen := make(map[string]bool, len(values)+len(additions))
	for _, value := range values {
		encoded, _ := json.Marshal(value)
		seen[string(encoded)] = true
	}
	for _, value := range additions {
		encoded, _ := json.Marshal(value)
		if !seen[string(encoded)] {
			values = append(values, value)
			seen[string(encoded)] = true
		}
	}
	return values
}

func appendUniqueJSONObjects(values []any, additions ...map[string]any) []any {
	for _, addition := range additions {
		values = appendUniqueJSONValues(values, addition)
	}
	return values
}

type kerberosFindingGroup struct {
	finding       storage.Finding
	account       string
	domain        string
	technique     string
	material      bool
	refs          []string
	lineNumbers   []int
	configuration []string
}

func (m *model) consolidateKerberosFindings(rows []storage.Finding) []storage.Finding {
	groups := make([]*kerberosFindingGroup, 0)
	result := make([]storage.Finding, 0, len(rows))
	for _, finding := range rows {
		technique, material := kerberosFindingTechnique(finding)
		if technique == "" {
			result = append(result, finding)
			continue
		}
		account, domain := kerberosFindingPrincipal(finding)
		if account == "" {
			result = append(result, finding)
			continue
		}
		var group *kerberosFindingGroup
		for _, candidate := range groups {
			if candidate.technique == technique && candidate.account == account && kerberosDomainsCompatible(candidate.domain, domain) {
				group = candidate
				break
			}
		}
		if group == nil {
			metadata := findingMetadata(finding)
			refs := appendUniqueStrings(nil, finding.ArtifactRef)
			refs = appendUniqueStrings(refs, stringSlice(metadata["artifact_records"])...)
			group = &kerberosFindingGroup{
				finding:     finding,
				account:     account,
				domain:      domain,
				technique:   technique,
				material:    material,
				refs:        refs,
				lineNumbers: appendUniqueInts(nil, intSlice(metadata["record_line_numbers"])...),
			}
			if !material {
				group.configuration = appendUniqueStrings(group.configuration, finding.ArtifactRef)
			}
			groups = append(groups, group)
			continue
		}
		if material && !group.material {
			group.finding = finding
			group.material = true
		}
		if group.domain == "" {
			group.domain = domain
		}
		metadata := findingMetadata(finding)
		group.refs = appendUniqueStrings(group.refs, finding.ArtifactRef)
		group.refs = appendUniqueStrings(group.refs, stringSlice(metadata["artifact_records"])...)
		group.lineNumbers = appendUniqueInts(group.lineNumbers, intSlice(metadata["record_line_numbers"])...)
		if !material {
			group.configuration = appendUniqueStrings(group.configuration, finding.ArtifactRef)
		}
	}
	for _, group := range groups {
		metadata := findingMetadata(group.finding)
		metadata["supporting_configuration_refs"] = group.configuration
		if len(group.refs) > 0 {
			metadata["artifact_records"] = appendUniqueStrings(nil, group.refs...)
		}
		if len(group.lineNumbers) > 0 {
			metadata["record_line_numbers"] = group.lineNumbers
		}
		if encoded, err := json.Marshal(metadata); err == nil {
			group.finding.EvidenceJSON = string(encoded)
		}
		result = append(result, group.finding)
	}
	return result
}

func appendUniqueInts(values []int, additions ...int) []int {
	seen := make(map[int]bool, len(values)+len(additions))
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range additions {
		if value > 0 && !seen[value] {
			values = append(values, value)
			seen[value] = true
		}
	}
	return values
}

func kerberosFindingTechnique(finding storage.Finding) (string, bool) {
	typ := strings.ToLower(strings.TrimSpace(finding.FindingType))
	switch typ {
	case "kerberoastable_account", "kerberos_ticket_material_collected":
		return "kerberoast", typ == "kerberos_ticket_material_collected"
	case "asrep_roastable_account", "asrep_material_collected":
		return "asrep", typ == "asrep_material_collected"
	default:
		return "", false
	}
}

func kerberosFindingPrincipal(finding storage.Finding) (account, domain string) {
	value := strings.Trim(strings.TrimSpace(finding.AffectedObject), "\\\"")
	if value == "" {
		value = metadataString(findingMetadata(finding), "principal")
	}
	value = strings.Trim(strings.TrimSpace(value), "\\\"")
	if slash := strings.LastIndexByte(value, '\\'); slash >= 0 {
		domain = strings.ToLower(strings.TrimSpace(value[:slash]))
		value = value[slash+1:]
	} else if at := strings.LastIndexByte(value, '@'); at >= 0 {
		domain = strings.ToLower(strings.TrimSpace(value[at+1:]))
		value = value[:at]
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), "$"), domain
}

func kerberosDomainsCompatible(left, right string) bool {
	return left == "" || right == "" || strings.EqualFold(left, right)
}

func (m *model) consolidatePXEFindings(rows []storage.Finding) []storage.Finding {
	type grouped struct {
		finding storage.Finding
		values  map[string]string
		refs    []string
	}
	groups := make(map[string]*grouped)
	order := make([]string, 0, len(rows))
	for _, finding := range rows {
		if !isPXECredentialFinding(finding) {
			key := "row:" + findingRowIdentity(finding)
			groups[key] = &grouped{finding: finding}
			order = append(order, key)
			continue
		}
		metadata := findingMetadata(finding)
		values := pxeCredentialValues(metadata)
		if len(values) < 3 && m.cfg.ResultsRoot() != "" {
			inline := loadInlineEvidence(m.cfg, finding)
			values = pxeCredentialValuesFromLines(inline.lines)
			if len(values) < 3 {
				unscoped := cloneFindingMetadata(metadata)
				delete(unscoped, "task_sequence_context")
				delete(unscoped, "artifact_records")
				path, pathErr := safeEvidencePathForRoot(m.cfg.ResultsRoot(), finding.ArtifactPath)
				if pathErr == nil {
					if lines, readErr := readEvidenceLines(path); readErr == nil {
						values = pxeCredentialValuesFromLines(extractPXEInline(lines, unscoped, finding))
					}
				}
			}
		}
		if len(values) < 3 && filepath.IsAbs(finding.ArtifactPath) {
			if lines, readErr := readEvidenceLines(finding.ArtifactPath); readErr == nil {
				values = pxeCredentialValuesFromRawLines(lines)
			}
		}
		if len(values) < 3 {
			key := "row:" + findingRowIdentity(finding)
			groups[key] = &grouped{finding: finding}
			order = append(order, key)
			continue
		}
		key := pxeCredentialSetKey(values)
		entry := groups[key]
		if entry == nil {
			entry = &grouped{finding: finding, values: values}
			groups[key] = entry
			order = append(order, key)
		}
		entry.refs = appendUniqueStrings(entry.refs, finding.ArtifactRef)
		entry.refs = appendUniqueStrings(entry.refs, stringSlice(metadata["artifact_records"])...)
		if entry.finding.ArtifactPath == "" {
			entry.finding.ArtifactPath = finding.ArtifactPath
		}
	}
	result := make([]storage.Finding, 0, len(order))
	for _, key := range order {
		entry := groups[key]
		if len(entry.values) < 3 {
			result = append(result, entry.finding)
			continue
		}
		metadata := findingMetadata(entry.finding)
		metadata["credential_values"] = entry.values
		metadata["credential_variables"] = []string{"OSDJoinAccount", "OSDJoinPassword", "OSDLocalAdminPassword"}
		metadata["artifact_records"] = entry.refs
		encoded, err := json.Marshal(metadata)
		if err == nil {
			entry.finding.EvidenceJSON = string(encoded)
		}
		result = append(result, entry.finding)
	}
	return result
}

func cloneFindingMetadata(metadata map[string]any) map[string]any {
	clone := make(map[string]any, len(metadata))
	for key, value := range metadata {
		clone[key] = value
	}
	return clone
}

func appendUniqueStrings(values []string, additions ...string) []string {
	seen := make(map[string]bool, len(values)+len(additions))
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range additions {
		if value != "" && !seen[value] {
			values = append(values, value)
			seen[value] = true
		}
	}
	return values
}

func pxeCredentialValues(metadata map[string]any) map[string]string {
	values := make(map[string]string)
	raw, _ := metadata["credential_values"].(map[string]any)
	if raw == nil {
		if typed, ok := metadata["credential_values"].(map[string]string); ok {
			for name, value := range typed {
				if strings.TrimSpace(value) != "" {
					values[canonicalInlinePXEName(name)] = value
				}
			}
			return values
		}
	}
	for name, value := range raw {
		if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
			values[canonicalInlinePXEName(name)] = text
		}
	}
	return values
}

func pxeCredentialValuesFromLines(lines []string) map[string]string {
	values := make(map[string]string)
	for _, line := range lines {
		match := pxeInlineVariable.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) != 3 {
			continue
		}
		name := canonicalInlinePXEName(strings.TrimSpace(match[1]))
		if !containsString([]string{"OSDJoinAccount", "OSDJoinPassword", "OSDLocalAdminPassword"}, name) {
			continue
		}
		value := strings.TrimSpace(match[2])
		if value != "" {
			if name == "OSDJoinAccount" {
				value = normalizePXEAccountDisplay(value)
			}
			values[name] = value
		}
	}
	return values
}

func isPXECredentialFinding(finding storage.Finding) bool {
	typ := strings.ToLower(finding.FindingType)
	return (strings.EqualFold(finding.SourceTool, "PXEThief") || strings.Contains(strings.ToLower(finding.SourceTool), "pxethief")) && strings.Contains(typ, "credential")
}

func pxeCredentialValuesFromRawLines(lines []string) map[string]string {
	values := make(map[string]string)
	for _, line := range lines {
		match := pxeInlineVariable.FindStringSubmatch(line)
		if len(match) != 3 {
			continue
		}
		name := canonicalInlinePXEName(match[1])
		value := strings.TrimSpace(match[2])
		if value == "" || strings.EqualFold(value, "none") || strings.EqualFold(value, "null") || values[name] != "" {
			continue
		}
		if name == "OSDJoinAccount" {
			value = normalizePXEAccountDisplay(value)
		}
		values[name] = value
	}
	return values
}

func pxeCredentialSetKey(values map[string]string) string {
	return strings.Join([]string{values["OSDJoinAccount"], values["OSDJoinPassword"], values["OSDLocalAdminPassword"]}, "\x00")
}

func normalizePXEAccountDisplay(value string) string {
	for strings.Contains(value, `\\`) {
		value = strings.ReplaceAll(value, `\\`, `\`)
	}
	return value
}

func (m *model) beginFindingsLoad() tea.Cmd {
	if !m.findingsAsync || m.db == nil || m.findingsLoaded || m.findingsLoading {
		return nil
	}
	m.findingsLoading = true
	m.findingsLoadGeneration++
	generation := m.findingsLoadGeneration
	db, ctx, targetID := m.db, m.ctx, m.targetID
	return func() tea.Msg {
		rows, err := db.ListFindings(ctx, targetID)
		if err != nil {
			return findingsLoadedMsg{generation: generation, err: err}
		}
		rows = append(rows, findingengine.DeriveInformationalFindings(ctx, rows)...)
		return findingsLoadedMsg{generation: generation, rows: rows, status: findingsStatusLabel(db, ctx, targetID)}
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
	m.findingCursor = min(max(0, m.findingCategoryCursor), max(0, len(m.findingCategories)-1))
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
		target := displayFindingObject(finding.AffectedObject, finding.AffectedObjectID)
		if len(entry.rights) == 1 && strings.EqualFold(entry.rights[0], "genericall") {
			finding.Title = fmt.Sprintf("GenericAll over AD User: %s", target)
		} else {
			finding.Title = fmt.Sprintf("AD ACL relationship over %s (%s)", target, strings.Join(entry.rights, ", "))
		}
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
	return findingSeverityForDisplay(finding) != "informational"
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
		if m.findingCategory == "critical" {
			return m.criticalNavigationOverview(width)
		}
		if m.findingTieringView {
			return m.findingTieringOverview(width)
		}
		if m.findingSubcategoryView {
			return m.findingSubcategoryOverview(width)
		}
		return m.findingCategoryOverview(width)
	}
	var content strings.Builder
	content.WriteString(m.findingsHeader() + "\n")
	content.WriteString("\n")
	if m.findingCategory == "critical" {
		content.WriteString(dim.Render(wrapFindingNotice(criticalFindingsNotice, width-4)) + "\n\n")
	}
	m.keepFindingVisible()
	end := min(len(m.findingRows), m.findingTop+m.findingPageSize())
	if m.findingDetail && len(m.findingRows) > 0 {
		projectionFinding := m.findingRows[m.findingCursor]
		finding := m.activeFindingForDetail(projectionFinding)
		finding = m.hydrateHistoricalACLInventory(finding)
		finding = m.hydrateHistoricalUserDescription(finding)
		var detail strings.Builder
		detail.WriteString(findingDetailHeader(finding, width-4) + "\n\n")
		detail.WriteString(wrapPaneText(findingCondition(finding), width-4) + "\n\n")
		detail.WriteString(findingAttributes(finding, width-4))
		if state := findingengine.CriticalStateOf(projectionFinding); state == findingengine.CriticalConfirmed || state == findingengine.CriticalPotential {
			metadata := findingMetadata(projectionFinding)
			section := "CRITICAL QUALIFICATION"
			style := severityCriticalStyle
			if state == findingengine.CriticalPotential {
				section = "POTENTIAL CRITICAL — NOT VERIFIED"
				style = unverified
			}
			value := style.Render(metadataString(metadata, "reason"))
			if unknown := stringSlice(metadata["unverified_prerequisites"]); len(unknown) > 0 {
				value += "\n" + unverified.Render("Unverified: "+strings.Join(unknown, "; "))
			}
			detail.WriteString("\n" + findingSection(section, value, width-4))
		} else if qualification, ok := findingengine.ClassifyCritical(finding); ok {
			detail.WriteString("\n" + findingSection("CRITICAL QUALIFICATION", severityCriticalStyle.Render(qualification.RuleID)+"\n"+qualification.Reason, width-4))
		}
		if m.inlineEvidenceLoading {
			detail.WriteString("\n" + dim.Render("Loading recovered evidence…") + "\n")
		} else if m.inlineEvidence.section != "" {
			detail.WriteString("\n" + lipgloss.NewStyle().Bold(true).Render(m.inlineEvidence.section) + "\n")
			detail.WriteString(dim.Render("────────────────────────────────────────────") + "\n")
			if m.inlineEvidence.error != "" {
				detail.WriteString(warn.Render(m.inlineEvidence.error) + "\n")
			} else if isKerberosMaterialFinding(finding) {
				metadata := findingMetadata(finding)
				sourceCount := m.inlineEvidence.sourceRecordCount
				if sourceCount == 0 {
					sourceCount = metadataInt(metadata, "record_count")
				}
				if sourceCount > 0 {
					detail.WriteString(fmt.Sprintf("Matching source records: %d\n", sourceCount))
				}
				uniqueCount := m.inlineEvidence.uniqueMaterialCount
				if uniqueCount == 0 && len(m.inlineEvidence.lines) > 0 {
					uniqueCount = len(m.inlineEvidence.lines)
				}
				detail.WriteString(fmt.Sprintf("Unique material entries: %d\n", uniqueCount))
				detail.WriteString(fmt.Sprintf("Duplicate records: %d\n", m.inlineEvidence.duplicateRecordCount))
				detail.WriteString("\n" + infoBlueStyle().Bold(true).Render("COLLECTED KERBEROS MATERIAL") + "\n")
				for _, line := range m.inlineEvidence.lines {
					wrapped := strings.Split(wrapPaneText(line, max(8, width-6)), "\n")
					for _, wrappedLine := range wrapped {
						detail.WriteString("  " + warn.Render(wrappedLine) + "\n")
					}
				}
				if additional := m.inlineEvidence.uniqueMaterialCount - 1; additional > 0 {
					detail.WriteString(fmt.Sprintf("Additional unique hashes: %d\n", additional))
				}
				if m.inlineEvidence.accountScopedPath != "" {
					detail.WriteString("Account-scoped evidence: " + m.inlineEvidence.accountScopedPath + "\n")
				}
				detail.WriteString(dim.Render("E opens the complete original artifact; it may contain additional accounts." + "\n"))
			} else {
				page := max(1, m.findingPageSize()-10)
				endEvidence := min(len(m.inlineEvidence.lines), m.inlineEvidenceTop+page)
				for index := m.inlineEvidenceTop; index < endEvidence; index++ {
					line := m.inlineEvidence.lines[index]
					if strings.EqualFold(finding.SourceTool, "PXEThief") {
						line = stylePXECredentialLine(line)
					}
					detail.WriteString(line + "\n")
				}
				detail.WriteString(dim.Render(fmt.Sprintf("Evidence lines %d-%d of %d\n", min(m.inlineEvidenceTop+1, len(m.inlineEvidence.lines)), endEvidence, len(m.inlineEvidence.lines))))
			}
		}
		sectionName := "SECURITY IMPACT"
		if isInformationalFinding(finding) {
			sectionName = "OBSERVED CONFIGURATION"
		}
		detail.WriteString("\n" + findingSection(sectionName, findingImpact(finding), width-4))
		detail.WriteString(findingSection("EVIDENCE", findingEvidenceSummary(finding), width-4))
		if technique := findingTechniqueReference(finding); technique != "" {
			detail.WriteString(findingTechniqueSection(technique, width-4))
		}
		if len(m.criticalSourceFindings) > 1 {
			var supporting strings.Builder
			supporting.WriteString(fmt.Sprintf("Selected %d of %d source Findings\n", m.criticalSourceIndex+1, len(m.criticalSourceFindings)))
			for index, source := range m.criticalSourceFindings {
				supporting.WriteString(fmt.Sprintf("  %d. %s · Execution %d · %s\n", index+1, source.Title, source.SourceExecution, fallbackText(shortEvidencePath(source.ArtifactPath), "artifact unavailable")))
			}
			detail.WriteString(findingSection("SUPPORTING FINDINGS", strings.TrimSpace(supporting.String()), width-4))
		}
		detailLines := strings.Split(detail.String(), "\n")
		detailPageSize := max(1, m.findingPageSize()-4)
		maxDetailTop := max(0, len(detailLines)-detailPageSize)
		m.findingDetailTop = min(max(0, m.findingDetailTop), maxDetailTop)
		endDetail := min(len(detailLines), m.findingDetailTop+detailPageSize)
		content.WriteString(strings.Join(detailLines[m.findingDetailTop:endDetail], "\n"))
		footer := "\n↑/↓ Scroll    PgUp/PgDn Change Finding    ←/Esc Back    A Account Evidence    E Original Evidence    Q Quit"
		if len(m.criticalSourceFindings) > 1 {
			footer = "\n[/] Supporting Finding    " + strings.TrimPrefix(footer, "\n")
		}
		content.WriteString(dim.Render(footer))
		return paneStyle(false).Width(width).Render(content.String())
	}
	if len(m.findingRows) == 0 {
		if m.findingCategory == "critical" {
			content.WriteString(warn.Render("No findings meet the strict evidence-backed Critical Findings rules. This does not prove the environment is secure.") + "\n\n")
		} else {
			content.WriteString("No findings match the current filters.\n\n")
		}
	} else {
		for index := m.findingTop; index < end; index++ {
			finding := m.findingRows[index]
			if m.findingCategory == "critical" {
				stateChanged := index == m.findingTop || findingengine.CriticalStateOf(finding) != findingengine.CriticalStateOf(m.findingRows[index-1])
				groupChanged := index == m.findingTop || criticalDisplayGroup(finding) != criticalDisplayGroup(m.findingRows[index-1])
				if stateChanged {
					label := "CONFIRMED CRITICAL"
					if findingengine.CriticalStateOf(finding) == findingengine.CriticalPotential {
						label = "POTENTIAL CRITICAL — NOT VERIFIED"
					}
					content.WriteString(infoBlueStyle().Bold(true).Render(label) + "\n")
				}
				if stateChanged || groupChanged {
					content.WriteString("  " + infoBlueStyle().Render(criticalDisplayGroup(finding)) + "\n")
				}
			}
			selected := index == m.findingCursor
			content.WriteString(findingListRow(max(1, width-2), finding, selected) + "\n")
		}
	}
	content.WriteString(fmt.Sprintf("\n%d visible records (total database results are filtered)  rows %d-%d", len(m.findingRows), min(m.findingTop+1, len(m.findingRows)), min(end, len(m.findingRows))))
	content.WriteString(dim.Render("\n\n→/Enter Open    ←/Esc Back    Q Quit"))
	return paneStyle(false).Width(width).Render(content.String())
}

func isInformationalFinding(finding storage.Finding) bool {
	typ := strings.ToLower(strings.TrimSpace(finding.FindingType))
	return strings.HasPrefix(typ, "domain_information_") || typ == "ad_domain_policy_password_policy_snapshot"
}

func wrapFindingNotice(value string, width int) string {
	if width < 1 {
		width = 1
	}
	const breakSpace = "\ue000"
	wrapped := ansi.WrapWc(strings.ReplaceAll(value, " ", breakSpace), width, breakSpace+"\t/-")
	return strings.ReplaceAll(wrapped, breakSpace, " ")
}

func (m *model) findingsHeader() string {
	header := title.Render("PwnFlow // FINDINGS")
	if m.findingsOnly() {
		header += "  " + dim.Render("FINDINGS ONLY · OFFLINE")
	}
	return header
}

func isKerberosMaterialFinding(finding storage.Finding) bool {
	typ := strings.ToLower(finding.FindingType)
	return typ == "asrep_material_collected" || typ == "kerberos_ticket_material_collected"
}

type findingTableColumns struct {
	Name, Count, Severity int
}

func findingTableColumnsForWidth(width int) findingTableColumns {
	innerWidth := max(1, width-4)
	countWidth, severityWidth := 10, 12
	if width < 80 {
		countWidth = 6
	}
	return findingTableColumns{
		Name: max(16, innerWidth-2-1-countWidth-2-severityWidth), Count: countWidth, Severity: severityWidth,
	}
}

func findingTableHeader(width int, label string) string {
	columns := findingTableColumnsForWidth(width)
	countLabel := "FINDINGS"
	if width < 80 {
		countLabel = "COUNT"
	}
	return dim.Render(fmt.Sprintf("  %-*s %*s  %*s", columns.Name, label, columns.Count, countLabel, columns.Severity, severityHeader(width)))
}

func severityHeader(width int) string {
	if width < 80 {
		return "SEV"
	}
	return "SEVERITY"
}

func findingTableRow(width int, name string, count int, severity string, selected bool) string {
	columns := findingTableColumnsForWidth(width)
	name = truncateFinding(name, columns.Name)
	nameField := selectionLabel(name, selected) + strings.Repeat(" ", max(0, columns.Name-ansi.StringWidthWc(name)))
	severityText := strings.ToUpper(strings.TrimSpace(severity))
	severityField := severityStyle(severity).Render(fmt.Sprintf("%*s", columns.Severity, severityText))
	return fmt.Sprintf("%s%s %*d  %s", selectionPrefix(selected), nameField, columns.Count, count, severityField)
}

func findingListRow(width int, finding storage.Finding, selected bool) string {
	severity := findingSeverityForDisplay(finding)
	severityText := strings.ToUpper(strings.TrimSpace(severity))
	severityWidth := max(12, ansi.StringWidthWc("INFORMATIONAL"))
	prefix := selectionPrefix(selected)
	contentWidth := max(1, width-ansi.StringWidthWc(prefix))
	bodyWidth := max(1, contentWidth-severityWidth-1)
	title := displayFindingTitle(finding)
	object := displayFindingObject(finding.AffectedObject, finding.AffectedObjectID)
	const minimumTitleWidth = 12
	objectWidth := 0
	if bodyWidth > minimumTitleWidth+1 {
		objectWidth = min(max(18, bodyWidth/3), bodyWidth-minimumTitleWidth-1)
	}
	titleWidth := bodyWidth
	if objectWidth > 0 {
		titleWidth = bodyWidth - objectWidth - 1
	}
	title = truncateFinding(title, titleWidth)
	titleField := selectionLabel(title, selected) + strings.Repeat(" ", max(0, titleWidth-ansi.StringWidthWc(title)))
	if objectWidth > 0 {
		object = truncateFinding(object, objectWidth)
		titleField += " " + object + strings.Repeat(" ", max(0, objectWidth-ansi.StringWidthWc(object)))
	}
	severityField := severityStyle(severity).Render(fmt.Sprintf("%*s", severityWidth, severityText))
	return prefix + titleField + " " + severityField
}

func (m *model) findingTieringOverview(width int) string {
	counts := map[string]int{"tier0_context": 0, "tier1_context": 0, "tier2_context": 0}
	highest := map[string]string{"tier0_context": "NOT ASSESSED", "tier1_context": "NOT ASSESSED", "tier2_context": "NOT ASSESSED"}
	for _, finding := range m.findingAllRows {
		if findingCategoryKey(finding) == "active_directory" {
			if scope := findingTierScopeKey(finding); scope != "" {
				counts[scope]++
				if highest[scope] == "NOT ASSESSED" || severityRank(finding.Severity) > severityRank(highest[scope]) {
					highest[scope] = strings.ToUpper(finding.Severity)
				}
			}
		}
	}
	rows := []struct {
		name, description, severity string
		count                       int
	}{
		{"Tier 0 — Identity Control Plane", "Source-backed identity-control plane context", highest["tier0_context"], counts["tier0_context"]},
		{"Tier 1 — Server Administration", "Declared server-administration evidence scope", highest["tier1_context"], counts["tier1_context"]},
		{"Tier 2 — Workstation Administration", "Declared workstation-administration evidence scope", highest["tier2_context"], counts["tier2_context"]},
	}
	var content strings.Builder
	content.WriteString(title.Render("PwnFlow // ADMINISTRATIVE TIERING") + "\n")
	content.WriteString(dim.Render("Conceptual tier scopes; organization-specific policy is not inferred.") + "\n\n")
	content.WriteString(findingTableHeader(width, "CATEGORY") + "\n\n")
	for index, row := range rows {
		selected := index == m.findingCursor
		content.WriteString(findingTableRow(width, row.name, row.count, row.severity, selected) + "\n")
		content.WriteString("   " + dim.Render(wrapPaneText(row.description, max(20, width-7))) + "\n")
	}
	content.WriteString(dim.Render("\n→/Enter Open Tier    ←/Esc Back    Q Quit"))
	return paneStyle(false).Width(width).Render(content.String())
}

func findingDetailHeader(finding storage.Finding, width int) string {
	titleText := strings.ToUpper(displayFindingTitle(finding))
	displayedSeverity := findingSeverityForDisplay(finding)
	severity := strings.ToUpper(displayedSeverity)
	severityDisplayStyle := severityStyle(displayedSeverity)
	if width < 1 {
		width = 1
	}
	line := titleText + "  " + severityDisplayStyle.Render(severity)
	if ansi.StringWidthWc(line) <= width {
		return lipgloss.NewStyle().Bold(true).Render(titleText) + "  " + severityDisplayStyle.Render(severity)
	}
	return lipgloss.NewStyle().Bold(true).Render(wrapPaneText(titleText, width)) + "\n" + severityDisplayStyle.Render(severity)
}

func displayFindingTitle(finding storage.Finding) string {
	if !strings.EqualFold(finding.FindingType, "ghostspn_orphaned_spn") {
		return finding.Title
	}
	metadata := findingMetadata(finding)
	spn := metadataString(metadata, "spn")
	if spn == "" {
		spn = fallbackText(metadataString(metadata, "SPN"), finding.AffectedObject)
	}
	if spn == "" {
		return finding.Title
	}
	reason := metadataString(metadata, "reason")
	if ghostSPNAccountTypeObservationText(finding, reason) {
		return "SPN Account-Type Observation: " + spn
	}
	dnsStatus := strings.ToLower(metadataString(metadata, "dns_status"))
	lowerReason := strings.ToLower(reason)
	if strings.Contains(lowerReason, "orphan") || strings.Contains(lowerReason, "stale") || strings.Contains(lowerReason, "ghost") || strings.Contains(dnsStatus, "not resolved") {
		return "Potential Orphaned SPN: " + spn
	}
	return "SPN Configuration Anomaly: " + spn
}

func findingSeverityForDisplay(finding storage.Finding) string {
	if strings.EqualFold(finding.FindingType, "ghostspn_orphaned_spn") && ghostSPNAccountTypeObservationText(finding, metadataString(findingMetadata(finding), "reason")) {
		return "informational"
	}
	return finding.Severity
}

func findingCondition(finding storage.Finding) string {
	typ := strings.ToLower(finding.FindingType)
	if strings.HasPrefix(typ, "critical_projection_") {
		metadata := findingMetadata(finding)
		return fmt.Sprintf("%s: %s → %s\nCapability: %s\n%s", strings.ToUpper(metadataString(metadata, "family")), fallbackText(metadataString(metadata, "starting_principal"), "starting principal not specified"), fallbackText(metadataString(metadata, "target"), "target not specified"), fallbackText(metadataString(metadata, "capability"), "observed attack-path capability"), fallbackText(metadataString(metadata, "reason"), finding.Description))
	}
	if strings.HasPrefix(typ, "ad_user_description_") {
		principal := fallbackText(metadataString(findingMetadata(finding), "principal"), fallbackText(finding.AffectedObject, finding.AffectedObjectID))
		attribute := fallbackText(metadataString(findingMetadata(finding), "attribute"), "info")
		if typ == "ad_user_description_credential_exposed" {
			return fmt.Sprintf("NetExec observed a populated credential-related value in the %s attribute of %s. The value has not been tested for authentication.", attribute, principal)
		}
		return fmt.Sprintf("The LDAP %s attribute of %s contains credential-related text. No usable credential was established from this observation; it does not prove that a credential was disclosed.", attribute, principal)
	}
	if typ == "netexec_gpp_password_exposure" {
		metadata := findingMetadata(finding)
		return fmt.Sprintf("NetExec confirmed a recoverable password in a legacy Group Policy Preferences %s XML file.", fallbackText(metadataString(metadata, "preference_type"), "preference"))
	}
	if strings.HasPrefix(typ, "domain_information_") {
		return informationalFindingCondition(finding)
	}
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
	metadata := protectedFindingMetadata(finding)
	typ := strings.ToLower(strings.TrimSpace(finding.FindingType))
	if strings.HasPrefix(typ, "critical_projection_") {
		lines := []string{}
		add := func(label, value string) {
			if strings.TrimSpace(value) != "" {
				lines = append(lines, fmt.Sprintf("  %-22s %s", label, value))
			}
		}
		add("TARGET", metadataString(metadata, "target"))
		add("TARGET TYPE", metadataString(metadata, "target_type"))
		add("STARTING PRINCIPAL", metadataString(metadata, "starting_principal"))
		add("CAPABILITY", metadataString(metadata, "capability"))
		if values := stringSlice(metadata["confirmed_prerequisites"]); len(values) > 0 {
			add("CONFIRMED", strings.Join(values, "; "))
		}
		return strings.Join(lines, "\n")
	}
	if typ == "ad_acl_group" || (strings.HasPrefix(typ, "ad_acl_") && !isGeneralACLInventory(finding)) || typ == "ad_writable_object_assessment" || strings.HasPrefix(typ, "adcs_esc_") {
		return ""
	}
	if typ == "unconstrained_delegation_configured" || typ == "constrained_delegation_configured" || typ == "rbcd_observed" {
		return delegationFindingAttributes(finding, metadata, width)
	}
	if strings.HasPrefix(typ, "ad_account_") {
		return accountSecurityFindingAttributes(metadata, finding, width)
	}
	if strings.HasPrefix(strings.ToLower(finding.FindingType), "ad_user_description_") {
		return userDescriptionAttributes(metadata, finding, width)
	}
	if strings.EqualFold(finding.FindingType, "netexec_gpp_password_exposure") {
		return gppFindingAttributes(metadata, width)
	}
	if strings.EqualFold(finding.FindingType, "ghostspn_orphaned_spn") {
		return ghostSPNFindingAttributes(metadata, finding, width)
	}
	if strings.EqualFold(finding.FindingType, "gpo_security_configuration_observed") {
		return gpoConfigurationAttributes(metadata, finding, width)
	}
	var lines []string
	add := func(label, value string) {
		if strings.TrimSpace(value) != "" {
			lines = append(lines, fmt.Sprintf("  %-12s %s", label, value))
		}
	}
	if strings.EqualFold(finding.FindingType, "netexec_gpp_password_exposure") {
		add("SOURCE", fallbackText(metadataString(metadata, "source"), finding.SourceTool))
		add("PREFERENCE", metadataString(metadata, "preference_type"))
		add("GPO", metadataString(metadata, "gpo"))
		add("XML PATH", metadataString(metadata, "xml_path"))
		add("ACCOUNT", metadataString(metadata, "account"))
		add("CREDENTIAL", metadataString(metadata, "credential_state"))
	} else if isGeneralACLInventory(finding) {
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
		affected := displayFindingObject(finding.AffectedObject, finding.AffectedObjectID)
		if relayTargetIsExplicit(finding, metadata, affected) {
			affected = warn.Render(affected)
		}
		add("AFFECTED", affected)
	}
	if finding.RelatedObject != "" || finding.RelatedObjectID != "" {
		add("ACCOUNT", displayFindingObject(finding.RelatedObject, finding.RelatedObjectID))
	}
	add("PROTOCOL", metadataString(metadata, "protocol"))
	add("HOST", metadataString(metadata, "host"))
	add("INDICATOR", findingIndicator(finding))
	add("OBJECT", metadataString(metadata, "object_name"))
	condition := explicitCondition(finding)
	if strings.EqualFold(finding.FindingType, "smb_signing_not_required") && smbSigningObservationIsFalse(metadata) {
		condition = warn.Render(condition)
	}
	add("CONDITION", condition)
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

func ghostSPNFindingAttributes(metadata map[string]any, finding storage.Finding, width int) string {
	account := fallbackText(metadataString(metadata, "account_sam"), fallbackText(metadataString(metadata, "account"), fallbackText(metadataString(metadata, "principal"), finding.AffectedObject)))
	spn := metadataString(metadata, "spn")
	if spn == "" {
		spn = metadataString(metadata, "SPN")
	}
	hostname := metadataString(metadata, "hostname")
	dnsState := fallbackText(metadataString(metadata, "dns_status"), metadataString(metadata, "resolution"))
	if dnsState == "" {
		dnsState = "NOT VERIFIED"
	}
	reason := metadataString(metadata, "reason")
	if reason == "" {
		reason = finding.Description
	}
	fields := [][2]string{{"Account", account}, {"SPN", spn}, {"Host component", hostname}, {"DNS verification", dnsState}, {"Account state", "NOT VERIFIED"}, {"Condition", ghostSPNConditionLabel(finding, reason)}, {"Reason", reason}}
	var content strings.Builder
	content.WriteString(infoBlueStyle().Bold(true).Render("SPN OBSERVATION") + "\n")
	content.WriteString(formatGhostSPNFields(fields[:4], width))
	content.WriteString(infoBlueStyle().Bold(true).Render("DETECTOR RESULT") + "\n")
	content.WriteString(formatGhostSPNFields(fields[4:], width))
	return content.String()
}

func ghostSPNConditionLabel(finding storage.Finding, reason string) string {
	if ghostSPNAccountTypeObservationText(finding, reason) {
		return "Account-type observation"
	}
	if strings.Contains(strings.ToLower(finding.Title), "orphaned") {
		return "Potential orphaned or stale SPN"
	}
	return "Configuration anomaly reported by GhostSPN"
}

func ghostSPNAccountTypeObservationText(finding storage.Finding, reason string) bool {
	return strings.Contains(strings.ToLower(reason), "user account spns cannot request service tickets") || strings.Contains(strings.ToLower(finding.Title), "account-type observation")
}

func formatGhostSPNFields(fields [][2]string, width int) string {
	const labelWidth = 18
	valueWidth := max(8, width-labelWidth-5)
	continuation := "  " + strings.Repeat(" ", labelWidth+3)
	var content strings.Builder
	for _, field := range fields {
		if strings.TrimSpace(field[1]) == "" {
			continue
		}
		wrapped := strings.Split(wrapPaneText(field[1], valueWidth), "\n")
		value := wrapped[0]
		if strings.EqualFold(value, "NOT VERIFIED") {
			value = unverified.Render(value)
		} else if strings.EqualFold(field[0], "Condition") || strings.EqualFold(field[0], "DNS state") {
			value = warn.Render(value)
		}
		label := infoBlueStyle().Render(field[0]) + strings.Repeat(" ", max(0, labelWidth-ansi.StringWidthWc(field[0])))
		content.WriteString("  " + label + " : " + value + "\n")
		for _, line := range wrapped[1:] {
			content.WriteString(continuation + line + "\n")
		}
	}
	return content.String()
}

func accountSecurityFindingAttributes(metadata map[string]any, finding storage.Finding, width int) string {
	account := fallbackText(metadataString(metadata, "account"), fallbackText(finding.AffectedObject, finding.AffectedObjectID))
	flag := fallbackText(metadataString(metadata, "flag"), "account security condition")
	uac := fallbackText(metadataString(metadata, "user_account_control"), "NOT VERIFIED")
	enabled := "NOT VERIFIED"
	if value, ok := metadata["enabled"].(bool); ok {
		if value {
			enabled = "Enabled"
		} else {
			enabled = "Disabled"
		}
	}
	fields := [][2]string{{"Account", account}, {"Condition", flag}, {"Enabled", enabled}, {"Observed state", uac}}
	var content strings.Builder
	content.WriteString(infoBlueStyle().Bold(true).Render("ACCOUNT SECURITY CONDITION") + "\n")
	content.WriteString(formatAccountSecurityFields(fields, width))
	return content.String()
}

func formatAccountSecurityFields(fields [][2]string, width int) string {
	const labelWidth = 18
	valueWidth := max(8, width-labelWidth-5)
	continuation := "  " + strings.Repeat(" ", labelWidth+3)
	var content strings.Builder
	for _, field := range fields {
		if strings.TrimSpace(field[1]) == "" {
			continue
		}
		wrapped := strings.Split(wrapPaneText(field[1], valueWidth), "\n")
		value := wrapped[0]
		if strings.EqualFold(value, "NOT VERIFIED") {
			value = unverified.Render(value)
		}
		if strings.EqualFold(field[0], "Condition") {
			value = warn.Render(value)
		}
		label := infoBlueStyle().Render(field[0]) + strings.Repeat(" ", max(0, labelWidth-ansi.StringWidthWc(field[0])))
		content.WriteString("  " + label + " : " + value + "\n")
		for _, line := range wrapped[1:] {
			content.WriteString(continuation + line + "\n")
		}
	}
	return content.String()
}

func userDescriptionAttributes(metadata map[string]any, finding storage.Finding, width int) string {
	account := fallbackText(metadataString(metadata, "principal"), fallbackText(finding.AffectedObject, finding.AffectedObjectID))
	attribute := fallbackText(metadataString(metadata, "attribute"), "info")
	value := metadataString(metadata, "value")
	if value == "" {
		value = metadataString(metadata, "attribute_value")
	}
	if account == "" && attribute == "" && value == "" {
		return ""
	}
	fields := [][2]string{{"Account", account}, {"Attribute", attribute}, {"Value", value}}
	var content strings.Builder
	content.WriteString(infoBlueStyle().Bold(true).Render("OBSERVED DIRECTORY ATTRIBUTE") + "\n")
	// The matched directory attribute value is the suspicious evidence for
	// both keyword-only and credential-like observations. Keep the label
	// styling separate so emphasis never colors the literal "Value" label.
	content.WriteString(formatObservedAttributeFields(fields, width, true))
	return content.String()
}

func formatObservedAttributeFields(fields [][2]string, width int, sensitive bool) string {
	const labelWidth = 12
	valueWidth := max(8, width-labelWidth-5)
	continuation := "  " + strings.Repeat(" ", labelWidth+3)
	var content strings.Builder
	for _, field := range fields {
		if strings.TrimSpace(field[1]) == "" {
			continue
		}
		wrapped := strings.Split(wrapPaneText(field[1], valueWidth), "\n")
		valueStyle := lipgloss.NewStyle()
		if sensitive && field[0] == "Value" {
			valueStyle = warn
		}
		label := infoBlueStyle().Render(field[0]) + strings.Repeat(" ", max(0, labelWidth-ansi.StringWidthWc(field[0])))
		content.WriteString("  " + label + " : " + valueStyle.Render(wrapped[0]) + "\n")
		for _, line := range wrapped[1:] {
			content.WriteString(continuation + valueStyle.Render(line) + "\n")
		}
	}
	return content.String()
}

func gppFindingAttributes(metadata map[string]any, width int) string {
	fields := [][2]string{
		{"ACCOUNT", metadataString(metadata, "account")},
		{"PASSWORD", metadataString(metadata, "password")},
		{"CREDENTIAL", metadataString(metadata, "credential_state")},
		{"PREFERENCE", metadataString(metadata, "preference_type")},
		{"SOURCE", metadataString(metadata, "source")},
		{"GPO", metadataString(metadata, "gpo")},
		{"XML PATH", metadataString(metadata, "xml_path")},
	}
	var content strings.Builder
	content.WriteString(infoBlueStyle().Bold(true).Render("RECOVERED CREDENTIAL") + "\n")
	content.WriteString(formatCredentialFields(fields[:2], width))
	content.WriteString(formatFindingFields(fields[2:], width))
	return content.String() + "\n"
}

func formatCredentialFields(fields [][2]string, width int) string {
	if width < 1 {
		width = 1
	}
	const labelWidth = 12
	valueWidth := max(8, width-labelWidth-5)
	continuation := "  " + strings.Repeat(" ", labelWidth+3)
	var content strings.Builder
	for _, field := range fields {
		if strings.TrimSpace(field[1]) == "" {
			continue
		}
		wrapped := strings.Split(wrapPaneText(field[1], valueWidth), "\n")
		label := infoBlueStyle().Render(field[0]) + strings.Repeat(" ", max(0, labelWidth-ansi.StringWidthWc(field[0])))
		content.WriteString("  " + label + " = " + warn.Render(wrapped[0]) + "\n")
		for _, line := range wrapped[1:] {
			content.WriteString(continuation + warn.Render(line) + "\n")
		}
	}
	return content.String()
}

func formatFindingFields(fields [][2]string, width int) string {
	if width < 1 {
		width = 1
	}
	const labelWidth = 12
	valueWidth := max(8, width-labelWidth-3)
	continuation := "  " + strings.Repeat(" ", labelWidth) + " "
	var content strings.Builder
	for _, field := range fields {
		if strings.TrimSpace(field[1]) == "" {
			continue
		}
		wrapped := strings.Split(wrapPaneText(field[1], valueWidth), "\n")
		content.WriteString(fmt.Sprintf("  %-12s %s", field[0], wrapped[0]))
		for _, line := range wrapped[1:] {
			content.WriteString("\n" + continuation + line)
		}
		content.WriteByte('\n')
	}
	return content.String()
}

func findingSection(name, value string, width int) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return "\n" + findingSectionStyle(name).Render(name) + "\n" + wrapPaneText(value, width) + "\n"
}

func infoBlueStyle() lipgloss.Style { return lipgloss.NewStyle().Foreground(infoBlue).Bold(true) }

var highImpactADPermissionTokens = map[string]struct{}{
	"genericall": {}, "genericwrite": {}, "writedacl": {}, "writeowner": {}, "owns": {}, "allextendedrights": {},
	"forcechangepassword": {}, "addmember": {}, "addmembers": {}, "addself": {}, "addkeycredentiallink": {},
	"addallowedtoact": {}, "writeaccountrestrictions": {}, "writespn": {}, "writegplink": {},
	"getchanges": {}, "getchangesall": {}, "getchangesinfilteredset": {}, "manageca": {}, "managecertificates": {},
}

var adPermissionTokenPattern = regexp.MustCompile(`[[:alpha:]][[:alnum:]]*`)

func highlightADPermissionValues(value string) string {
	return adPermissionTokenPattern.ReplaceAllStringFunc(value, func(token string) string {
		if _, ok := highImpactADPermissionTokens[strings.ToLower(token)]; ok {
			return warn.Render(token)
		}
		return token
	})
}

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

func formatACLSourceRecords(metadata map[string]any) string {
	records, ok := metadata["source_records"].([]any)
	if !ok || len(records) < 2 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\nContributing executions:")
	for _, raw := range records {
		record, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "\n  %d — %s", metadataInt(record, "execution"), fallbackText(shortEvidencePath(stringValue(record["artifact"])), "artifact unavailable"))
	}
	return b.String()
}

func findingEvidenceSummary(finding storage.Finding) string {
	if strings.HasPrefix(strings.ToLower(finding.FindingType), "critical_projection_") {
		metadata := findingMetadata(finding)
		lines := []string{"PwnFlow Critical Projection"}
		records, _ := metadata["evidence_chain"].([]any)
		for _, raw := range records {
			record, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			lines = append(lines, fmt.Sprintf("Execution %d · Artifact: %s · Reference: %s", metadataInt(record, "source_execution"), fallbackText(shortEvidencePath(stringValue(record["artifact_path"])), "artifact unavailable"), fallbackText(stringValue(record["artifact_ref"]), "reference unavailable")))
		}
		return strings.Join(lines, "\n")
	}
	if strings.EqualFold(finding.SourceTool, "PXEThief") && strings.Contains(strings.ToLower(finding.FindingType), "credential") {
		metadata := findingMetadata(finding)
		refs := stringSlice(metadata["artifact_records"])
		if len(refs) == 0 && finding.ArtifactRef != "" {
			refs = []string{finding.ArtifactRef}
		}
		return fmt.Sprintf("PXEThief — Execution %d\nArtifact: %s\nSource lines: %s", finding.SourceExecution, fallbackText(shortEvidencePath(finding.ArtifactPath), "source artifact unavailable"), strings.Join(refs, ", "))
	}
	if strings.EqualFold(finding.FindingType, "netexec_gpp_password_exposure") {
		metadata := findingMetadata(finding)
		return fmt.Sprintf("%s — Execution %d\nArtifact: %s\nSource reference: %s\nEvidence: %s", fallbackText(finding.SourceTool, "NetExec (nxc)"), finding.SourceExecution, fallbackText(shortEvidencePath(finding.ArtifactPath), "source artifact unavailable"), fallbackText(finding.ArtifactRef, "source reference unavailable"), fallbackText(metadataString(metadata, "evidence_excerpt"), "GPP recovery marker"))
	}
	if strings.HasPrefix(strings.ToLower(finding.FindingType), "adcs_esc_") {
		metadata := findingMetadata(finding)
		return fmt.Sprintf("Certipy · Execution %d\nOriginal artifact: %s\nSource reference: %s%s", finding.SourceExecution, fallbackText(shortEvidencePath(finding.ArtifactPath), "source artifact unavailable"), fallbackText(finding.ArtifactRef, "source reference unavailable"), formatACLSourceRecords(metadata))
	}
	if strings.EqualFold(finding.FindingType, "ad_replication_rights_evidence_overview") {
		metadata := findingMetadata(finding)
		return fmt.Sprintf("%s\nFull report: %s\nStructured evidence: %s%s", fallbackText(finding.SourceTool, "RustHound-CE"), fallbackText(shortEvidencePath(metadataString(metadata, "human_report")), shortEvidencePath(finding.ArtifactPath)), fallbackText(shortEvidencePath(metadataString(metadata, "structured_artifact")), "execution-associated replication-rights JSON"), formatACLSourceRecords(metadata))
	}
	if strings.EqualFold(finding.FindingType, "ad_writable_object_assessment") {
		metadata := findingMetadata(finding)
		lines := []string{fmt.Sprintf("%s — Execution %d", fallbackText(finding.SourceTool, "AD Writable Object Assessment"), finding.SourceExecution), fmt.Sprintf("Authenticated identity: %s", fallbackText(metadataString(metadata, "authenticated_user"), fallbackText(finding.AffectedObject, finding.AffectedObjectID))), fmt.Sprintf("Relationships included: %d of %d", metadataIntDefault(metadata, "included_relationships", lenMetadataRelationships(metadata)), metadataIntDefault(metadata, "qualifying_relationships", lenMetadataRelationships(metadata))), fmt.Sprintf("Source artifact: %s", fallbackText(metadataString(metadata, "source_artifact"), "source artifact unavailable")), fmt.Sprintf("Assessment report: %s", fallbackText(shortEvidencePath(finding.ArtifactPath), "writable-objects.json"))}
		if records, ok := metadata["source_records"].([]any); ok && len(records) > 1 {
			lines = append(lines, "Contributing reports:")
			for _, raw := range records {
				record, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				lines = append(lines, fmt.Sprintf("  Execution %d — %s", metadataInt(record, "execution"), fallbackText(shortEvidencePath(stringValue(record["artifact"])), "artifact unavailable")))
			}
		}
		return strings.Join(lines, "\n")
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
		return fmt.Sprintf("%s\nSource artifacts: %s\nFull report: %s\nStructured inventory: %s%s", fallbackText(finding.SourceTool, "RustHound-CE"), aclEvidenceNames(metadata), fallbackText(metadataString(metadata, "human_report"), "AD_PRIVILEGED_ACL_EVIDENCE.txt"), fallbackText(structured, "execution-associated ACL inventory JSON"), formatACLSourceRecords(metadata))
	}
	if isGeneralACLInventory(finding) {
		metadata := findingMetadata(finding)
		return fmt.Sprintf("%s\nFull report: %s\nStructured inventory: %s%s", fallbackText(finding.SourceTool, "RustHound-CE"), fallbackText(shortEvidencePath(metadataString(metadata, "human_report")), shortEvidencePath(finding.ArtifactPath)), fallbackText(shortEvidencePath(metadataString(metadata, "structured_artifact")), "execution-associated ACL inventory JSON"), formatACLSourceRecords(metadata))
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
	if strings.EqualFold(finding.FindingType, "unconstrained_delegation_configured") {
		return "The Hacker Recipes — Unconstrained Kerberos Delegation\nhttps://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained"
	}
	if strings.EqualFold(finding.FindingType, "constrained_delegation_configured") {
		return "The Hacker Recipes — Constrained Kerberos Delegation\nhttps://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained"
	}
	if strings.EqualFold(finding.FindingType, "rbcd_observed") {
		return "The Hacker Recipes — Resource-Based Constrained Delegation\nhttps://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd"
	}
	if strings.EqualFold(finding.FindingType, "ad_gpo_privilege_relationship_evidence") {
		metadata := findingMetadata(finding)
		return fmt.Sprintf("%s — Execution %d\nFull report: %s\nStructured evidence: %s", finding.SourceTool, finding.SourceExecution, shortEvidencePath(finding.ArtifactPath), fallbackText(metadataString(metadata, "structured_artifact"), "execution-associated GPO privilege JSON"))
	}
	if strings.HasPrefix(strings.ToLower(finding.FindingType), "adcs_esc_") {
		return "Certipy — " + certipyESCType(finding, findingMetadata(finding)) + "\nhttps://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation\nhttps://www.thehacker.recipes/ad/movement/adcs/"
	}
	if strings.HasPrefix(strings.ToLower(finding.FindingType), "ad_domain_policy_") {
		metadata := findingMetadata(finding)
		lines := []string{"NetExec domain password-policy evidence"}
		if records, ok := metadata["source_records"].([]any); ok {
			for _, raw := range records {
				record, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				lines = append(lines, fmt.Sprintf("%s — Execution %v · Artifact: %s · Reference: %s", fallbackText(stringValue(record["title"]), "Password policy observation"), record["execution"], fallbackText(shortEvidencePath(stringValue(record["artifact"])), "artifact unavailable"), fallbackText(stringValue(record["reference"]), "reference unavailable")))
			}
		}
		if len(lines) == 1 {
			lines = append(lines, fmt.Sprintf("Execution %d · Artifact: %s · Reference: %s", finding.SourceExecution, fallbackText(shortEvidencePath(finding.ArtifactPath), "artifact unavailable"), fallbackText(finding.ArtifactRef, "reference unavailable")))
		}
		return strings.Join(lines, "\n")
	}
	if strings.EqualFold(finding.FindingType, "ad_protected_accounts_admincount_evidence") {
		metadata := findingMetadata(finding)
		lines := []string{"RustHound protected-account evidence"}
		if records, ok := metadata["source_records"].([]any); ok && len(records) > 0 {
			for _, raw := range records {
				record, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				lines = append(lines, fmt.Sprintf("Execution %v · Artifact: %s · Reference: %s", fallbackText(fmt.Sprint(record["execution"]), "unknown"), fallbackText(shortEvidencePath(stringValue(record["artifact"])), "artifact unavailable"), fallbackText(stringValue(record["reference"]), "reference unavailable")))
			}
		} else {
			lines = append(lines, fmt.Sprintf("Execution %d · Artifact: %s · Reference: %s", finding.SourceExecution, fallbackText(shortEvidencePath(finding.ArtifactPath), "artifact unavailable"), fallbackText(finding.ArtifactRef, "reference unavailable")))
		}
		return strings.Join(lines, "\n")
	}
	if isTierContextFinding(finding) {
		metadata := findingMetadata(finding)
		lines := []string{finding.SourceTool + " administrative tier evidence"}
		if records, ok := metadata["source_records"].([]any); ok && len(records) > 0 {
			for _, raw := range records {
				record, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				lines = append(lines, fmt.Sprintf("Execution %v · Artifact: %s · Reference: %s", record["execution"], fallbackText(shortEvidencePath(stringValue(record["artifact"])), "artifact unavailable"), fallbackText(stringValue(record["reference"]), "reference unavailable")))
			}
		} else {
			lines = append(lines, fmt.Sprintf("Execution %d · Artifact: %s · Reference: %s", finding.SourceExecution, fallbackText(shortEvidencePath(finding.ArtifactPath), "artifact unavailable"), fallbackText(finding.ArtifactRef, "reference unavailable")))
		}
		return strings.Join(lines, "\n")
	}
	return fmt.Sprintf("%s · Execution %d\n%s %s", finding.SourceTool, finding.SourceExecution, finding.ArtifactPath, finding.ArtifactRef)
}

func findingTechniqueReference(finding storage.Finding) string {
	typ := strings.ToLower(strings.TrimSpace(finding.FindingType))
	if strings.HasPrefix(typ, "critical_projection_") {
		switch {
		case strings.Contains(typ, "adcs_esc_"):
			return certipyTechniqueReference(finding, strings.TrimPrefix(typ, "critical_projection_"))
		case strings.Contains(typ, "dcsync"):
			return "The Hacker Recipes — DCSync\nhttps://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync"
		case strings.Contains(typ, "acl_control"):
			return "The Hacker Recipes — DACL Abuse\nhttps://legacy.thehacker.recipes/a-d/movement/dacl"
		case strings.Contains(typ, "ntlm_relay"):
			return "The Hacker Recipes — NTLM relay\nhttps://www.thehacker.recipes/ad/movement/ntlm/relay"
		case strings.Contains(typ, "credential_disclosure"):
			return "The Hacker Recipes — SCCM / MECM\nhttps://www.thehacker.recipes/ad/movement/sccm-mecm/"
		}
	}
	if strings.HasPrefix(typ, "adcs_esc_") {
		return certipyTechniqueReference(finding, typ)
	}
	if strings.EqualFold(finding.FindingType, "ghostspn_orphaned_spn") {
		if ghostSPNAccountTypeObservationText(finding, metadataString(findingMetadata(finding), "reason")) {
			return ""
		}
		return "The Hacker Recipes — SPN Jacking\nhttps://dev.thehacker.recipes/ad/movement/kerberos/spn-jacking"
	}
	if isPXECredentialFinding(finding) {
		return "Misconfiguration Manager — CRED-1: Retrieve secrets from PXE boot media\nhttps://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-1/cred-1_description.md"
	}
	if strings.EqualFold(finding.FindingType, "netexec_gpp_password_exposure") {
		return "SpecterOps / SharpUp — Cached GPP Password\nhttps://docs.specterops.io/ghostpack-docs/SharpUp-mdx/checks/cachedgpppassword"
	}
	if strings.EqualFold(finding.FindingType, "kerberos_ticket_material_collected") || strings.EqualFold(finding.FindingType, "kerberoastable_account") {
		return "The Hacker Recipes — Kerberoasting\nhttps://www.thehacker.recipes/ad/movement/kerberos/roasting/kerberoast"
	}
	if strings.EqualFold(finding.FindingType, "asrep_material_collected") || strings.EqualFold(finding.FindingType, "asrep_roastable_account") {
		return "The Hacker Recipes — AS-REP Roasting\nhttps://www.thehacker.recipes/ad/movement/kerberos/roasting/asreproast"
	}
	if typ == "relay_exposure_observed" {
		return "The Hacker Recipes — NTLM relay\nhttps://www.thehacker.recipes/ad/movement/ntlm/relay"
	}
	if typ == "smb_signing_not_required" {
		return "The Hacker Recipes — NTLM relay\nhttps://www.thehacker.recipes/ad/movement/ntlm/relay"
	}
	if typ == "unconstrained_delegation_configured" || typ == "constrained_delegation_configured" || typ == "rbcd_observed" {
		return "The Hacker Recipes — Kerberos delegations\nhttps://legacy.thehacker.recipes/a-d/movement/kerberos/delegations"
	}
	if typ == "ad_replication_rights_evidence_overview" {
		return "The Hacker Recipes — DCSync\nhttps://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync"
	}
	if typ == "sccm_task_sequence_credentials_exposed" {
		return "The Hacker Recipes — SCCM / MECM\nhttps://www.thehacker.recipes/ad/movement/sccm-mecm/"
	}
	if strings.EqualFold(finding.FindingType, "ad_tier0_context_evidence") {
		return "SpecterOps — The Security Principle Every Attacker Needs to Follow\nhttps://specterops.io/blog/2024/07/17/the-security-principle-every-attacker-needs-to-follow/\nSpecterOps — TierZeroTable\nhttps://github.com/SpecterOps/TierZeroTable"
	}
	if strings.EqualFold(finding.FindingType, "ad_gpo_privilege_relationship_evidence") {
		return "The Hacker Recipes — Group Policies\nhttps://www.thehacker.recipes/ad/movement/group-policies"
	}
	if isGeneralACLInventory(finding) || strings.HasPrefix(strings.ToLower(finding.FindingType), "ad_acl_") {
		return "The Hacker Recipes — DACL Abuse\nhttps://legacy.thehacker.recipes/a-d/movement/dacl\nBloodHound — GenericAll edge\nhttps://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html"
	}
	return ""
}

func certipyTechniqueReference(finding storage.Finding, typ string) string {
	esc := strings.ToUpper(strings.TrimPrefix(typ, "adcs_esc_"))
	switch esc {
	case "ESC1", "ESC2", "ESC3", "ESC15", "ESC17":
		return "The Hacker Recipes — AD CS certificate templates\nhttps://www.thehacker.recipes/ad/movement/adcs/certificate-templates"
	case "ESC4":
		return "The Hacker Recipes — AD CS access controls\nhttps://legacy.thehacker.recipes/a-d/movement/ad-cs/access-controls"
	case "ESC6", "ESC7":
		return "The Hacker Recipes — AD CS certificate authority\nhttps://www.thehacker.recipes/ad/movement/adcs/certificate-authority"
	case "ESC8":
		return "The Hacker Recipes — AD CS unsigned endpoints / ESC8\nhttps://www.thehacker.recipes/ad/movement/adcs/unsigned-endpoints\nThe Hacker Recipes — AD CS\nhttps://www.thehacker.recipes/ad/movement/adcs/"
	default:
		return ""
	}
}

func relayTargetIsExplicit(finding storage.Finding, metadata map[string]any, affected string) bool {
	if !strings.EqualFold(strings.TrimSpace(finding.FindingType), "relay_exposure_observed") {
		return false
	}
	destination := strings.TrimSpace(metadataString(metadata, "destination"))
	return destination != "" && strings.EqualFold(destination, strings.TrimSpace(affected)) && net.ParseIP(destination) != nil
}

func findingTechniqueSection(reference string, width int) string {
	if strings.TrimSpace(reference) == "" {
		return ""
	}
	return "\n" + findingSectionStyle("TECHNIQUES").Render("TECHNIQUES") + "\n" + wrapPaneText(reference, width) + "\n" + dim.Render("Shift + Left Mouse — Copy link") + "\n"
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
	if strings.EqualFold(finding.FindingType, "netexec_gpp_password_exposure") {
		return "The exposed account's privileges, credential validity and subsequent access were not established. No additional access was attempted solely from this detection."
	}
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
	if strings.EqualFold(finding.FindingType, "ad_writable_object_assessment") {
		metadata := findingMetadata(finding)
		lines := []string{"Observed permissions do not establish effective Windows access or a verified directory modification. Deny precedence, inheritance applicability, object-specific schema resolution, SIDHistory, protected groups and complete membership expansion were not fully evaluated."}
		if count := metadataInt(metadata, "omitted_relationships"); count > 0 {
			lines = append(lines, fmt.Sprintf("%d qualifying relationships were omitted by the bounded report cap.", count))
		}
		if limitations := metadataStringSlice(metadata, "limitations"); len(limitations) > 0 {
			lines = append(lines, "Analysis limitations: "+strings.Join(limitations, "; "))
		}
		return strings.Join(lines, "\n")
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
	return metadataIntDefault(metadata, key, 0)
}

func metadataBool(metadata map[string]any, key string) bool {
	value, ok := metadata[key]
	if !ok {
		return false
	}
	boolean, _ := value.(bool)
	return boolean
}

func metadataIntDefault(metadata map[string]any, key string, fallback int) int {
	value, ok := metadata[key]
	if !ok {
		return fallback
	}
	switch number := value.(type) {
	case float64:
		return int(number)
	case int:
		return number
	default:
		return fallback
	}
}

func lenMetadataRelationships(metadata map[string]any) int {
	values, ok := metadata["relationships"].([]any)
	if !ok {
		return 0
	}
	return len(values)
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
		fmt.Fprintf(&b, "\n%s\n", infoBlueStyle().Bold(true).Render("DOMAIN ROOT"))
		fmt.Fprintf(&b, "  %s : %s [%s]\n", infoBlueStyle().Render("IDENTITY"), fallbackText(metadataString(root, "name"), metadataString(root, "id")), metadataString(root, "id"))
		principals, _ := root["principals"].([]any)
		for _, rawPrincipal := range principals {
			principal, ok := rawPrincipal.(map[string]any)
			if !ok {
				continue
			}
			fmt.Fprintf(&b, "\n  %s : %s [%s]\n", infoBlueStyle().Render("PRINCIPAL"), fallbackText(metadataString(principal, "name"), metadataString(principal, "id")), metadataString(principal, "id"))
			fmt.Fprintf(&b, "  %s : %s\n", infoBlueStyle().Render("TYPE"), fallbackText(metadataString(principal, "type"), "unknown"))
			rights, _ := principal["rights"].([]any)
			for _, rawRight := range rights {
				right, ok := rawRight.(map[string]any)
				if !ok {
					continue
				}
				status := strings.ToUpper(metadataString(right, "status"))
				if status == "NOT_OBSERVED" || status == "UNKNOWN" {
					status = unverified.Render(status)
				}
				fmt.Fprintf(&b, "    %s : %s\n", infoBlueStyle().Render("RIGHT"), highlightADPermissionValues(metadataString(right, "right")))
				fmt.Fprintf(&b, "    %s : %s\n", infoBlueStyle().Render("STATUS"), status)
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
		for index, raw := range relationships {
			relation, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			principal := fallbackText(metadataString(relation, "principal_name"), "(unresolved principal)")
			principalID := metadataString(relation, "principal_id")
			target := fallbackText(metadataString(relation, "target_name"), "(unnamed target)")
			targetID := metadataString(relation, "target_id")
			fmt.Fprintf(&b, "\nRELATIONSHIP %d\n", index+1)
			fmt.Fprintf(&b, "  %s : %s [%s]\n", infoBlueStyle().Render("PRINCIPAL"), principal, principalID)
			fmt.Fprintf(&b, "  %s : %s [%s]\n", infoBlueStyle().Render("TARGET"), target, targetID)
			fmt.Fprintf(&b, "  %s : %s\n", infoBlueStyle().Render("TARGET TYPE"), metadataString(relation, "target_type"))
			fmt.Fprintf(&b, "  %s : %s\n", infoBlueStyle().Render("PERMISSION"), highlightADPermissionValues(metadataString(relation, "permission")))
			fmt.Fprintf(&b, "  %s : %s\n", infoBlueStyle().Render("ACE DECISION"), fallbackText(metadataString(relation, "decision"), "unknown"))
			fmt.Fprintf(&b, "  %s : %s\n", infoBlueStyle().Render("INHERITANCE"), fallbackText(metadataString(relation, "inheritance"), "unknown"))
			fmt.Fprintf(&b, "  %s : %s", infoBlueStyle().Render("EFFECTIVE ACCESS"), unverified.Render("NOT VERIFIED"))
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
	b.WriteString(infoBlueStyle().Bold(true).Render("ACL EVIDENCE INVENTORY") + "\n")
	b.WriteString("RustHound recorded an aggregate Active Directory ACL inventory.\n\n")
	b.WriteString(infoBlueStyle().Bold(true).Render("SUMMARY") + "\n")
	for _, field := range [][2]string{{"Observed ACL records", metadataCount(metadata, "source_supported_ace_count")}, {"Retained records", metadataCount(metadata, "retained_ace_count")}, {"Explicit ACEs", metadataCount(metadata, "explicit_count")}, {"Inherited ACEs", metadataCount(metadata, "inherited_count")}, {"Unknown decisions", metadataCount(metadata, "unknown_decision_count")}} {
		fmt.Fprintf(&b, "  %s : %s\n", infoBlueStyle().Render(field[0]), field[1])
	}
	if examples, ok := metadata["examples"].([]any); ok && len(examples) > 0 {
		type relationship struct {
			principal, target, targetType, decision, inheritance string
			rights                                               []string
		}
		groups := make(map[string]*relationship)
		order := make([]string, 0)
		for _, raw := range examples {
			record, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			principal := fallbackText(metadataString(record, "principal_name"), metadataString(record, "principal_id"))
			target := fallbackText(metadataString(record, "target_name"), metadataString(record, "target_id"))
			key := strings.Join([]string{principal, target, metadataString(record, "target_type"), metadataString(record, "decision"), metadataString(record, "inheritance")}, "\x00")
			group := groups[key]
			if group == nil {
				group = &relationship{principal: principal, target: target, targetType: metadataString(record, "target_type"), decision: fallbackText(metadataString(record, "decision"), "unknown"), inheritance: fallbackText(metadataString(record, "inheritance"), "unknown")}
				groups[key] = group
				order = append(order, key)
			}
			right := fallbackText(metadataString(record, "permission"), "UNKNOWN")
			if !containsString(group.rights, right) {
				group.rights = append(group.rights, right)
			}
		}
		b.WriteString("\n" + infoBlueStyle().Bold(true).Render("OBSERVED ACL RELATIONSHIPS") + "\n")
		for index, key := range order {
			if index >= 12 {
				break
			}
			group := groups[key]
			fmt.Fprintf(&b, "\nRELATIONSHIP %d\n", index+1)
			fmt.Fprintf(&b, "  %s : %s\n", infoBlueStyle().Render("PRINCIPAL"), group.principal)
			fmt.Fprintf(&b, "  %s : %s\n", infoBlueStyle().Render("TARGET"), group.target)
			if group.targetType != "" {
				fmt.Fprintf(&b, "  %s : %s\n", infoBlueStyle().Render("TARGET TYPE"), group.targetType)
			}
			fmt.Fprintf(&b, "  %s : %s\n", infoBlueStyle().Render("PERMISSION"), highlightADPermissionValues(strings.Join(group.rights, ", ")))
			fmt.Fprintf(&b, "  %s : %s\n", infoBlueStyle().Render("ACE DECISION"), group.decision)
			fmt.Fprintf(&b, "  %s : %s\n", infoBlueStyle().Render("INHERITANCE"), group.inheritance)
			fmt.Fprintf(&b, "  %s : %s\n", infoBlueStyle().Render("EFFECTIVE ACCESS"), unverified.Render("NOT VERIFIED"))
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
	case typ == "ghostspn_orphaned_spn":
		spn := fallbackText(metadataString(metadata, "spn"), fallbackText(finding.AffectedObject, "SPN unavailable in source evidence"))
		reason := metadataString(metadata, "reason")
		if reason == "" {
			reason = finding.Description
		}
		if ghostSPNAccountTypeObservationText(finding, reason) {
			return fmt.Sprintf("ghostSPN reported an account-type observation for %s. %s This is not evidence of an orphaned host or SPN-jacking.", spn, reason)
		}
		return fmt.Sprintf("ghostSPN reported a possible orphaned or stale SPN %s. %s This does not establish SPN-jacking or effective control.", spn, reason)
	case strings.HasPrefix(typ, "domain_information_"):
		return informationalFindingConditionFromMetadata(finding, metadata)
	case typ == "ad_domain_policy_password_policy_snapshot":
		domain := fallbackText(metadataString(metadata, "domain"), fallbackText(finding.AffectedObject, "domain identity unavailable in source evidence"))
		scope := fallbackText(metadataString(metadata, "policy_scope"), "domain policy")
		return formatPasswordPolicyFindingCondition(finding, metadata, domain, scope)
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
		return formatPasswordPolicyFindingCondition(finding, metadata, domain, scope)
	case typ == "asrep_material_collected" || typ == "kerberos_ticket_material_collected":
		kind := fallbackText(metadataString(metadata, "material_type"), "Kerberos material")
		principal := fallbackText(metadataString(metadata, "principal"), fallbackText(finding.AffectedObject, "principal identity unavailable in source evidence"))
		count := metadataInt(metadata, "record_count")
		scope := "The original evidence artifact may contain additional qualifying records."
		if count > 0 {
			return fmt.Sprintf("NetExec recorded %s associated with %s (%d source record(s) for this principal). This Finding represents one principal; %s Matching material is limited to this principal.", kind, principal, count, scope)
		}
		return fmt.Sprintf("NetExec recorded %s associated with %s. %s Matching material is limited to this principal.", kind, principal, scope)
	case typ == "ad_user_description_keyword_observed":
		principal := fallbackText(metadataString(metadata, "principal"), fallbackText(finding.AffectedObject, "principal identity unavailable in source evidence"))
		attribute := fallbackText(metadataString(metadata, "attribute"), "account information")
		keyword := fallbackText(metadataString(metadata, "keyword"), "credential-related language")
		return fmt.Sprintf("NetExec observed the keyword %q in the %s attribute for %s. The keyword is not proof that a credential was disclosed.", keyword, attribute, principal)
	case typ == "ad_writable_object_assessment":
		return formatWritableObjectCondition(metadata, finding)
	case typ == "ad_acl_group" || (strings.HasPrefix(typ, "ad_acl_") && !isGeneralACLInventory(finding)):
		principal := fallbackText(metadataString(metadata, "principal_name"), finding.RelatedObject)
		target := fallbackText(metadataString(metadata, "target_name"), finding.AffectedObject)
		permission := fallbackText(metadataString(metadata, "permission"), strings.TrimPrefix(typ, "ad_acl_"))
		decision := fallbackText(metadataString(metadata, "ace_decision"), "unknown")
		inheritance := fallbackText(metadataString(metadata, "inheritance"), "unknown")
		return strings.Join([]string{
			infoBlueStyle().Bold(true).Render("OBSERVED ACL RELATIONSHIP"),
			infoBlueStyle().Render("PRINCIPAL") + " : " + principal,
			infoBlueStyle().Render("TARGET") + " : " + target,
			infoBlueStyle().Render("PERMISSION") + " : " + highlightADPermissionValues(permission),
			infoBlueStyle().Render("ACE DECISION") + " : " + decision,
			infoBlueStyle().Render("INHERITANCE") + " : " + inheritance,
			infoBlueStyle().Render("EFFECTIVE AUTHORIZATION") + " : " + unverified.Render("NOT VERIFIED"),
		}, "\n")
	case strings.HasPrefix(typ, "adcs_esc_"):
		return formatCertipyESCCondition(finding, metadata)
	case typ == "gpo_evidence_inventory":
		return formatGPOEvidenceCondition(metadata, finding)
	case typ == "ad_gpo_privilege_relationship_evidence":
		return formatGPOPrivilegeCondition(metadata, finding)
	case typ == "gpo_security_configuration_observed":
		return formatGPOConfigurationCondition(metadata, finding)
	case typ == "ad_protected_accounts_admincount_evidence":
		return formatProtectedAccountsCondition(metadata, finding)
	case typ == "ad_tier0_context_evidence":
		return formatTier0StyledCondition(metadata, finding)
	case typ == "ad_tier1_context_evidence" || typ == "ad_tier2_context_evidence":
		return formatTierContextCondition(finding)
	}
	return ""
}

func informationalFindingCondition(finding storage.Finding) string {
	return informationalFindingConditionFromMetadata(finding, findingMetadata(finding))
}

func formatWritableObjectCondition(metadata map[string]any, finding storage.Finding) string {
	identity := fallbackText(metadataString(metadata, "authenticated_user"), fallbackText(finding.AffectedObject, finding.AffectedObjectID))
	relationships, _ := metadata["relationships"].([]any)
	lines := []string{
		infoBlueStyle().Bold(true).Render("ASSESSMENT IDENTITY"),
		infoBlueStyle().Render("ACCOUNT") + " : " + identity,
		"",
		infoBlueStyle().Bold(true).Render("OBSERVED WRITABLE RELATIONSHIPS"),
	}
	if len(relationships) == 0 {
		lines = append(lines, "No source-backed writable relationships were retained in this report.")
		return strings.Join(lines, "\n")
	}
	for index, raw := range relationships {
		relationship, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		principal := fallbackText(metadataString(relationship, "principal_name"), metadataString(relationship, "principal_id"))
		target := fallbackText(metadataString(relationship, "target_name"), metadataString(relationship, "target_id"))
		permission := fallbackText(metadataString(relationship, "permission"), "unknown")
		decision := fallbackText(metadataString(relationship, "decision"), "unknown")
		inheritance := fallbackText(metadataString(relationship, "inheritance"), "unknown")
		targetType := metadataString(relationship, "target_type")
		lines = append(lines,
			fmt.Sprintf("\nRELATIONSHIP %d", index+1),
			infoBlueStyle().Render("TARGET")+" : "+target,
		)
		if targetType != "" {
			lines = append(lines, infoBlueStyle().Render("TARGET TYPE")+" : "+targetType)
		}
		lines = append(lines,
			infoBlueStyle().Render("PERMISSION")+" : "+highlightADPermissionValues(permission),
			infoBlueStyle().Render("PRINCIPAL")+" : "+principal,
			infoBlueStyle().Render("ACE DECISION")+" : "+decision,
			infoBlueStyle().Render("INHERITANCE")+" : "+inheritance,
			infoBlueStyle().Render("EFFECTIVE ACCESS")+" : "+unverified.Render("NOT VERIFIED"),
		)
	}
	return strings.Join(lines, "\n")
}

func informationalFindingConditionFromMetadata(finding storage.Finding, metadata map[string]any) string {
	typ := strings.ToLower(finding.FindingType)
	switch typ {
	case "domain_information_user_inventory":
		return informationalFieldRows("DOMAIN USER INVENTORY", []informationalField{
			{"Total users:", strconv.Itoa(metadataInt(metadata, "distinct_user_count"))},
			{"Enabled:", strconv.Itoa(metadataInt(metadata, "enabled_count"))},
			{"Disabled:", strconv.Itoa(metadataInt(metadata, "disabled_count"))},
			{"Unknown status:", strconv.Itoa(metadataInt(metadata, "status_unknown_count"))},
			{"Coverage:", fallbackText(metadataString(metadata, "coverage"), "unknown")},
		})
	case "domain_information_privileged_group_membership":
		return informationalFieldRows("PRIVILEGED GROUP MEMBERSHIP", []informationalField{
			{"Group:", fallbackText(metadataString(metadata, "group_name"), fallbackText(finding.AffectedObject, "unknown group"))},
			{"SID:", fallbackText(metadataString(metadata, "group_id"), finding.AffectedObjectID)},
			{"Direct members:", strconv.Itoa(metadataInt(metadata, "direct_member_count"))},
			{"Effective members:", strconv.Itoa(metadataInt(metadata, "effective_member_count"))},
			{"Unresolved members:", strconv.Itoa(metadataInt(metadata, "unresolved_count"))},
			{"Coverage:", fallbackText(metadataString(metadata, "coverage"), "unknown")},
		})
	case "domain_information_domain_controllers":
		controllers, _ := metadata["controllers"].([]any)
		rows := []informationalField{{"Verified count:", strconv.Itoa(metadataInt(metadata, "verified_domain_controller_count"))}}
		for index, raw := range controllers {
			controller, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			addresses := metadataStringSlice(controller, "addresses")
			prefix := fmt.Sprintf("DC %d ", index+1)
			rows = append(rows,
				informationalField{prefix + "FQDN:", fallbackText(metadataString(controller, "fqdn"), "unknown")},
				informationalField{prefix + "Domain:", fallbackText(metadataString(controller, "domain"), "unknown")},
				informationalField{prefix + "IP addresses:", fallbackText(strings.Join(addresses, ", "), "unknown")},
			)
		}
		rows = append(rows, informationalField{"Coverage:", fallbackText(metadataString(metadata, "coverage"), "unknown")})
		return informationalFieldRows("DOMAIN CONTROLLERS", rows)
	case "ad_domain_policy_password_policy_snapshot":
		return formatPasswordPolicyObservation(metadata)
	default:
		return finding.Description
	}
}

type informationalField struct {
	label string
	value string
}

func informationalFieldRows(title string, fields []informationalField) string {
	lines := []string{title}
	for _, field := range fields {
		lines = append(lines, fmt.Sprintf("%-20s %s", field.label, field.value))
	}
	return strings.Join(lines, "\n")
}

func formatPasswordPolicyObservation(metadata map[string]any) string {
	fields, _ := metadata["fields"].(map[string]any)
	if len(fields) == 0 {
		return "Observed domain default password policy; no structured policy fields were retained."
	}
	labels := []struct{ key, label string }{
		{"minimum_password_length", "minimum length"}, {"maximum_password_age", "maximum age"}, {"minimum_password_age", "minimum age"},
		{"password_history_length", "history length"}, {"account_lockout_threshold", "lockout threshold"}, {"account_lockout_duration", "lockout duration"},
		{"lockout_observation_window", "lockout observation window"}, {"password_complexity", "complexity"},
	}
	values := make([]informationalField, 0, len(labels)+1)
	for _, item := range labels {
		field, ok := fields[item.key].(map[string]any)
		if !ok {
			continue
		}
		value := fallbackText(metadataString(field, "raw"), "unknown")
		state := metadataString(field, "state")
		if state != "" && !strings.EqualFold(state, "observed") {
			value += " [" + state + "]"
		}
		values = append(values, informationalField{strings.Title(item.label) + ":", value})
	}
	return informationalFieldRows("PASSWORD POLICY", append([]informationalField{{"Scope:", fallbackText(metadataString(metadata, "policy_scope"), "domain default policy")}}, values...))
}

func formatPasswordPolicyFindingCondition(finding storage.Finding, metadata map[string]any, domain, scope string) string {
	var content strings.Builder
	section := func(name string) { content.WriteString("\n" + infoBlueStyle().Bold(true).Render(name) + "\n") }
	row := func(label, value, state string, highlight bool) {
		if strings.TrimSpace(value) == "" {
			return
		}
		padding := max(1, 27-ansi.StringWidthWc(label))
		style := lipgloss.NewStyle()
		switch {
		case tierWarningState(state) || strings.EqualFold(state, "unknown"):
			style = unverified
		case highlight:
			style = warn
		}
		content.WriteString("  " + infoBlueStyle().Render(label) + strings.Repeat(" ", padding) + ": " + style.Render(value))
		if state != "" && !strings.EqualFold(state, "observed") {
			content.WriteString(" " + style.Render("["+state+"]"))
		}
		content.WriteByte('\n')
	}
	section("PASSWORD POLICY")
	row("Scope", scope, "", false)
	row("Domain", domain, "", false)
	fields, _ := metadata["fields"].(map[string]any)
	labels := []struct{ key, label string }{
		{"minimum_password_length", "Minimum Length"},
		{"maximum_password_age", "Maximum Age"},
		{"minimum_password_age", "Minimum Age"},
		{"password_history_length", "History Length"},
		{"account_lockout_threshold", "Lockout Threshold"},
		{"account_lockout_duration", "Lockout Duration"},
		{"lockout_observation_window", "Lockout Reset Window"},
		{"password_complexity", "Complexity"},
	}
	for _, item := range labels {
		field, _ := fields[item.key].(map[string]any)
		value := metadataString(field, "raw")
		state := metadataString(field, "state")
		if value == "" && item.key == "minimum_password_length" {
			if minimum := metadataInt(metadata, "minimum_password_length"); minimum > 0 {
				value, state = strconv.Itoa(minimum), "observed"
			}
		}
		highlight := item.key == "minimum_password_length" && metadataInt(metadata, "minimum_password_length") > 0 && metadataInt(metadata, "minimum_password_length") < 8
		row(item.label, value, state, highlight)
	}
	if limitation := metadataString(metadata, "fine_grained_policy_limitation"); limitation != "" {
		section("VERIFICATION STATE")
		content.WriteString("  " + infoBlueStyle().Render("Fine-grained policies") + strings.Repeat(" ", 27-ansi.StringWidthWc("Fine-grained policies")) + ": " + unverified.Render(limitation) + "\n")
	}
	content.WriteString(dim.Render("Original password-policy evidence remains available through E — Original Evidence.\n"))
	_ = finding
	return strings.TrimSpace(content.String())
}

func formatProtectedAccountsCondition(metadata map[string]any, finding storage.Finding) string {
	var content strings.Builder
	section := func(name string) { content.WriteString("\n" + infoBlueStyle().Bold(true).Render(name) + "\n") }
	row := func(label, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		labelWidth := 28
		padding := max(1, labelWidth-ansi.StringWidthWc(label))
		content.WriteString("  " + infoBlueStyle().Render(label) + strings.Repeat(" ", padding) + ": " + warn.Render(value) + "\n")
	}
	section("ADMINCOUNT OBSERVATIONS")
	if execution := finding.SourceExecution; execution > 0 {
		row("Execution", strconv.FormatInt(execution, 10))
	}
	if value := metadataInt(metadata, "admincount_users"); value >= 0 {
		row("Users adminCount=true", strconv.Itoa(value))
	}
	if value := metadataInt(metadata, "admincount_groups"); value >= 0 {
		row("Groups adminCount=true", strconv.Itoa(value))
	}
	if value := metadataInt(metadata, "membership_paths"); value >= 0 {
		row("Membership paths retained", strconv.Itoa(value))
	}
	if users, ok := metadata["admincount_user_examples"].([]any); ok {
		section("PRIVILEGED ACCOUNT OBSERVATIONS")
		for index, raw := range users {
			if index >= 16 {
				break
			}
			if object, ok := raw.(map[string]any); ok {
				row("Account", fallbackText(stringValue(object["name"]), stringValue(object["id"])))
				row("adminCount", fallbackText(stringValue(object["admin_count"]), "unknown"))
				row("Membership", fallbackText(stringValue(object["membership"]), "not_observed"))
			}
		}
	}
	if paths, ok := metadata["membership_examples"].([]any); ok && len(paths) > 0 {
		section("PROTECTED-GROUP MEMBERSHIP")
		for index, raw := range paths {
			if index >= 8 {
				content.WriteString(dim.Render("  Additional membership paths are available through E.\n"))
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
				row("Path", strings.Join(names, " → "))
				row("Membership", classification)
			}
		}
	}
	if differences, ok := metadata["attribute_membership_differences"].([]any); ok && len(differences) > 0 {
		section("ATTRIBUTE / MEMBERSHIP DIFFERENCES")
		for index, raw := range differences {
			if index >= 6 {
				content.WriteString(dim.Render("  Additional differences are available through E.\n"))
				break
			}
			object, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			row("Principal", fallbackText(stringValue(object["name"]), stringValue(object["id"])))
			row("adminCount", fallbackText(stringValue(object["admin_count"]), "unknown"))
			row("Membership", fallbackText(stringValue(object["membership"]), "unknown"))
		}
	}
	if holder, ok := metadata["admin_sdholder"].(map[string]any); ok {
		section("ADMINSDHOLDER")
		row("Object", fallbackText(stringValue(holder["distinguished_name"]), fallbackText(stringValue(holder["name"]), stringValue(holder["id"]))))
		if aces, ok := holder["aces"].([]any); ok {
			row("Observed ACEs", strconv.Itoa(len(aces)))
			for index, raw := range aces {
				if index >= 3 {
					content.WriteString(dim.Render("  Additional ACEs are available through E.\n"))
					break
				}
				ace, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				row("Principal", fallbackText(stringValue(ace["principal"]), stringValue(ace["principal_id"])))
				row("Right", fallbackText(stringValue(ace["rights"]), "right unavailable"))
			}
		}
		row("Security descriptor", "NOT VERIFIED")
		row("SDProp application", "NOT VERIFIED")
	}
	if unavailable := metadataString(metadata, "identity_preview_unavailable"); unavailable != "" {
		content.WriteString(warn.Render("Identity preview unavailable: "+unavailable) + "\n")
		content.WriteString(dim.Render("Full evidence remains available through E — Original Evidence.\n"))
	}
	if value := metadataInt(metadata, "omitted_membership_paths"); value > 0 {
		row("Membership paths omitted", strconv.Itoa(value))
	}
	row("Effective protection", "NOT VERIFIED")
	content.WriteString(dim.Render("Additional original evidence is available through E — Original Evidence.\n"))
	return strings.TrimSpace(content.String())
}

func formatTier0StyledCondition(metadata map[string]any, finding storage.Finding) string {
	var content strings.Builder
	section := func(name string) { content.WriteString("\n" + infoBlueStyle().Bold(true).Render(name) + "\n") }
	row := func(label, value string, warning bool) {
		if strings.TrimSpace(value) == "" {
			return
		}
		padding := max(1, 27-ansi.StringWidthWc(label))
		content.WriteString("  " + infoBlueStyle().Render(label) + strings.Repeat(" ", padding) + ": ")
		content.WriteString(tierValueStyle(label, value, warning).Render(value))
		content.WriteByte('\n')
	}
	section("TIER 0 ADMINISTRATIVE CONTEXT")
	row("Domain", metadataString(metadata, "domain"), false)
	row("Source execution", strconv.FormatInt(finding.SourceExecution, 10), false)
	if controllers, ok := metadata["domain_controllers"].([]any); ok && len(controllers) > 0 {
		section("DOMAIN CONTROL CONTEXT")
		for _, raw := range controllers {
			if controller, ok := raw.(map[string]any); ok {
				row("Domain controller", fallbackText(stringValue(controller["name"]), stringValue(controller["id"])), false)
			}
		}
	}
	if groups, ok := metadata["tier0_groups"].([]any); ok && len(groups) > 0 {
		section("TIER 0-ASSOCIATED GROUPS")
		for index, raw := range groups {
			if index >= 16 {
				content.WriteString(dim.Render("  Additional groups are available through E — Original Evidence.\n"))
				break
			}
			if group, ok := raw.(map[string]any); ok {
				row("Group", fallbackText(stringValue(group["name"]), stringValue(group["id"])), false)
			}
		}
	}
	if principals, ok := metadata["tier0_principals"].([]any); ok && len(principals) > 0 {
		section("PRIVILEGED PRINCIPALS")
		for index, raw := range principals {
			if index >= 16 {
				content.WriteString(dim.Render("  Additional principals are available through E — Original Evidence.\n"))
				break
			}
			if principal, ok := raw.(map[string]any); ok {
				row("Principal", fallbackText(stringValue(principal["name"]), stringValue(principal["id"])), false)
			}
		}
	}
	if paths, ok := metadata["membership_paths"].([]any); ok && len(paths) > 0 {
		section("OBSERVED MEMBERSHIPS")
		for index, raw := range paths {
			if index >= 16 {
				content.WriteString(dim.Render("  Additional memberships are available through E — Original Evidence.\n"))
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
				row("Membership path", strings.Join(names, " → "), false)
			}
			row("Membership state", fallbackText(stringValue(path["classification"]), "observed"), false)
		}
	}
	if acls, ok := metadata["acl_relationships"].([]any); ok && len(acls) > 0 {
		section("ACL CONFIGURATION CONTEXT")
		for index, raw := range acls {
			if index >= 16 {
				content.WriteString(dim.Render("  Additional ACL relationships are available through E — Original Evidence.\n"))
				break
			}
			acl, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			row("Principal", fallbackText(stringValue(acl["principal_name"]), stringValue(acl["principal_id"])), false)
			row("Permission", fallbackText(stringValue(acl["permission"]), "unknown"), false)
			row("Target", fallbackText(stringValue(acl["target_name"]), stringValue(acl["target_id"])), false)
		}
		row("Effective authorization", "NOT VERIFIED", true)
	}
	if roots, ok := metadata["replication_rights"].([]any); ok && len(roots) > 0 {
		section("REPLICATION RIGHTS")
		for _, rawRoot := range roots {
			root, ok := rawRoot.(map[string]any)
			if !ok {
				continue
			}
			for _, rawPrincipal := range anySlice(root["principals"]) {
				principal, ok := rawPrincipal.(map[string]any)
				if !ok {
					continue
				}
				for _, rawRight := range anySlice(principal["rights"]) {
					right, ok := rawRight.(map[string]any)
					if !ok {
						continue
					}
					row("Principal", fallbackText(stringValue(principal["name"]), stringValue(principal["id"])), false)
					row("Right", stringValue(right["right"]), false)
					row("Status", strings.ToUpper(fallbackText(stringValue(right["status"]), "unknown")), true)
				}
			}
		}
		content.WriteString(dim.Render("Observed replication rights do not by themselves verify effective DCSync capability.\n"))
	}
	if users, ok := metadata["admincount_users"].([]any); ok && len(users) > 0 {
		section("ADMINCOUNT / ADMINSDHOLDER")
		row("adminCount observations", strconv.Itoa(len(users)), false)
	}
	section("ADMINISTRATIVE ACCESS VERIFICATION")
	row("Host-local Administrators", "NOT VERIFIED", true)
	row("Effective authorization", "NOT VERIFIED", true)
	row("Tier boundary status", "NOT VERIFIED", true)
	content.WriteString(dim.Render("Additional original evidence is available through E — Original Evidence.\n"))
	return strings.TrimSpace(content.String())
}

func tierValueStyle(label, value string, warning bool) lipgloss.Style {
	if warning || tierWarningState(value) {
		return unverified
	}
	if strings.EqualFold(strings.TrimSpace(label), "Source execution") || strings.Contains(strings.ToLower(label), "source") {
		return dim
	}
	return lipgloss.NewStyle()
}

func tierWarningState(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.Contains(value, "not verified") || strings.Contains(value, "incomplete") || strings.Contains(value, "unknown") || strings.Contains(value, "unverified")
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
	return strings.Join(lines, "\n")
}

func formatTierContextCondition(finding storage.Finding) string {
	metadata := findingMetadata(finding)
	typ := strings.ToLower(finding.FindingType)
	tier := metadataInt(metadata, "tier")
	if tier == 0 {
		if strings.Contains(typ, "tier2") {
			tier = 2
		} else if strings.Contains(typ, "tier1") {
			tier = 1
		}
	}
	var content strings.Builder
	section := func(name string) { content.WriteString("\n" + infoBlueStyle().Bold(true).Render(name) + "\n") }
	row := func(label, value string, warning bool) {
		if strings.TrimSpace(value) == "" {
			return
		}
		labelWidth := 27
		padding := max(1, labelWidth-ansi.StringWidthWc(label))
		content.WriteString("  " + infoBlueStyle().Render(label) + strings.Repeat(" ", padding) + ": " + tierValueStyle(label, value, warning).Render(value) + "\n")
	}
	section(fmt.Sprintf("TIER %d ADMINISTRATIVE CONTEXT", tier))
	row("Domain", metadataString(metadata, "domain"), false)
	row("Source execution", strconv.FormatInt(finding.SourceExecution, 10), false)
	if policy := metadataString(metadata, "policy_id"); policy != "" {
		section("DECLARED POLICY")
		row("Policy", policy, false)
		row("Policy source", metadataString(metadata, "policy_source"), false)
		row("Policy status", "DECLARED / EXTERNALLY DOCUMENTED", false)
	}
	if groups, ok := metadata["declared_groups"].([]any); ok && len(groups) > 0 {
		section("OBSERVED GROUPS")
		for _, raw := range groups {
			if group, ok := raw.(map[string]any); ok {
				row("Group", fallbackText(stringValue(group["name"]), stringValue(group["id"])), false)
			}
		}
	}
	if groups, ok := metadata["tier0_groups"].([]any); ok && len(groups) > 0 {
		section("TIER 0-ASSOCIATED GROUPS")
		for index, raw := range groups {
			if index >= 16 {
				break
			}
			if group, ok := raw.(map[string]any); ok {
				row("Group", fallbackText(stringValue(group["name"]), stringValue(group["id"])), false)
			}
		}
	}
	if principals, ok := metadata["tier0_principals"].([]any); ok && len(principals) > 0 {
		section("PRIVILEGED PRINCIPALS")
		for index, raw := range principals {
			if index >= 16 {
				break
			}
			if principal, ok := raw.(map[string]any); ok {
				row("Principal", fallbackText(stringValue(principal["name"]), stringValue(principal["id"])), false)
			}
		}
	}
	if paths, ok := metadata["membership_paths"].([]any); ok && len(paths) > 0 {
		section("OBSERVED MEMBERSHIPS")
		for index, raw := range paths {
			if index >= 16 {
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
				row("Path", strings.Join(names, " → "), false)
			}
			row("Classification", fallbackText(stringValue(path["classification"]), "observed"), false)
		}
	}
	if controllers, ok := metadata["domain_controllers"].([]any); ok && len(controllers) > 0 {
		section("DOMAIN CONTROLLERS")
		for _, raw := range controllers {
			if controller, ok := raw.(map[string]any); ok {
				row("Controller", fallbackText(stringValue(controller["name"]), stringValue(controller["id"])), false)
			}
		}
	}
	if targets, ok := metadata["targets"].([]any); ok && len(targets) > 0 {
		section("DECLARED ADMINISTRATIVE SCOPE")
		for _, raw := range targets {
			target, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			declared, _ := target["declared"].(map[string]any)
			row("Target", fallbackText(stringValue(declared["name"]), stringValue(declared["ip"])), false)
			row("Scope status", fallbackText(stringValue(target["status"]), "unresolved"), false)
		}
	}
	if acls, ok := metadata["acl_relationships"].([]any); ok && len(acls) > 0 {
		section("OBSERVED ACL RIGHTS")
		for index, raw := range acls {
			if index >= 16 {
				break
			}
			acl, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			row("Principal", fallbackText(stringValue(acl["principal_name"]), stringValue(acl["principal_id"])), false)
			row("Permission", fallbackText(stringValue(acl["permission"]), "unknown"), false)
			row("Target", fallbackText(stringValue(acl["target_name"]), stringValue(acl["target_id"])), false)
		}
	}
	if rights, ok := metadata["replication_rights"].([]any); ok && len(rights) > 0 {
		section("OBSERVED REPLICATION RIGHTS")
		for _, rawRoot := range rights {
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
				for _, rawRight := range anySlice(principal["rights"]) {
					right, ok := rawRight.(map[string]any)
					if !ok {
						continue
					}
					row("Principal", fallbackText(stringValue(principal["name"]), stringValue(principal["id"])), false)
					row("Right", stringValue(right["right"]), false)
					row("Status", strings.ToUpper(fallbackText(stringValue(right["status"]), "unknown")), false)
				}
			}
		}
		content.WriteString(dim.Render("Observed replication rights do not by themselves verify effective DCSync capability.\n"))
	}
	section("ADMINISTRATIVE ACCESS VERIFICATION")
	row("Host-local Administrators", "NOT VERIFIED", true)
	row("Effective authorization", "NOT VERIFIED", true)
	row("Tier-policy violation", "NOT VERIFIED", true)
	content.WriteString(dim.Render("Additional original evidence is available through E — Original Evidence.\n"))
	return strings.TrimSpace(content.String())
}

func anySlice(value any) []any {
	values, _ := value.([]any)
	return values
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
	var content strings.Builder
	section := func(name string) { content.WriteString("\n" + infoBlueStyle().Bold(true).Render(name) + "\n") }
	row := func(label, value string, warning, muted bool) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		padding := max(1, 24-ansi.StringWidthWc(label))
		style := lipgloss.NewStyle()
		if warning {
			style = unverified
		} else if muted {
			style = dim
		}
		content.WriteString("  " + infoBlueStyle().Render(label) + strings.Repeat(" ", padding) + ": " + style.Render(value) + "\n")
	}
	section("GPO PRIVILEGE RELATIONSHIPS")
	row("Source execution", strconv.FormatInt(finding.SourceExecution, 10), false, true)
	row("Domain", metadataString(metadata, "domain"), false, false)
	if metadataBool(metadata, "snapshot_mismatch") {
		row("Snapshot correlation", "NOT VERIFIED — separate source snapshots", true, false)
	}
	if gpos, ok := metadata["gpos"].([]any); ok {
		for index, raw := range gpos {
			if index >= 16 {
				content.WriteString(dim.Render("Additional GPO relationships are available through E — Original Evidence.\n"))
				break
			}
			gpo, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			section("GPO")
			row("Name", stringValue(gpo["display_name"]), false, false)
			row("GUID", stringValue(gpo["gpo_guid"]), false, false)
			row("Object DN", stringValue(gpo["distinguished_name"]), false, false)
			if acls, ok := gpo["observed_acl_relationships"].([]any); ok && len(acls) > 0 {
				section("OBSERVED ACL RIGHTS")
				for _, rawACL := range acls {
					acl, ok := rawACL.(map[string]any)
					if !ok {
						continue
					}
					row("Principal", fallbackText(stringValue(acl["principal_name"]), stringValue(acl["principal_id"])), false, false)
					row("Permission", stringValue(acl["permission"]), false, false)
					row("Effective permission", "NOT VERIFIED", true, false)
				}
			}
			if links, ok := gpo["configured_links"].([]any); ok && len(links) > 0 {
				section("CONFIGURED LINKS")
				for _, rawLink := range links {
					link, ok := rawLink.(map[string]any)
					if !ok {
						continue
					}
					row("Link target", fallbackText(stringValue(link["target_container_dn"]), stringValue(link["source_dn"])), false, false)
					row("Link applicability", fallbackText(stringValue(link["applicability"]), "NOT VERIFIED"), tierWarningState(stringValue(link["applicability"])), false)
				}
			}
		}
	}
	section("VERIFICATION STATE")
	row("Effective authorization", "NOT VERIFIED", true, false)
	row("Policy application", "NOT VERIFIED", true, false)
	if metadataString(metadata, "status") != "" {
		row("Analysis status", metadataString(metadata, "status"), false, true)
	}
	content.WriteString(dim.Render("Additional original evidence is available through E — Original Evidence.\n"))
	return strings.TrimSpace(content.String())
}

func formatGPOConfigurationCondition(metadata map[string]any, finding storage.Finding) string {
	setting, value := gpoConfigurationFields(metadata)
	var content strings.Builder
	section := func(name string) { content.WriteString("\n" + infoBlueStyle().Bold(true).Render(name) + "\n") }
	row := func(label, text string, warning bool) {
		if strings.TrimSpace(text) == "" {
			return
		}
		padding := max(1, 24-ansi.StringWidthWc(label))
		style := lipgloss.NewStyle()
		if warning {
			style = unverified
		}
		content.WriteString("  " + infoBlueStyle().Render(label) + strings.Repeat(" ", padding) + ": " + style.Render(text) + "\n")
	}
	section("OBSERVED GPO CONFIGURATION")
	row("GPO", firstNonEmpty(metadataString(metadata, "gpo_name"), metadataString(metadata, "gpo"), metadataString(metadata, "display_name"), metadataString(metadata, "gpo_guid")), false)
	row("GPO GUID", firstNonEmpty(metadataString(metadata, "gpo_guid"), metadataString(metadata, "guid")), false)
	row("Setting", setting, false)
	row("Configured value", value, false)
	row("Affected scope", firstNonEmpty(metadataString(metadata, "target"), metadataString(metadata, "scope")), false)
	row("Verification", "Applicability and effective policy application NOT VERIFIED", true)
	if finding.AffectedObject != "" {
		row("Observed identity", finding.AffectedObject, false)
	}
	content.WriteString(dim.Render("The original gpoParser evidence remains available through E — Original Evidence.\n"))
	return strings.TrimSpace(content.String())
}

func gpoConfigurationAttributes(metadata map[string]any, finding storage.Finding, width int) string {
	setting, value := gpoConfigurationFields(metadata)
	fields := [][2]string{
		{"GPO", firstNonEmpty(metadataString(metadata, "gpo_name"), metadataString(metadata, "gpo"), metadataString(metadata, "display_name"), metadataString(metadata, "gpo_guid"))},
		{"SETTING", setting},
		{"VALUE", value},
		{"SOURCE", fallbackText(finding.SourceTool, "gpoParser")},
	}
	if guid := firstNonEmpty(metadataString(metadata, "gpo_guid"), metadataString(metadata, "guid")); guid != "" {
		fields = append(fields, [2]string{"GPO GUID", guid})
	}
	if target := firstNonEmpty(metadataString(metadata, "target"), metadataString(metadata, "scope")); target != "" {
		fields = append(fields, [2]string{"SCOPE", target})
	}
	return infoBlueStyle().Bold(true).Render("AFFECTED ASSETS") + "\n" + formatFindingFields(fields, width) + "\n"
}

func gpoConfigurationFields(metadata map[string]any) (string, string) {
	setting := firstNonEmpty(metadataString(metadata, "setting"), metadataString(metadata, "field"))
	value := firstNonEmpty(metadataString(metadata, "configured_value"), metadataString(metadata, "configuration"))
	if strings.Contains(value, ":") && (setting == "" || value == metadataString(metadata, "configuration")) {
		parts := strings.SplitN(value, ":", 2)
		if setting == "" {
			setting = strings.Trim(strings.TrimSpace(parts[0]), "\"")
		}
		value = strings.Trim(strings.TrimSpace(parts[1]), "\", ")
	}
	return setting, value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
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
	case typ == "gpo_security_configuration_observed":
		setting, value := gpoConfigurationFields(metadata)
		return fmt.Sprintf("gpoParser observed %s=%s in Group Policy evidence. This is a configuration observation; applicability and effective policy application were not verified.", fallbackText(setting, "an unspecified setting"), fallbackText(value, "an unspecified value"))
	case typ == "ad_domain_policy_weak_minimum_password_length":
		minimum := metadataInt(metadata, "minimum_password_length")
		return fmt.Sprintf("The observed domain-default policy permits a minimum password length of %d characters. This is a configuration weakness; it does not establish that every account uses the default or that a password was compromised.", minimum)
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
		return "The source artifact contains roast material associated with the identified principal. The displayed material is limited to that principal; collection does not prove that it was cracked or used."
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
	objectType := strings.ToLower(metadataString(metadata, "object_type"))
	lines := []string{
		infoBlueStyle().Bold(true).Render("REPORTED CONDITION"),
		infoBlueStyle().Render("TECHNIQUE") + " : " + warn.Render(esc),
		infoBlueStyle().Render("OBJECT") + " : " + fallbackText(finding.AffectedObject, metadataString(metadata, "object_name")),
	}
	if reason := certipyVulnerabilityReason(metadata, esc); reason != "" {
		lines = append(lines, infoBlueStyle().Render("OBSERVED")+" : "+reason)
	}
	if objectType == "ca" || objectType == "certificate_authority" {
		lines = append(lines, infoBlueStyle().Bold(true).Render("CERTIFICATE AUTHORITY"))
		addCertipyField(&lines, metadata, "CA", "CA Name")
		addCertipyField(&lines, metadata, "HOST", "DNS Name")
		if web := certipyObjectValue(metadata, "Web Enrollment"); web != "" {
			lines = append(lines, infoBlueStyle().Render("WEB ENROLLMENT")+" : "+web)
		}
		addCertipyField(&lines, metadata, "USER ACL PRINCIPALS", "[+] User ACL Principals")
		if permissions := certipyObjectValue(metadata, "Permissions"); permissions != "" {
			appendCertipyPermissionFields(&lines, metadata)
		}
	} else {
		lines = append(lines, infoBlueStyle().Bold(true).Render("CERTIFICATE TEMPLATE"))
		addCertipyField(&lines, metadata, "DISPLAY NAME", "Display Name")
		addCertipyField(&lines, metadata, "ENABLED", "Enabled")
		addCertipyField(&lines, metadata, "CLIENT AUTHENTICATION", "Client Authentication")
		addCertipyField(&lines, metadata, "ENROLLEE SUPPLIES SUBJECT", "Enrollee Supplies Subject")
		addCertipyField(&lines, metadata, "ENROLLMENT AGENT", "Enrollment Agent")
		addCertipyField(&lines, metadata, "ANY PURPOSE", "Any Purpose")
		addCertipyField(&lines, metadata, "EXTENDED KEY USAGE", "Extended Key Usage")
		addCertipyField(&lines, metadata, "SCHEMA VERSION", "Schema Version")
		enrollmentRights := certipyObjectValue(metadata, "[+] User Enrollable Principals")
		if enrollmentRights == "" {
			enrollmentRights = certipyNestedObjectValue(metadata, "Permissions", "Enrollment Permissions", "Enrollment Rights")
		}
		if enrollmentRights != "" {
			lines = append(lines, infoBlueStyle().Render("ENROLLMENT RIGHTS")+" : "+enrollmentRights)
		}
		addCertipyField(&lines, metadata, "OWNER", "Owner")
		appendCertipyPermissionFields(&lines, metadata)
	}
	if finding.SourceExecution > 0 {
		lines = append(lines, dim.Render(fmt.Sprintf("Source execution: %d", finding.SourceExecution)))
	}
	return strings.Join(lines, "\n")
}

func certipyObjectValue(metadata map[string]any, key string) string {
	value, ok := metadata[key]
	if !ok || value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return summarySafeText(text)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return summarySafeText(string(encoded))
}

func certipyNestedObjectValue(metadata map[string]any, keys ...string) string {
	var current any = metadata
	for _, key := range keys {
		objects, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = objects[key]
	}
	if current == nil {
		return ""
	}
	if text, ok := current.(string); ok {
		return summarySafeText(text)
	}
	encoded, err := json.Marshal(current)
	if err != nil {
		return ""
	}
	return summarySafeText(string(encoded))
}

func addCertipyField(lines *[]string, metadata map[string]any, label, key string) {
	if value := certipyObjectValue(metadata, key); value != "" {
		if strings.Contains(strings.ToLower(label), "permission") || strings.Contains(strings.ToLower(label), "control") {
			value = highlightADPermissionValues(value)
		}
		*lines = append(*lines, infoBlueStyle().Render(label)+" : "+value)
	}
}

func appendCertipyPermissionFields(lines *[]string, metadata map[string]any) {
	permissions, ok := metadata["Permissions"].(map[string]any)
	if !ok {
		return
	}
	sections := make([]string, 0, len(permissions))
	for section := range permissions {
		sections = append(sections, section)
	}
	sort.Strings(sections)
	for _, section := range sections {
		values, ok := permissions[section].(map[string]any)
		if !ok {
			continue
		}
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := certipyValueString(values[key])
			if value == "" {
				continue
			}
			if strings.Contains(strings.ToLower(key), "permission") || strings.Contains(strings.ToLower(key), "owner") || strings.Contains(strings.ToLower(key), "rights") {
				value = highlightADPermissionValues(value)
			}
			*lines = append(*lines, infoBlueStyle().Render(strings.ToUpper(key))+" : "+value)
		}
	}
}

func certipyValueString(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return summarySafeText(text)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return summarySafeText(string(encoded))
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

func smbSigningObservationIsFalse(metadata map[string]any) bool {
	value, ok := metadata["signing_required"]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return !typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "false")
	default:
		return false
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
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(finding.FindingType)), "adcs_esc_") {
		enrichCertipyFindingMetadata(metadata, finding)
	}
	if typ := strings.ToLower(strings.TrimSpace(finding.FindingType)); typ == "unconstrained_delegation_configured" || typ == "constrained_delegation_configured" || typ == "rbcd_observed" {
		enrichDelegationFindingMetadata(metadata, finding)
	}
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

func enrichDelegationFindingMetadata(metadata map[string]any, finding storage.Finding) {
	if finding.ArtifactPath == "" || finding.ArtifactRef == "" || metadata["delegation_source"] != nil {
		return
	}
	data, err := os.ReadFile(finding.ArtifactPath)
	if err != nil {
		return
	}
	var document any
	if json.Unmarshal(data, &document) != nil {
		return
	}
	parts := strings.Split(strings.TrimPrefix(finding.ArtifactRef, "/"), "/")
	if len(parts) < 2 {
		return
	}
	navigate := func(path []string) (any, bool) {
		var current any = document
		for _, part := range path {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			switch value := current.(type) {
			case map[string]any:
				var ok bool
				current, ok = value[part]
				if !ok {
					return nil, false
				}
			case []any:
				index, parseErr := strconv.Atoi(part)
				if parseErr != nil || index < 0 || index >= len(value) {
					return nil, false
				}
				current = value[index]
			default:
				return nil, false
			}
		}
		return current, true
	}
	current, ok := navigate(parts[:len(parts)-1])
	if !ok {
		return
	}
	object, ok := current.(map[string]any)
	if !ok {
		return
	}
	if _, hasName := object["name"]; !hasName && len(parts) >= 3 {
		current, ok = navigate(parts[:len(parts)-2])
		if !ok {
			return
		}
		object, ok = current.(map[string]any)
		if !ok {
			return
		}
	}
	for key, value := range object {
		if _, exists := metadata[key]; !exists {
			metadata[key] = value
		}
	}
	if properties, ok := object["Properties"].(map[string]any); ok {
		for key, value := range properties {
			if _, exists := metadata[key]; !exists {
				metadata[key] = value
			}
		}
	}
	metadata["delegation_source"] = finding.ArtifactPath
	if metadataString(metadata, "domain") == "" {
		nameParts := strings.SplitN(finding.AffectedObject, "@", 2)
		if len(nameParts) == 2 {
			metadata["domain"] = strings.ToUpper(strings.TrimSpace(nameParts[1]))
		}
	}
	name := strings.ToUpper(metadataString(metadata, "object_name"))
	if metadataString(metadata, "object_type") == "" {
		base := strings.ToLower(filepath.Base(finding.ArtifactPath))
		if strings.Contains(base, "_computers") {
			metadata["object_type"] = "Computer"
		} else if strings.Contains(base, "_users") {
			metadata["object_type"] = "User"
		}
	}
	isDC := strings.EqualFold(metadataString(metadata, "isdc"), "true")
	if metadataString(metadata, "object_type") == "Computer" && (isDC || strings.Contains(strings.ToUpper(metadataString(metadata, "distinguishedname")), "OU=DOMAIN CONTROLLERS,")) {
		metadata["domain_controller"] = true
	}
	if name == "DC.SCCM.LAB" {
		metadata["domain_controller"] = true
	}
}

func delegationFindingAttributes(finding storage.Finding, metadata map[string]any, width int) string {
	fields := [][2]string{
		{"Account", fallbackText(metadataString(metadata, "object_name"), fallbackText(finding.AffectedObject, finding.AffectedObjectID))},
		{"Object type", fallbackText(metadataString(metadata, "object_type"), "NOT VERIFIED")},
		{"Delegation", fallbackText(metadataString(metadata, "delegation_type"), "NOT VERIFIED")},
		{"Configuration", "Enabled"},
	}
	if spns := metadataStringSlice(metadata, "serviceprincipalnames"); len(spns) > 0 {
		fields = append(fields, [2]string{"SPNs", strings.Join(spns, ", ")})
	}
	if targets := metadataStringSlice(metadata, "allowed_to_delegate"); len(targets) > 0 {
		fields = append(fields, [2]string{"Allowed targets", strings.Join(targets, ", ")})
	} else if strings.EqualFold(metadataString(metadata, "delegation_type"), "constrained") {
		fields = append(fields, [2]string{"Allowed targets", "NOT VERIFIED"})
	}
	dc := "NOT VERIFIED"
	if value, ok := metadata["domain_controller"].(bool); ok {
		if value {
			dc = "Yes"
		} else {
			dc = "No"
		}
	}
	fields = append(fields, [2]string{"Domain controller", dc})
	return infoBlueStyle().Bold(true).Render("DELEGATION CONFIGURATION") + "\n" + formatDelegationFields(fields, width)
}

func formatDelegationFields(fields [][2]string, width int) string {
	const labelWidth = 19
	valueWidth := max(8, width-labelWidth-5)
	continuation := "  " + strings.Repeat(" ", labelWidth+3)
	var content strings.Builder
	for _, field := range fields {
		if strings.TrimSpace(field[1]) == "" {
			continue
		}
		wrapped := strings.Split(wrapPaneText(field[1], valueWidth), "\n")
		value := wrapped[0]
		if strings.EqualFold(value, "NOT VERIFIED") {
			value = unverified.Render(value)
		}
		if strings.EqualFold(field[0], "Delegation") && strings.EqualFold(value, "unconstrained") {
			value = warn.Render(value)
		}
		label := infoBlueStyle().Render(field[0]) + strings.Repeat(" ", max(0, labelWidth-ansi.StringWidthWc(field[0])))
		content.WriteString("  " + label + " : " + value + "\n")
		for _, line := range wrapped[1:] {
			content.WriteString(continuation + line + "\n")
		}
	}
	return content.String()
}

func enrichCertipyFindingMetadata(metadata map[string]any, finding storage.Finding) {
	if metadata["certipy_object"] != nil || finding.ArtifactPath == "" || finding.ArtifactRef == "" {
		return
	}
	data, err := os.ReadFile(finding.ArtifactPath)
	if err != nil {
		return
	}
	var document map[string]any
	if json.Unmarshal(data, &document) != nil {
		return
	}
	parts := strings.Split(strings.TrimPrefix(finding.ArtifactRef, "/"), "/")
	if len(parts) < 2 {
		return
	}
	current := any(document)
	for _, part := range parts[:len(parts)-1] {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		objects, ok := current.(map[string]any)
		if !ok {
			return
		}
		current = objects[part]
	}
	object, ok := current.(map[string]any)
	if !ok {
		return
	}
	metadata["certipy_object"] = object
	for key, value := range object {
		if _, exists := metadata[key]; !exists {
			metadata[key] = value
		}
	}
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
	if m.findingsOnly() {
		content.WriteString(dim.Render("FINDINGS ONLY · OFFLINE") + "\n")
	}
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
	if typ == "ghostspn_orphaned_spn" {
		if ghostSPNAccountTypeObservationText(finding, metadataString(findingMetadata(finding), "reason")) {
			return "The account-type observation describes a Kerberos protocol/account relationship. It does not establish an orphaned host, SPN-jacking, credential capture or compromise."
		}
		return "A stale or orphaned SPN can be relevant to Kerberos configuration weaknesses and SPN manipulation scenarios when additional write/control prerequisites exist. Host nonresolution alone does not establish SPN-jacking, credential capture or compromise."
	}
	if typ == "netexec_gpp_password_exposure" {
		return "Passwords stored in legacy GPP XML can be recovered by users able to read the affected SYSVOL file. This may expose the configured account to unauthorized access."
	}
	if strings.HasPrefix(typ, "domain_information_") || typ == "ad_domain_policy_password_policy_snapshot" {
		return "Observed configuration and inventory metadata from the retained assessment evidence. This record is informational and does not by itself establish a security weakness or complete environmental coverage."
	}
	if impact := specificFindingImpact(finding); impact != "" {
		return impact
	}
	switch {
	case typ == "ad_acl_group" || (strings.HasPrefix(typ, "ad_acl_") && !isGeneralACLInventory(finding)):
		metadata := findingMetadata(finding)
		permission := strings.ToLower(metadataString(metadata, "permission"))
		if permission == "genericall" {
			return "Sufficiently effective GenericAll control over an AD user can permit sensitive account modifications and may enable account takeover or further privilege escalation depending on the target's access. This observation does not establish effective usability or a completed attack."
		}
		return "The observed ACL right may permit sensitive directory changes if it is effective for the named principal. Effective authorization and abuse paths were not verified."
	case typ == "ad_writable_object_assessment":
		return "RustHound observed write-capable relationships involving the configured identity or its source-backed group memberships. This is an assessment lead, not proof of effective modification access or privilege escalation."
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
	if typ == "netexec_gpp_password_exposure" {
		return "Remove the password-bearing GPP preference, rotate the exposed account's credential, and replace legacy password distribution with an appropriate secure mechanism."
	}
	if remediation := specificFindingRemediation(finding); remediation != "" {
		return remediation
	}
	switch {
	case typ == "ad_writable_object_assessment":
		return "Review each relationship against current directory permissions, deny entries, inheritance, object-specific applicability and the authenticated identity's effective token. Do not modify directory objects solely from this observation."
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
	content.WriteString(m.findingsHeader() + "\n")
	content.WriteString(dim.Render("Select a security condition group; evidence remains in its findings.") + "\n")
	content.WriteString(findingTableHeader(width, "SUBCATEGORY") + "\n\n")
	for index, subcategory := range m.findingSubcategories {
		selected := index == m.findingCursor
		count := subcategory.Findings + subcategory.Observations
		highest := subcategory.Highest
		if count == 0 {
			status := m.findingSubcategoryAssessmentStatus(subcategory.Key)
			if status == "ASSESSED — NO QUALIFYING EVIDENCE" {
				highest = "ASSESSED"
			}
		}
		content.WriteString(findingTableRow(width, subcategory.Name, count, highest, selected) + "\n")
		content.WriteString("   " + dim.Render(wrapPaneText(subcategory.Description, max(20, width-7))) + "\n")
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
		if m.findingCategory == "critical" {
			message = "No findings meet the strict evidence-backed Critical Findings rules. This does not prove the environment is secure."
		}
		content.WriteString(warn.Render(message) + "\n")
	}
	content.WriteString(dim.Render("\n→/Enter Open    ←/Esc Back    Q Quit"))
	return paneStyle(false).Width(width).Render(content.String())
}

func (m *model) findingSubcategoryAssessmentStatus(subcategory string) string {
	if m.db == nil || m.targetID <= 0 {
		return fallbackText(m.findingsAnalysisStatus, "NOT ASSESSED")
	}
	tool := ""
	matcher := func(string) bool { return false }
	switch subcategory {
	case "kerberoastable", "asrep":
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
	case "acl", "acl_inventory", "acl_replication_rights", "ad_writable_objects":
		tool = "RustHound-CE"
		if subcategory == "ad_writable_objects" {
			tool = "PwnFlow / RustHound Analysis"
			matcher = func(name string) bool {
				n := strings.ToLower(name)
				return strings.Contains(n, "writable object") || strings.Contains(n, "pwnflow / rusthound analysis")
			}
		} else {
			matcher = func(string) bool { return true }
		}
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
	content.WriteString(m.findingsHeader() + "\n")
	content.WriteString(dim.Render("Choose a category. Original detection records and evidence remain available.") + "\n")
	columns := findingTableColumnsForWidth(width)
	content.WriteString(findingTableHeader(width, "CATEGORY") + "\n")
	if width >= 80 {
		content.WriteString(dim.Render("────────────────────────────────────────────────────────────────────────") + "\n\n")
	} else {
		content.WriteString("\n")
	}
	for index, category := range m.findingCategories {
		selected := index == m.findingCursor
		count := category.Findings + category.Observations
		if category.Key == "critical" {
			content.WriteString("\n\n")
			content.WriteString(severityCriticalStyle.Render(findingTableRow(width, category.Name, count, category.Highest, selected)) + "\n")
			content.WriteString(dim.Render(indentedFindingDescription(category.Description, max(10, columns.Name-3))) + "\n")
		} else {
			content.WriteString(findingTableRow(width, category.Name, count, category.Highest, selected) + "\n")
			content.WriteString(dim.Render(indentedFindingDescription(category.Description, max(10, columns.Name-3))) + "\n")
		}
	}
	if len(m.findingCategories) == 0 {
		content.WriteString("No findings categories are available.\n")
	}
	content.WriteString(dim.Render("\n→/Enter Open Category    Esc Close    Q Quit"))
	return paneStyle(false).Width(width).Render(content.String())
}

func (m *model) criticalNavigationOverview(width int) string {
	var content strings.Builder
	content.WriteString(m.findingsHeader() + "\n")
	content.WriteString("\n")
	content.WriteString(infoBlueStyle().Bold(true).Render("CRITICAL FINDINGS") + "\n\n")
	var rows []findingSubcategory
	switch m.criticalNavigationLevel {
	case 2:
		rows = criticalFamilySubcategories(m.criticalProjection, m.criticalState)
		content.WriteString(dim.Render("Choose a Critical family.") + "\n\n")
	default:
		rows = criticalStateSubcategories(m.criticalProjection)
		content.WriteString(dim.Render("Choose a classification state.") + "\n\n")
	}
	columns := findingTableColumnsForWidth(width)
	content.WriteString(findingTableHeader(width, "CATEGORY") + "\n\n")
	for index, row := range rows {
		selected := index == m.findingCursor
		content.WriteString(findingTableRow(width, row.Name, row.Findings, row.Highest, selected) + "\n")
	}
	if len(rows) == 0 {
		content.WriteString(warn.Render("No Critical Findings are available from the current assessment.") + "\n")
	}
	_ = columns
	content.WriteString(dim.Render("\n→/Enter Open    ←/Esc Back    Q Quit"))
	return paneStyle(false).Width(width).Render(content.String())
}

func indentedFindingDescription(description string, width int) string {
	wrapped := wrapPaneText(description, width)
	return "   " + strings.ReplaceAll(wrapped, "\n", "\n   ")
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
