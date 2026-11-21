package tui

import (
	"fmt"
	"strings"

	"github.com/pwnflow/pwnflow/internal/storage"
)

// findingSearchFields returns the text a search matches: title, objects,
// tool, type and the object names a Finding lists in its evidence. Evidence
// values other than those names are not searched, so a recovered secret
// cannot be found by typing it.
func findingSearchFields(finding storage.Finding) []string {
	fields := []string{finding.Title, finding.AffectedObject, finding.AffectedObjectID, finding.RelatedObject, finding.RelatedObjectID, finding.SourceTool, finding.FindingType}
	fields = append(fields, metadataStringSlice(findingMetadata(finding), "affected_objects")...)
	return fields
}

// searchFindings returns the rows whose fields contain every word of query.
func searchFindings(rows []storage.Finding, query string) []storage.Finding {
	words := strings.Fields(strings.ToLower(query))
	if len(words) == 0 {
		return nil
	}
	var result []storage.Finding
	for _, row := range rows {
		text := strings.ToLower(strings.Join(findingSearchFields(row), "\x00"))
		matched := true
		for _, word := range words {
			if !strings.Contains(text, word) {
				matched = false
				break
			}
		}
		if matched {
			result = append(result, row)
		}
	}
	return result
}

// normalizeObjectName reduces the forms one host or account takes in
// different tools - HOST, host.domain, HOST$, DOMAIN\user, user@domain,
// "name → detail" list entries - to one comparable key.
func normalizeObjectName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if index := strings.Index(name, " → "); index >= 0 {
		name = name[:index]
	}
	if index := strings.Index(name, " ("); index >= 0 {
		name = name[:index]
	}
	if index := strings.LastIndexByte(name, '\\'); index >= 0 {
		name = name[index+1:]
	}
	if index := strings.IndexByte(name, '@'); index >= 0 {
		name = name[:index]
	}
	if index := strings.IndexByte(name, '.'); index > 0 && !looksLikeAddress(name) {
		name = name[:index]
	}
	return strings.TrimSuffix(name, "$")
}

func looksLikeAddress(name string) bool {
	return strings.Trim(name, "0123456789.:") == ""
}

// findingsAboutObject returns every row that names object (in any of its
// forms) as its affected or related object, or lists it in its evidence.
func findingsAboutObject(rows []storage.Finding, object string) []storage.Finding {
	key := normalizeObjectName(object)
	if key == "" {
		return nil
	}
	var result []storage.Finding
	for _, row := range rows {
		names := []string{row.AffectedObject, row.AffectedObjectID, row.RelatedObject, row.RelatedObjectID}
		names = append(names, metadataStringSlice(findingMetadata(row), "affected_objects")...)
		for _, name := range names {
			if name != "" && normalizeObjectName(name) == key {
				result = append(result, row)
				break
			}
		}
	}
	return result
}

// openFindingResults shows rows as the "results" list.
func (m *model) openFindingResults(title string, rows []storage.Finding) {
	if m.findingCategory == "" && m.findingCursor >= 0 && m.findingCursor < len(m.findingCategories) {
		m.findingCategorySelection = m.findingCategories[m.findingCursor].Key
		m.findingCategoryTop = m.findingTop
	}
	m.findingResults = rows
	m.findingResultsTitle = fmt.Sprintf("%s — %d Finding(s)", title, len(rows))
	m.findingCategory = "results"
	m.findingCategoryView = false
	m.findingSubcategoryView = false
	m.findingSubcategory = ""
	m.findingDetail = false
	m.findingCursor, m.findingTop = 0, 0
	m.refreshFindings()
}

// handleFindingSearchKey edits the search line while it is open.
func (m *model) handleFindingSearchKey(key string) {
	switch key {
	case "esc":
		m.findingSearchActive = false
		m.findingSearchQuery = ""
	case "enter":
		m.findingSearchActive = false
		query := strings.TrimSpace(m.findingSearchQuery)
		if query != "" {
			m.openFindingResults(fmt.Sprintf("Search %q", query), searchFindings(m.findingAllRows, query))
		}
	case "backspace":
		if runes := []rune(m.findingSearchQuery); len(runes) > 0 {
			m.findingSearchQuery = string(runes[:len(runes)-1])
		}
	case "space":
		m.findingSearchQuery += " "
	default:
		if runes := []rune(key); len(runes) == 1 {
			m.findingSearchQuery += key
		}
	}
}
