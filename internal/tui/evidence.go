package tui

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/storage"
)

const maxEvidenceViewBytes = 4 << 20

type inlineEvidence struct {
	section string
	lines   []string
	error   string
}

var pxeInlineVariable = regexp.MustCompile(`(?i)\b(OSDJoinAccount|OSDJoinPassword|OSDLocalAdminPassword)\b\s*(?:[:=\-]|=>)?\s*(.*)$`)

func (m *model) findingInlineEvidence(finding storage.Finding) tea.Cmd {
	if !findingHasInlineEvidence(finding) {
		return nil
	}
	cfg, id := m.cfg, finding.ID
	return func() tea.Msg {
		evidence := loadInlineEvidence(cfg, finding)
		return inlineEvidenceLoadedMsg{findingID: id, evidence: evidence}
	}
}

func findingHasInlineEvidence(finding storage.Finding) bool {
	if strings.EqualFold(finding.SourceTool, "PXEThief") {
		return strings.Contains(strings.ToLower(finding.FindingType), "credential")
	}
	if strings.EqualFold(finding.SourceTool, "NetExec") {
		typeName := strings.ToLower(finding.FindingType)
		return strings.Contains(typeName, "material_collected") || strings.HasPrefix(typeName, "ad_user_description_")
	}
	return false
}

func loadInlineEvidence(cfg config.Config, finding storage.Finding) inlineEvidence {
	result := inlineEvidence{}
	path, err := safeEvidencePathForRoot(cfg.ResultsRoot(), finding.ArtifactPath)
	if err != nil {
		result.error = err.Error()
		return result
	}
	lines, err := readEvidenceLines(path)
	if err != nil {
		result.error = err.Error()
		return result
	}
	var metadata map[string]any
	_ = json.Unmarshal([]byte(finding.EvidenceJSON), &metadata)
	if strings.EqualFold(finding.SourceTool, "PXEThief") {
		result.section = "RECOVERED CREDENTIALS"
		result.lines = extractPXEInline(lines, metadata, finding)
		if len(result.lines) == 0 {
			result.error = "Recovered credential evidence could not be loaded from the referenced artifact."
		}
		return result
	}
	if strings.HasPrefix(strings.ToLower(finding.FindingType), "ad_user_description_") {
		result.section = "RECOVERED CREDENTIAL EXPOSURE"
		lineNumber := refLine([]string{finding.ArtifactRef})
		if lineNumber > 0 && lineNumber <= len(lines) {
			result.lines = []string{lines[lineNumber-1]}
		}
		if len(result.lines) == 0 {
			result.error = "Recovered credential evidence could not be loaded from the referenced artifact."
		}
		return result
	}
	result.section = "RECOVERED KERBEROS MATERIAL"
	result.lines = extractKerberosInline(lines, metadata, finding)
	if len(result.lines) == 0 {
		result.error = "Recovered Kerberos material could not be loaded from the referenced artifact."
	}
	return result
}

func extractPXEInline(lines []string, metadata map[string]any, finding storage.Finding) []string {
	variables := stringSlice(metadata["credential_variables"])
	if len(variables) == 0 {
		return nil
	}
	if result := extractPXEXMLInline(lines, variables); len(result) > 0 {
		return result
	}
	targetContext, _ := metadata["task_sequence_context"].(string)
	refs := stringSlice(metadata["artifact_records"])
	anchor := refLine(refs)
	if anchor == 0 {
		anchor = refLine([]string{finding.ArtifactRef})
	}
	contextName := "artifact"
	if targetContext == "" {
		targetContext = contextName
	}
	values := make(map[string]string)
	for index, raw := range lines {
		lineNumber := index + 1
		lower := strings.ToLower(raw)
		if strings.Contains(lower, "task sequence") && !strings.Contains(lower, "no task sequence") {
			contextName = fmt.Sprintf("task-sequence-line:%d", lineNumber)
		}
		if contextName != targetContext && !(anchor > 0 && lineNumber == anchor) {
			continue
		}
		match := pxeInlineVariable.FindStringSubmatch(raw)
		if len(match) < 3 {
			continue
		}
		name := canonicalInlinePXEName(match[1])
		_, exists := values[strings.ToLower(name)]
		if !containsFold(variables, name) || exists {
			continue
		}
		value := strings.TrimSpace(match[2])
		if value == "" || strings.EqualFold(value, "none") || strings.EqualFold(value, "null") {
			continue
		}
		values[strings.ToLower(name)] = value
	}
	result := make([]string, 0, len(variables))
	for _, variable := range variables {
		if value, ok := values[strings.ToLower(variable)]; ok {
			result = append(result, fmt.Sprintf("%-22s = %s", variable, value))
		}
	}
	return result
}

func extractPXEXMLInline(lines, variables []string) []string {
	data := []byte(strings.Join(lines, "\n"))
	if !bytes.Contains(bytes.ToLower(data), []byte("<var")) {
		return nil
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	values := make(map[string]string)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil
		}
		start, ok := token.(xml.StartElement)
		if !ok || !strings.EqualFold(start.Name.Local, "var") {
			continue
		}
		name := ""
		for _, attribute := range start.Attr {
			if strings.EqualFold(attribute.Name.Local, "name") {
				name = canonicalInlinePXEName(attribute.Value)
			}
		}
		if !containsFold(variables, name) || values[strings.ToLower(name)] != "" {
			continue
		}
		var value string
		if err := decoder.DecodeElement(&value, &start); err != nil {
			return nil
		}
		value = strings.TrimSpace(value)
		if value != "" && !strings.EqualFold(value, "none") && !strings.EqualFold(value, "null") {
			values[strings.ToLower(name)] = value
		}
	}
	result := make([]string, 0, len(variables))
	for _, variable := range variables {
		if value := values[strings.ToLower(variable)]; value != "" {
			result = append(result, fmt.Sprintf("%-22s = %s", variable, value))
		}
	}
	return result
}

func extractKerberosInline(lines []string, metadata map[string]any, finding storage.Finding) []string {
	numbers := intSlice(metadata["record_line_numbers"])
	principal, _ := metadata["principal"].(string)
	result := make([]string, 0, len(numbers))
	for _, number := range numbers {
		if number < 1 || number > len(lines) {
			continue
		}
		line := strings.TrimSpace(lines[number-1])
		if !strings.HasPrefix(strings.ToLower(line), "$krb5tgs$") && !strings.HasPrefix(strings.ToLower(line), "$krb5asrep$") {
			continue
		}
		if principal != "" && !strings.EqualFold(principal, "unresolved principal") && !strings.EqualFold(principal, kerberosPrincipalInline(line)) {
			continue
		}
		if !containsString(result, line) {
			result = append(result, line)
		}
	}
	return result
}

func kerberosPrincipalInline(line string) string {
	value := line[strings.IndexByte(line, '$')+1:]
	if start := strings.IndexByte(value, '*'); start >= 0 {
		value = value[start+1:]
		if end := strings.IndexByte(value, '*'); end >= 0 {
			value = value[:end]
		}
	}
	parts := strings.Split(value, "$")
	if strings.HasPrefix(strings.ToLower(line), "$krb5asrep$") && len(parts) > 1 {
		return strings.TrimSpace(strings.SplitN(parts[1], ":", 2)[0])
	}
	if strings.HasPrefix(strings.ToLower(line), "$krb5tgs$") && len(parts) > 0 {
		return strings.TrimSpace(parts[0])
	}
	return ""
}

func stringSlice(value any) []string {
	items, _ := value.([]any)
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func intSlice(value any) []int {
	items, _ := value.([]any)
	result := make([]int, 0, len(items))
	for _, item := range items {
		if number, ok := item.(float64); ok {
			result = append(result, int(number))
		}
	}
	return result
}

func refLine(refs []string) int {
	for _, ref := range refs {
		parts := strings.Split(strings.Trim(ref, "/"), "/")
		for index := len(parts) - 1; index >= 1; index-- {
			if parts[index-1] == "lines" || parts[index-1] == "line" {
				value, _ := strconv.Atoi(parts[index])
				return value
			}
		}
		if strings.HasPrefix(ref, "line:") {
			value, _ := strconv.Atoi(strings.TrimPrefix(ref, "line:"))
			return value
		}
	}
	return 0
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func canonicalInlinePXEName(value string) string {
	for _, name := range []string{"OSDJoinAccount", "OSDJoinPassword", "OSDLocalAdminPassword"} {
		if strings.EqualFold(name, value) {
			return name
		}
	}
	return value
}

func readEvidenceLines(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("evidence unavailable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("evidence is not a regular text file")
	}
	if info.Size() > maxEvidenceViewBytes {
		return nil, fmt.Errorf("evidence exceeds the %d-byte viewer limit", maxEvidenceViewBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("evidence unavailable: %w", err)
	}
	defer file.Close()
	reader := bufio.NewReader(io.LimitReader(file, maxEvidenceViewBytes+1))
	var lines []string
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 {
			lines = append(lines, strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"))
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("evidence read failed: %w", readErr)
		}
	}
	return lines, nil
}

func (m *model) openFindingEvidence(finding storage.Finding) {
	m.evidenceView, m.evidenceTop = true, 0
	evidenceReference := finding.ArtifactPath
	if strings.EqualFold(finding.FindingType, "ad_privileged_acl_evidence_inventory") {
		metadata := findingMetadata(finding)
		if report := metadataString(metadata, "human_report"); report != "" {
			evidenceReference = report
		}
	}
	m.evidencePath, m.evidenceError, m.evidenceLines = evidenceReference, "", nil
	path, err := m.safeEvidencePath(evidenceReference)
	if err != nil {
		m.evidenceError = err.Error()
		return
	}
	m.evidenceLines, err = readEvidenceLines(path)
	if err != nil {
		m.evidenceError = err.Error()
		return
	}
	if len(m.evidenceLines) == 0 {
		m.evidenceLines = []string{"(empty artifact)"}
	}
}

func (m *model) safeEvidencePath(raw string) (string, error) {
	return safeEvidencePathForRoot(m.cfg.ResultsRoot(), raw)
}

func safeEvidencePathForRoot(rawRoot, raw string) (string, error) {
	root, err := filepath.Abs(rawRoot)
	if err != nil {
		return "", fmt.Errorf("invalid results root")
	}
	path := raw
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	path, err = filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("invalid evidence path")
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("evidence path is outside the assessment results")
	}
	current := root
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		current = filepath.Join(current, part)
		entry, statErr := os.Lstat(current)
		if statErr != nil {
			return "", statErr
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink evidence paths are not allowed")
		}
	}
	return path, nil
}
