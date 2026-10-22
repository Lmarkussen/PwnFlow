package findings

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const netExecCredentialParserVersion = "netexec-ad-user-credentials-v2"

var credentialKeyword = regexp.MustCompile(`(?i)\b(?:passwords?|passwd|pwd|passphrase|pass|secrets?|credentials?|creds|user[ _-]+name|login|logon|tokens?|api[ _-]?key)\b`)
var userField = regexp.MustCompile(`(?i)\buser\s*[:=]\s*([^\s,;]+)`)
var attributeField = regexp.MustCompile(`(?i)\b(description|info|notes?)\s*[:=]`)
var attributeValueField = regexp.MustCompile(`(?i)\b(?:description|info|notes?)\s*[:=]\s*(.*)$`)
var assignmentAfterKeyword = regexp.MustCompile(`(?i)(?:passwords?|passwd|pwd|passphrase|pass|secrets?|credentials?|creds|user[ _-]?name|login|logon|tokens?|api[ _-]?key)\s*(?:[:=]|=>)\s*["']?([^"'\r\n,;]+)`)

// AnalyzeNetExecCredentials extracts keyword observations and potential
// credential exposures from NetExec user attribute records. Values remain in
// the restricted source artifact and are loaded only for deliberate detail
// viewing.
func AnalyzeNetExecCredentials(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	info, err := os.Stat(artifactPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("NetExec user artifact is not a regular file")
	}
	if info.Size() > 64<<20 {
		return nil, fmt.Errorf("NetExec user artifact exceeds parser size limit")
	}
	file, err := os.Open(artifactPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	defaultAttribute := "user-info"
	if strings.Contains(strings.ToLower(filepath.Base(artifactPath)), "description") {
		defaultAttribute = "description"
	}
	seen := make(map[string]bool)
	var result []storage.FindingInput
	var principal string
	var attribute string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := scanner.Text()
		if match := userField.FindStringSubmatch(line); len(match) == 2 {
			principal = strings.TrimSpace(match[1])
			attribute = defaultAttribute
		}
		if match := attributeField.FindStringSubmatch(line); len(match) == 2 {
			attribute = normalizeUserAttribute(match[1])
		}
		if principal == "" || !credentialKeyword.MatchString(line) {
			continue
		}
		keywords := credentialKeyword.FindAllString(line, -1)
		keyword := strings.ToLower(keywords[0])
		attributeValue := ""
		if match := attributeValueField.FindStringSubmatch(line); len(match) == 2 {
			attributeValue = strings.TrimSpace(match[1])
		}
		potential := credentialAssignmentPresent(line)
		findingType := "ad_user_description_keyword_observed"
		title := "Credential-related keyword in " + attribute
		description := "A credential-related keyword appears in a NetExec user attribute. The source text is an observation; it does not by itself prove that a usable secret was disclosed."
		severity := "informational"
		confidence := "observed-sensitive-keyword"
		if potential {
			findingType = "ad_user_description_credential_exposed"
			title = "Potential credential exposure in " + attribute
			description = "A NetExec user attribute contains a credential-related field with a populated value. Treat it as potential exposed credential material; it has not been tested for authentication."
			severity = "high"
			confidence = "observed-credential-like-value"
		}
		key := stableSourceKey(assessmentID, "netexec-user-attribute", principal, map[string]any{"attribute": attribute, "finding_type": findingType})
		if seen[key] {
			continue
		}
		seen[key] = true
		evidenceFields := map[string]any{"attribute": attribute, "keyword": keyword, "principal": principal, "line": lineNumber}
		if attributeValue != "" && !potential {
			evidenceFields["value"] = attributeValue
		}
		evidence, _ := json.Marshal(evidenceFields)
		result = append(result, storage.FindingInput{
			FindingKey: key, AssessmentID: assessmentID, SourceTool: "NetExec", SourceExecution: executionID,
			FindingType: findingType, Title: title, Description: description, Severity: severity,
			Confidence: confidence, AffectedObject: principal, EvidenceJSON: string(evidence),
			ArtifactPath: artifactPath, ArtifactRef: fmt.Sprintf("line:%d", lineNumber), ObservedAt: now,
			Status: "open", ParserVersion: netExecCredentialParserVersion,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func normalizeUserAttribute(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "note" || value == "notes" {
		return "info/notes"
	}
	return value
}

func credentialAssignmentPresent(line string) bool {
	for _, match := range assignmentAfterKeyword.FindAllStringSubmatch(line, -1) {
		if len(match) != 2 {
			continue
		}
		value := strings.TrimSpace(match[1])
		if value == "" || strings.EqualFold(value, "null") || strings.EqualFold(value, "none") || value == "-" || value == "<empty>" {
			continue
		}
		return true
	}
	return false
}
