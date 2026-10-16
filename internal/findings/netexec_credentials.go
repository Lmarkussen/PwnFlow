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

const netExecCredentialParserVersion = "netexec-ad-user-credentials-v1"

var credentialAssignment = regexp.MustCompile(`(?i)\b(password|passwd|pwd|passphrase|pass|secret|token|api[_ -]?key)\b\s*(?:[:=]|=>)\s*["']?([^"'\r\n,;]+)`)
var followingField = regexp.MustCompile(`(?i)\s+\b(?:password|passwd|pwd|passphrase|secret|token|api[_ -]?key|username|user|login|account)\b\s*(?:[:=]|=>)`)
var principalAssignment = regexp.MustCompile(`(?i)\b(?:user(?:name)?|account|login|principal)\b\s*(?:[:=]|=>)\s*([^\s,;]+)`)

// AnalyzeNetExecCredentials extracts only non-empty credential-like values from
// user info/description output. The value is intentionally absent from the
// FindingInput: the restricted source line is loaded only when the operator
// deliberately opens the finding detail.
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
	attribute := "user-info"
	if strings.Contains(strings.ToLower(filepath.Base(artifactPath)), "description") {
		attribute = "user-description"
	}
	seen := make(map[string]bool)
	var result []storage.FindingInput
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := scanner.Text()
		match := credentialAssignment.FindStringSubmatch(line)
		if len(match) != 3 {
			continue
		}
		value := strings.TrimSpace(match[2])
		if next := followingField.FindStringIndex(value); next != nil {
			value = strings.TrimSpace(value[:next[0]])
		}
		if !credentialValueLikelySecret(value) {
			continue
		}
		principal := ""
		if principalMatch := principalAssignment.FindStringSubmatch(line); len(principalMatch) == 2 {
			principal = strings.TrimSpace(principalMatch[1])
		}
		if principal == "" {
			principal = principalFromPrefix(line)
		}
		if principal == "" {
			principal = "unresolved principal"
		}
		credentialType := strings.ToLower(strings.ReplaceAll(match[1], "_", " "))
		key := stableSourceKey(assessmentID, "netexec-user-credential", principal, map[string]any{"attribute": attribute, "credential_type": credentialType})
		if seen[key] {
			continue
		}
		seen[key] = true
		evidence, _ := json.Marshal(map[string]any{"attribute": attribute, "credential_type": credentialType, "principal": principal, "line": lineNumber})
		result = append(result, storage.FindingInput{
			FindingKey: key, AssessmentID: assessmentID, SourceTool: "NetExec", SourceExecution: executionID,
			FindingType: "ad_user_description_credential_exposed", Title: "Credential-like value exposed in " + attribute,
			Description: "A NetExec user attribute contains a non-empty credential-like assignment. The value is potential exposed credential material; it has not been tested for authentication.",
			Severity:    "high", Confidence: "observed-credential-like-value", AffectedObject: principal,
			EvidenceJSON: string(evidence), ArtifactPath: artifactPath, ArtifactRef: fmt.Sprintf("line:%d", lineNumber),
			ObservedAt: now, Status: "open", ParserVersion: netExecCredentialParserVersion,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func credentialValueLikelySecret(value string) bool {
	value = strings.Trim(strings.TrimSpace(value), "\"'")
	if value == "" || strings.EqualFold(value, "null") || strings.EqualFold(value, "none") || value == "-" || value == "<empty>" {
		return false
	}
	lower := strings.ToLower(value)
	for _, phrase := range []string{"expires", "policy", "managed by", "reset your", "format is"} {
		if strings.Contains(lower, phrase) {
			return false
		}
	}
	return true
}

func principalFromPrefix(line string) string {
	if index := strings.Index(strings.ToLower(line), "description:"); index > 0 {
		prefix := strings.TrimSpace(line[:index])
		prefix = strings.Trim(prefix, "[]()")
		if fields := strings.Fields(prefix); len(fields) > 0 {
			candidate := strings.Trim(fields[len(fields)-1], ":")
			if candidate != "LDAP" && candidate != "SMB" {
				return candidate
			}
		}
	}
	return ""
}
