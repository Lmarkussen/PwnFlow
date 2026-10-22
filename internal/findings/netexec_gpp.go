package findings

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const netExecGPPParserVersion = "netexec-gpp-password-v2"

var (
	gppXMLPathPattern   = regexp.MustCompile(`(?i)(?:found\s+credentials\s+in|found|file)\s+((?:[a-z]:[\\/])?[^\r\n]*?\.xml)\b`)
	gppAccountPattern   = regexp.MustCompile(`(?i)(?:accountname|username|runas|user)\s*:\s*([^\r\n]+)`)
	gppRecoveredPattern = regexp.MustCompile(`(?i)(?:decrypted|recovered|found)\s+(?:gpp\s+)?password\s+for\s+([^:\r\n]+)\s*:\s*([^\r\n]+)`)
	gppPasswordPattern  = regexp.MustCompile(`(?i)\bpassword\s*:\s*([^\r\n]+)`)
	gppGUIDPattern      = regexp.MustCompile(`(?i)\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}`)
	ansiEscapePattern   = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
)

// AnalyzeNetExecGPP extracts explicit recovered GPP password reports. The
// recovered value is assessment evidence and is retained only in the normal
// Finding evidence payload; it is never copied into logs, titles or summaries.
func AnalyzeNetExecGPP(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	if strings.TrimSpace(artifactPath) == "" {
		return nil, fmt.Errorf("GPP artifact path is empty")
	}
	info, err := os.Stat(artifactPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("GPP artifact is not a regular file")
	}
	if info.Size() > 64<<20 {
		return nil, fmt.Errorf("GPP artifact exceeds parser size limit")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	file, err := os.Open(artifactPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var xmlPath, account, password string
	seen := make(map[string]bool)
	var findings []storage.FindingInput
	appendFinding := func(lineNumber int) {
		if password == "" || xmlPath == "" {
			return
		}
		if account == "" {
			account = "unknown account"
		}
		keyMaterial := strings.ToLower(strings.Join([]string{xmlPath, account}, "\x00"))
		hash := sha256.Sum256([]byte(keyMaterial))
		key := "netexec-gpp:" + hex.EncodeToString(hash[:])
		if seen[key] {
			return
		}
		seen[key] = true
		gpo := ""
		if match := gppGUIDPattern.FindString(xmlPath); match != "" {
			gpo = strings.ToUpper(match)
		}
		evidence := map[string]any{
			"source":           "NetExec -M gpp_password",
			"preference_type":  "Local Users and Groups",
			"gpo":              gpo,
			"xml_path":         xmlPath,
			"account":          account,
			"password":         password,
			"credential_state": "recoverable GPP password detected",
			"evidence_excerpt": "NetExec reported a recovered GPP password; the recovered value is retained as assessment evidence.",
			"evidence_line":    lineNumber,
		}
		evidenceJSON, _ := json.Marshal(evidence)
		findings = append(findings, storage.FindingInput{
			FindingKey: key, AssessmentID: assessmentID, SourceTool: "NetExec (nxc)", SourceExecution: executionID,
			FindingType: "netexec_gpp_password_exposure", Title: "Recoverable Password Stored in Group Policy Preferences",
			Description: "NetExec confirmed a recoverable password in a legacy Group Policy Preferences XML file.",
			Severity:    "high", Confidence: "explicit-gpp-password-recovery", AffectedObject: account,
			EvidenceJSON: string(evidenceJSON), ArtifactPath: artifactPath, ArtifactRef: fmt.Sprintf("line:%d", lineNumber), ObservedAt: now, Status: "open", ParserVersion: netExecGPPParserVersion,
		})
	}

	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := ansiEscapePattern.ReplaceAllString(scanner.Text(), "")
		if match := gppXMLPathPattern.FindStringSubmatch(line); len(match) == 2 {
			if password != "" {
				appendFinding(lineNumber)
				account, password = "", ""
			}
			xmlPath = normalizeGPPPath(match[1])
		}
		if match := gppRecoveredPattern.FindStringSubmatch(line); len(match) == 3 {
			account = normalizeGPPAccount(match[1])
			password = strings.TrimSpace(match[2])
			continue
		}
		if match := gppAccountPattern.FindStringSubmatch(line); len(match) == 2 {
			account = normalizeGPPAccount(match[1])
		}
		if match := gppPasswordPattern.FindStringSubmatch(line); len(match) == 2 {
			password = strings.TrimSpace(match[1])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	appendFinding(0)
	return findings, nil
}

func normalizeGPPAccount(value string) string {
	value = strings.TrimSpace(strings.Trim(value, "'\""))
	for strings.Contains(value, `\\`) {
		value = strings.ReplaceAll(value, `\\`, `\`)
	}
	return value
}

func normalizeGPPPath(value string) string {
	value = strings.TrimSpace(strings.Trim(value, "'\""))
	value = strings.ReplaceAll(value, "\\", "/")
	value = strings.TrimPrefix(value, "//")
	return value
}
