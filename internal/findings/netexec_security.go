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
	"strconv"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const netExecSecurityParserVersion = "netexec-security-v1"

var (
	netExecSMBSigningLine = regexp.MustCompile(`(?i)^\s*SMB\s+(\S+)\s+(\d+)\s+(\S+).*?\(\s*signing\s*:\s*(true|false)\s*\)`)
	netExecAccountLine    = regexp.MustCompile(`(?i)\b(?:samaccountname|sAMAccountName|username|user|account|principal)\s*[:=]\s*([A-Za-z0-9._$\\/@-]+)`) //nolint:lll
	netExecUACLine        = regexp.MustCompile(`(?i)\b(?:useraccountcontrol|uac)\s*[:=]\s*([^\s,;]+(?:\s*[|,]\s*[A-Za-z_]+)*)`)
)

const (
	netExecUACDisabled          uint64 = 0x0002
	netExecUACPasswdNotRequired uint64 = 0x0020
	netExecUACDontExpire        uint64 = 0x10000
)

type netExecSMBSigningEvidence struct {
	Protocol        string `json:"protocol"`
	Target          string `json:"target"`
	Port            string `json:"port"`
	Host            string `json:"host"`
	SigningRequired bool   `json:"signing_required"`
}

type netExecAccountControlEvidence struct {
	Account      string `json:"account"`
	Flag         string `json:"flag"`
	UAC          string `json:"user_account_control"`
	Enabled      *bool  `json:"enabled,omitempty"`
	AccountClass string `json:"account_class,omitempty"`
}

// AnalyzeNetExecSecurity extracts only explicit SMB signing state and AD UAC
// flags from finalized NetExec artifacts. It never treats passwords,
// descriptions, or generic password text as account-control evidence.
func AnalyzeNetExecSecurity(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	file, err := os.Open(artifactPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var result []storage.FindingInput
	seen := make(map[string]bool)
	principal := ""
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := netExecANSI.ReplaceAllString(scanner.Text(), "")

		if match := netExecSMBSigningLine.FindStringSubmatch(line); len(match) == 5 && strings.EqualFold(match[4], "false") {
			evidence := netExecSMBSigningEvidence{Protocol: "SMB", Target: match[1], Port: match[2], Host: match[3], SigningRequired: false}
			result = appendUniqueNetExecSecurity(result, seen, storage.FindingInput{
				FindingKey: stableNetExecSecurityKey(assessmentID, "smb-signing-not-required", strings.ToLower(match[1])+":"+match[2]), AssessmentID: assessmentID,
				SourceTool: "NetExec (nxc)", SourceExecution: executionID, FindingType: "smb_signing_not_required", Title: "SMB Signing Not Required",
				Description: fmt.Sprintf("NetExec reported that SMB message signing is not required by %s on %s:%s. This is a configuration exposure and does not prove relay success or compromise.", match[3], match[1], match[2]),
				Severity:    "medium", Confidence: "explicit-signing-state", AffectedObjectID: strings.ToLower(match[1]) + ":" + match[2], AffectedObject: match[3],
				EvidenceJSON: mustMarshalNetExecSecurity(evidence), ArtifactPath: artifactPath, ArtifactRef: fmt.Sprintf("line:%d", lineNumber), ObservedAt: now, Status: "open", ParserVersion: netExecSecurityParserVersion,
			})
		}

		if match := netExecAccountLine.FindStringSubmatch(line); len(match) == 2 {
			principal = strings.TrimSpace(match[1])
		}
		uacMatch := netExecUACLine.FindStringSubmatch(line)
		if len(uacMatch) != 2 || principal == "" {
			continue
		}
		uacText := strings.TrimSpace(uacMatch[1])
		uac, numeric := parseNetExecUAC(uacText)
		if !numeric && !hasNamedNetExecUAC(uacText) {
			continue
		}
		enabled := uac&netExecUACDisabled == 0
		accountClass := "user"
		if strings.HasSuffix(principal, "$") {
			accountClass = "service-or-computer"
		}
		flags := []struct {
			name, typ, title, description, severity string
			bit                                     uint64
		}{
			{"PASSWD_NOTREQD", "ad_account_passwd_notreqd", "Password Not Required Account", "The account has the PASSWD_NOTREQD user-account-control flag. This indicates password-not-required behavior; it does not prove that the account has a blank password.", "medium", netExecUACPasswdNotRequired},
			{"DONT_EXPIRE_PASSWORD", "ad_account_dont_expire_password", "Password Never Expires", "The account has the DONT_EXPIRE_PASSWORD user-account-control flag. Review whether its credential lifecycle is appropriate for this account type.", "low", netExecUACDontExpire},
		}
		for _, flag := range flags {
			if !uacHasFlag(uacText, uac, numeric, flag.name, flag.bit) {
				continue
			}
			flagSeverity := flag.severity
			if !enabled || accountClass != "user" {
				flagSeverity = "informational"
			}
			evidence := netExecAccountControlEvidence{Account: principal, Flag: flag.name, UAC: uacText, Enabled: &enabled, AccountClass: accountClass}
			result = appendUniqueNetExecSecurity(result, seen, storage.FindingInput{
				FindingKey: stableNetExecSecurityKey(assessmentID, flag.typ, strings.ToLower(principal)), AssessmentID: assessmentID,
				SourceTool: "NetExec (nxc)", SourceExecution: executionID, FindingType: flag.typ, Title: flag.title,
				Description: flag.description, Severity: flagSeverity, Confidence: "explicit-uac-flag", AffectedObjectID: strings.ToLower(principal), AffectedObject: principal,
				EvidenceJSON: mustMarshalNetExecSecurity(evidence), ArtifactPath: artifactPath, ArtifactRef: fmt.Sprintf("line:%d", lineNumber), ObservedAt: now, Status: "open", ParserVersion: netExecSecurityParserVersion,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func appendUniqueNetExecSecurity(result []storage.FindingInput, seen map[string]bool, input storage.FindingInput) []storage.FindingInput {
	if seen[input.FindingKey] {
		return result
	}
	seen[input.FindingKey] = true
	return append(result, input)
}

func stableNetExecSecurityKey(assessmentID int64, detector, identity string) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s", assessmentID, detector, identity)))
	return "netexec-security:" + hex.EncodeToString(hash[:])
}

func mustMarshalNetExecSecurity(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func parseNetExecUAC(value string) (uint64, bool) {
	value = strings.TrimSpace(strings.Trim(value, "[](){}\"'"))
	base := 10
	if strings.HasPrefix(strings.ToLower(value), "0x") {
		base = 16
		value = value[2:]
	}
	number, err := strconv.ParseUint(value, base, 64)
	return number, err == nil
}

func hasNamedNetExecUAC(value string) bool {
	upper := strings.ToUpper(value)
	return strings.Contains(upper, "PASSWD_NOTREQD") || strings.Contains(upper, "DONT_EXPIRE_PASSWORD")
}

func uacHasFlag(text string, numericValue uint64, numeric bool, name string, bit uint64) bool {
	if numeric {
		return numericValue&bit != 0
	}
	upper := strings.ToUpper(text)
	return strings.Contains(upper, name)
}
