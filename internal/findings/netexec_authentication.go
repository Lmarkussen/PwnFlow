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

const netExecAuthenticationParserVersion = "netexec-authentication-v1"

var (
	netExecANSI     = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	netExecAuthLine = regexp.MustCompile(`(?i)^\s*(SMB|LDAP|WINRM|RDP|SSH|WMI|FTP|VNC|MSSQL|NFS)\s+(\S+)\s+(\d+)\s+(\S+)\s+\[\+\]\s+(.+?)\s*$`)
	netExecPwned    = regexp.MustCompile(`(?i)\bpwn3d!`)
)

type netExecAuthenticationEvidence struct {
	Protocol   string `json:"protocol"`
	Target     string `json:"target"`
	Port       string `json:"port"`
	Host       string `json:"host,omitempty"`
	Principal  string `json:"principal"`
	Outcome    string `json:"outcome"`
	Privileged bool   `json:"privileged"`
}

// AnalyzeNetExecAuthentication parses only explicit successful NetExec
// authentication records. Credentials after the principal delimiter are
// intentionally discarded from all derived metadata; the source artifact is
// the authoritative evidence for deliberate inspection.
func AnalyzeNetExecAuthentication(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	file, err := os.Open(artifactPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result := make([]storage.FindingInput, 0)
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := netExecANSI.ReplaceAllString(scanner.Text(), "")
		match := netExecAuthLine.FindStringSubmatch(line)
		if len(match) != 6 {
			continue
		}
		principal := strings.TrimSpace(strings.SplitN(match[5], ":", 2)[0])
		if principal == "" {
			continue
		}
		protocol := strings.ToUpper(match[1])
		target, port, host := match[2], match[3], match[4]
		privileged := netExecPwned.MatchString(match[5])
		condition := "authentication-success"
		if privileged {
			condition = "privileged-access"
		}
		identity := strings.ToLower(strings.Join([]string{protocol, target, port, principal, condition}, "\x00"))
		if seen[identity] {
			continue
		}
		seen[identity] = true
		evidence := netExecAuthenticationEvidence{Protocol: protocol, Target: target, Port: port, Host: host, Principal: principal, Outcome: "success", Privileged: privileged}
		evidenceJSON, _ := json.Marshal(evidence)
		ref := fmt.Sprintf("/lines/%d", lineNumber)
		if privileged {
			result = append(result, netExecAuthenticationFinding(assessmentID, executionID, now, artifactPath, ref, evidence, string(evidenceJSON), true))
		}
		result = append(result, netExecAuthenticationFinding(assessmentID, executionID, now, artifactPath, ref, evidence, string(evidenceJSON), false))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func netExecAuthenticationFinding(assessmentID, executionID int64, now time.Time, artifactPath, ref string, evidence netExecAuthenticationEvidence, evidenceJSON string, privileged bool) storage.FindingInput {
	typ, title, severity, confidence := "netexec_auth_success", "Authentication successful — "+evidence.Protocol, "informational", "explicit-success"
	condition := "authentication-success"
	if privileged {
		typ, title, severity, confidence = "netexec_privileged_access", "Privileged access reported — "+evidence.Protocol, "high", "explicit-pwn3d-marker"
		condition = "privileged-access"
	}
	keyHash := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00%s", assessmentID, strings.ToLower(evidence.Protocol), strings.ToLower(evidence.Target), strings.ToLower(evidence.Principal), condition)))
	return storage.FindingInput{
		FindingKey: "netexec-auth:" + hex.EncodeToString(keyHash[:]), AssessmentID: assessmentID, SourceTool: "NetExec (nxc)", SourceExecution: executionID,
		FindingType: typ, Title: title, Description: fmt.Sprintf("NetExec reported successful %s authentication for %s against %s:%s. The source artifact is authoritative; this does not by itself prove broader domain compromise.", evidence.Protocol, evidence.Principal, evidence.Target, evidence.Port),
		Severity: severity, Confidence: confidence, AffectedObjectID: strings.ToLower(evidence.Target + "\x00" + evidence.Protocol), AffectedObject: evidence.Target, RelatedObjectID: strings.ToLower(evidence.Principal), RelatedObject: evidence.Principal,
		EvidenceJSON: evidenceJSON, ArtifactPath: artifactPath, ArtifactRef: ref, ObservedAt: now, Status: "open", ParserVersion: netExecAuthenticationParserVersion,
	}
}
