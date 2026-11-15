package findings

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const enumDetailParserVersion = "enum-detail-v1"

var enumCVELine = regexp.MustCompile(`(?i)^\s*ENUM_CVE\s+(\S+)\s+\d+\s+(\S+)\s+(.*)$`)
var enumCVEPositive = regexp.MustCompile(`(?i)^(?:\[\+\]\s*)?((?:CVE-\d{4}-\d{4,}|KB\d+))\s+-\s+.+\s+-\s+.+$`)

// AnalyzeEnumCVE retains check outcomes without treating registry patch heuristics
// as verified vulnerabilities. Only the dedicated module's result rows are read.
func AnalyzeEnumCVE(ctx context.Context, path string, assessment, execution int64, now time.Time) ([]storage.FindingInput, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	seen := map[string]bool{}
	var out []storage.FindingInput
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := netExecANSI.ReplaceAllString(scanner.Text(), "")
		row := enumCVELine.FindStringSubmatch(line)
		if row == nil {
			continue
		}
		text := row[3]
		lower := strings.ToLower(text)
		outcome := "inconclusive"
		id := ""
		severity := "informational"
		switch {
		case strings.Contains(lower, "not vulnerable"):
			outcome = "negative"
		case strings.Contains(lower, "cannot check"), strings.Contains(lower, "not listed"), strings.Contains(lower, "skipping"), strings.Contains(lower, "unknown cve"), strings.Contains(lower, "cannot determine"):
			outcome = "unsupported"
		case strings.Contains(lower, "error"), strings.Contains(lower, "could not"), strings.Contains(lower, "deactivated"):
			outcome = "execution-failure"
		default:
			if match := enumCVEPositive.FindStringSubmatch(text); match != nil {
				outcome = "potential-exposure"
				id = strings.ToUpper(match[1])
				if knownEnumCVEMessage(lower) {
					severity = "medium"
				} else {
					outcome = "inconclusive"
				}
			}
		}
		// Debug, authentication and exploitation links are not check results.
		if outcome == "inconclusive" && id == "" {
			continue
		}
		identity := strings.ToLower(row[1]) + ":" + id + ":" + outcome
		if id == "" {
			identity += ":" + lower
		}
		key := stableNetExecSecurityKey(assessment, "enum-cve", identity)
		out = appendUniqueNetExecSecurity(out, seen, storage.FindingInput{FindingKey: key, AssessmentID: assessment, SourceTool: "NetExec (nxc)", SourceExecution: execution, FindingType: "netexec_cve_check", Title: strings.TrimSpace("NetExec CVE check " + id + " — " + outcome), Description: "Registry OS/build and UBR check only. Components, mitigations and exploitation are unverified.", Severity: severity, Confidence: "registry-patch-heuristic", AffectedObjectID: strings.ToLower(row[1]), AffectedObject: row[2], EvidenceJSON: mustMarshalNetExecSecurity(map[string]string{"target": row[1], "host": row[2], "identifier": id, "outcome": outcome, "source_line": text}), ArtifactPath: path, ArtifactRef: fmt.Sprintf("line:%d", lineNo), ObservedAt: now, Status: "open", ParserVersion: enumDetailParserVersion})
	}
	return out, scanner.Err()
}

// AnalyzeBloodyADWritable stores each DN's complete detail block as permission
// evidence. No inferred ACL edge or exploitation claim is generated.
func AnalyzeBloodyADWritable(ctx context.Context, path string, assessment, execution int64, now time.Time) ([]storage.FindingInput, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []storage.FindingInput
	seen := map[string]bool{}
	dn := ""
	var block []string
	start := 0
	flush := func() {
		details := bloodyADPermissionDetails(block)
		if dn == "" || !strings.Contains(dn, "=") || len(details) == 0 {
			return
		}
		key := stableNetExecSecurityKey(assessment, "bloodyad-writable", strings.ToLower(dn))
		out = appendUniqueNetExecSecurity(out, seen, storage.FindingInput{FindingKey: key, AssessmentID: assessment, SourceTool: "BloodyAD", SourceExecution: execution, FindingType: "bloodyad_writable_permissions", Title: "Writable directory object permissions", Description: "BloodyAD reported effective writable permissions. This does not establish exploitation or a privileged attack path.", Severity: "informational", Confidence: "tool-reported-permissions", AffectedObjectID: strings.ToLower(dn), AffectedObject: dn, EvidenceJSON: mustMarshalNetExecSecurity(map[string]any{"distinguished_name": dn, "permission_detail": strings.Join(block, "\n"), "effective_permissions": details}), ArtifactPath: path, ArtifactRef: fmt.Sprintf("line:%d", start), ObservedAt: now, Status: "open", ParserVersion: enumDetailParserVersion})
	}
	for i, line := range strings.Split(netExecANSI.ReplaceAllString(string(data), ""), "\n") {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), "distinguishedname:") {
			flush()
			dn = strings.TrimSpace(strings.SplitN(trimmed, ":", 2)[1])
			block = nil
			start = i + 1
		}
		if dn != "" && trimmed != "" {
			block = append(block, line)
		}
	}
	flush()
	return out, nil
}

func knownEnumCVEMessage(line string) bool {
	for _, marker := range []string{"relay possible from smb", "can relay smb", "only windows server 2025 is exploitable", "escalation to domain admin possible", "may be vulnerable to esc15", "may be vulnerable to certighost", "password reset of any account possible", "can coerce to a webdav listener", "does not negotiate ntlm signing", "smb-to-ldap ntlm relay is possible"} {
		if strings.Contains(line, marker) {
			return true
		}
	}
	return false
}

func bloodyADPermissionDetails(block []string) map[string][]string {
	result := map[string][]string{}
	for _, line := range block {
		fields := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(fields) != 2 {
			continue
		}
		for _, right := range strings.Split(fields[1], ";") {
			right = strings.TrimSpace(right)
			if right == "WRITE" || right == "CREATE_CHILD" {
				result[fields[0]] = append(result[fields[0]], right)
			}
		}
	}
	return result
}
