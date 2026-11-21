package findings

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

// AnalyzeNetExecCoercion reads the spooler and webdav module results. Both
// report a service that lets an authenticated user make the host
// authenticate to a machine of their choosing: the Print Spooler over
// MS-RPRN, and the WebClient over HTTP, which is relayable to LDAP. PwnFlow
// runs SMB modules against the configured domain controller, so a positive
// result concerns that host. No coercion is attempted.
func AnalyzeNetExecCoercion(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	file, err := os.Open(artifactPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var result []storage.FindingInput
	seen := map[string]bool{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		columns := netExecLogLine.FindStringSubmatch(netExecANSI.ReplaceAllString(scanner.Text(), ""))
		if len(columns) != 6 {
			continue
		}
		label, target, port, host := strings.ToUpper(columns[1]), columns[2], columns[3], columns[4]
		message := strings.TrimSpace(columns[5])
		identity := strings.ToLower(target) + ":" + port
		evidence := mustMarshalNetExecSecurity(map[string]any{"protocol": "SMB", "target": target, "port": port, "host": host, "module_output": message})
		ref := fmt.Sprintf("line:%d", lineNumber)
		switch {
		case label == "SPOOLER" && strings.EqualFold(message, "Spooler service enabled"):
			result = appendUniqueNetExecSecurity(result, seen, storage.FindingInput{
				FindingKey: stableNetExecSecurityKey(assessmentID, "smb-spooler-running", identity), AssessmentID: assessmentID,
				SourceTool: "NetExec (nxc)", SourceExecution: executionID, FindingType: "smb_spooler_service_running",
				Title:       "Print Spooler reachable: " + host,
				Description: fmt.Sprintf("The Print Spooler RPC interface answered on %s (%s). Any authenticated user can ask it to connect to a host of their choosing (the 'printer bug'), which makes the machine account authenticate there. On a domain controller this feeds NTLM relay and unconstrained-delegation paths. No coercion was attempted.", host, target),
				Severity:    "medium", Confidence: "explicit-module-result", AffectedObjectID: identity, AffectedObject: host,
				EvidenceJSON: evidence, ArtifactPath: artifactPath, ArtifactRef: ref, ObservedAt: now, Status: "open", ParserVersion: netExecSecurityParserVersion,
			})
		case label == "WEBDAV" && message != "" && !strings.HasPrefix(message, "["):
			// The module prints a line only when the WebClient pipe exists; the
			// text itself is operator-configurable through MSG.
			result = appendUniqueNetExecSecurity(result, seen, storage.FindingInput{
				FindingKey: stableNetExecSecurityKey(assessmentID, "smb-webclient-running", identity), AssessmentID: assessmentID,
				SourceTool: "NetExec (nxc)", SourceExecution: executionID, FindingType: "smb_webclient_service_running",
				Title:       "WebClient service running: " + host,
				Description: fmt.Sprintf("The WebClient service's 'DAV RPC Service' pipe exists on %s (%s). A coerced authentication from this host can then be sent over HTTP, which is relayable to LDAP even where SMB signing is required. No coercion was attempted.", host, target),
				Severity:    "medium", Confidence: "explicit-module-result", AffectedObjectID: identity, AffectedObject: host,
				EvidenceJSON: evidence, ArtifactPath: artifactPath, ArtifactRef: ref, ObservedAt: now, Status: "open", ParserVersion: netExecSecurityParserVersion,
			})
		}
	}
	return result, scanner.Err()
}
