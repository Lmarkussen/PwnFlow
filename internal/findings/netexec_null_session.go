package findings

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

var (
	netExecNullLogin      = regexp.MustCompile(`^\[\+\]\s+[^\\\s]*\\:\s*$`)
	netExecUsersCount     = regexp.MustCompile(`(?i)^\[\*\]\s+Enumerated\s+(\d+)\s+(?:local\s+)?users`)
	netExecShareRow       = regexp.MustCompile(`^(\S+)\s+(READ(?:,WRITE)?|WRITE)\b`)
	netExecPasswordPolicy = regexp.MustCompile(`(?i)Dumping password info for domain`)
)

// AnalyzeNetExecNullSession reads the smb-null-session artifact: an SMB run
// with an empty user name and password that asks for users, the password
// policy and shares. A Finding is produced only when the anonymous session
// returned data; an accepted session that returned nothing is already covered
// by the banner observation.
func AnalyzeNetExecNullSession(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	file, err := os.Open(artifactPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var (
		target, port, host string
		loggedIn, policy   bool
		users              int
		shares             []string
		firstLine          int
	)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		columns := netExecLogLine.FindStringSubmatch(netExecANSI.ReplaceAllString(scanner.Text(), ""))
		if len(columns) != 6 || !strings.EqualFold(columns[1], "SMB") {
			continue
		}
		message := strings.TrimSpace(columns[5])
		if target == "" {
			target, port, host = columns[2], columns[3], columns[4]
		}
		switch {
		case netExecNullLogin.MatchString(message):
			loggedIn = true
		case !loggedIn:
			continue
		case netExecUsersCount.MatchString(message):
			if count, err := strconv.Atoi(netExecUsersCount.FindStringSubmatch(message)[1]); err == nil && count > users {
				users = count
				firstLine = max(firstLine, lineNumber)
			}
		case netExecPasswordPolicy.MatchString(message):
			policy = true
			if firstLine == 0 {
				firstLine = lineNumber
			}
		default:
			if match := netExecShareRow.FindStringSubmatch(message); len(match) == 3 && !strings.EqualFold(match[1], "IPC$") {
				shares = append(shares, match[1]+" ("+match[2]+")")
				if firstLine == 0 {
					firstLine = lineNumber
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !loggedIn || (users == 0 && !policy && len(shares) == 0) {
		return nil, nil
	}
	var exposed []string
	if users > 0 {
		exposed = append(exposed, fmt.Sprintf("%d domain users", users))
	}
	if policy {
		exposed = append(exposed, "the password policy")
	}
	if len(shares) > 0 {
		exposed = append(exposed, fmt.Sprintf("%d share(s)", len(shares)))
	}
	severity := "medium"
	if users > 0 || policy {
		severity = "high"
	}
	identity := strings.ToLower(target) + ":" + port
	evidence := mustMarshalNetExecSecurity(map[string]any{
		"protocol": "SMB", "target": target, "port": port, "host": host, "users_enumerated": users,
		"password_policy_read": policy, "readable_shares": shares, "session": "empty user name and password",
	})
	return []storage.FindingInput{{
		FindingKey: stableNetExecSecurityKey(assessmentID, "smb-null-session-enumeration", identity), AssessmentID: assessmentID,
		SourceTool: "NetExec (nxc)", SourceExecution: executionID, FindingType: "smb_null_session_enumeration",
		Title:       "Anonymous SMB enumeration: " + host,
		Description: fmt.Sprintf("An SMB session with an empty user name and password on %s (%s) returned %s. Unauthenticated clients can collect the same data, which supports password spraying and target selection without any credential.", host, target, strings.Join(exposed, ", ")),
		Severity:    severity, Confidence: "explicit-module-result", AffectedObjectID: identity, AffectedObject: host,
		EvidenceJSON: evidence, ArtifactPath: artifactPath, ArtifactRef: fmt.Sprintf("line:%d", max(firstLine, 1)), ObservedAt: now, Status: "open", ParserVersion: netExecSecurityParserVersion,
	}}, nil
}
