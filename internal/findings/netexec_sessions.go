package findings

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const netExecSessionsParserVersion = "netexec-sessions-v1"

var (
	netExecSMBRow      = regexp.MustCompile(`^\s*SMB\s+(\S+)\s+(\d+)\s+(\S+)\s+(.*?)\s*$`)
	netExecSessionUser = regexp.MustCompile(`(?:^|\s)([A-Za-z0-9][^\s\\]*\\[^\s\\]+)(?:\s|$)`)
	// Built-in identities whose domain part contains a space.
	netExecBuiltinOwner = regexp.MustCompile(`(?i)\b(NT AUTHORITY|NT SERVICE|Window Manager|Font Driver Host|IIS APPPOOL|NT VIRTUAL MACHINE|AUTORITE NT)\\`)
)

// netExecSessionSources names the fan-out session outputs and how each one
// sees a signed-in account.
var netExecSessionSources = map[string]string{
	"smb_loggedon_users.txt":    "logged-on users",
	"smb_registry_sessions.txt": "registry sessions",
	"smb_terminal_sessions.txt": "terminal sessions",
	"smb_running_processes.txt": "process owners",
}

// isNetExecSessionArtifact reports whether path is a fan-out session output.
func isNetExecSessionArtifact(path string) bool {
	_, ok := netExecSessionSources[strings.ToLower(filepath.Base(path))]
	return ok
}

// AnalyzeNetExecSessions reads the session outputs PwnFlow runs against every
// confirmed SMB host. It reports, per host, the domain and local accounts the
// output shows signed in, and per credential the hosts where NetExec marked it
// Pwn3d! (local administrator). Built-in, service and machine accounts are not
// listed; nothing beyond the account names is recorded.
func AnalyzeNetExecSessions(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	source, ok := netExecSessionSources[strings.ToLower(filepath.Base(artifactPath))]
	if !ok {
		return nil, nil
	}
	file, err := os.Open(artifactPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	type hostSessions struct {
		host, target string
		line         int
		accounts     map[string]bool
	}
	hosts := map[string]*hostSessions{}
	adminHosts := map[string]map[string]bool{} // principal -> "HOST (target)"
	adminLine := map[string]int{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		match := netExecSMBRow.FindStringSubmatch(netExecANSI.ReplaceAllString(scanner.Text(), ""))
		if match == nil {
			continue
		}
		target, host, rest := match[1], match[3], match[4]
		if strings.HasPrefix(rest, "[+]") {
			if netExecPwned.MatchString(rest) {
				principal := strings.TrimSpace(strings.SplitN(strings.TrimSpace(strings.TrimPrefix(rest, "[+]")), ":", 2)[0])
				if principal != "" && !strings.ContainsAny(principal, " \t") {
					key := strings.ToLower(principal)
					if adminHosts[key] == nil {
						adminHosts[key] = map[string]bool{}
						adminLine[key] = lineNumber
					}
					adminHosts[key][fmt.Sprintf("%s (%s)", host, target)] = true
				}
			}
			continue
		}
		if strings.HasPrefix(rest, "[") || strings.HasPrefix(rest, "=") || strings.HasPrefix(strings.ToUpper(rest), "USERNAME ") || strings.HasPrefix(strings.ToUpper(rest), "SESSIONNAME ") {
			continue
		}
		if netExecBuiltinOwner.MatchString(rest) {
			continue
		}
		user := netExecSessionUser.FindStringSubmatch(rest)
		if user == nil || !interestingSessionAccount(user[1]) {
			continue
		}
		entry := hosts[strings.ToLower(target)]
		if entry == nil {
			entry = &hostSessions{host: host, target: target, line: lineNumber, accounts: map[string]bool{}}
			hosts[strings.ToLower(target)] = entry
		}
		entry.accounts[user[1]] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	var result []storage.FindingInput
	targets := make([]string, 0, len(hosts))
	for target := range hosts {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	for _, target := range targets {
		entry := hosts[target]
		accounts := sortedKeys(entry.accounts)
		encoded, _ := json.Marshal(map[string]any{"host": entry.host, "target": entry.target, "source": source, "accounts": accounts, "affected_objects": accounts})
		result = append(result, storage.FindingInput{
			FindingKey: stableSourceKey(assessmentID, "netexec-sessions", strings.ToLower(entry.target), source), AssessmentID: assessmentID,
			SourceTool: "NetExec (nxc)", SourceExecution: executionID, FindingType: "smb_signed_in_accounts",
			Title:       fmt.Sprintf("Accounts signed in on %s (%s)", entry.host, source),
			Description: fmt.Sprintf("NetExec %s on %s (%s) shows %d account(s) signed in. The credentials of an interactively signed-in account can usually be taken from memory by anyone who administers the host; whether this host keeps reusable material was not verified.", source, entry.host, entry.target, len(accounts)),
			Severity:    "informational", Confidence: "explicit-module-result", AffectedObjectID: strings.ToLower(entry.target), AffectedObject: entry.host,
			EvidenceJSON: string(encoded), ArtifactPath: artifactPath, ArtifactRef: fmt.Sprintf("/lines/%d", entry.line), ObservedAt: now, Status: "open", ParserVersion: netExecSessionsParserVersion,
		})
	}
	principals := make([]string, 0, len(adminHosts))
	for principal := range adminHosts {
		principals = append(principals, principal)
	}
	sort.Strings(principals)
	for _, principal := range principals {
		hostList := sortedKeys(adminHosts[principal])
		encoded, _ := json.Marshal(map[string]any{"account": principal, "host_count": len(hostList), "affected_objects": hostList})
		result = append(result, storage.FindingInput{
			FindingKey: stableSourceKey(assessmentID, "netexec-admin-reach", principal, ""), AssessmentID: assessmentID,
			SourceTool: "NetExec (nxc)", SourceExecution: executionID, FindingType: "netexec_admin_reach",
			Title:       fmt.Sprintf("Local administrator on %d host(s): %s", len(hostList), principal),
			Description: fmt.Sprintf("NetExec marked %s Pwn3d! - local administrator - on %d of the SMB hosts it reached. Each host is also reported on its own as privileged access; this lists them together to show how far the credential reaches.", principal, len(hostList)),
			Severity:    "informational", Confidence: "explicit-pwn3d-marker", AffectedObjectID: principal, AffectedObject: principal,
			EvidenceJSON: string(encoded), ArtifactPath: artifactPath, ArtifactRef: fmt.Sprintf("/lines/%d", adminLine[principal]), ObservedAt: now, Status: "open", ParserVersion: netExecSessionsParserVersion,
		})
	}
	return result, nil
}

// interestingSessionAccount drops machine accounts and the built-in and
// service identities that own sessions and processes on every Windows host.
func interestingSessionAccount(account string) bool {
	domain, name, _ := strings.Cut(account, `\`)
	if name == "" || strings.HasSuffix(name, "$") {
		return false
	}
	switch strings.ToUpper(domain) {
	case "NT AUTHORITY", "NT SERVICE", "WINDOW MANAGER", "FONT DRIVER HOST", "IIS APPPOOL", "NT VIRTUAL MACHINE", "AUTORITE NT":
		return false
	}
	return true
}
