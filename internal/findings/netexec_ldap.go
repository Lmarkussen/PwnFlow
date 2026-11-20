package findings

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const netExecLDAPParserVersion = "netexec-ldap-v1"

var (
	// netExecLogLine splits a NetExec log line into its fixed columns: the
	// protocol or module label, target, port, host name, and the message.
	netExecLogLine = regexp.MustCompile(`^\s*(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s*(.*)$`)
	// netExecLDAPBanner is the LDAP host banner, which reports the signing and
	// LDAPS channel-binding state NetExec probed before authenticating.
	netExecLDAPBanner = regexp.MustCompile(`(?i)\(domain:([^)]*)\)\s*\(signing:([^)]*)\)\s*\(channel binding:([^)]*)\)`)
	// netExecLDAPLogin captures only the domain and account of a successful
	// login line. The password that follows the colon is never captured.
	netExecLDAPLogin = regexp.MustCompile(`^\[\+\]\s+([^\\\s]+)\\([^:\s]+):`)
	// netExecObsoleteHost is one host line of -M obsolete.
	netExecObsoleteHost = regexp.MustCompile(`^(\S+)\s+\(([^)]*)\)\s+:\s+(.+?)\s+\[pwd-last-set:\s*([^\]]*)\]\s*$`)
	// netExecPasswordAttribute is one account line of -M get-userPassword or
	// -M get-unixUserPassword. Only the account and attribute are captured.
	netExecPasswordAttribute = regexp.MustCompile(`^User:\s+(\S+)\s+(userPassword|unixUserPassword):\s`)
)

type netExecLDAPHost struct {
	Protocol string `json:"protocol"`
	Target   string `json:"target"`
	Port     string `json:"port"`
	Host     string `json:"host"`
	Domain   string `json:"domain,omitempty"`
}

// AnalyzeNetExecLDAP reads the LDAP-specific observations from a finalized
// NetExec artifact: the signing and channel-binding state in the LDAP banner,
// and the results of the dns-nonsecure, obsolete, get-userPassword and
// get-unixUserPassword modules. Password attribute values are never stored:
// a Finding records which account's attribute the assessment account could
// read, not what it contains.
func AnalyzeNetExecLDAP(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	file, err := os.Open(artifactPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var (
		result    []storage.FindingInput
		seen      = make(map[string]bool)
		host      netExecLDAPHost
		readBy    string
		dnsScope  string
		obsolete  []map[string]string
		firstLine int
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
		if len(columns) != 6 {
			continue
		}
		label := strings.ToUpper(columns[1])
		message := strings.TrimSpace(columns[5])
		ref := fmt.Sprintf("line:%d", lineNumber)

		switch {
		case label == "LDAP" || label == "LDAPS":
			if banner := netExecLDAPBanner.FindStringSubmatch(message); len(banner) == 4 {
				host = netExecLDAPHost{Protocol: label, Target: columns[2], Port: columns[3], Host: columns[4], Domain: strings.TrimSpace(banner[1])}
				result = appendNetExecLDAPBanner(result, seen, host, strings.TrimSpace(banner[2]), strings.TrimSpace(banner[3]), assessmentID, executionID, artifactPath, ref, now)
			}
			if login := netExecLDAPLogin.FindStringSubmatch(message); len(login) == 3 {
				readBy = login[1] + `\` + login[2]
			}
		case strings.HasPrefix(label, "DNS-NONS"):
			lower := strings.ToLower(message)
			switch {
			case strings.HasPrefix(message, "[+]") && strings.Contains(lower, "allowing nonsecure dynamic updates"):
				dnsScope = strings.ToLower(strings.Fields(strings.TrimSpace(strings.TrimPrefix(message, "[+]")))[0])
			case strings.HasPrefix(message, "["):
				dnsScope = ""
			case dnsScope != "" && message != "":
				result = appendNetExecLDAPFinding(result, seen, storage.FindingInput{
					FindingKey: stableNetExecSecurityKey(assessmentID, "ldap-dns-nonsecure-zone", strings.ToLower(host.Domain+"|"+message)), AssessmentID: assessmentID,
					SourceTool: "NetExec (nxc)", SourceExecution: executionID, FindingType: "ad_domain_config_dns_nonsecure_updates",
					Title:       "DNS zone accepts nonsecure dynamic updates: " + message,
					Description: fmt.Sprintf("NetExec's dns-nonsecure module reported that the AD-integrated %s DNS zone %s allows nonsecure dynamic updates. Any client that can reach the DNS server may then register or overwrite records in this zone without authenticating. No record was created or changed.", dnsScope, message),
					Severity:    "medium", Confidence: "explicit-module-result", AffectedObjectID: strings.ToLower(message), AffectedObject: message,
					EvidenceJSON: mustMarshalNetExecSecurity(map[string]any{"zone": message, "zone_scope": dnsScope, "domain": host.Domain, "dns_server": host.Host, "target": host.Target, "dynamic_update": "nonsecure and secure"}),
					ArtifactPath: artifactPath, ArtifactRef: ref, ObservedAt: now, Status: "open", ParserVersion: netExecLDAPParserVersion,
				})
			}
		case label == "OBSOLETE":
			if match := netExecObsoleteHost.FindStringSubmatch(message); len(match) == 5 {
				if firstLine == 0 {
					firstLine = lineNumber
				}
				obsolete = append(obsolete, map[string]string{"host": match[1], "address": match[2], "operating_system": match[3], "pwd_last_set": match[4]})
			}
		case strings.HasPrefix(label, "GET-USER") || strings.HasPrefix(label, "GET-UNIX"):
			// The module prints "Found following users" even when the search
			// returned only referrals, so only explicit account lines count.
			match := netExecPasswordAttribute.FindStringSubmatch(message)
			if len(match) != 3 {
				continue
			}
			account, attribute := match[1], match[2]
			reader := fallbackString(readBy, "the assessment account")
			result = appendNetExecLDAPFinding(result, seen, storage.FindingInput{
				FindingKey: stableNetExecSecurityKey(assessmentID, "ldap-password-attribute-readable", strings.ToLower(host.Domain+"|"+account+"|"+attribute)), AssessmentID: assessmentID,
				SourceTool: "NetExec (nxc)", SourceExecution: executionID, FindingType: "ad_account_password_attribute_readable",
				Title:       fmt.Sprintf("%s readable: %s", attribute, account),
				Description: fmt.Sprintf("NetExec read a populated %s attribute on %s while authenticated as %s. The attribute may hold a reusable password and should be cleared. The value is kept only in the restricted original artifact and is not recorded in this Finding.", attribute, account, reader),
				Severity:    "high", Confidence: "explicit-module-result", AffectedObjectID: strings.ToLower(account), AffectedObject: account,
				EvidenceJSON: mustMarshalNetExecSecurity(map[string]any{"account": account, "domain": host.Domain, "flag": attribute + " readable", "user_account_control": "read by " + reader + " (value withheld)", "attribute": attribute, "read_by": reader, "value_recorded": false}),
				ArtifactPath: artifactPath, ArtifactRef: ref, ObservedAt: now, Status: "open", ParserVersion: netExecLDAPParserVersion,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(obsolete) > 0 {
		sort.Slice(obsolete, func(i, j int) bool { return obsolete[i]["host"] < obsolete[j]["host"] })
		names := make([]string, 0, len(obsolete))
		for _, item := range obsolete {
			names = append(names, item["host"])
		}
		domain := fallbackString(host.Domain, host.Target)
		result = appendNetExecLDAPFinding(result, seen, storage.FindingInput{
			FindingKey: stableNetExecSecurityKey(assessmentID, "ldap-obsolete-os", strings.ToLower(domain)), AssessmentID: assessmentID,
			SourceTool: "NetExec (nxc)", SourceExecution: executionID, FindingType: "ad_account_obsolete_operating_system",
			Title:       fmt.Sprintf("Enabled computers with unsupported operating systems (%s)", domain),
			Description: fmt.Sprintf("NetExec's obsolete module found %d enabled computer account(s) whose operatingSystem attribute names a Windows release that no longer receives security updates. The attribute is self-reported by the computer and may be stale; the hosts were not contacted.", len(obsolete)),
			Severity:    "medium", Confidence: "explicit-module-result", AffectedObjectID: strings.ToLower(domain), AffectedObject: domain,
			EvidenceJSON: mustMarshalNetExecSecurity(map[string]any{"account": fmt.Sprintf("%d enabled computer(s)", len(obsolete)), "domain": host.Domain, "flag": "unsupported operating system", "enabled": true, "user_account_control": "operatingSystem attribute", "object_count": len(obsolete), "affected_objects": names, "objects": obsolete}),
			ArtifactPath: artifactPath, ArtifactRef: fmt.Sprintf("line:%d", firstLine), ObservedAt: now, Status: "open", ParserVersion: netExecLDAPParserVersion,
		})
	}
	return result, nil
}

// appendNetExecLDAPBanner turns the banner's signing and channel-binding
// fields into Findings. NetExec prints "signing:None" and "channel
// binding:Never" both when its probe proved the setting and when the probe
// failed for another reason, so these remain tool-reported observations.
func appendNetExecLDAPBanner(result []storage.FindingInput, seen map[string]bool, host netExecLDAPHost, signing, binding string, assessmentID, executionID int64, artifactPath, ref string, now time.Time) []storage.FindingInput {
	identity := strings.ToLower(host.Target + "|" + host.Host)
	caveat := " NetExec reports this state from its own pre-authentication probe and prints the same value when that probe fails for another reason, for example when NTLM is disabled, so confirm it against the domain controller policy. No relay was attempted."
	if strings.EqualFold(signing, "None") {
		evidence := map[string]any{"target": host.Target, "port": "389", "host": host.Host, "domain": host.Domain, "signing": signing, "reported_by": "NetExec LDAP banner"}
		result = appendNetExecLDAPFinding(result, seen, storage.FindingInput{
			FindingKey: stableNetExecSecurityKey(assessmentID, "ldap-signing-not-enforced", identity), AssessmentID: assessmentID,
			SourceTool: "NetExec (nxc)", SourceExecution: executionID, FindingType: "ldap_signing_not_enforced",
			Title:       "LDAP signing not enforced: " + host.Host,
			Description: fmt.Sprintf("NetExec reported that %s (%s) accepted an unsigned LDAP bind, which leaves LDAP open to NTLM relay.", host.Host, host.Target) + caveat,
			Severity:    "medium", Confidence: "tool-reported-not-verified", AffectedObjectID: identity, AffectedObject: host.Host,
			EvidenceJSON: mustMarshalNetExecSecurity(evidence), ArtifactPath: artifactPath, ArtifactRef: ref, ObservedAt: now, Status: "open", ParserVersion: netExecLDAPParserVersion,
		})
	}
	severity := ""
	switch strings.ToLower(binding) {
	case "never":
		severity = "medium"
	case "when supported":
		severity = "low"
	}
	if severity != "" {
		evidence := map[string]any{"target": host.Target, "port": "636", "host": host.Host, "domain": host.Domain, "channel_binding": binding, "reported_by": "NetExec LDAP banner"}
		result = appendNetExecLDAPFinding(result, seen, storage.FindingInput{
			FindingKey: stableNetExecSecurityKey(assessmentID, "ldaps-channel-binding-not-enforced", identity), AssessmentID: assessmentID,
			SourceTool: "NetExec (nxc)", SourceExecution: executionID, FindingType: "ldap_channel_binding_not_enforced",
			Title:       "LDAPS channel binding not required: " + host.Host,
			Description: fmt.Sprintf("NetExec reported LDAPS channel binding as %q on %s (%s). Unless channel binding is required, NTLM authentication relayed to LDAPS is not rejected.", binding, host.Host, host.Target) + caveat,
			Severity:    severity, Confidence: "tool-reported-not-verified", AffectedObjectID: identity, AffectedObject: host.Host,
			EvidenceJSON: mustMarshalNetExecSecurity(evidence), ArtifactPath: artifactPath, ArtifactRef: ref, ObservedAt: now, Status: "open", ParserVersion: netExecLDAPParserVersion,
		})
	}
	return result
}

func appendNetExecLDAPFinding(result []storage.FindingInput, seen map[string]bool, input storage.FindingInput) []storage.FindingInput {
	return appendUniqueNetExecSecurity(result, seen, input)
}
