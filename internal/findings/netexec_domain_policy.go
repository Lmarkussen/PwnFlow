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

const netExecDomainPolicyParserVersion = "netexec-domain-policy-v1"

const domainPolicyWeakMinimumThreshold = 8

var (
	domainPolicyDomain   = regexp.MustCompile(`(?i)\b(?:domain(?:\s+name)?|dnsroot)\s*[:=]\s*([a-z0-9][a-z0-9.-]*\.[a-z0-9.-]+)`)
	domainPolicyIdentity = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9.-]*\.[a-z0-9.-]+)\\[a-z0-9._$-]+`)
	domainPolicyMinimum  = regexp.MustCompile(`(?i)\b(?:minPwdLength|minimum\s+password\s+length|min(?:imum)?\s+password\s+length)\s*[:=]?\s*(\d+)`)
	domainPolicyMaximum  = regexp.MustCompile(`(?i)\b(?:maxPwdAge|maximum\s+password\s+age)\s*[:=]?\s*([-+]?\d+|never|none|does\s+not\s+expire|[^\r\n]*)`)
	domainPolicyQuota    = regexp.MustCompile(`(?i)\b(?:ms-DS-MachineAccountQuota|machine\s*account\s*quota|MachineAccountQuota)\s*[:=]?\s*(-?\d+)`)
)

type domainPolicyAge struct {
	NonExpiring bool
	Display     string
}

// AnalyzeNetExecDomainPolicy extracts only domain-default policy values from
// the existing NetExec LDAP policy artifacts. Fine-grained policy artifacts
// are intentionally not interpreted as domain defaults.
func AnalyzeNetExecDomainPolicy(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
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
	domain := ""
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := netExecANSI.ReplaceAllString(scanner.Text(), "")
		if match := domainPolicyDomain.FindStringSubmatch(line); len(match) == 2 {
			domain = normalizeDomain(match[1])
		}
		if match := domainPolicyIdentity.FindStringSubmatch(line); len(match) == 2 {
			domain = normalizeDomain(match[1])
		}
		if domain == "" {
			continue
		}

		if match := domainPolicyMinimum.FindStringSubmatch(line); len(match) == 2 {
			minimum, parseErr := strconv.Atoi(match[1])
			if parseErr == nil && minimum > 0 && minimum < domainPolicyWeakMinimumThreshold {
				input := domainPolicyFinding(assessmentID, executionID, now, artifactPath, lineNumber, domain, "weak_minimum_password_length", "Weak Minimum Password Length", "low", fmt.Sprintf("The domain default password policy permits a minimum password length of %d characters. This is a policy observation, not evidence that any password was cracked or compromised.", minimum), map[string]any{
					"domain": domain, "minimum_password_length": minimum, "policy_scope": "domain default policy", "source_field": match[0], "threshold": domainPolicyWeakMinimumThreshold, "fine_grained_policy_limitation": "Fine-grained password policies may override this domain default for selected users or groups.",
				})
				if !seen[input.FindingKey] {
					seen[input.FindingKey] = true
					result = append(result, input)
				}
			}
		}

		if match := domainPolicyMaximum.FindStringSubmatch(line); len(match) == 2 {
			if age, ok := parseDomainPolicyAge(match[1]); ok && age.NonExpiring {
				input := domainPolicyFinding(assessmentID, executionID, now, artifactPath, lineNumber, domain, "password_expiration_not_enforced", "Domain Password Expiration Not Enforced", "informational", fmt.Sprintf("The domain default password policy reports no maximum password age (%s). This is a policy observation and does not establish that every account has an expired, weak, or compromised password.", age.Display), map[string]any{
					"domain": domain, "maximum_password_age": age.Display, "policy_scope": "domain default policy", "source_field": match[0], "fine_grained_policy_limitation": "Fine-grained password policies may override this domain default for selected users or groups; this detector does not reconcile those policies.",
				})
				if !seen[input.FindingKey] {
					seen[input.FindingKey] = true
					result = append(result, input)
				}
			}
		}

		if match := domainPolicyQuota.FindStringSubmatch(line); len(match) == 2 {
			quota, parseErr := strconv.ParseInt(match[1], 10, 64)
			if parseErr == nil && quota > 0 {
				input := domainPolicyFinding(assessmentID, executionID, now, artifactPath, lineNumber, domain, "machine_account_creation_quota", "Machine Account Creation Quota", "informational", fmt.Sprintf("The domain is configured with a machine account creation quota of %d. Eligible authenticated users may be able to create computer accounts subject to directory permissions and policy; this evidence does not show that one was created.", quota), map[string]any{
					"domain": domain, "machine_account_quota": quota, "policy_scope": "domain default policy", "source_field": match[0], "fine_grained_policy_limitation": "This quota is a domain-level setting and is not evidence of effective permissions for any particular user.",
				})
				if !seen[input.FindingKey] {
					seen[input.FindingKey] = true
					result = append(result, input)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func domainPolicyFinding(assessmentID, executionID int64, now time.Time, artifactPath string, line int, domain, detector, title, severity, description string, evidence map[string]any) storage.FindingInput {
	keyHash := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s\x00%s", assessmentID, domain, detector, "domain-default")))
	encoded, _ := json.Marshal(evidence)
	return storage.FindingInput{
		FindingKey: "netexec-domain-policy:" + hex.EncodeToString(keyHash[:]), AssessmentID: assessmentID, SourceTool: "NetExec (nxc)", SourceExecution: executionID,
		FindingType: "ad_domain_policy_" + detector, Title: title, Description: description, Severity: severity, Confidence: "observed-domain-default-policy", AffectedObjectID: domain, AffectedObject: domain,
		EvidenceJSON: string(encoded), ArtifactPath: artifactPath, ArtifactRef: fmt.Sprintf("line:%d", line), ObservedAt: now, Status: "open", ParserVersion: netExecDomainPolicyParserVersion,
	}
}

func normalizeDomain(value string) string {
	return strings.ToLower(strings.TrimSpace(strings.Trim(value, "<>[](){}\"'")))
}

func parseDomainPolicyAge(value string) (domainPolicyAge, bool) {
	value = strings.TrimSpace(strings.Trim(value, "<>[](){}\"'"))
	if value == "" {
		return domainPolicyAge{}, false
	}
	lower := strings.ToLower(value)
	if lower == "never" || lower == "none" || strings.Contains(lower, "does not expire") {
		return domainPolicyAge{NonExpiring: true, Display: "non-expiring"}, true
	}
	if numeric, err := strconv.ParseInt(value, 10, 64); err == nil {
		if numeric == 0 {
			return domainPolicyAge{NonExpiring: true, Display: "non-expiring (maxPwdAge=0)"}, true
		}
		return domainPolicyAge{Display: formatADInterval(numeric)}, true
	}
	if strings.Contains(lower, "0 days") && strings.Contains(lower, "0 hours") {
		return domainPolicyAge{NonExpiring: true, Display: "non-expiring (zero duration)"}, true
	}
	return domainPolicyAge{}, false
}

func formatADInterval(value int64) string {
	negative := value < 0
	var ticks uint64
	if negative {
		ticks = uint64(-(value + 1)) + 1
	} else {
		ticks = uint64(value)
	}
	seconds := ticks / 10_000_000
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60
	remaining := seconds % 60
	if negative {
		return fmt.Sprintf("%d days %d hours %d minutes %d seconds", days, hours, minutes, remaining)
	}
	return fmt.Sprintf("%d days %d hours %d minutes %d seconds (positive interval)", days, hours, minutes, remaining)
}
