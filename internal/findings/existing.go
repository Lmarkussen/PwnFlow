package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

var certipyESCIdentifier = regexp.MustCompile(`(?i)\b(ESC[0-9]+)\b`)
var certipyESCEntry = regexp.MustCompile(`(?i)^\s*\[?\b(ESC[0-9]+)\b`)

// AnalyzeCertipy extracts only template records that Certipy itself marked with
// a vulnerability. Enabled templates without a documented vulnerability are
// collection observations, not findings.
func AnalyzeCertipy(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	var document map[string]any
	if err := readBoundedJSON(artifactPath, &document); err != nil {
		return analyzeCertipyText(ctx, artifactPath, assessmentID, executionID, now)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var result []storage.FindingInput
	for section, kind := range map[string]string{"Certificate Authorities": "ca", "Certificate Templates": "template"} {
		objects, _ := document[section].(map[string]any)
		for name, raw := range objects {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			template, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			vulnerability := template["[!] Vulnerabilities"]
			for _, esc := range extractESCIdentifiers(vulnerability) {
				objectName, objectLabel := certipyObjectIdentity(kind, name, template)
				evidence, _ := json.Marshal(map[string]any{"object_type": kind, "object_name": name, "enabled": template["Enabled"], "esc": esc, "vulnerability": vulnerability, "owner": template["Owner"], "manager_approval": template["Requires Manager Approval"], "authorized_signatures": template["Authorized Signatures Required"]})
				ref := "/" + section + "/" + jsonPointer(name) + "/[!] Vulnerabilities"
				constraints := certipyConstraints(template, kind)
				result = append(result, storage.FindingInput{
					FindingKey: stableSourceKey(assessmentID, "certipy", kind+"/"+name, esc), AssessmentID: assessmentID,
					SourceTool: "Certipy", SourceExecution: executionID, FindingType: "adcs_esc_" + strings.ToLower(esc),
					Title: "Certipy reported " + esc + " — " + objectLabel, Description: "Certipy explicitly reported this ESC condition for a " + kind + ". This is tool evidence of a potential configuration exposure, not proof of exploitation or a complete attack path." + constraints,
					Severity: certipyESCSeverity(esc), Confidence: "tool-reported-esc", AffectedObjectID: objectName, AffectedObject: objectLabel,
					EvidenceJSON: string(evidence), ArtifactPath: artifactPath, ArtifactRef: ref, ObservedAt: now, Status: "open", ParserVersion: "certipy-v2",
				})
			}
		}
	}
	return result, nil
}

func certipyObjectIdentity(kind, key string, object map[string]any) (string, string) {
	if kind == "ca" {
		for _, field := range []string{"CA Name", "Name", "DNS Name"} {
			if value, ok := object[field].(string); ok && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value), strings.TrimSpace(value)
			}
		}
		return key, key
	}
	if _, err := strconv.ParseInt(key, 10, 64); err == nil {
		for _, field := range []string{"Template Name", "Name"} {
			if value, ok := object[field].(string); ok && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value), strings.TrimSpace(value)
			}
		}
		return "", "affected template identity unresolved"
	}
	return key, key
}

func certipyConstraints(object map[string]any, kind string) string {
	if kind == "ca" {
		return ""
	}
	var constraints []string
	if value, ok := object["Enabled"].(bool); ok && !value {
		constraints = append(constraints, " The template is disabled or unpublished in the collected configuration.")
	}
	if value, ok := object["Requires Manager Approval"].(bool); ok && value {
		constraints = append(constraints, " Manager approval is required.")
	}
	if value, ok := object["Authorized Signatures Required"]; ok && meaningful(value) && fmt.Sprint(value) != "0" {
		constraints = append(constraints, " Authorized signatures are required.")
	}
	return strings.Join(constraints, "")
}

func analyzeCertipyText(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	data, err := readBoundedText(artifactPath)
	if err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	section, kind, object := "", "", ""
	inVulnerabilities := false
	var result []storage.FindingInput
	seen := map[string]bool{}
	for lineNumber, line := range strings.Split(data, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "certificate authorities"):
			section, kind, object = "Certificate Authorities", "ca", ""
			inVulnerabilities = false
		case strings.HasPrefix(lower, "certificate templates"):
			section, kind, object = "Certificate Templates", "template", ""
			inVulnerabilities = false
		case strings.HasPrefix(lower, "ca name") && kind == "ca":
			object = textFieldValue(trimmed)
			inVulnerabilities = false
		case strings.HasPrefix(lower, "template name") && kind == "template":
			object = textFieldValue(trimmed)
			inVulnerabilities = false
		case strings.EqualFold(trimmed, "[!] Vulnerabilities"):
			inVulnerabilities = true
		case inVulnerabilities && section != "" && object != "":
			matches := certipyESCEntry.FindStringSubmatch(trimmed)
			if len(matches) < 2 {
				continue
			}
			esc := strings.ToUpper(matches[1])
			key := stableSourceKey(assessmentID, "certipy", kind+"/"+object, esc)
			if seen[key] {
				continue
			}
			seen[key] = true
			ref := fmt.Sprintf("%s/%s/[!] Vulnerabilities/line/%d", section, object, lineNumber+1)
			result = append(result, storage.FindingInput{
				FindingKey: key, AssessmentID: assessmentID, SourceTool: "Certipy", SourceExecution: executionID,
				FindingType: "adcs_esc_" + strings.ToLower(esc), Title: "Certipy reported " + esc + " — " + object,
				Description: "Certipy explicitly reported this ESC condition in its text vulnerability output. This is tool evidence of a potential configuration exposure, not proof of exploitation or a complete attack path.",
				Severity:    certipyESCSeverity(esc), Confidence: "tool-reported-esc", AffectedObjectID: object, AffectedObject: object,
				EvidenceJSON: certipyJSON(map[string]any{"object_type": kind, "object_name": object, "esc": esc, "line": trimmed}), ArtifactPath: artifactPath, ArtifactRef: ref,
				ObservedAt: now, Status: "open", ParserVersion: "certipy-text-v1",
			})
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func textFieldValue(line string) string {
	if index := strings.Index(line, ":"); index >= 0 {
		return strings.TrimSpace(line[index+1:])
	}
	return ""
}

func certipyJSON(value any) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func extractESCIdentifiers(value any) []string {
	seen := make(map[string]bool)
	var result []string
	var walk func(any, bool)
	walk = func(current any, explicitKey bool) {
		switch typed := current.(type) {
		case string:
			matches := certipyESCEntry.FindAllStringSubmatch(typed, 1)
			if explicitKey {
				matches = certipyESCIdentifier.FindAllStringSubmatch(typed, 1)
			}
			for _, match := range matches {
				if len(match) < 2 {
					continue
				}
				esc := strings.ToUpper(match[1])
				if !seen[esc] {
					seen[esc] = true
					result = append(result, esc)
				}
			}
		case []any:
			for _, item := range typed {
				walk(item, false)
			}
		case map[string]any:
			for key, item := range typed {
				walk(key, true)
				walk(item, false)
			}
		}
	}
	walk(value, false)
	sort.Strings(result)
	return result
}

func certipyESCSeverity(esc string) string {
	switch strings.ToUpper(esc) {
	case "ESC1", "ESC4", "ESC8", "ESC13", "ESC15":
		return "high"
	default:
		return "medium"
	}
}

// AnalyzeRelayKing extracts explicit relay-path records. NTLM being enabled or
// an endpoint being reachable alone is not treated as confirmed relayability.
func AnalyzeRelayKing(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	var document map[string]any
	if err := readBoundedJSON(artifactPath, &document); err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var result []storage.FindingInput
	paths, ok := document["relay_paths"]
	if !ok {
		return result, nil
	}
	walkJSON(ctx, paths, "/relay_paths", func(ref string, value map[string]any) bool {
		if !meaningful(value["level"]) && !meaningful(value["impact"]) && !meaningful(value["vulnerable"]) {
			return true
		}
		level := strings.ToLower(fmt.Sprint(value["level"]))
		severity := "informational"
		if level == "critical" || level == "high" {
			severity = "high"
		} else if level == "medium" {
			severity = "medium"
		}
		protocol := firstValue(value, "protocol", "dest_protocol", "source_protocol")
		destination := firstValue(value, "dest_host", "dest_ip", "host")
		evidence, _ := json.Marshal(map[string]any{"level": value["level"], "impact": value["impact"], "protocol": protocol, "destination": destination, "details": value["details"]})
		result = append(result, storage.FindingInput{
			FindingKey: stableSourceKey(assessmentID, "relayking", ref, value), AssessmentID: assessmentID,
			SourceTool: "RelayKing", SourceExecution: executionID, FindingType: "relay_exposure_observed",
			Title: "RelayKing reported an explicit relay path", Description: "RelayKing reported a relay path for the configured assessment. This is evidence of the tool's classified path, not a claim that every NTLM-enabled endpoint is exploitable.",
			Severity: severity, Confidence: "tool-reported-path", AffectedObjectID: destination, AffectedObject: destination,
			EvidenceJSON: string(evidence), ArtifactPath: artifactPath, ArtifactRef: ref, ObservedAt: now, Status: "open", ParserVersion: "relayking-v1",
		})
		return true
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func readBoundedJSON(path string, target any) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Size() > MaxJSONBytes {
		return fmt.Errorf("artifact exceeds parser size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, MaxJSONBytes+1))
	return decoder.Decode(target)
}

func readBoundedText(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Size() > MaxJSONBytes {
		return "", fmt.Errorf("artifact exceeds parser size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxJSONBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > MaxJSONBytes {
		return "", fmt.Errorf("artifact exceeds parser size limit")
	}
	return string(data), nil
}

func meaningful(value any) bool {
	if value == nil {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.TrimSpace(typed) != "" && typed != "[]" && !strings.EqualFold(typed, "none")
	case []any:
		return len(typed) > 0
	default:
		return true
	}
}

func walkJSON(ctx context.Context, value any, ref string, visit func(string, map[string]any) bool) {
	if ctx.Err() != nil {
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		if !visit(ref, typed) {
			return
		}
		for key, child := range typed {
			walkJSON(ctx, child, ref+"/"+jsonPointer(key), visit)
		}
	case []any:
		for index, child := range typed {
			walkJSON(ctx, child, ref+"/"+strconv.Itoa(index), visit)
		}
	}
}

func firstValue(value map[string]any, keys ...string) string {
	for _, key := range keys {
		if item, ok := value[key]; ok && meaningful(item) {
			return fmt.Sprint(item)
		}
	}
	return ""
}

func jsonPointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func stableSourceKey(assessmentID int64, source, object string, detail any) string {
	canonical, _ := json.Marshal(detail)
	hash := sha256.Sum256([]byte(strconv.FormatInt(assessmentID, 10) + "\x00" + source + "\x00" + object + "\x00" + string(canonical)))
	return source + ":" + hex.EncodeToString(hash[:])
}
