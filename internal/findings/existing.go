package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

// AnalyzeCertipy extracts only template records that Certipy itself marked with
// a vulnerability. Enabled templates without a documented vulnerability are
// collection observations, not findings.
func AnalyzeCertipy(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	var document map[string]any
	if err := readBoundedJSON(artifactPath, &document); err != nil {
		return nil, err
	}
	templates, ok := document["Certificate Templates"].(map[string]any)
	if !ok {
		return nil, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var result []storage.FindingInput
	for name, raw := range templates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		template, ok := raw.(map[string]any)
		if !ok || !meaningful(template["[!] Vulnerabilities"]) {
			continue
		}
		vulnerability := template["[!] Vulnerabilities"]
		evidence, _ := json.Marshal(map[string]any{"template_name": name, "enabled": template["Enabled"], "vulnerabilities": vulnerability, "owner": template["Owner"]})
		ref := "/Certificate Templates/" + jsonPointer(name)
		result = append(result, storage.FindingInput{
			FindingKey: stableSourceKey(assessmentID, "certipy", name, vulnerability), AssessmentID: assessmentID,
			SourceTool: "Certipy", SourceExecution: executionID, FindingType: "adcs_template_vulnerability",
			Title: "Certipy flagged certificate template " + name, Description: "Certipy marked this certificate template with a vulnerability condition. The finding preserves the tool's evidence and does not claim exploitability without the template context.",
			Severity: "medium", Confidence: "tool-flagged-potential", AffectedObjectID: name, AffectedObject: name,
			EvidenceJSON: string(evidence), ArtifactPath: artifactPath, ArtifactRef: ref, ObservedAt: now, Status: "open", ParserVersion: "certipy-v1",
		})
	}
	return result, nil
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
