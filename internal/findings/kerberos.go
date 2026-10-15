package findings

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const kerberosParserVersion = "netexec-kerberos-v1"

const maxKerberosArtifactBytes = 64 << 20

type kerberosMaterial struct {
	principal string
	line      int
}

// AnalyzeNetExecKerberos records only the fact that roast material was emitted.
// It deliberately never stores or logs the ticket/hash line itself.
func AnalyzeNetExecKerberos(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	info, err := os.Stat(artifactPath)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("Kerberos artifact is a directory")
	}
	if info.Size() > maxKerberosArtifactBytes {
		return nil, fmt.Errorf("Kerberos artifact exceeds parser size limit")
	}
	file, err := os.Open(artifactPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	kind := "kerberoast"
	if strings.Contains(strings.ToLower(filepath.Base(artifactPath)), "asrep") {
		kind = "asrep"
	}
	byPrincipal := map[string][]int{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := strings.TrimSpace(scanner.Text())
		principal, material := kerberosPrincipal(line, kind)
		if !material {
			continue
		}
		if principal == "" {
			principal = "unresolved principal"
		}
		byPrincipal[principal] = append(byPrincipal[principal], lineNumber)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result := make([]storage.FindingInput, 0, len(byPrincipal))
	for principal, lines := range byPrincipal {
		evidence, _ := json.Marshal(map[string]any{
			"material_type":       kind,
			"material_collected":  true,
			"principal":           principal,
			"record_count":        len(lines),
			"record_line_numbers": lines,
		})
		findingType := "kerberos_ticket_material_collected"
		title := "Kerberoast material collected: " + principal
		if kind == "asrep" {
			findingType = "asrep_material_collected"
			title = "AS-REP material collected: " + principal
		}
		result = append(result, storage.FindingInput{
			FindingKey: stableSourceKey(assessmentID, "netexec-"+kind+"-material", principal, kind), AssessmentID: assessmentID,
			SourceTool: "NetExec", SourceExecution: executionID, FindingType: findingType,
			Title: title, Description: "The NetExec artifact contains roast material associated with this principal. The original restricted artifact remains the source of the material; PwnFlow does not store it in the finding summary.",
			Severity: "medium", Confidence: "observed-material", AffectedObject: principal,
			EvidenceJSON: string(evidence), ArtifactPath: artifactPath, ArtifactRef: fmt.Sprintf("/lines/%d", lines[0]), ObservedAt: now,
			Status: "open", ParserVersion: kerberosParserVersion,
		})
	}
	return result, nil
}

func kerberosPrincipal(line, kind string) (string, bool) {
	if kind == "asrep" {
		if !strings.HasPrefix(strings.ToLower(line), "$krb5asrep$") {
			return "", false
		}
		value := strings.TrimPrefix(line, "$krb5asrep$")
		parts := strings.SplitN(value, "$", 2)
		if len(parts) != 2 {
			return "", true
		}
		principal := strings.TrimSpace(strings.SplitN(parts[1], ":", 2)[0])
		return principal, true
	}
	if !strings.HasPrefix(strings.ToLower(line), "$krb5tgs$") {
		return "", false
	}
	value := strings.TrimPrefix(line, "$krb5tgs$")
	if start := strings.IndexByte(value, '*'); start >= 0 {
		value = value[start+1:]
		if end := strings.IndexByte(value, '*'); end >= 0 {
			value = value[:end]
		}
	}
	parts := strings.Split(value, "$")
	if len(parts) > 0 {
		return strings.TrimSpace(parts[0]), true
	}
	return "", true
}
