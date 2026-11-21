package findings

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const enumDetailParserVersion = "enum-detail-v1"

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
