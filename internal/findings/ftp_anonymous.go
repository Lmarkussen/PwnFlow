package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const ftpAnonymousParserVersion = "pwntools-ftp-anonymous-v1"

type ftpAnonymousResult struct {
	Target          string `json:"target"`
	Port            int    `json:"port"`
	Username        string `json:"username"`
	Accepted        bool   `json:"accepted"`
	WelcomeResponse string `json:"welcome_response,omitempty"`
	AuthResponse    string `json:"auth_response,omitempty"`
	Stage           string `json:"stage"`
	Error           string `json:"error,omitempty"`
}

type ftpAnonymousReport struct {
	Results []ftpAnonymousResult `json:"results"`
}

// AnalyzeFTPAnonymous creates findings only from an explicit positive FTP login
// response. Rejected, timed-out, malformed, and indeterminate attempts remain
// in the source artifact but intentionally produce no finding.
func AnalyzeFTPAnonymous(ctx context.Context, path string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var report ftpAnonymousReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("FTP anonymous artifact is invalid JSON: %w", err)
	}
	if len(report.Results) == 0 {
		var single ftpAnonymousResult
		if err := json.Unmarshal(data, &single); err != nil {
			return nil, fmt.Errorf("FTP anonymous artifact is invalid JSON: %w", err)
		}
		report.Results = []ftpAnonymousResult{single}
	}
	inputs := make([]storage.FindingInput, 0, len(report.Results))
	seen := make(map[string]bool)
	for _, result := range report.Results {
		if !result.Accepted || result.Port < 1 || result.Port > 65535 || strings.TrimSpace(result.Target) == "" || result.Username != "anonymous" {
			continue
		}
		identity := fmt.Sprintf("%d\x00%s\x00%d\x00%s", assessmentID, strings.ToLower(result.Target), result.Port, strings.ToLower(result.Username))
		hash := sha256.Sum256([]byte(identity))
		key := hex.EncodeToString(hash[:])
		if seen[key] {
			continue
		}
		seen[key] = true
		evidence := map[string]any{
			"target": result.Target, "port": result.Port, "username": result.Username,
			"accepted": true, "welcome_response": result.WelcomeResponse,
			"auth_response": result.AuthResponse, "source_execution": executionID,
		}
		evidenceJSON, err := json.Marshal(evidence)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, storage.FindingInput{
			FindingKey: "pwntools-ftp-anonymous:" + key, AssessmentID: assessmentID,
			SourceTool: "PwnFlow FTP Probe", SourceExecution: executionID,
			FindingType: "pwntools_ftp_anonymous_access", Title: "FTP Anonymous Access Accepted",
			Description: fmt.Sprintf("The FTP service at %s:%d accepted the anonymous account. This confirms authentication acceptance only; file readability, writability and effective access were not tested.", result.Target, result.Port),
			Severity:    "medium", Confidence: "explicit-success", AffectedObjectID: strings.ToLower(fmt.Sprintf("%s:%d", result.Target, result.Port)),
			AffectedObject: fmt.Sprintf("%s:%d", result.Target, result.Port), RelatedObjectID: "anonymous", RelatedObject: "anonymous",
			EvidenceJSON: string(evidenceJSON), ArtifactPath: path, ArtifactRef: "/", ObservedAt: now.UTC(), Status: "open", ParserVersion: ftpAnonymousParserVersion,
		})
	}
	return inputs, nil
}
