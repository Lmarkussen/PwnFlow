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
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const masscanParserVersion = "masscan-grepable-v1"

var masscanHostLine = regexp.MustCompile(`^Host:\s+([^\s(]+).*?Ports:\s+(.+)$`)

func AnalyzeMasscan(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	info, err := os.Stat(artifactPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("Masscan artifact is not a regular file")
	}
	if info.Size() > 64<<20 {
		return nil, fmt.Errorf("Masscan artifact exceeds parser size limit")
	}
	file, err := os.Open(artifactPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var findings []storage.FindingInput
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	seen := make(map[string]bool)
	for scanner.Scan() {
		lineNumber++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := strings.TrimSpace(scanner.Text())
		match := masscanHostLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		host := match[1]
		for _, rawPort := range strings.Split(match[2], ",") {
			parts := strings.Split(strings.TrimSpace(rawPort), "/")
			if len(parts) < 3 || strings.ToLower(parts[1]) != "open" {
				continue
			}
			port, protocol := parts[0], strings.ToLower(parts[2])
			if port == "" || protocol == "" {
				continue
			}
			ref := fmt.Sprintf("line:%d:%s/%s", lineNumber, port, protocol)
			if seen[ref] {
				continue
			}
			seen[ref] = true
			evidence, _ := json.Marshal(map[string]any{"host": host, "port": port, "protocol": protocol, "state": "open", "line": line})
			keyHash := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s\x00%s", assessmentID, host, ref, artifactPath)))
			findings = append(findings, storage.FindingInput{
				FindingKey:      "masscan:" + hex.EncodeToString(keyHash[:]),
				AssessmentID:    assessmentID,
				SourceTool:      "Masscan",
				SourceExecution: executionID,
				FindingType:     "masscan_open_port_observed",
				Title:           fmt.Sprintf("Open port observed on %s", host),
				Description:     "Masscan observed an open TCP port. This is a network observation, not proof of a vulnerability, product identity, anonymous access, relay exposure, or compromise.",
				Severity:        "informational",
				Confidence:      "observed-artifact",
				AffectedObject:  host,
				EvidenceJSON:    string(evidence),
				ArtifactPath:    artifactPath,
				ArtifactRef:     ref,
				ObservedAt:      now,
				Status:          "open",
				ParserVersion:   masscanParserVersion,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}
