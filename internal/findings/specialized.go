package findings

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const specializedParserVersion = "specialized-artifacts-v1"
const maxSpecializedArtifactBytes = 64 << 20

func AnalyzeSpecialized(ctx context.Context, artifactPath, source string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	if strings.EqualFold(source, "AD GPO Evidence") {
		return analyzeGPOEvidence(ctx, artifactPath, assessmentID, executionID, now)
	}
	info, err := os.Stat(artifactPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("specialized artifact is not a regular file")
	}
	if info.Size() > maxSpecializedArtifactBytes {
		return nil, fmt.Errorf("specialized artifact exceeds parser size limit")
	}
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	switch strings.ToLower(source) {
	case "ghostspn":
		return parseGhostSPN(data, artifactPath, assessmentID, executionID, now)
	case "gpoparser":
		return parseGPO(data, artifactPath, assessmentID, executionID, now)
	case "mssqlrelay":
		return parseMSSQLRelay(data, artifactPath, assessmentID, executionID, now)
	case "mssqlpwner":
		return parseMSSqlPwner(data, artifactPath, assessmentID, executionID, now)
	default:
		return nil, nil
	}
}

func analyzeGPOEvidence(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	if artifactPath == "" {
		return nil, fmt.Errorf("GPO evidence artifact is empty")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	directory := artifactPath
	if info, statErr := os.Stat(artifactPath); statErr == nil && !info.IsDir() {
		directory = filepath.Dir(artifactPath)
	}
	manifestPath := filepath.Join(directory, "GPO_evidence_manifest.json")
	metadataPath := filepath.Join(directory, "GPO_metadata.json")
	linksPath := filepath.Join(directory, "GPO_links.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("GPO evidence manifest unavailable: %w", err)
	}
	var manifest struct {
		GPOs []struct {
			GPOGUID       string `json:"gpo_guid"`
			Status        string `json:"status"`
			Retrieved     int    `json:"retrieved_files"`
			Failed        int    `json:"failed_files"`
			Limited       int    `json:"limited_files"`
			Stage         string `json:"stage"`
			ErrorCategory string `json:"error_category"`
			ErrorSummary  string `json:"error_summary"`
		} `json:"gpos"`
		Files []struct {
			Status string `json:"status"`
		} `json:"files"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("GPO evidence manifest is invalid: %w", err)
	}
	if len(manifest.GPOs) == 0 && len(manifest.Files) == 0 {
		return nil, fmt.Errorf("GPO evidence contains no usable metadata or SYSVOL files")
	}
	metadata, _ := os.ReadFile(metadataPath)
	links, _ := os.ReadFile(linksPath)
	if len(metadata) == 0 || len(links) == 0 {
		return nil, fmt.Errorf("GPO evidence metadata or links artifact is unavailable")
	}
	complete, partial := 0, 0
	for _, gpo := range manifest.GPOs {
		if gpo.Status == "complete" {
			complete++
		} else {
			partial++
		}
	}
	failed, limited := 0, 0
	for _, file := range manifest.Files {
		if file.Status == "failed" || file.Status == "permission_denied" {
			failed++
		}
		if file.Status == "limited" {
			limited++
		}
	}
	limitations := make([]string, 0)
	for _, gpo := range manifest.GPOs {
		if gpo.ErrorSummary != "" {
			limitations = append(limitations, fmt.Sprintf("%s: %s (%s)", gpo.GPOGUID, gpo.ErrorSummary, gpo.Stage))
		}
	}
	evidence, _ := json.Marshal(map[string]any{"execution_id": executionID, "gpos_discovered": len(manifest.GPOs), "gpos_complete": complete, "gpos_partial": partial, "sysvol_files": len(manifest.Files), "file_failures": failed, "file_limits": limited, "metadata": metadataPath, "links": linksPath, "manifest": manifestPath, "applicability": "not_verified", "wmi_filters": "references preserved; runtime results not evaluated", "security_filtering": "raw evidence only; effective rights not calculated", "retrieval_limitations": limitations})
	description := fmt.Sprintf("Collected %d GPO(s) and %d preserved SYSVOL file record(s) from execution %d. Complete GPOs: %d; partial/limited GPOs: %d; file failures: %d; file limits: %d. Retrieval limitations: %s. Authoritative artifacts: %s, %s, %s, and %sSYSVOL/. Configured links are not proof of applicability; WMI runtime results, effective security filtering and client-side policy application were not verified.", len(manifest.GPOs), len(manifest.Files), executionID, complete, partial, failed, limited, strings.Join(limitations, "; "), filepath.Base(metadataPath), filepath.Base(linksPath), filepath.Base(manifestPath), filepath.Base(directory)+string(os.PathSeparator))
	return []storage.FindingInput{specializedFinding(assessmentID, executionID, "gpo_evidence_inventory", "AD Group Policy Evidence Inventory", description, "informational", "", string(evidence), metadataPath, "GPO_metadata.json; GPO_links.json; GPO_evidence_manifest.json; SYSVOL/<GPO-GUID>/", now)}, nil
}

func parseGhostSPN(data []byte, path string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("ghostSPN output is not valid JSON: %w", err)
	}
	var findings []storage.FindingInput
	var walk func(any, string)
	walk = func(item any, ref string) {
		switch typed := item.(type) {
		case []any:
			for i, child := range typed {
				walk(child, fmt.Sprintf("%s/%d", ref, i))
			}
		case map[string]any:
			exploitability, _ := typed["exploitability"].(string)
			exploitability = strings.ToUpper(strings.TrimSpace(exploitability))
			explicit := exploitability == "HIGH" || exploitability == "MEDIUM" || exploitability == "LOW"
			for key, child := range typed {
				lower := strings.ToLower(key)
				if (strings.Contains(lower, "ghost") || strings.Contains(lower, "orphan") || strings.Contains(lower, "stale")) && child == true {
					explicit = true
				}
			}
			if explicit {
				spn, _ := typed["spn"].(string)
				if spn == "" {
					spn, _ = typed["SPN"].(string)
				}
				principal, _ := typed["account_sam"].(string)
				if principal == "" {
					principal, _ = typed["account"].(string)
				}
				if principal == "" {
					principal, _ = typed["principal"].(string)
				}
				if spn != "" {
					reason, _ := typed["reason"].(string)
					if reason == "" {
						reason = "ghostSPN explicitly marked this SPN as a possible orphan; this does not establish compromise."
					}
					evidence, _ := json.Marshal(typed)
					severity := strings.ToLower(exploitability)
					if severity == "" || severity == "self" || severity == "excluded" {
						severity = "informational"
					}
					findings = append(findings, specializedFinding(assessmentID, executionID, "ghostspn_orphaned_spn", "Orphaned or stale SPN: "+spn, reason, severity, principal, string(evidence), path, ref, now))
				}
			}
			for key, child := range typed {
				walk(child, ref+"/"+key)
			}
		}
	}
	walk(value, "")
	return findings, nil
}

func parseGPO(data []byte, path string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	var structured any
	if json.Unmarshal(data, &structured) == nil {
		var findings []storage.FindingInput
		var walk func(any, string)
		walk = func(item any, ref string) {
			switch typed := item.(type) {
			case []any:
				for index, child := range typed {
					walk(child, fmt.Sprintf("%s/%d", ref, index))
				}
			case map[string]any:
				for key, child := range typed {
					text, ok := child.(string)
					if ok {
						lower := strings.ToLower(text)
						if strings.Contains(lower, "cpassword") || strings.Contains(lower, "local group") || strings.Contains(lower, "remote desktop") {
							kind, severity := "gpo_security_configuration_observed", "informational"
							if strings.Contains(lower, "cpassword") {
								kind, severity = "gpo_preference_credential_exposed", "high"
							}
							evidence, _ := json.Marshal(map[string]any{"field": key, "configuration": text})
							findings = append(findings, specializedFinding(assessmentID, executionID, kind, "GPO security configuration observed", "gpoParser output contains an explicit security-relevant policy setting. Applicability and resulting access must be confirmed from GPO linkage and filtering data.", severity, "", string(evidence), path, ref+"/"+key, now))
						}
					}
					walk(child, ref+"/"+key)
				}
			}
		}
		walk(structured, "")
		return findings, nil
	}
	var findings []storage.FindingInput
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		lower := strings.ToLower(text)
		if !strings.Contains(lower, "cpassword") && !strings.Contains(lower, "local group") && !strings.Contains(lower, "remote desktop") {
			continue
		}
		kind := "gpo_security_configuration_observed"
		severity := "informational"
		if strings.Contains(lower, "cpassword") {
			kind = "gpo_preference_credential_exposed"
			severity = "high"
		}
		evidence, _ := json.Marshal(map[string]any{"line": line, "configuration": text})
		findings = append(findings, specializedFinding(assessmentID, executionID, kind, "GPO security configuration observed", "gpoParser output contains an explicit security-relevant policy setting. Applicability and resulting access must be confirmed from the GPO linkage and filtering data.", severity, "", string(evidence), path, fmt.Sprintf("line:%d", line), now))
	}
	return findings, scanner.Err()
}

func parseMSSQLRelay(data []byte, path string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	text := string(data)
	if !strings.Contains(strings.ToLower(text), "encryption: not enforced") {
		return nil, nil
	}
	line := lineContaining(text, "Encryption: not enforced")
	evidence, _ := json.Marshal(map[string]any{"condition": "encryption not enforced", "line": line})
	return []storage.FindingInput{specializedFinding(assessmentID, executionID, "mssql_encryption_not_enforced", "MSSQL encryption is not enforced", "mssqlrelay directly reported that the selected SQL Server does not enforce encryption. This is a relay prerequisite observation, not proof that relay succeeded.", "medium", "", string(evidence), path, fmt.Sprintf("line:%d", line), now)}, nil
}

func parseMSSqlPwner(data []byte, path string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	var findings []storage.FindingInput
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		lower := strings.ToLower(text)
		if !strings.Contains(lower, "linked_server_list") && !strings.Contains(lower, "imperson") {
			continue
		}
		evidence, _ := json.Marshal(map[string]any{"line": line, "relationship": text})
		findings = append(findings, specializedFinding(assessmentID, executionID, "mssql_relationship_observed", "MSSQL relationship observed", "MSSqlPwner reported a linked-server or impersonation relationship. The relationship alone does not establish an executable escalation path.", "informational", "", string(evidence), path, fmt.Sprintf("line:%d", line), now))
	}
	return findings, scanner.Err()
}

func lineContaining(text, needle string) int {
	for line, value := range strings.Split(text, "\n") {
		if strings.Contains(strings.ToLower(value), strings.ToLower(needle)) {
			return line + 1
		}
	}
	return 1
}
func specializedFinding(assessmentID, executionID int64, typ, title, description, severity, affected, evidence, path, ref string, now time.Time) storage.FindingInput {
	keyHash := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s\x00%s", assessmentID, typ, affected, ref)))
	return storage.FindingInput{FindingKey: "specialized:" + hex.EncodeToString(keyHash[:]), AssessmentID: assessmentID, SourceTool: sourceForType(typ), SourceExecution: executionID, FindingType: typ, Title: title, Description: description, Severity: severity, Confidence: "observed-artifact", AffectedObject: affected, EvidenceJSON: evidence, ArtifactPath: path, ArtifactRef: ref, ObservedAt: now, Status: "open", ParserVersion: specializedParserVersion}
}
func sourceForType(typ string) string {
	if strings.HasPrefix(typ, "ghostspn") {
		return "ghostSPN"
	}
	if strings.HasPrefix(typ, "gpo") {
		if typ == "gpo_evidence_inventory" {
			return "AD GPO Evidence"
		}
		return "gpoParser"
	}
	if strings.HasPrefix(typ, "mssql_encryption") {
		return "mssqlrelay"
	}
	return "MSSqlPwner"
}
