package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const generalACLParserVersion = "rusthound-general-acl-v1"

// GeneralACLInventoryReport is the lossless, execution-scoped index for every
// supported ACL record parsed from a RustHound export. The source export
// remains authoritative for unsupported or omitted records.
type GeneralACLInventoryReport struct {
	SchemaVersion       int                `json:"schema_version"`
	ParserVersion       string             `json:"parser_version"`
	Domain              string             `json:"domain,omitempty"`
	SourceExecutionID   int64              `json:"source_execution_id"`
	SourceArtifact      string             `json:"source_artifact"`
	AnalysisTimestamp   time.Time          `json:"analysis_timestamp"`
	Status              string             `json:"status"`
	SourceACECount      int                `json:"source_supported_ace_count"`
	RetainedACECount    int                `json:"retained_ace_count"`
	OmittedACECount     int                `json:"omitted_ace_count"`
	UnsupportedACECount int                `json:"unsupported_ace_count"`
	ExplicitCount       int                `json:"explicit_count"`
	InheritedCount      int                `json:"inherited_count"`
	UnknownInheritance  int                `json:"unknown_inheritance_count"`
	UnknownDecision     int                `json:"unknown_decision_count"`
	Records             []GeneralACLRecord `json:"records"`
	Limitations         []string           `json:"limitations"`
}

func buildGeneralACLInventory(report AnalysisReport, executionID int64, inputPath string, now time.Time) GeneralACLInventoryReport {
	result := GeneralACLInventoryReport{
		SchemaVersion: 1, ParserVersion: generalACLParserVersion, Domain: report.Domain,
		SourceExecutionID: executionID, SourceArtifact: inputPath, AnalysisTimestamp: now.UTC(),
		Status: "complete", SourceACECount: report.ACLs, RetainedACECount: len(report.ACLRecords),
		OmittedACECount: report.ACLRecordsOmitted, UnsupportedACECount: report.UnsupportedACLs,
		Records: append([]GeneralACLRecord(nil), report.ACLRecords...),
		Limitations: []string{
			"Records are observed source ACL relationships; effective authorization and exploitability were not evaluated.",
			"Unknown decisions are not interpreted as allow, deny, absence, or vulnerability.",
			"Unsupported rights and records omitted by the bound remain in the original RustHound source artifact.",
		},
	}
	for _, record := range result.Records {
		switch record.Inheritance {
		case "explicit":
			result.ExplicitCount++
		case "inherited":
			result.InheritedCount++
		default:
			result.UnknownInheritance++
		}
		if strings.EqualFold(record.Decision, "unknown") || record.Decision == "" {
			result.UnknownDecision++
		}
	}
	if result.OmittedACECount > 0 {
		result.Status = "partial"
		result.Limitations = append(result.Limitations, "The retained report is bounded; omitted supported records remain discoverable through the original source artifact pointers.")
	}
	return result
}

func generalACLInventoryInput(report GeneralACLInventoryReport, assessmentID int64, reportPath, structuredPath string, now time.Time) storage.FindingInput {
	examples := representativeACLRecords(report.Records, 12)
	evidence, _ := json.Marshal(map[string]any{
		"source_execution_id": report.SourceExecutionID, "source_artifact": report.SourceArtifact,
		"structured_artifact": structuredPath, "human_report": reportPath,
		"source_supported_ace_count": report.SourceACECount, "retained_ace_count": report.RetainedACECount,
		"omitted_ace_count": report.OmittedACECount, "unsupported_ace_count": report.UnsupportedACECount,
		"explicit_count": report.ExplicitCount, "inherited_count": report.InheritedCount,
		"unknown_inheritance_count": report.UnknownInheritance, "unknown_decision_count": report.UnknownDecision,
		"examples": examples, "limitations": report.Limitations,
	})
	description := fmt.Sprintf("RustHound execution %d recorded %d supported ACL ACEs across %d retained source records. This is consolidated informational evidence; effective authorization and exploitability were not evaluated.", report.SourceExecutionID, report.SourceACECount, report.RetainedACECount)
	return storage.FindingInput{
		FindingKey:   generalACLInventoryFindingKey(assessmentID, report.SourceExecutionID, report.SourceArtifact),
		AssessmentID: assessmentID, SourceTool: "RustHound-CE", SourceExecution: report.SourceExecutionID,
		FindingType: "ad_acl_evidence_inventory", Title: "AD ACL Evidence Inventory", Description: description,
		Severity: "informational", Confidence: "observed-source-acl-inventory", AffectedObjectID: report.Domain,
		AffectedObject: fallbackGeneralText(report.Domain, "RustHound ACL collection"), EvidenceJSON: string(evidence),
		ArtifactPath: reportPath, ArtifactRef: "/", ObservedAt: now, Status: "open", ParserVersion: generalACLParserVersion,
	}
}

func representativeACLRecords(records []GeneralACLRecord, limit int) []GeneralACLRecord {
	copyRecords := append([]GeneralACLRecord(nil), records...)
	sort.SliceStable(copyRecords, func(i, j int) bool {
		left := strings.Join([]string{copyRecords[i].TargetType, copyRecords[i].TargetID, copyRecords[i].Permission, copyRecords[i].PrincipalID, copyRecords[i].ArtifactRef}, "\x00")
		right := strings.Join([]string{copyRecords[j].TargetType, copyRecords[j].TargetID, copyRecords[j].Permission, copyRecords[j].PrincipalID, copyRecords[j].ArtifactRef}, "\x00")
		return left < right
	})
	if len(copyRecords) > limit {
		copyRecords = copyRecords[:limit]
	}
	return copyRecords
}

func FormatGeneralACLInventoryReport(report GeneralACLInventoryReport) string {
	var b strings.Builder
	fmt.Fprintln(&b, "======================================================================")
	fmt.Fprintln(&b, "                    PWNFLOW AD ACL EVIDENCE INVENTORY")
	fmt.Fprintln(&b, "======================================================================")
	fmt.Fprintf(&b, "\nDOMAIN: %s\nSOURCE EXECUTION: %d\nSOURCE ARTIFACT: %s\nSTATUS: %s\nANALYZED: %s\n", report.Domain, report.SourceExecutionID, report.SourceArtifact, report.Status, report.AnalysisTimestamp.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "\nSupported source ACEs: %d\nRetained records: %d\nOmitted by bound: %d\nUnsupported rights/records: %d\nExplicit: %d\nInherited: %d\nUnknown inheritance: %d\nUnknown decision: %d\n", report.SourceACECount, report.RetainedACECount, report.OmittedACECount, report.UnsupportedACECount, report.ExplicitCount, report.InheritedCount, report.UnknownInheritance, report.UnknownDecision)
	fmt.Fprintln(&b, "\nClassification: INFORMATIONAL OBSERVED ACL EVIDENCE")
	fmt.Fprintln(&b, "Effective authorization: NOT VERIFIED")
	fmt.Fprintln(&b, "Exploitability: NOT ESTABLISHED")
	fmt.Fprintln(&b, "\n----------------------------------------------------------------------\nRETAINED SOURCE RECORDS\n----------------------------------------------------------------------")
	for _, record := range report.Records {
		fmt.Fprintf(&b, "Target: %s [%s] (%s)\n  Principal: %s [%s] (%s)\n  Permission: %s | Decision: %s | Inheritance: %s\n", fallbackGeneralText(record.TargetName, record.TargetID), record.TargetID, fallbackGeneralText(record.TargetType, "unknown"), fallbackGeneralText(record.PrincipalName, record.PrincipalID), record.PrincipalID, fallbackGeneralText(record.PrincipalType, "unknown"), record.Permission, fallbackGeneralText(record.Decision, "unknown"), fallbackGeneralText(record.Inheritance, "unknown"))
		if record.ObjectType != "" || record.InheritedObjectType != "" {
			fmt.Fprintf(&b, "  Object restriction: object_type=%s inherited_object_type=%s\n", record.ObjectType, record.InheritedObjectType)
		}
		fmt.Fprintf(&b, "  Source: %s#%s\n\n", record.Artifact, record.ArtifactRef)
	}
	fmt.Fprintln(&b, "LIMITATIONS")
	for _, limitation := range report.Limitations {
		fmt.Fprintf(&b, "- %s\n", limitation)
	}
	return b.String()
}

func WriteGeneralACLInventoryArtifacts(resultsRoot string, report GeneralACLInventoryReport) (string, string, error) {
	if report.SourceExecutionID <= 0 {
		return "", "", fmt.Errorf("general ACL inventory source execution is missing")
	}
	directory := filepath.Join(resultsRoot, "Enumeration", "ActiveDirectory", "ACL", fmt.Sprintf("execution-%d", report.SourceExecutionID))
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", "", err
	}
	structuredPath := filepath.Join(directory, "AD_acl_evidence_inventory.json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := writeProtectedFile(structuredPath, data, 0600); err != nil {
		return "", "", err
	}
	reportPath := filepath.Join(directory, "AD_ACL_EVIDENCE.txt")
	if err := writeProtectedFile(reportPath, []byte(FormatGeneralACLInventoryReport(report)), 0600); err != nil {
		return "", "", err
	}
	return reportPath, structuredPath, nil
}

func writeProtectedFile(path string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".acl-evidence-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func generalACLInventoryFindingKey(assessmentID, executionID int64, source string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%d\x00%s\x00%s", assessmentID, executionID, generalACLParserVersion, source)))
	return "adacl:" + hex.EncodeToString(sum[:])
}

func fallbackGeneralText(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
