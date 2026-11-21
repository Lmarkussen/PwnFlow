package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// FindingInput is the storage boundary for an analyzer. EvidenceJSON is a
// compact copy of parsed, non-secret evidence; the original artifact remains
// authoritative and is never rewritten.
type FindingInput struct {
	FindingKey       string
	AssessmentID     int64
	SourceTool       string
	SourceExecution  int64
	FindingType      string
	Title            string
	Description      string
	Severity         string
	Confidence       string
	AffectedObjectID string
	AffectedObject   string
	RelatedObjectID  string
	RelatedObject    string
	EvidenceJSON     string
	ArtifactPath     string
	ArtifactRef      string
	ObservedAt       time.Time
	Status           string
	ParserVersion    string
}

type Finding struct {
	FindingInput
	ID        int64
	FirstSeen time.Time
	LastSeen  time.Time
	// NotReobserved is set when the module that produced the Finding has run
	// again later, completed, and been analyzed without reporting it. Such a
	// Finding describes an earlier state of the target.
	NotReobserved bool
	// SourceModule and SourceModuleTool name the module of the source
	// execution, empty when unknown. SourceModuleRetired is set by callers
	// that know the current registry when that module no longer exists, so
	// the Finding can never be re-observed.
	SourceModule        string
	SourceModuleTool    string
	SourceModuleRetired bool
}

// notReobservedExpression is true when a later, completed and analyzed
// execution of the Finding's source module exists that started after the
// Finding was last observed. Re-observation moves last_seen to the later
// execution, so a Finding that is still present never matches.
// Modules are matched by name and tool: every PwnFlow session registers its
// modules again under new ids.
const notReobservedExpression = `EXISTS (
	SELECT 1 FROM executions source
	JOIN modules source_def ON source_def.id = source.module_id
	JOIN executions later ON later.target_id = source.target_id AND later.id <> source.id
	JOIN modules later_def ON later_def.id = later.module_id AND later_def.name = source_def.name AND later_def.tool = source_def.tool
	JOIN analysis_jobs job ON job.execution_id = later.id AND upper(job.status) = 'COMPLETE'
	WHERE source.id = findings.source_execution_id
	  AND lower(later.status) = 'completed'
	  AND julianday(later.started_at) > julianday(findings.last_seen))`

// ResetDerivedState removes only findings-engine state for one assessment. It
// deliberately leaves targets, executions, modules, endpoints, schema metadata,
// and every original artifact untouched.
func (d *DB) ResetDerivedState(ctx context.Context, assessmentID int64) (int64, error) {
	transaction, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer transaction.Rollback()
	var args []any
	where := ""
	if assessmentID > 0 {
		where = " WHERE assessment_id=?"
		args = append(args, assessmentID)
	}
	var count int64
	query := "SELECT COUNT(*) FROM findings" + where
	if err := transaction.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	if assessmentID > 0 {
		if _, err := transaction.ExecContext(ctx, "DELETE FROM finding_evidence WHERE finding_id IN (SELECT id FROM findings WHERE assessment_id=?)", assessmentID); err != nil {
			return 0, err
		}
		if _, err := transaction.ExecContext(ctx, "DELETE FROM findings WHERE assessment_id=?", assessmentID); err != nil {
			return 0, err
		}
		if _, err := transaction.ExecContext(ctx, "DELETE FROM analysis_jobs WHERE assessment_id=?", assessmentID); err != nil {
			return 0, err
		}
	} else {
		if _, err := transaction.ExecContext(ctx, "DELETE FROM finding_evidence"); err != nil {
			return 0, err
		}
		if _, err := transaction.ExecContext(ctx, "DELETE FROM findings"); err != nil {
			return 0, err
		}
		if _, err := transaction.ExecContext(ctx, "DELETE FROM analysis_jobs"); err != nil {
			return 0, err
		}
	}
	return count, transaction.Commit()
}

func (d *DB) IngestFindings(ctx context.Context, inputs []FindingInput) error {
	transaction, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	for _, input := range inputs {
		if err := validateFinding(input); err != nil {
			return err
		}
		observed := input.ObservedAt.UTC().Format(time.RFC3339Nano)
		if _, err := transaction.ExecContext(ctx, `INSERT INTO findings(finding_key,assessment_id,source_tool,source_execution_id,finding_type,title,description,severity,confidence,affected_object_id,affected_object_name,related_object_id,related_object_name,evidence_json,artifact_path,artifact_ref,first_seen,last_seen,status,parser_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(finding_key) DO UPDATE SET source_tool=excluded.source_tool,source_execution_id=excluded.source_execution_id,finding_type=excluded.finding_type,title=excluded.title,description=excluded.description,severity=excluded.severity,confidence=excluded.confidence,affected_object_id=excluded.affected_object_id,affected_object_name=excluded.affected_object_name,related_object_id=excluded.related_object_id,related_object_name=excluded.related_object_name,evidence_json=excluded.evidence_json,artifact_path=excluded.artifact_path,artifact_ref=excluded.artifact_ref,last_seen=excluded.last_seen,status=excluded.status,parser_version=excluded.parser_version`, input.FindingKey, input.AssessmentID, input.SourceTool, nullableID(input.SourceExecution), input.FindingType, input.Title, input.Description, input.Severity, input.Confidence, input.AffectedObjectID, input.AffectedObject, input.RelatedObjectID, input.RelatedObject, input.EvidenceJSON, input.ArtifactPath, input.ArtifactRef, observed, observed, input.Status, input.ParserVersion); err != nil {
			return err
		}
		var findingID int64
		if err := transaction.QueryRowContext(ctx, `SELECT id FROM findings WHERE finding_key=?`, input.FindingKey).Scan(&findingID); err != nil {
			return err
		}
		evidenceKey := evidenceKey(input)
		if _, err := transaction.ExecContext(ctx, `INSERT INTO finding_evidence(finding_id,evidence_key,source_execution_id,artifact_path,artifact_ref,evidence_json,observed_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(evidence_key) DO NOTHING`, findingID, evidenceKey, nullableID(input.SourceExecution), input.ArtifactPath, input.ArtifactRef, input.EvidenceJSON, observed); err != nil {
			return err
		}
	}
	return transaction.Commit()
}

func validateFinding(input FindingInput) error {
	for name, value := range map[string]string{"finding key": input.FindingKey, "source tool": input.SourceTool, "finding type": input.FindingType, "title": input.Title, "artifact path": input.ArtifactPath, "artifact reference": input.ArtifactRef, "parser version": input.ParserVersion} {
		if value == "" {
			return fmt.Errorf("finding %s is required", name)
		}
	}
	if input.AssessmentID <= 0 {
		return fmt.Errorf("finding assessment id must be positive")
	}
	if !json.Valid([]byte(input.EvidenceJSON)) {
		return fmt.Errorf("finding evidence is not valid JSON")
	}
	return nil
}

func nullableID(id int64) any {
	if id <= 0 {
		return nil
	}
	return id
}

func evidenceKey(input FindingInput) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%s\x00%s", input.FindingKey, input.SourceExecution, input.ArtifactPath, input.ArtifactRef)))
	return hex.EncodeToString(hash[:])
}

func (d *DB) ListFindings(ctx context.Context, assessmentID int64) ([]Finding, error) {
	rows, err := d.QueryContext(ctx, `SELECT findings.id,findings.finding_key,findings.assessment_id,findings.source_tool,COALESCE(findings.source_execution_id,0),findings.finding_type,findings.title,findings.description,findings.severity,findings.confidence,findings.affected_object_id,findings.affected_object_name,findings.related_object_id,findings.related_object_name,findings.evidence_json,findings.artifact_path,findings.artifact_ref,findings.first_seen,findings.last_seen,findings.status,findings.parser_version,`+notReobservedExpression+`,COALESCE(source_module.name,''),COALESCE(source_module.tool,'') FROM findings LEFT JOIN executions source_execution ON source_execution.id = findings.source_execution_id LEFT JOIN modules source_module ON source_module.id = source_execution.module_id WHERE findings.assessment_id=? ORDER BY findings.id`, assessmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []Finding
	for rows.Next() {
		var finding Finding
		var first, last string
		if err := rows.Scan(&finding.ID, &finding.FindingKey, &finding.AssessmentID, &finding.SourceTool, &finding.SourceExecution, &finding.FindingType, &finding.Title, &finding.Description, &finding.Severity, &finding.Confidence, &finding.AffectedObjectID, &finding.AffectedObject, &finding.RelatedObjectID, &finding.RelatedObject, &finding.EvidenceJSON, &finding.ArtifactPath, &finding.ArtifactRef, &first, &last, &finding.Status, &finding.ParserVersion, &finding.NotReobserved, &finding.SourceModule, &finding.SourceModuleTool); err != nil {
			return nil, err
		}
		finding.FirstSeen, err = time.Parse(time.RFC3339Nano, first)
		if err != nil {
			return nil, err
		}
		finding.LastSeen, err = time.Parse(time.RFC3339Nano, last)
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func (d *DB) FindingEvidenceCount(ctx context.Context, findingID int64) (int, error) {
	var count int
	err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM finding_evidence WHERE finding_id=?`, findingID).Scan(&count)
	return count, err
}
