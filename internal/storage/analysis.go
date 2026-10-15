package storage

import (
	"context"
	"time"
)

const (
	AnalysisPending    = "PENDING"
	AnalysisAnalyzing  = "ANALYZING"
	AnalysisComplete   = "COMPLETE"
	AnalysisPartial    = "PARTIAL"
	AnalysisFailed     = "FAILED"
	AnalysisNotSupport = "NOT SUPPORTED"
)

type AnalysisJob struct {
	ID, AssessmentID, ExecutionID       int64
	JobKey, SourceTool, ArtifactPath    string
	Status, ErrorSummary, ParserVersion string
	CreatedAt, UpdatedAt                time.Time
}

func (d *DB) QueueAnalysis(ctx context.Context, jobKey string, assessmentID, executionID int64, sourceTool, artifactPath string) (bool, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := d.ExecContext(ctx, `INSERT INTO analysis_jobs(job_key,assessment_id,execution_id,source_tool,artifact_path,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(job_key) DO NOTHING`, jobKey, assessmentID, executionID, sourceTool, artifactPath, AnalysisPending, now, now)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

func (d *DB) SetAnalysisStatus(ctx context.Context, jobKey, status, parserVersion, summary string) error {
	_, err := d.ExecContext(ctx, `UPDATE analysis_jobs SET status=?,parser_version=?,error_summary=?,updated_at=? WHERE job_key=?`, status, parserVersion, summary, time.Now().UTC().Format(time.RFC3339Nano), jobKey)
	return err
}

func (d *DB) ListAnalysisJobs(ctx context.Context, assessmentID int64) ([]AnalysisJob, error) {
	rows, err := d.QueryContext(ctx, `SELECT id,job_key,assessment_id,execution_id,source_tool,artifact_path,status,error_summary,parser_version,created_at,updated_at FROM analysis_jobs WHERE assessment_id=? ORDER BY id`, assessmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []AnalysisJob
	for rows.Next() {
		var job AnalysisJob
		var created, updated string
		if err := rows.Scan(&job.ID, &job.JobKey, &job.AssessmentID, &job.ExecutionID, &job.SourceTool, &job.ArtifactPath, &job.Status, &job.ErrorSummary, &job.ParserVersion, &created, &updated); err != nil {
			return nil, err
		}
		job.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, err
		}
		job.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func (d *DB) LatestExecutionForTool(ctx context.Context, assessmentID int64, tool string) (int64, error) {
	var id int64
	err := d.QueryRowContext(ctx, `SELECT e.id FROM executions e JOIN modules m ON m.id=e.module_id WHERE e.target_id=? AND lower(m.tool)=lower(?) ORDER BY e.id DESC LIMIT 1`, assessmentID, tool).Scan(&id)
	return id, err
}
