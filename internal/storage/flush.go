package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FlushReport describes the assessment-scoped state removed by a preflight
// flush. Raw evidence is deliberately outside this database operation.
type FlushReport struct {
	BackupPath   string
	Findings     int64
	Evidence     int64
	AnalysisJobs int64
	Executions   int64
	Runs         int64
	Endpoints    int64
}

// FlushAssessment creates a consistent SQLite backup and clears only the
// selected assessment's derived state and execution ledger. Targets, modules,
// schema migrations, settings, and every raw artifact remain intact.
func FlushAssessment(ctx context.Context, databasePath, domain, target, backupDir string) (FlushReport, error) {
	var report FlushReport
	if strings.TrimSpace(databasePath) == "" || strings.TrimSpace(domain) == "" || strings.TrimSpace(target) == "" {
		return report, fmt.Errorf("database path, domain, and target are required")
	}
	if info, err := os.Stat(databasePath); err == nil && !info.Mode().IsRegular() {
		return report, fmt.Errorf("active database is not a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return report, err
	}
	if err := os.MkdirAll(backupDir, 0750); err != nil {
		return report, fmt.Errorf("create backup directory: %w", err)
	}
	db, err := Open(databasePath)
	if err != nil {
		return report, fmt.Errorf("open active database: %w", err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
		return report, err
	}
	if err := checkIntegrity(ctx, db); err != nil {
		return report, fmt.Errorf("active database integrity check failed: %w", err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA wal_checkpoint(FULL)"); err != nil {
		return report, fmt.Errorf("checkpoint active database: %w", err)
	}
	backupName := fmt.Sprintf("enumeration.%s.%s.%s.db", safeBackupPart(domain), safeBackupPart(target), time.Now().UTC().Format("20060102T150405.000000000Z"))
	report.BackupPath = filepath.Join(backupDir, backupName)
	if _, err := os.Stat(report.BackupPath); err == nil {
		return report, fmt.Errorf("backup path already exists")
	} else if !os.IsNotExist(err) {
		return report, err
	}
	if _, err := db.ExecContext(ctx, "VACUUM INTO "+quoteSQL(report.BackupPath)); err != nil {
		return report, fmt.Errorf("create consistent backup: %w", err)
	}
	if err := verifyDatabaseFile(ctx, report.BackupPath); err != nil {
		return report, fmt.Errorf("verify backup: %w", err)
	}

	var assessmentID int64
	if err := db.QueryRowContext(ctx, `SELECT id FROM targets WHERE domain=? AND target_address=?`, domain, target).Scan(&assessmentID); err != nil {
		if err == sql.ErrNoRows {
			return report, nil
		}
		return report, err
	}
	transaction, err := db.BeginTx(ctx, nil)
	if err != nil {
		return report, fmt.Errorf("begin flush transaction: %w", err)
	}
	rollback := func(err error) (FlushReport, error) {
		_ = transaction.Rollback()
		return report, err
	}
	if err := countFor(transaction, `SELECT COUNT(*) FROM findings WHERE assessment_id=?`, assessmentID, &report.Findings); err != nil {
		return rollback(err)
	}
	if err := countFor(transaction, `SELECT COUNT(*) FROM finding_evidence WHERE finding_id IN (SELECT id FROM findings WHERE assessment_id=?)`, assessmentID, &report.Evidence); err != nil {
		return rollback(err)
	}
	if err := countFor(transaction, `SELECT COUNT(*) FROM analysis_jobs WHERE assessment_id=?`, assessmentID, &report.AnalysisJobs); err != nil {
		return rollback(err)
	}
	if err := countFor(transaction, `SELECT COUNT(*) FROM executions WHERE target_id=?`, assessmentID, &report.Executions); err != nil {
		return rollback(err)
	}
	if err := countFor(transaction, `SELECT COUNT(*) FROM runs WHERE target_id=?`, assessmentID, &report.Runs); err != nil {
		return rollback(err)
	}
	if err := countFor(transaction, `SELECT COUNT(*) FROM endpoints WHERE domain=?`, domain, &report.Endpoints); err != nil {
		return rollback(err)
	}
	statements := []struct {
		query string
		args  []any
	}{
		{`DELETE FROM finding_evidence WHERE finding_id IN (SELECT id FROM findings WHERE assessment_id=?)`, []any{assessmentID}},
		{`DELETE FROM findings WHERE assessment_id=?`, []any{assessmentID}},
		{`DELETE FROM analysis_jobs WHERE assessment_id=?`, []any{assessmentID}},
		{`DELETE FROM executions WHERE target_id=?`, []any{assessmentID}},
		{`DELETE FROM runs WHERE target_id=?`, []any{assessmentID}},
		{`DELETE FROM endpoints WHERE domain=?`, []any{domain}},
	}
	for _, statement := range statements {
		if _, err := transaction.ExecContext(ctx, statement.query, statement.args...); err != nil {
			return rollback(fmt.Errorf("flush %s: %w", statement.query[:minInt(len(statement.query), 32)], err))
		}
	}
	var integrity string
	if err := transaction.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil || !strings.EqualFold(integrity, "ok") {
		if err == nil {
			err = fmt.Errorf("%s", integrity)
		}
		return rollback(fmt.Errorf("post-flush integrity check failed: %w", err))
	}
	if err := transaction.Commit(); err != nil {
		return report, fmt.Errorf("commit flush transaction: %w", err)
	}
	if err := checkIntegrity(ctx, db); err != nil {
		return report, fmt.Errorf("post-commit integrity check failed: %w", err)
	}
	return report, nil
}

func countFor(transaction *sql.Tx, query string, arg any, destination *int64) error {
	return transaction.QueryRow(query, arg).Scan(destination)
}

func checkIntegrity(ctx context.Context, db *DB) error {
	var result string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result); err != nil {
		return err
	}
	if !strings.EqualFold(result, "ok") {
		return fmt.Errorf("%s", result)
	}
	return nil
}

func verifyDatabaseFile(ctx context.Context, path string) error {
	candidate, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer candidate.Close()
	candidate.SetMaxOpenConns(1)
	var result string
	if err := candidate.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result); err != nil {
		return err
	}
	if !strings.EqualFold(result, "ok") {
		return fmt.Errorf("%s", result)
	}
	return nil
}

func quoteSQL(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func safeBackupPart(value string) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '.' || character == '-' || character == '_' {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('_')
		}
	}
	if builder.Len() == 0 {
		return "assessment"
	}
	return builder.String()
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
