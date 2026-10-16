package storage

import (
	"context"
	"database/sql"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"time"
)

type DB struct{ *sql.DB }

func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	d := &DB{db}
	if err := d.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return d, nil
}

// migrate creates the schema. The endpoints table holds SCCM discovery state:
// addresses and host names only, scoped by assessment domain, with the role and
// provenance that explain where each record came from. Credentials are never
// stored here.
func (d *DB) migrate() error {
	transaction, err := d.Begin()
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if _, err := transaction.Exec(`PRAGMA foreign_keys=ON; CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);`); err != nil {
		return err
	}
	var version int
	if err := transaction.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		return err
	}
	if version < 1 {
		if _, err := transaction.Exec(`CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY, domain TEXT NOT NULL, target_address TEXT NOT NULL, created_at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS modules (id INTEGER PRIMARY KEY, name TEXT NOT NULL, tool TEXT NOT NULL, protocol TEXT NOT NULL, description TEXT NOT NULL, output_filename TEXT NOT NULL); CREATE TABLE IF NOT EXISTS executions (id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, module_id INTEGER NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, duration_ms INTEGER, status TEXT NOT NULL, exit_code INTEGER, output_path TEXT, error_summary TEXT, FOREIGN KEY(target_id) REFERENCES targets(id), FOREIGN KEY(module_id) REFERENCES modules(id)); CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL, FOREIGN KEY(target_id) REFERENCES targets(id)); CREATE TABLE IF NOT EXISTS endpoints (id INTEGER PRIMARY KEY, domain TEXT NOT NULL, address TEXT NOT NULL, hostname TEXT NOT NULL DEFAULT '', role TEXT NOT NULL, source TEXT NOT NULL, discovered_at TEXT NOT NULL, UNIQUE(domain, address, role, hostname)); INSERT INTO schema_migrations(version) VALUES(1);`); err != nil {
			return err
		}
		version = 1
	}
	if version < 2 {
		if _, err := transaction.Exec(`CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, finding_key TEXT NOT NULL UNIQUE, assessment_id INTEGER NOT NULL, source_tool TEXT NOT NULL, source_execution_id INTEGER, finding_type TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, severity TEXT NOT NULL, confidence TEXT NOT NULL, affected_object_id TEXT NOT NULL DEFAULT '', affected_object_name TEXT NOT NULL DEFAULT '', related_object_id TEXT NOT NULL DEFAULT '', related_object_name TEXT NOT NULL DEFAULT '', evidence_json TEXT NOT NULL, artifact_path TEXT NOT NULL, artifact_ref TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, status TEXT NOT NULL, parser_version TEXT NOT NULL, FOREIGN KEY(assessment_id) REFERENCES targets(id), FOREIGN KEY(source_execution_id) REFERENCES executions(id)); CREATE TABLE IF NOT EXISTS finding_evidence (id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL, evidence_key TEXT NOT NULL UNIQUE, source_execution_id INTEGER, artifact_path TEXT NOT NULL, artifact_ref TEXT NOT NULL, evidence_json TEXT NOT NULL, observed_at TEXT NOT NULL, FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE, FOREIGN KEY(source_execution_id) REFERENCES executions(id)); CREATE INDEX IF NOT EXISTS findings_assessment_idx ON findings(assessment_id); CREATE INDEX IF NOT EXISTS findings_type_idx ON findings(finding_type); CREATE INDEX IF NOT EXISTS finding_evidence_finding_idx ON finding_evidence(finding_id); INSERT INTO schema_migrations(version) VALUES(2);`); err != nil {
			return err
		}
	}
	if version < 3 {
		if _, err := transaction.Exec(`CREATE TABLE IF NOT EXISTS analysis_jobs (id INTEGER PRIMARY KEY, job_key TEXT NOT NULL UNIQUE, assessment_id INTEGER NOT NULL, execution_id INTEGER NOT NULL, source_tool TEXT NOT NULL, artifact_path TEXT NOT NULL, status TEXT NOT NULL, error_summary TEXT NOT NULL DEFAULT '', parser_version TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL, FOREIGN KEY(assessment_id) REFERENCES targets(id), FOREIGN KEY(execution_id) REFERENCES executions(id)); CREATE INDEX IF NOT EXISTS analysis_jobs_assessment_idx ON analysis_jobs(assessment_id); CREATE INDEX IF NOT EXISTS analysis_jobs_status_idx ON analysis_jobs(status); INSERT INTO schema_migrations(version) VALUES(3);`); err != nil {
			return err
		}
	}
	return transaction.Commit()
}
func (d *DB) UpsertTarget(ctx context.Context, domain, address string) error {
	_, err := d.ExecContext(ctx, `INSERT INTO targets(domain,target_address,created_at) SELECT ?,?,? WHERE NOT EXISTS (SELECT 1 FROM targets WHERE domain=? AND target_address=?)`, domain, address, time.Now().UTC().Format(time.RFC3339), domain, address)
	return err
}
func (d *DB) TargetID(ctx context.Context, domain, address string) (int64, error) {
	var id int64
	err := d.QueryRowContext(ctx, `SELECT id FROM targets WHERE domain=? AND target_address=?`, domain, address).Scan(&id)
	return id, err
}
func (d *DB) RegisterModule(ctx context.Context, name, tool, protocol, description, output string) (int64, error) {
	_, err := d.ExecContext(ctx, `INSERT INTO modules(name,tool,protocol,description,output_filename) VALUES(?,?,?,?,?)`, name, tool, protocol, description, output)
	if err != nil {
		return 0, err
	}
	var id int64
	err = d.QueryRowContext(ctx, `SELECT last_insert_rowid()`).Scan(&id)
	return id, err
}
func (d *DB) RecordExecution(ctx context.Context, targetID, moduleID int64, started, finished time.Time, status string, exitCode int, output, summary string) error {
	_, err := d.RecordExecutionID(ctx, targetID, moduleID, started, finished, status, exitCode, output, summary)
	return err
}

func (d *DB) RecordExecutionID(ctx context.Context, targetID, moduleID int64, started, finished time.Time, status string, exitCode int, output, summary string) (int64, error) {
	result, err := d.ExecContext(ctx, `INSERT INTO executions(target_id,module_id,started_at,finished_at,duration_ms,status,exit_code,output_path,error_summary) VALUES(?,?,?,?,?,?,?,?,?)`, targetID, moduleID, started.UTC().Format(time.RFC3339Nano), finished.UTC().Format(time.RFC3339Nano), finished.Sub(started).Milliseconds(), status, exitCode, output, summary)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (d *DB) RecordExecutionFor(ctx context.Context, domain, address, moduleName, moduleTool string, started, finished time.Time, status string, exitCode int, output, summary string) error {
	var targetID, moduleID int64
	if err := d.QueryRowContext(ctx, `SELECT id FROM targets WHERE domain=? AND target_address=?`, domain, address).Scan(&targetID); err != nil {
		return err
	}
	if err := d.QueryRowContext(ctx, `SELECT id FROM modules WHERE name=? AND tool=? ORDER BY id DESC LIMIT 1`, moduleName, moduleTool).Scan(&moduleID); err != nil {
		return err
	}
	return d.RecordExecution(ctx, targetID, moduleID, started, finished, status, exitCode, output, summary)
}

// EndpointRecord is one stored discovery record. It mirrors the assessment's
// endpoint model: a validated address (when discovery produced one), the name it
// was discovered as, the SCCM role, the provenance, and when it was seen.
type EndpointRecord struct {
	Address      string
	Hostname     string
	Role         string
	Source       string
	Domain       string
	DiscoveredAt time.Time
}

// RecordEndpoints stores discovery results for one domain, replacing any earlier
// record for the same domain, address, role, and hostname so repeated runs do not
// duplicate rows.
func (d *DB) RecordEndpoints(ctx context.Context, endpoints []EndpointRecord) error {
	transaction, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	statement, err := transaction.PrepareContext(ctx, `INSERT INTO endpoints(domain,address,hostname,role,source,discovered_at) VALUES(?,?,?,?,?,?) ON CONFLICT(domain,address,role,hostname) DO UPDATE SET source=excluded.source, discovered_at=excluded.discovered_at`)
	if err != nil {
		return err
	}
	defer statement.Close()
	for _, endpoint := range endpoints {
		hostname := endpoint.Hostname
		if _, err := statement.ExecContext(ctx, endpoint.Domain, endpoint.Address, hostname, endpoint.Role, endpoint.Source, endpoint.DiscoveredAt.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	return transaction.Commit()
}

// Endpoints returns the stored discovery records of one domain, ordered by role
// and address so callers get deterministic results.
func (d *DB) Endpoints(ctx context.Context, domain string) ([]EndpointRecord, error) {
	rows, err := d.QueryContext(ctx, `SELECT address, hostname, role, source, domain, discovered_at FROM endpoints WHERE domain=? ORDER BY role ASC, address ASC, hostname ASC`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]EndpointRecord, 0)
	for rows.Next() {
		var record EndpointRecord
		var discovered string
		if err := rows.Scan(&record.Address, &record.Hostname, &record.Role, &record.Source, &record.Domain, &discovered); err != nil {
			return nil, err
		}
		if parsed, parseErr := time.Parse(time.RFC3339, discovered); parseErr == nil {
			record.DiscoveredAt = parsed
		}
		records = append(records, record)
	}
	return records, rows.Err()
}
