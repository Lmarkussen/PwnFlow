package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

// Job is the durable hand-off between execution and offline evidence analysis.
// ArtifactPath is captured after the module has finalized its run directory.
type Job struct {
	AssessmentID int64
	ExecutionID  int64
	SourceTool   string
	ArtifactPath string
	ObservedAt   time.Time
	Force        bool
}

type Manager struct {
	db        *storage.DB
	ctx       context.Context
	queue     chan queuedJob
	workers   sync.WaitGroup
	pending   sync.WaitGroup
	closeOnce sync.Once
}

// ReanalyzeLatest queues an existing execution's finalized artifact for an
// explicit offline parser retry. It never starts the associated module.
func (m *Manager) ReanalyzeLatest(ctx context.Context, assessmentID int64, sourceTool string) error {
	if m == nil || m.db == nil {
		return nil
	}
	executionID, err := m.db.LatestExecutionForTool(ctx, assessmentID, sourceTool)
	if err != nil {
		return err
	}
	output, err := m.db.ExecutionOutputPath(ctx, executionID)
	if err != nil {
		return err
	}
	artifact := DiscoverArtifact(sourceTool, output)
	return m.Submit(Job{AssessmentID: assessmentID, ExecutionID: executionID, SourceTool: sourceTool, ArtifactPath: artifact, ObservedAt: time.Now().UTC(), Force: true})
}

// ReanalyzeLatestSupported queues one latest finalized execution for each
// supported source. It is deliberately bounded to avoid reimporting the
// historical assessment tree after a findings reset.
func (m *Manager) ReanalyzeLatestSupported(ctx context.Context, assessmentID int64) error {
	for _, source := range []string{"NetExec (nxc)", "RustHound-CE", "Certipy", "RelayKing", "PXEThief"} {
		if err := m.ReanalyzeLatest(ctx, assessmentID, source); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "no execution") {
				continue
			}
			return err
		}
	}
	return nil
}

type queuedJob struct {
	job Job
	key string
}

func NewManager(ctx context.Context, db *storage.DB) *Manager {
	manager := &Manager{db: db, ctx: ctx, queue: make(chan queuedJob, 32)}
	manager.workers.Add(1)
	go manager.worker()
	manager.recoverPending()
	return manager
}

func (m *Manager) recoverPending() {
	jobs, err := m.db.ListPendingAnalysisJobs(m.ctx)
	if err != nil {
		return
	}
	for _, persisted := range jobs {
		artifact := persisted.ArtifactPath
		if artifact == "" {
			if output, outputErr := m.db.ExecutionOutputPath(m.ctx, persisted.ExecutionID); outputErr == nil {
				artifact = DiscoverArtifact(persisted.SourceTool, output)
			}
		}
		job := Job{AssessmentID: persisted.AssessmentID, ExecutionID: persisted.ExecutionID, SourceTool: persisted.SourceTool, ArtifactPath: artifact, ObservedAt: persisted.UpdatedAt}
		m.pending.Add(1)
		select {
		case m.queue <- queuedJob{job: job, key: persisted.JobKey}:
		case <-m.ctx.Done():
			m.pending.Done()
			return
		}
	}
}

func (m *Manager) Submit(job Job) error {
	if m == nil || m.db == nil {
		return nil
	}
	if job.ObservedAt.IsZero() {
		job.ObservedAt = time.Now().UTC()
	}
	key := jobKey(job)
	inserted, err := m.db.QueueAnalysis(m.ctx, key, job.AssessmentID, job.ExecutionID, job.SourceTool, job.ArtifactPath)
	if err != nil || (!inserted && !job.Force) {
		return err
	}
	if !inserted {
		if err := m.db.SetAnalysisStatus(m.ctx, key, storage.AnalysisPending, "", "queued for explicit reanalysis"); err != nil {
			return err
		}
	}
	m.pending.Add(1)
	select {
	case m.queue <- queuedJob{job: job, key: key}:
		return nil
	case <-m.ctx.Done():
		_ = m.db.SetAnalysisStatus(context.Background(), key, storage.AnalysisPending, "", "queued for a later run")
		m.pending.Done()
		return m.ctx.Err()
	}
}

func (m *Manager) Wait(ctx context.Context) error {
	if m == nil {
		return nil
	}
	done := make(chan struct{})
	go func() { m.pending.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() { m.pending.Wait(); close(m.queue) })
	m.workers.Wait()
}

// Summary is intentionally small enough for a status line; the Findings view
// remains the detailed, cached inspection surface.
func (m *Manager) Summary(ctx context.Context, assessmentID int64) (string, error) {
	if m == nil || m.db == nil {
		return "", nil
	}
	jobs, err := m.db.ListAnalysisJobs(ctx, assessmentID)
	if err != nil {
		return "", err
	}
	counts := map[string]int{}
	for _, job := range jobs {
		counts[job.Status]++
	}
	rows, err := m.db.ListFindings(ctx, assessmentID)
	if err != nil {
		return "", err
	}
	severity := map[string]int{}
	for _, row := range rows {
		severity[strings.ToLower(row.Severity)]++
	}
	return fmt.Sprintf("Findings: %d High · %d Medium · %d Informational (%d analyzed, %d pending)", severity["high"], severity["medium"], severity["informational"], counts[storage.AnalysisComplete], counts[storage.AnalysisPending]+counts[storage.AnalysisAnalyzing]), nil
}

func (m *Manager) worker() {
	defer m.workers.Done()
	for queued := range m.queue {
		m.analyze(queued)
		m.pending.Done()
	}
}

func (m *Manager) analyze(queued queuedJob) {
	job := queued.job
	_ = m.db.SetAnalysisStatus(context.Background(), queued.key, storage.AnalysisAnalyzing, "", "")
	var inputs []storage.FindingInput
	var err error
	switch strings.ToLower(job.SourceTool) {
	case "rusthound-ce", "rusthound":
		inputs, err = analyzeRustHoundJob(m.ctx, job)
	case "certipy":
		inputs, err = AnalyzeCertipy(m.ctx, job.ArtifactPath, job.AssessmentID, job.ExecutionID, job.ObservedAt)
	case "relayking":
		inputs, err = AnalyzeRelayKing(m.ctx, job.ArtifactPath, job.AssessmentID, job.ExecutionID, job.ObservedAt)
	case "pxethief":
		inputs, err = AnalyzePXEThief(m.ctx, job.ArtifactPath, job.AssessmentID, job.ExecutionID, job.ObservedAt)
	case "netexec", "netexec (nxc)":
		lowerPath := strings.ToLower(job.ArtifactPath)
		if strings.Contains(lowerPath, "kerberoast") || strings.Contains(lowerPath, "asreproast") {
			inputs, err = AnalyzeNetExecKerberos(m.ctx, job.ArtifactPath, job.AssessmentID, job.ExecutionID, job.ObservedAt)
		} else if strings.Contains(lowerPath, "get_users_info") || strings.Contains(lowerPath, "get_users_description") {
			inputs, err = AnalyzeNetExecCredentials(m.ctx, job.ArtifactPath, job.AssessmentID, job.ExecutionID, job.ObservedAt)
		} else {
			_ = m.db.SetAnalysisStatus(context.Background(), queued.key, storage.AnalysisNotSupport, "", "no supported NetExec artifact extractor")
			return
		}
	case "ghostspn", "gpoparser", "mssqlrelay", "mssqlpwner":
		inputs, err = AnalyzeSpecialized(m.ctx, job.ArtifactPath, job.SourceTool, job.AssessmentID, job.ExecutionID, job.ObservedAt)
	case "masscan":
		inputs, err = AnalyzeMasscan(m.ctx, job.ArtifactPath, job.AssessmentID, job.ExecutionID, job.ObservedAt)
	default:
		_ = m.db.SetAnalysisStatus(context.Background(), queued.key, storage.AnalysisNotSupport, "", "no evidence extractor for source tool")
		return
	}
	if err != nil {
		status := storage.AnalysisFailed
		if job.ArtifactPath == "" || err == context.Canceled || err == context.DeadlineExceeded {
			status = storage.AnalysisPartial
		}
		_ = m.db.SetAnalysisStatus(context.Background(), queued.key, status, ParserVersionFor(job.SourceTool), err.Error())
		return
	}
	if err := m.db.IngestFindings(m.ctx, inputs); err != nil {
		_ = m.db.SetAnalysisStatus(context.Background(), queued.key, storage.AnalysisFailed, ParserVersionFor(job.SourceTool), err.Error())
		return
	}
	_ = m.db.SetAnalysisStatus(context.Background(), queued.key, storage.AnalysisComplete, ParserVersionFor(job.SourceTool), "")
}

func analyzeRustHoundJob(ctx context.Context, job Job) ([]storage.FindingInput, error) {
	if job.ArtifactPath == "" {
		return nil, fmt.Errorf("RustHound artifact directory not found")
	}
	inputs, _, err := AnalyzeRustHound(ctx, job.ArtifactPath, job.AssessmentID, job.ExecutionID, job.ObservedAt)
	if err != nil {
		return nil, err
	}
	return inputs, nil
}

func ParserVersionFor(tool string) string {
	switch strings.ToLower(tool) {
	case "rusthound-ce", "rusthound":
		return ParserVersion
	case "certipy":
		return "certipy-v2"
	case "relayking":
		return "relayking-v1"
	case "pxethief":
		return PXEThiefParserVersion
	case "netexec", "netexec (nxc)":
		return netExecCredentialParserVersion
	case "ghostspn", "gpoparser", "mssqlrelay", "mssqlpwner":
		return specializedParserVersion
	case "masscan":
		return masscanParserVersion
	default:
		return ""
	}
}

func jobKey(job Job) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%d\x00%s\x00%s", job.AssessmentID, job.ExecutionID, job.SourceTool, job.ArtifactPath)))
	return "analysis:" + hex.EncodeToString(hash[:])
}

// DiscoverArtifact chooses only the newest run-scoped artifact. It never scans
// the whole historical results tree and therefore cannot re-analyze old runs as
// a side effect of a new execution.
func DiscoverArtifact(tool, outputPath string) string {
	if outputPath == "" {
		return ""
	}
	specializedTool := map[string]bool{"ghostspn": true, "gpoparser": true, "mssqlrelay": true, "mssqlpwner": true, "masscan": true}
	if specializedTool[strings.ToLower(tool)] {
		if strings.EqualFold(tool, "masscan") {
			if info, err := os.Stat(outputPath); err == nil && info.Mode().IsRegular() {
				return outputPath
			}
		}
		if info, err := os.Stat(outputPath); err == nil && info.Mode().IsRegular() {
			return outputPath
		}
	}
	if strings.EqualFold(tool, "pxethief") {
		if info, err := os.Stat(outputPath); err == nil {
			if info.IsDir() || strings.EqualFold(filepath.Base(outputPath), "pxethief.log") || strings.EqualFold(filepath.Ext(outputPath), ".xml") || strings.HasSuffix(strings.ToLower(filepath.Base(outputPath)), ".boot.var") {
				return outputPath
			}
		}
	}
	if strings.EqualFold(tool, "netexec") || strings.EqualFold(tool, "netexec (nxc)") {
		baseName := strings.ToLower(filepath.Base(outputPath))
		lowerPath := strings.ToLower(filepath.Clean(outputPath))
		if info, err := os.Stat(outputPath); err == nil && info.Mode().IsRegular() &&
			(strings.Contains(lowerPath, string(filepath.Separator)+"ldap_asreproast"+string(filepath.Separator)) ||
				strings.Contains(lowerPath, string(filepath.Separator)+"ldap_kerberoasting"+string(filepath.Separator))) {
			name := "kerberoast.txt"
			if strings.Contains(lowerPath, string(filepath.Separator)+"ldap_asreproast"+string(filepath.Separator)) {
				name = "asreproast.txt"
			}
			if material := filepath.Join(filepath.Dir(outputPath), name); fileExists(material) {
				return material
			}
			return outputPath
		}
		if baseName == "kerberoast.txt" || baseName == "asreproast.txt" || baseName == "ldap_get_users_info.txt" || baseName == "ldap_get_users_description.txt" {
			if _, err := os.Stat(outputPath); err == nil {
				return outputPath
			}
		}
		for _, name := range []string{"kerberoast.txt", "asreproast.txt", "LDAP_get_users_info.txt", "LDAP_get_users_description.txt"} {
			if path := newestMatching(filepath.Dir(outputPath), name); path != "" {
				return path
			}
		}
	}
	base := filepath.Join(filepath.Dir(outputPath), "artifacts")
	entries, err := os.ReadDir(base)
	if err != nil {
		return ""
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() > entries[j].Name() })
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(base, entry.Name())
		switch strings.ToLower(tool) {
		case "rusthound-ce", "rusthound":
			return dir
		case "certipy":
			if path := newestMatching(dir, ".json"); path != "" {
				return path
			}
		case "relayking":
			if path := newestMatching(dir, "relayking-scan.json"); path != "" {
				return path
			}
		case "pxethief":
			if path := newestPXEArtifact(dir); path != "" {
				return dir
			}
		case "netexec", "netexec (nxc)":
			if path := newestMatching(dir, "kerberoast.txt"); path != "" {
				return path
			}
			if path := newestMatching(dir, "asreproast.txt"); path != "" {
				return path
			}
			if path := newestMatching(dir, "LDAP_get_users_info.txt"); path != "" {
				return path
			}
			if path := newestMatching(dir, "LDAP_get_users_description.txt"); path != "" {
				return path
			}
		}
	}
	return ""
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func newestPXEArtifact(dir string) string {
	for _, name := range []string{"pxethief.log", "variables.xml"} {
		if path := newestMatching(dir, name); path != "" {
			return path
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".boot.var") {
			return filepath.Join(dir, entry.Name())
		}
	}
	return ""
}

func newestMatching(dir, suffix string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for i := len(entries) - 1; i >= 0; i-- {
		if !entries[i].IsDir() && strings.HasSuffix(strings.ToLower(entries[i].Name()), strings.ToLower(suffix)) {
			return filepath.Join(dir, entries[i].Name())
		}
	}
	return ""
}
