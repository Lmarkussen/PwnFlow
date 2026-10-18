package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	findingengine "github.com/pwnflow/pwnflow/internal/findings"
	"github.com/pwnflow/pwnflow/internal/storage"
)

func (m *model) exportADPrivilegedACL() {
	if m.adPrivilegedACLExported {
		return
	}
	m.adPrivilegedACLExported = true
	if m.db == nil || len(m.batchExecutionIDs) == 0 {
		m.status += " · privileged ACL report unavailable: no recorded execution IDs"
		return
	}
	if err := writeADPrivilegedACL(m.ctx, m.db, m.cfg.ResultsRoot(), m.cfg.Domain, m.targetID, m.batchExecutionIDs, time.Now().UTC()); err != nil {
		m.status += " · privileged ACL report failed: " + summarySafeText(err.Error())
		return
	}
	m.status += " · privileged ACL report written"
}

func writeADPrivilegedACL(ctx context.Context, db *storage.DB, resultsRoot, domain string, assessmentID int64, executionIDs []int64, generatedAt time.Time) error {
	executions, err := loadPublicationExecutions(ctx, db, assessmentID, uniqueInt64Values(executionIDs))
	if err != nil {
		return err
	}
	if len(executions) != uniqueInt64Count(executionIDs) {
		return fmt.Errorf("privileged ACL execution provenance is incomplete")
	}
	var reports []findingengine.ACLInventoryReport
	for _, execution := range executions {
		if !strings.EqualFold(execution.Status, "completed") || !strings.EqualFold(execution.Tool, "RustHound-CE") {
			continue
		}
		artifact := findingengine.DiscoverArtifact(execution.Tool, execution.OutputPath)
		if artifact == "" {
			continue
		}
		report, _, analyzeErr := findingengine.AnalyzeRustHoundACLInventory(ctx, artifact, assessmentID, execution.ID, execution.Finished)
		if analyzeErr == nil && report.SupportedACLs > 0 {
			if report.Domain == "" {
				report.Domain = domain
			}
			reports = append(reports, report)
		}
	}
	if len(reports) == 0 {
		return nil
	}
	var builder strings.Builder
	for index, report := range reports {
		if index > 0 {
			builder.WriteString("\n\n")
		}
		builder.WriteString(findingengine.FormatACLInventoryReport(report))
	}
	return atomicWriteSummary(filepath.Join(resultsRoot, "AD_PRIVILEGED_ACL_EVIDENCE.txt"), builder.String())
}
