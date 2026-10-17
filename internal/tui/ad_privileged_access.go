package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	findingengine "github.com/pwnflow/pwnflow/internal/findings"
	"github.com/pwnflow/pwnflow/internal/storage"
)

func (m *model) exportADPrivilegedAccess() {
	if m.adPrivilegedAccessExported {
		return
	}
	m.adPrivilegedAccessExported = true
	if m.db == nil || len(m.batchExecutionIDs) == 0 {
		m.status += " · privileged access report unavailable: no recorded execution IDs"
		return
	}
	if err := writeADPrivilegedAccess(m.ctx, m.db, m.cfg.ResultsRoot(), m.cfg.Domain, m.targetID, m.batchExecutionIDs, time.Now().UTC()); err != nil {
		m.status += " · privileged access report failed: " + summarySafeText(err.Error())
		return
	}
	m.status += " · privileged access report written"
}

func writeADPrivilegedAccess(ctx context.Context, db *storage.DB, resultsRoot, domain string, assessmentID int64, executionIDs []int64, generatedAt time.Time) error {
	executions, err := loadPublicationExecutions(ctx, db, assessmentID, uniqueInt64Values(executionIDs))
	if err != nil {
		return err
	}
	if len(executions) != uniqueInt64Count(executionIDs) {
		return fmt.Errorf("privileged access execution provenance is incomplete")
	}
	var reports []findingengine.GroupMembershipReport
	seenArtifacts := map[string]bool{}
	for _, execution := range executions {
		if !strings.EqualFold(execution.Status, "completed") || !strings.Contains(strings.ToLower(execution.Tool), "rusthound") {
			continue
		}
		artifact := findingengine.DiscoverArtifact(execution.Tool, execution.OutputPath)
		if artifact == "" || seenArtifacts[artifact] {
			continue
		}
		seenArtifacts[artifact] = true
		report, _, parseErr := findingengine.AnalyzeRustHoundGroups(ctx, artifact, assessmentID, execution.ID, generatedAt)
		if parseErr == nil {
			reports = append(reports, report)
		}
	}
	report := combineGroupReports(reports)
	text := formatADPrivilegedAccess(resultsRoot, domain, generatedAt, report)
	return atomicWriteSummary(filepath.Join(resultsRoot, "AD_PRIVILEGED_ACCESS.txt"), text)
}

func combineGroupReports(reports []findingengine.GroupMembershipReport) findingengine.GroupMembershipReport {
	combined := findingengine.GroupMembershipReport{Coverage: "Not assessed"}
	seenGroups := map[string]bool{}
	for _, report := range reports {
		if combined.Coverage == "Not assessed" {
			combined.Coverage = report.Coverage
		}
		combined.GroupsExamined += report.GroupsExamined
		combined.DirectEdges += report.DirectEdges
		combined.NestedRelationships += report.NestedRelationships
		combined.UnresolvedReferences += report.UnresolvedReferences
		for _, group := range report.PrivilegedGroups {
			key := strings.ToLower(group.ID)
			if seenGroups[key] {
				continue
			}
			seenGroups[key] = true
			combined.PrivilegedGroups = append(combined.PrivilegedGroups, group)
		}
	}
	sort.Slice(combined.PrivilegedGroups, func(i, j int) bool {
		return strings.ToLower(combined.PrivilegedGroups[i].Privilege+combined.PrivilegedGroups[i].Name) < strings.ToLower(combined.PrivilegedGroups[j].Privilege+combined.PrivilegedGroups[j].Name)
	})
	return combined
}

func formatADPrivilegedAccess(resultsRoot, domain string, generatedAt time.Time, report findingengine.GroupMembershipReport) string {
	var b strings.Builder
	line := strings.Repeat("=", 70)
	fmt.Fprintln(&b, line)
	fmt.Fprintln(&b, "                 PWNFLOW AD PRIVILEGED ACCESS INVENTORY")
	fmt.Fprintln(&b, line)
	fmt.Fprintf(&b, "\nDOMAIN: %s\nSOURCE: RustHound-CE\nCOVERAGE: %s\nGENERATED: %s\n", safeADText(domain), safeADText(report.Coverage), generatedAt.UTC().Format("2006-01-02 15:04:05"))
	fmt.Fprintln(&b, "\n----------------------------------------------------------------------\nOVERVIEW\n----------------------------------------------------------------------")
	fmt.Fprintf(&b, "\nGroups examined:              %d\nDirect memberships observed:  %d\nNested relationships:         %d\nPrivileged groups identified: %d\nUnresolved references:        %d\n", report.GroupsExamined, report.DirectEdges, report.NestedRelationships, len(report.PrivilegedGroups), report.UnresolvedReferences)
	for _, group := range report.PrivilegedGroups {
		fmt.Fprintf(&b, "\n----------------------------------------------------------------------\nPRIVILEGED GROUP: %s\n----------------------------------------------------------------------\n\nIdentity: %s\nDomain:   %s\n", safeADText(group.Privilege), safeADText(group.Name), safeADText(group.Domain))
		fmt.Fprintln(&b, "\nDirect members:")
		writeADMembers(&b, group.DirectMembers, false)
		fmt.Fprintln(&b, "\nNested members:")
		writeADMembers(&b, group.NestedMembers, true)
		if len(group.Unresolved) > 0 {
			fmt.Fprintln(&b, "\nUnresolved / foreign:")
			writeADMembers(&b, group.Unresolved, false)
		}
	}
	fmt.Fprintln(&b, "\n----------------------------------------------------------------------\nCOLLECTION LIMITATIONS\n----------------------------------------------------------------------\n\n- RustHound membership coverage is not independently established.\n- Observed paths do not prove exhaustive membership coverage.\n- Membership does not establish that an account is active or currently usable.\n- Original RustHound artifacts remain the authoritative evidence.")
	fmt.Fprintf(&b, "\nSource root: %s\n\n%s\n", safeADText(resultsRoot), line)
	return b.String()
}

func writeADMembers(b *strings.Builder, members []findingengine.GroupPrincipal, includePath bool) {
	if len(members) == 0 {
		b.WriteString("  (none observed)\n")
		return
	}
	for _, member := range members {
		label := member.Name
		if member.Domain != "" {
			label += " [" + member.Domain + "]"
		}
		if member.Deleted {
			label += " (deleted)"
		} else if member.Disabled {
			label += " (disabled)"
		}
		fmt.Fprintf(b, "  - %s (%s)\n", safeADText(label), safeADText(member.Type))
		if includePath && len(member.Path) > 0 {
			parts := make([]string, len(member.Path))
			for i, part := range member.Path {
				parts[i] = safeADText(part)
			}
			fmt.Fprintf(b, "    Path: %s\n", strings.Join(parts, " <- "))
		}
	}
}

func safeADText(value string) string {
	value = summarySafeText(value)
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	return strings.TrimSpace(value)
}
