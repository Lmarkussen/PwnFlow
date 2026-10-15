package sccm

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// discoveredRecord is one SCCM system as the tool reported it, before address
// resolution. It mirrors the columns SCCMhunter stores rather than anything parsed
// out of free-form text.
type discoveredRecord struct {
	Hostname string
	Role     string
}

// discoveryTables maps the SCCMhunter tables to the SCCM role their rows describe.
// Reading the rows by table is what keeps this a structured read: the tool's own
// schema decides which column is the host name, not a pattern over its text.
var discoveryTables = []struct {
	Table   string
	Column  string
	Role    string
	Sources []string
}{
	{Table: "PXEDistributionPoints", Column: "Hostname", Role: rolePXEDistributionPoint},
	{Table: "ManagementPoints", Column: "Hostname", Role: roleManagementPoint},
	{Table: "SiteServers", Column: "Hostname", Role: roleSiteServer},
	{Table: "SiteDatabases", Column: "Hostname", Role: roleSiteDatabase},
	{Table: "Computers", Column: "Hostname", Role: roleSCCMComputer},
}

// readDiscoveryDatabase reads the SCCMhunter database of one run. A table the
// installed version does not have is skipped, because the schema is the tool's to
// change.
func readDiscoveryDatabase(path string) ([]discoveredRecord, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("SCCMhunter database %s is unavailable: %w", path, err)
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	defer database.Close()
	records := make([]discoveredRecord, 0)
	read := 0
	for _, table := range discoveryTables {
		rows, err := database.Query(fmt.Sprintf("SELECT %s FROM %s", table.Column, table.Table))
		if err != nil {
			// The table may not exist in this version; another table may still have
			// what the assessment needs.
			continue
		}
		for rows.Next() {
			var hostname string
			if err := rows.Scan(&hostname); err != nil {
				rows.Close()
				return records, err
			}
			read++
			if hostname = strings.TrimSpace(hostname); hostname == "" {
				continue
			}
			records = append(records, discoveredRecord{Hostname: hostname, Role: table.Role})
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return records, err
		}
		rows.Close()
	}
	if read == 0 && len(records) == 0 {
		return records, nil
	}
	return records, nil
}

// parseDiscoveryTables extracts host names from SCCMhunter's own table output, used
// when the run's database cannot be read. It reads the tabulate grid the tool
// prints: the header row names the columns, and the host name is read from the
// "Hostname" column of a table whose title the tool also prints.
func parseDiscoveryTables(output string) []discoveredRecord {
	records := make([]discoveredRecord, 0)
	role := ""
	header := []string(nil)
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "Site Servers Table"), strings.Contains(line, "Site Servers Table"):
			role = roleSiteServer
		case strings.Contains(line, "Potential Site Databases"):
			role = roleSiteDatabase
		case strings.Contains(line, "Management Points Table"):
			role = roleManagementPoint
		case strings.Contains(line, "Potential PXE Distribution Points"):
			role = rolePXEDistributionPoint
		case strings.Contains(line, "Computers Table"):
			role = roleSCCMComputer
			continue
		}
		if !strings.HasPrefix(line, "|") {
			// A border or a log line ends the current table's rows.
			if !strings.HasPrefix(line, "+") {
				header = nil
			}
			continue
		}
		cells := splitGridRow(line)
		if len(cells) == 0 {
			continue
		}
		if header == nil || isGridHeader(cells) {
			header = cells
			continue
		}
		index := indexOfCell(header, "hostname")
		if index < 0 || index >= len(cells) || role == "" {
			continue
		}
		if hostname := strings.TrimSpace(cells[index]); hostname != "" {
			records = append(records, discoveredRecord{Hostname: hostname, Role: role})
		}
	}
	return records
}

// splitGridRow splits one tabulate grid row into its cells.
func splitGridRow(line string) []string {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(line, "|"), "|")
	parts := strings.Split(trimmed, "|")
	cells := make([]string, 0, len(parts))
	for _, part := range parts {
		cells = append(cells, strings.TrimSpace(part))
	}
	return cells
}

// isGridHeader reports whether a row is the column header rather than data.
func isGridHeader(cells []string) bool {
	return indexOfCell(cells, "hostname") >= 0
}

func indexOfCell(cells []string, wanted string) int {
	for index, cell := range cells {
		if strings.EqualFold(cell, wanted) {
			return index
		}
	}
	return -1
}

// discoveryEndpoints converts discovered records into assessment endpoints,
// resolving names to addresses and removing duplicates. Records that resolve to no
// address are kept with an empty address so the operator can see what was found
// and why it cannot be probed, but they never become targets.
func discoveryEndpoints(ctx context.Context, resolver Resolver, records []discoveredRecord, domain, source string, discoveredAt time.Time) []modules.Endpoint {
	endpoints := make([]modules.Endpoint, 0, len(records))
	seen := make(map[string]bool, len(records))
	for _, record := range records {
		hostname := strings.TrimSuffix(strings.TrimSpace(record.Hostname), ".")
		if hostname == "" {
			continue
		}
		addresses := resolveAddresses(ctx, resolver, hostname, domain)
		if len(addresses) == 0 {
			key := strings.ToLower(hostname) + "|" + record.Role
			if seen[key] {
				continue
			}
			seen[key] = true
			endpoints = append(endpoints, modules.Endpoint{Hostname: hostname, Role: record.Role, Source: source, Domain: domain, DiscoveredAt: discoveredAt})
			continue
		}
		for _, address := range addresses {
			key := address + "|" + record.Role
			if seen[key] {
				continue
			}
			seen[key] = true
			endpoints = append(endpoints, modules.Endpoint{Address: address, Hostname: hostname, Role: record.Role, Source: source, Domain: domain, DiscoveredAt: discoveredAt})
		}
	}
	sort.SliceStable(endpoints, func(first, second int) bool {
		left, right := endpoints[first], endpoints[second]
		if left.Address != right.Address {
			return left.Address < right.Address
		}
		if left.Hostname != right.Hostname {
			return left.Hostname < right.Hostname
		}
		return rolePriority(left.Role) < rolePriority(right.Role)
	})
	return endpoints
}
