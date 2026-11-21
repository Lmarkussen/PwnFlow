package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const (
	sccmHunterParserVersion   = "sccmhunter-v1"
	networkHoundParserVersion = "networkhound-v1"
	maxInventoryEntries       = 200
)

// sccmHunterArtifact finds the find.db SCCMhunter wrote for the run whose
// artifact directory is the newest one not later than the run's completion.
func sccmHunterArtifact(outputPath string, completedAt time.Time) string {
	for _, dir := range runScopedDirectories(filepath.Join(filepath.Dir(outputPath), "artifacts"), "", completedAt) {
		candidate := filepath.Join(dir, "home", ".sccmhunter", "logs", "db", "find.db")
		if fileExists(candidate) {
			return candidate
		}
	}
	return ""
}

// networkHoundArtifact maps the topology and scope-validation transcripts to
// the JSON NetworkHound wrote for the same run.
func networkHoundArtifact(outputPath string, completedAt time.Time) string {
	prefix, name := "topology-", "network_opengraph.json"
	if strings.Contains(strings.ToLower(filepath.Base(outputPath)), "scope") {
		prefix, name = "ad-host-service-", "ad_host_service.json"
	}
	for _, dir := range runScopedDirectories(filepath.Join(filepath.Dir(outputPath), "artifacts"), prefix, completedAt) {
		if candidate := filepath.Join(dir, name); fileExists(candidate) {
			return candidate
		}
	}
	return ""
}

// runScopedDirectories lists artifact directories named <prefix>YYYYMMDD-HHMMSS,
// newest first, skipping any stamped after completedAt when it is known.
func runScopedDirectories(base, prefix string, completedAt time.Time) []string {
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	type stamped struct {
		dir   string
		stamp time.Time
	}
	var dirs []stamped
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		location := time.Local
		if !completedAt.IsZero() {
			location = completedAt.Location()
		}
		stamp, err := time.ParseInLocation("20060102-150405", strings.TrimPrefix(entry.Name(), prefix), location)
		if err != nil || (!completedAt.IsZero() && stamp.After(completedAt)) {
			continue
		}
		dirs = append(dirs, stamped{filepath.Join(base, entry.Name()), stamp})
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].stamp.After(dirs[j].stamp) })
	result := make([]string, 0, len(dirs))
	for _, item := range dirs {
		result = append(result, item.dir)
	}
	return result
}

// AnalyzeSCCMHunter reads SCCMhunter's find database. It reports the site
// roles SCCMhunter located, PXE-enabled distribution points, and any site
// system SCCMhunter recorded as not requiring SMB signing. The database is
// opened read-only and never modified.
func AnalyzeSCCMHunter(ctx context.Context, path string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	if !fileExists(path) {
		return nil, fmt.Errorf("SCCMhunter database %s is unavailable", path)
	}
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: path}).EscapedPath()+"?mode=ro&immutable=1")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows := func(table string) []map[string]string {
		result, err := sccmTable(ctx, db, table)
		if err != nil {
			return nil
		}
		return result
	}
	siteServers, managementPoints, pxe := rows("SiteServers"), rows("ManagementPoints"), rows("PXEDistributionPoints")
	databases, cas, computers := rows("SiteDatabases"), rows("CAS"), rows("Computers")
	users, groups := rows("Users"), rows("Groups")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(siteServers)+len(managementPoints)+len(pxe)+len(databases)+len(cas)+len(computers)+len(users)+len(groups) == 0 {
		return nil, nil
	}

	finding := func(detector, identity, typ, title, description, severity, ref string, evidence map[string]any) storage.FindingInput {
		encoded, _ := json.Marshal(evidence)
		return storage.FindingInput{
			FindingKey: stableSourceKey(assessmentID, "sccmhunter-"+detector, strings.ToLower(identity), detector), AssessmentID: assessmentID,
			SourceTool: "SCCMhunter", SourceExecution: executionID, FindingType: typ, Title: title, Description: description,
			Severity: severity, Confidence: "tool-reported", AffectedObjectID: strings.ToLower(identity), AffectedObject: identity,
			EvidenceJSON: string(encoded), ArtifactPath: path, ArtifactRef: ref, ObservedAt: now, Status: "open", ParserVersion: sccmHunterParserVersion,
		}
	}
	var result []storage.FindingInput

	siteCodes := map[string]bool{}
	for _, table := range [][]map[string]string{siteServers, managementPoints, databases, cas, computers} {
		for _, row := range table {
			if code := strings.TrimSpace(row["SiteCode"]); code != "" {
				siteCodes[strings.ToUpper(code)] = true
			}
		}
	}
	codes := sortedKeys(siteCodes)
	roles := map[string][]string{
		"site servers":                 hostnames(siteServers),
		"management points":            hostnames(managementPoints),
		"PXE distribution points":      hostnames(pxe),
		"site databases":               hostnames(databases),
		"central administration sites": hostnames(cas),
	}
	var affected []string
	for _, role := range []string{"site servers", "management points", "PXE distribution points", "site databases", "central administration sites"} {
		if len(roles[role]) > 0 {
			affected = append(affected, role+": "+strings.Join(roles[role], ", "))
		}
	}
	userNames := columnValues(users, "sAMAAccontName", "name", "cn")
	groupNames := columnValues(groups, "sAMAAccontName", "name", "cn")
	if len(userNames) > 0 {
		affected = append(affected, "accounts SCCMhunter matched by name: "+strings.Join(truncateList(userNames, 20), ", "))
	}
	if len(groupNames) > 0 {
		affected = append(affected, "groups SCCMhunter matched by name: "+strings.Join(truncateList(groupNames, 20), ", "))
	}
	identity := "SCCM"
	if len(codes) > 0 {
		identity = "SCCM site " + strings.Join(codes, ", ")
	}
	result = append(result, finding("inventory", identity, "sccm_site_inventory", "SCCM infrastructure in Active Directory ("+identity+")",
		"SCCMhunter located Configuration Manager infrastructure through LDAP: published site roles and principals whose names contain SCCM or MECM. Account and group matches are by name and do not establish what each account is used for. Site systems are attack surface for credential recovery and site takeover paths; none was tested.",
		"informational", "/", map[string]any{"site_codes": codes, "roles": roles, "account_matches": truncateList(userNames, maxInventoryEntries), "group_matches": truncateList(groupNames, maxInventoryEntries),
			"account": identity, "flag": "SCCM infrastructure located", "user_account_control": fmt.Sprintf("%d site system(s)", len(uniqueStrings(append(append(append(hostnames(siteServers), hostnames(managementPoints)...), hostnames(pxe)...), hostnames(databases)...)))), "affected_objects": affected}))

	for _, host := range hostnames(pxe) {
		result = append(result, finding("pxe-"+host, host, "sccm_pxe_distribution_point", "PXE-enabled SCCM distribution point: "+host,
			"SCCMhunter found a distribution point that may answer PXE boot requests. PXE boot media can carry task-sequence variables and network access account credentials, and media without a password can be requested by any host on the network segment. PXEThief evaluates the media itself; this observation does not show that it is unprotected.",
			"low", "/PXEDistributionPoints", map[string]any{"host": host, "account": host, "flag": "PXE-enabled distribution point", "user_account_control": "reported by SCCMhunter"}))
	}

	unsigned := map[string][]string{}
	for role, table := range map[string][]map[string]string{"site server": siteServers, "management point": managementPoints, "PXE distribution point": pxe, "site database": databases, "central administration site": cas, "site system": computers} {
		for _, row := range table {
			if strings.EqualFold(strings.TrimSpace(row["SigningStatus"]), "False") {
				host := strings.ToLower(strings.TrimSpace(row["Hostname"]))
				if host != "" {
					unsigned[host] = appendUniqueString(unsigned[host], role)
				}
			}
		}
	}
	for _, host := range sortedKeys(boolMap(unsigned)) {
		sort.Strings(unsigned[host])
		result = append(result, finding("unsigned-"+host, host, "sccm_site_system_smb_signing_not_required", "SCCM site system without required SMB signing: "+host,
			"SCCMhunter recorded that this Configuration Manager site system does not require SMB signing. Site servers and site databases that accept relayed NTLM are the core of the published SCCM site-takeover paths. No relay was attempted.",
			"medium", "/", map[string]any{"host": host, "roles": unsigned[host], "account": host, "flag": "SMB signing not required", "user_account_control": strings.Join(unsigned[host], ", ")}))
	}
	return result, nil
}

func sccmTable(ctx context.Context, db *sql.DB, table string) ([]map[string]string, error) {
	query, err := db.QueryContext(ctx, `SELECT * FROM "`+strings.ReplaceAll(table, `"`, ``)+`"`)
	if err != nil {
		return nil, err
	}
	defer query.Close()
	columns, err := query.Columns()
	if err != nil {
		return nil, err
	}
	var result []map[string]string
	for query.Next() && len(result) < maxInventoryEntries {
		values := make([]sql.NullString, len(columns))
		pointers := make([]any, len(columns))
		for index := range values {
			pointers[index] = &values[index]
		}
		if err := query.Scan(pointers...); err != nil {
			return nil, err
		}
		row := map[string]string{}
		for index, column := range columns {
			row[column] = strings.TrimSpace(values[index].String)
		}
		result = append(result, row)
	}
	return result, query.Err()
}

func hostnames(rows []map[string]string) []string {
	seen := map[string]bool{}
	for _, row := range rows {
		if host := strings.ToLower(strings.TrimSpace(row["Hostname"])); host != "" {
			seen[host] = true
		}
	}
	return sortedKeys(seen)
}

func columnValues(rows []map[string]string, columns ...string) []string {
	seen := map[string]bool{}
	for _, row := range rows {
		for _, column := range columns {
			if value := strings.TrimSpace(row[column]); value != "" {
				seen[value] = true
				break
			}
		}
	}
	return sortedKeys(seen)
}

func truncateList(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return append(append([]string(nil), values[:limit]...), fmt.Sprintf("… and %d more", len(values)-limit))
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func boolMap[T any](values map[string]T) map[string]bool {
	result := make(map[string]bool, len(values))
	for key := range values {
		result[key] = true
	}
	return result
}

// AnalyzeNetworkHound reads NetworkHound's OpenGraph output. The scope
// validation artifact becomes an open-service inventory per host; the
// topology artifact reports AD computers that did not resolve to an address.
func AnalyzeNetworkHound(ctx context.Context, path string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var document struct {
		Graph struct {
			Nodes []struct {
				ID         string         `json:"id"`
				Kinds      []string       `json:"kinds"`
				Properties map[string]any `json:"properties"`
			} `json:"nodes"`
		} `json:"graph"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	scope := strings.EqualFold(filepath.Base(path), "ad_host_service.json")
	var hosts, unresolved []string
	services := map[string][]string{}
	computers := 0
	for _, node := range document.Graph.Nodes {
		if !containsFold(node.Kinds, "Computer") {
			continue
		}
		computers++
		label := fallbackString(stringOf(node.Properties["name"]), node.ID)
		addresses := cpStringSlice(node.Properties["ip_addresses"])
		if len(addresses) > 0 {
			label = fallbackString(stringOf(node.Properties["name"]), addresses[0])
		}
		var ports []string
		for _, port := range anySlice(node.Properties["open_ports"]) {
			ports = append(ports, stringOf(port))
		}
		if len(addresses) == 0 {
			unresolved = append(unresolved, label)
			continue
		}
		hosts = append(hosts, label)
		if len(ports) > 0 {
			services[label] = ports
		}
	}
	sort.Strings(hosts)
	sort.Strings(unresolved)
	key := func(detector string) string {
		return stableSourceKey(assessmentID, "networkhound-"+detector, strings.ToLower(filepath.Base(path)), detector)
	}
	var result []storage.FindingInput
	if scope && len(services) > 0 {
		var affected []string
		for _, host := range sortedKeys(boolMap(services)) {
			affected = append(affected, host+": "+strings.Join(services[host], ", "))
		}
		evidence, _ := json.Marshal(map[string]any{"hosts": len(services), "open_ports": services, "affected_objects": truncateList(affected, maxInventoryEntries)})
		result = append(result, storage.FindingInput{
			FindingKey: key("open-ports"), AssessmentID: assessmentID, SourceTool: "NetworkHound", SourceExecution: executionID,
			FindingType: "networkhound_open_ports", Title: fmt.Sprintf("Open services on %d in-scope host(s)", len(services)),
			Description: "NetworkHound's scope validation found these TCP services open on hosts derived from the directory topology. This is an inventory for the other checks; an open port is not itself a weakness.",
			Severity:    "informational", Confidence: "tool-reported", AffectedObjectID: "networkhound-scope", AffectedObject: fmt.Sprintf("%d host(s)", len(services)),
			EvidenceJSON: string(evidence), ArtifactPath: path, ArtifactRef: "/graph/nodes", ObservedAt: now, Status: "open", ParserVersion: networkHoundParserVersion,
		})
	}
	if !scope && len(unresolved) > 0 {
		evidence, _ := json.Marshal(map[string]any{"computers": computers, "unresolved": len(unresolved), "affected_objects": truncateList(unresolved, maxInventoryEntries)})
		result = append(result, storage.FindingInput{
			FindingKey: key("unresolved"), AssessmentID: assessmentID, SourceTool: "NetworkHound", SourceExecution: executionID,
			FindingType: "networkhound_topology_unresolved_computers", Title: fmt.Sprintf("AD computers without a resolvable address (%d of %d)", len(unresolved), computers),
			Description: "These computer objects did not resolve to an address through the domain controller's DNS. They are often retired hosts whose accounts remain, or stale DNS registrations, and are worth reviewing together with the stale-account Findings.",
			Severity:    "informational", Confidence: "tool-reported", AffectedObjectID: "networkhound-topology", AffectedObject: fmt.Sprintf("%d computer(s)", len(unresolved)),
			EvidenceJSON: string(evidence), ArtifactPath: path, ArtifactRef: "/graph/nodes", ObservedAt: now, Status: "open", ParserVersion: networkHoundParserVersion,
		})
	}
	return result, nil
}
