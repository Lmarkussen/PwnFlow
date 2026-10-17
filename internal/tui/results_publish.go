package tui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	findingengine "github.com/pwnflow/pwnflow/internal/findings"
	"github.com/pwnflow/pwnflow/internal/storage"
)

type publicationExecution struct {
	ID                               int64
	Module, Tool, OutputPath, Status string
	Started, Finished                time.Time
}

type publishedFile struct {
	Tool, Name, Source string
	ExecutionID        int64
	Hash               string
}

type inventoryRecord struct {
	SID, Hostname string
	IPs           map[string]bool
	Users         map[string]bool
}

type publishedInventory struct {
	Names, IPs   []string
	Pairs        []string
	Users        []string
	Complete     bool
	UserEvidence bool
}

func (m *model) publishDefaultEnumerationResults() {
	if m.batchResultsPublished {
		return
	}
	m.batchResultsPublished = true
	if m.db == nil || len(m.batchExecutionIDs) == 0 {
		m.status += " · flat results unavailable: no recorded execution IDs"
		return
	}
	if err := publishDefaultResults(m.ctx, m.db, m.cfg.ResultsRoot(), m.cfg.Domain, m.targetID, m.batchExecutionIDs, time.Now().UTC()); err != nil {
		m.status += " · flat results publication failed: " + summarySafeText(err.Error())
		return
	}
	m.status += " · flat results published"
}

func publishDefaultResults(ctx context.Context, db *storage.DB, resultsRoot, domain string, assessmentID int64, executionIDs []int64, publishedAt time.Time) error {
	executions, err := loadPublicationExecutions(ctx, db, assessmentID, uniqueInt64Values(executionIDs))
	if err != nil {
		return err
	}
	if len(executions) != uniqueInt64Count(executionIDs) {
		return fmt.Errorf("publication execution provenance is incomplete")
	}
	stage, err := os.MkdirTemp(resultsRoot, ".pwnflow-publish-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0o700); err != nil {
		return err
	}

	var files []publishedFile
	var tools = map[string]bool{}
	for _, execution := range executions {
		tool := publicationTool(execution.Tool)
		tools[tool] = true
		if err := os.MkdirAll(filepath.Join(stage, tool), 0o700); err != nil {
			return err
		}
		if !strings.EqualFold(execution.Status, "completed") {
			continue
		}
		sources := publicationSources(execution, resultsRoot)
		for _, source := range sources {
			entries, walkErr := publicationEntries(source)
			if walkErr != nil {
				continue
			}
			for _, entry := range entries {
				name := filepath.Base(entry)
				if name == "" {
					continue
				}
				name = publicationName(stage, tool, name, execution.ID, entry)
				if err := copyPublishedFile(entry, filepath.Join(stage, tool, name)); err != nil {
					return err
				}
				hash, err := fileSHA256(entry)
				if err != nil {
					return err
				}
				files = append(files, publishedFile{Tool: tool, Name: name, Source: entry, ExecutionID: execution.ID, Hash: hash})
			}
		}
	}

	inventory, err := collectPublicationInventory(executions, resultsRoot, domain)
	if err != nil {
		return err
	}
	for name, values := range map[string][]string{
		"DNS_NAMES.txt":    inventory.Names,
		"DNS_NAME_IP.txt":  inventory.Pairs,
		"IP_ADDRESSES.txt": inventory.IPs,
		"AD_USERS.txt":     inventory.Users,
	} {
		if err := writePublishedList(filepath.Join(stage, name), values); err != nil {
			return err
		}
	}
	manifest := formatPublicationManifest(domain, assessmentID, executionIDs, publishedAt, executions, files, inventory, tools)
	if err := writePublishedList(filepath.Join(stage, "published_results_manifest.txt"), strings.Split(strings.TrimSuffix(manifest, "\n"), "\n")); err != nil {
		return err
	}
	for _, tool := range []string{"NetExec", "Certipy", "NetworkHound", "RustHound", "SCCMHunter", "PXEThief", "RelayKing"} {
		if err := os.MkdirAll(filepath.Join(stage, tool), 0o700); err != nil {
			return err
		}
	}
	return publishStage(stage, resultsRoot, tools)
}

func loadPublicationExecutions(ctx context.Context, db *storage.DB, assessmentID int64, ids []int64) ([]publicationExecution, error) {
	if db == nil || len(ids) == 0 {
		return nil, fmt.Errorf("publication requires a database and execution IDs")
	}
	args := []any{assessmentID}
	args = appendInt64Args(args, ids)
	rows, err := db.QueryContext(ctx, `SELECT e.id,m.name,m.tool,e.output_path,e.status,e.started_at,COALESCE(e.finished_at,'') FROM executions e JOIN modules m ON m.id=e.module_id WHERE e.target_id=? AND e.id IN (`+placeholders(len(ids))+`) ORDER BY e.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []publicationExecution
	for rows.Next() {
		var item publicationExecution
		var started, finished string
		if err := rows.Scan(&item.ID, &item.Module, &item.Tool, &item.OutputPath, &item.Status, &started, &finished); err != nil {
			return nil, err
		}
		item.Started, err = time.Parse(time.RFC3339Nano, started)
		if err != nil {
			return nil, err
		}
		if finished != "" {
			item.Finished, err = time.Parse(time.RFC3339Nano, finished)
			if err != nil {
				return nil, err
			}
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func publicationTool(tool string) string {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "netexec", "netexec (nxc)":
		return "NetExec"
	case "certipy":
		return "Certipy"
	case "networkhound":
		return "NetworkHound"
	case "rusthound-ce", "rusthound":
		return "RustHound"
	case "sccmhunter":
		return "SCCMHunter"
	case "pxethief":
		return "PXEThief"
	case "relayking":
		return "RelayKing"
	default:
		clean := strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
				return r
			}
			return '_'
		}, tool)
		if clean == "" {
			return "Other"
		}
		return clean
	}
}

func publicationSources(execution publicationExecution, root string) []string {
	seen := map[string]bool{}
	var result []string
	add := func(path string) {
		if path == "" {
			return
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		if seen[path] || !withinRoot(path, root) {
			return
		}
		if _, err := os.Stat(path); err == nil {
			seen[path] = true
			result = append(result, path)
		}
	}
	add(execution.OutputPath)
	add(findingengine.DiscoverArtifact(execution.Tool, execution.OutputPath))
	if execution.OutputPath != "" {
		base := filepath.Dir(execution.OutputPath)
		artifactRoot := filepath.Join(base, "artifacts")
		prefix := strings.TrimSuffix(filepath.Base(execution.OutputPath), filepath.Ext(execution.OutputPath)) + "-"
		if entries, err := os.ReadDir(artifactRoot); err == nil {
			var candidates []string
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				if !strings.HasPrefix(entry.Name(), prefix) && !strings.EqualFold(execution.Tool, "networkhound") {
					continue
				}
				path := filepath.Join(artifactRoot, entry.Name())
				if execution.Finished.IsZero() || !entryTimeNear(path, execution.Started, execution.Finished) {
					continue
				}
				candidates = append(candidates, path)
			}
			sort.Strings(candidates)
			for _, candidate := range candidates {
				add(candidate)
			}
		}
	}
	return result
}

func entryTimeNear(path string, started, finished time.Time) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	start := started.Add(-2 * time.Minute)
	end := finished.Add(2 * time.Minute)
	return !info.ModTime().Before(start) && !info.ModTime().After(end)
}

func publicationEntries(source string) ([]string, error) {
	info, err := os.Stat(source)
	if err != nil {
		return nil, err
	}
	if info.Mode().IsRegular() {
		return []string{source}, nil
	}
	var result []string
	err = filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			result = append(result, path)
		}
		return nil
	})
	sort.Strings(result)
	return result, err
}

func publicationName(stage, tool, name string, executionID int64, source string) string {
	dir := filepath.Join(stage, tool)
	if _, err := os.Stat(filepath.Join(dir, name)); os.IsNotExist(err) {
		return name
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	return fmt.Sprintf("%s--exec-%d%s", base, executionID, ext)
}

func copyPublishedFile(source, destination string) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".publish-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, destination)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writePublishedList(path string, values []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data := ""
	for _, value := range values {
		if value != "" {
			data += value + "\n"
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".publish-list-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.WriteString(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func publishStage(stage, root string, tools map[string]bool) error {
	paths := []string{"DNS_NAMES.txt", "DNS_NAME_IP.txt", "IP_ADDRESSES.txt", "AD_USERS.txt", "published_results_manifest.txt"}
	for _, tool := range []string{"NetExec", "Certipy", "NetworkHound", "RustHound", "SCCMHunter", "PXEThief", "RelayKing"} {
		tools[tool] = true
	}
	for tool := range tools {
		paths = append(paths, tool)
	}
	sort.Strings(paths)
	backup := filepath.Join(root, ".pwnflow-publish-backup")
	if err := os.RemoveAll(backup); err != nil {
		return err
	}
	if err := os.Mkdir(backup, 0o700); err != nil {
		return err
	}
	moved := make([]string, 0, len(paths))
	rollback := func() {
		for _, path := range moved {
			_ = os.RemoveAll(filepath.Join(root, path))
			_ = os.Rename(filepath.Join(backup, path), filepath.Join(root, path))
		}
	}
	for _, path := range paths {
		destination := filepath.Join(root, path)
		if _, err := os.Stat(destination); err == nil {
			if err := os.Rename(destination, filepath.Join(backup, path)); err != nil {
				rollback()
				return err
			}
			moved = append(moved, path)
		}
	}
	for _, path := range paths {
		if err := os.Rename(filepath.Join(stage, path), filepath.Join(root, path)); err != nil {
			rollback()
			return err
		}
	}
	return os.RemoveAll(backup)
}

func collectPublicationInventory(executions []publicationExecution, root, domain string) (publishedInventory, error) {
	records := map[string]*inventoryRecord{}
	complete := true
	for _, execution := range executions {
		if !strings.EqualFold(execution.Status, "completed") {
			complete = false
			continue
		}
		sources := publicationSources(execution, root)
		if len(sources) == 0 {
			complete = false
			continue
		}
		for _, source := range sources {
			entries, err := publicationEntries(source)
			if err != nil {
				complete = false
				continue
			}
			for _, path := range entries {
				if strings.HasSuffix(strings.ToLower(path), ".json") {
					data, err := os.ReadFile(path)
					if err != nil {
						complete = false
						continue
					}
					if !extractInventoryJSON(data, domain, records) {
						continue
					}
				}
			}
		}
	}
	var names, ips, pairs, users []string
	nameSet, ipSet, pairSet := map[string]bool{}, map[string]bool{}, map[string]bool{}
	userSet := map[string]string{}
	for _, record := range records {
		if record.Hostname != "" {
			nameSet[record.Hostname] = true
		}
		for ip := range record.IPs {
			ipSet[ip] = true
			if record.Hostname != "" {
				pairSet[record.Hostname+" "+ip] = true
			}
		}
		for user := range record.Users {
			key := strings.ToLower(user)
			if previous, exists := userSet[key]; !exists || user < previous {
				userSet[key] = user
			}
		}
	}
	for value := range nameSet {
		names = append(names, value)
	}
	for value := range ipSet {
		ips = append(ips, value)
	}
	for value := range pairSet {
		pairs = append(pairs, value)
	}
	for _, value := range userSet {
		users = append(users, value)
	}
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	sort.Strings(ips)
	sort.Strings(pairs)
	sort.Slice(users, func(i, j int) bool { return strings.ToLower(users[i]) < strings.ToLower(users[j]) })
	return publishedInventory{Names: names, IPs: ips, Pairs: pairs, Users: users, Complete: complete && len(users) > 0, UserEvidence: len(users) > 0}, nil
}

func extractInventoryJSON(data []byte, domain string, records map[string]*inventoryRecord) bool {
	var root any
	if json.Unmarshal(data, &root) != nil {
		return false
	}
	found := false
	var visit func(any)
	visit = func(value any) {
		switch item := value.(type) {
		case []any:
			for _, child := range item {
				visit(child)
			}
		case map[string]any:
			attributes, _ := item["attributes"].(map[string]any)
			kind := strings.ToLower(fmt.Sprint(item["kinds"]))
			isComputer := strings.Contains(kind, "computer") || hasKey(item, attributes, "dNSHostName") || hasKey(item, attributes, "dnsHostName")
			isUser := hasKey(item, attributes, "sAMAccountName") && !isComputer
			if isComputer || isUser {
				found = true
				addInventoryRecord(item, domain, records, isComputer, isUser)
			}
			for key, child := range item {
				if key == "attributes" || key == "properties" {
					continue
				}
				visit(child)
			}
		}
	}
	visit(root)
	return found
}

func addInventoryRecord(item map[string]any, domain string, records map[string]*inventoryRecord, isComputer, isUser bool) {
	props := item
	if nested, ok := item["properties"].(map[string]any); ok {
		props = nested
	}
	if attrs, ok := item["attributes"].(map[string]any); ok {
		for key, value := range attrs {
			if _, exists := props[key]; !exists {
				props[key] = value
			}
		}
	}
	if !inventoryObjectInDomain(item, props, domain) {
		return
	}
	sid := fieldText(item, props, "objectid", "objectSid", "objectSID", "sid")
	key := strings.ToLower(sid)
	if key == "" {
		key = "anon:" + strings.ToLower(fieldText(item, props, "dNSHostName", "dnsHostName", "hostname", "name", "sAMAccountName"))
	}
	if key == "anon:" {
		return
	}
	record := records[key]
	if record == nil {
		record = &inventoryRecord{SID: sid, IPs: map[string]bool{}, Users: map[string]bool{}}
		records[key] = record
	}
	if isComputer {
		if hostname := validInventoryHostname(fieldText(item, props, "dNSHostName", "dnsHostName", "hostname"), domain); hostname != "" {
			record.Hostname = hostname
		}
	}
	if isUser {
		if username := validInventoryUser(fieldText(item, props, "sAMAccountName")); username != "" {
			record.Users[username] = true
		}
	}
	for _, candidate := range textValues(item, props, "ip_addresses", "ipAddresses", "ips", "ip", "address") {
		if ip := validInventoryIP(candidate); ip != "" {
			record.IPs[ip] = true
		}
	}
}

func hasKey(item, attributes map[string]any, key string) bool {
	if _, ok := item[key]; ok {
		return true
	}
	_, ok := attributes[key]
	return ok
}
func fieldText(item, attributes map[string]any, keys ...string) string {
	for _, key := range keys {
		for _, source := range []map[string]any{item, attributes} {
			if value, ok := source[key]; ok {
				if text := scalarText(value); text != "" {
					return text
				}
			}
		}
	}
	return ""
}

func inventoryObjectInDomain(item, attributes map[string]any, domain string) bool {
	if value := fieldText(item, attributes, "distinguishedName", "dn"); value != "" {
		domainDN := "dc=" + strings.ReplaceAll(strings.ToLower(domain), ".", ",dc=")
		return strings.HasSuffix(strings.ToLower(value), ","+domainDN) || strings.EqualFold(value, domainDN)
	}
	if value := fieldText(item, attributes, "userPrincipalName"); value != "" {
		return strings.HasSuffix(strings.ToLower(value), "@"+strings.ToLower(domain))
	}
	return true
}
func scalarText(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case []any:
		if len(v) > 0 {
			return scalarText(v[0])
		}
	case []string:
		if len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
	}
	return ""
}
func textValues(items ...any) []string {
	var result []string
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			for _, key := range []string{"ip_addresses", "ipAddresses", "ips", "ip", "address"} {
				if value, exists := m[key]; exists {
					result = append(result, valuesFromAny(value)...)
					break
				}
			}
		}
	}
	return result
}
func valuesFromAny(value any) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, item := range v {
			out = append(out, valuesFromAny(item)...)
		}
		return out
	}
	return nil
}
func validInventoryIP(value string) string {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil || ip.To4() == nil || ip.To4().String() == "255.255.255.255" {
		return ""
	}
	four := ip.To4()
	if four[0] == 100 && four[1] >= 64 && four[1] <= 127 {
		return ""
	}
	return four.String()
}
func validInventoryHostname(value, domain string) string {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || !strings.HasSuffix(value, "."+strings.ToLower(domain)) {
		return ""
	}
	return value
}
func validInventoryUser(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\\/\x00\r\n") {
		return ""
	}
	return value
}

func formatPublicationManifest(domain string, assessmentID int64, ids []int64, at time.Time, executions []publicationExecution, files []publishedFile, inventory publishedInventory, tools map[string]bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "PwnFlow published results\nDomain: %s\nAssessment ID: %d\nPublished: %s\nExecution IDs: %s\nPublication completeness: %s\n\n", domain, assessmentID, at.Format(time.RFC3339), joinInt64(ids), map[bool]string{true: "complete", false: "partial"}[inventory.Complete])
	b.WriteString("Executions:\n")
	for _, execution := range executions {
		fmt.Fprintf(&b, "- %d | %s | %s | %s | %s\n", execution.ID, execution.Tool, execution.Module, execution.Status, execution.OutputPath)
	}
	b.WriteString("\nPublished files:\n")
	sort.Slice(files, func(i, j int) bool {
		if files[i].Tool != files[j].Tool {
			return files[i].Tool < files[j].Tool
		}
		return files[i].Name < files[j].Name
	})
	for _, file := range files {
		fmt.Fprintf(&b, "- %s/%s | execution=%d | source=%s | sha256=%s\n", file.Tool, file.Name, file.ExecutionID, file.Source, file.Hash)
	}
	b.WriteString("\nInventory:\n")
	completeness := map[bool]string{true: "complete", false: "partial"}
	fmt.Fprintf(&b, "- DNS_NAMES.txt: %d\n- DNS_NAME_IP.txt: %d\n- IP_ADDRESSES.txt: %d\n- AD_USERS.txt: %d\n- AD_USERS.txt completeness: %s\n", len(inventory.Names), len(inventory.Pairs), len(inventory.IPs), len(inventory.Users), completeness[inventory.UserEvidence])
	if len(tools) == 0 {
		b.WriteString("- No completed tool outputs were available.\n")
	}
	return b.String()
}
func joinInt64(values []int64) string {
	var out []string
	for _, value := range values {
		out = append(out, fmt.Sprint(value))
	}
	return strings.Join(out, ",")
}
func withinRoot(path, root string) bool {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	base, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(base, absolute)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
