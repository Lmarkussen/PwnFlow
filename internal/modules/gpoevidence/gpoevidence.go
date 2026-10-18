package gpoevidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/ldaptransport"
	"github.com/pwnflow/pwnflow/internal/modules"
)

const (
	moduleID       = "ad-gpo-evidence"
	outputRoot     = "Enumeration/ActiveDirectory/GPO"
	maxGPOs        = 128
	maxFilesPerGPO = 256
	maxFilesTotal  = 2048
	maxFileBytes   = 8 << 20
	maxTotalBytes  = 128 << 20
	maxDepth       = 12
	perGPOTimeout  = 2 * time.Minute
)

var guidPattern = regexp.MustCompile(`(?i)^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$`)

type Module struct{}

func (Module) ID() string                     { return moduleID }
func (Module) Name() string                   { return "AD GPO Evidence Collection" }
func (Module) ToolFamily() modules.ToolFamily { return modules.ToolFamilyActiveDirectory }
func (Module) Category() modules.Category     { return modules.CategoryConfigurationAuditing }
func (Module) Tool() string                   { return "AD GPO Evidence" }
func (Module) Protocol() modules.Protocol     { return modules.ProtocolLDAP }
func (Module) Description() string {
	return "Collects bounded LDAP GPO metadata, configured links and original per-GPO SYSVOL evidence without calculating applicability."
}
func (Module) Prerequisites() []string {
	return []string{"Authorized LDAP access and smbclient for SYSVOL evidence"}
}
func (Module) RequiredPrivileges() []string     { return nil }
func (Module) OutputFile() string               { return filepath.Join(outputRoot, "collection.log") }
func (Module) Sensitivity() modules.Sensitivity { return modules.SensitivitySensitive }
func (Module) ReadOnly() bool                   { return true }
func (Module) SecondaryConnections() []string {
	return []string{"configured domain controller LDAP and its validated SYSVOL share only"}
}
func (Module) IncludeInGlobalPlan() (bool, string) {
	return false, "GPO evidence collection is manual-only and may retrieve sensitive original policy files"
}
func (Module) OptionKeys() []string { return nil }

func (m Module) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil || runtime.Target == "" || runtime.Domain == "" || runtime.Username == "" {
		return errors.New("target, domain and username are required")
	}
	if _, err := exec.LookPath("smbclient"); err != nil {
		return fmt.Errorf("smbclient is required for SYSVOL evidence: %w", err)
	}
	return ctx.Err()
}

type attributeValue struct {
	Status string   `json:"status"`
	Values []string `json:"values,omitempty"`
}

type GPO struct {
	GUID         string                    `json:"guid"`
	ObjectGUID   string                    `json:"object_guid,omitempty"`
	OriginalGUID string                    `json:"original_guid,omitempty"`
	DN           string                    `json:"distinguished_name"`
	Attributes   map[string]attributeValue `json:"attributes"`
}

type Link struct {
	GPOGUID  string `json:"gpo_guid,omitempty"`
	Raw      string `json:"raw"`
	Enabled  *bool  `json:"enabled,omitempty"`
	Enforced *bool  `json:"enforced,omitempty"`
	Order    *int   `json:"order,omitempty"`
	Error    string `json:"error,omitempty"`
}

type LinkSource struct {
	DN         string         `json:"distinguished_name"`
	ObjectType string         `json:"object_type"`
	RawGLink   attributeValue `json:"gPLink"`
	RawOptions attributeValue `json:"gPOptions"`
	Links      []Link         `json:"links"`
}

type Collection struct {
	Status      string `json:"status"`
	Detail      string `json:"detail,omitempty"`
	ObjectCount int    `json:"object_count"`
	PageSize    int    `json:"page_size"`
	Pages       int    `json:"pages"`
	SourceDC    string `json:"source_dc"`
	CollectedAt string `json:"collected_at"`
}

type Metadata struct {
	SchemaVersion int        `json:"schema_version"`
	Domain        string     `json:"domain"`
	SourceDC      string     `json:"source_dc"`
	ExecutionHint string     `json:"execution_hint,omitempty"`
	Requested     []string   `json:"requested_attributes"`
	Collection    Collection `json:"collection"`
	GPOs          []GPO      `json:"gpos"`
}

type LinksDocument struct {
	SchemaVersion int          `json:"schema_version"`
	Domain        string       `json:"domain"`
	SourceDC      string       `json:"source_dc"`
	Collection    Collection   `json:"collection"`
	Sources       []LinkSource `json:"sources"`
}

type ManifestFile struct {
	GPOGUID       string `json:"gpo_guid"`
	Domain        string `json:"domain"`
	SourceDC      string `json:"source_dc"`
	SourceShare   string `json:"source_share"`
	SourcePath    string `json:"source_relative_path"`
	StoredPath    string `json:"stored_relative_path,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	Bytes         int64  `json:"bytes,omitempty"`
	Status        string `json:"status"`
	ErrorCategory string `json:"error_category,omitempty"`
	ExecutionID   string `json:"execution_id,omitempty"`
	CollectedAt   string `json:"collected_at"`
}

type GPOSummary struct {
	GPOGUID            string `json:"gpo_guid"`
	ExpectedPath       string `json:"expected_directory"`
	Listed             int    `json:"listed_files"`
	Retrieved          int    `json:"retrieved_files"`
	Denied             int    `json:"denied_files"`
	Missing            int    `json:"missing_files"`
	Failed             int    `json:"failed_files"`
	Limited            int    `json:"limited_files"`
	Status             string `json:"status"`
	Stage              string `json:"stage,omitempty"`
	ErrorCategory      string `json:"error_category,omitempty"`
	ErrorSummary       string `json:"error_summary,omitempty"`
	SourcePath         string `json:"source_path,omitempty"`
	RetrievalAttempted bool   `json:"retrieval_attempted"`
	ListingCompleted   bool   `json:"listing_completed"`
}

type Manifest struct {
	SchemaVersion int              `json:"schema_version"`
	Domain        string           `json:"domain"`
	SourceDC      string           `json:"source_dc"`
	ExecutionHint string           `json:"execution_hint,omitempty"`
	Limits        map[string]int64 `json:"limits"`
	Files         []ManifestFile   `json:"files"`
	GPOs          []GPOSummary     `json:"gpos"`
}

func (m Module) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	if err := m.Check(ctx, runtime); err != nil {
		return err
	}
	root := filepath.Join(runtime.ResultsRoot, outputRoot)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	metadata, links, gpos, err := collectLDAP(ctx, runtime)
	if err != nil {
		metadata.Collection.Status = statusFor(err)
		metadata.Collection.Detail = safeError(err)
	}
	if err := writeJSON(filepath.Join(root, "GPO_metadata.json"), metadata); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(root, "GPO_links.json"), links); err != nil {
		return err
	}
	manifest := Manifest{SchemaVersion: 1, Domain: runtime.Domain, SourceDC: runtime.Target, ExecutionHint: "assigned by execution lifecycle", Limits: map[string]int64{"max_gpos": maxGPOs, "max_files_per_gpo": maxFilesPerGPO, "max_files_total": maxFilesTotal, "max_file_bytes": maxFileBytes, "max_total_bytes": maxTotalBytes, "max_depth": maxDepth}, Files: []ManifestFile{}, GPOs: []GPOSummary{}}
	if err == nil {
		collectSYSVOL(ctx, runtime, root, gpos, &manifest)
	}
	if err := writeJSON(filepath.Join(root, "GPO_evidence_manifest.json"), manifest); err != nil {
		return err
	}
	var logBuilder strings.Builder
	fmt.Fprintf(&logBuilder, "GPO evidence collection: LDAP=%s GPOs=%d files=%d status=%s\n", metadata.Collection.Status, len(gpos), len(manifest.Files), manifestStatus(manifest))
	for _, summary := range manifest.GPOs {
		fmt.Fprintf(&logBuilder, "GPO %s:\n  LDAP metadata: collected\n  SYSVOL listing: %s\n  Stage: %s\n  Reason: %s\n  Files retrieved: %d\n", summary.GPOGUID, listingOutcome(summary), valueOrUnknown(summary.Stage), valueOrUnknown(summary.ErrorSummary), summary.Retrieved)
	}
	log := logBuilder.String()
	if err := os.WriteFile(filepath.Join(root, "collection.log"), []byte(log), 0o600); err != nil {
		return err
	}
	if _, err := sink.Write([]byte(log)); err != nil {
		return err
	}
	if err != nil {
		return err
	}
	if manifestStatus(manifest) != "complete" {
		return fmt.Errorf("GPO evidence collection partial: %s", manifestStatus(manifest))
	}
	return ctx.Err()
}

// WriteSummary publishes a secret-free operator summary after the execution
// lifecycle assigns the durable execution ID.
func WriteSummary(resultsRoot, domain string, executionID int64) error {
	path := filepath.Join(resultsRoot, outputRoot, "GPO_evidence_manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	var report strings.Builder
	fmt.Fprintf(&report, "PwnFlow AD Group Policy Evidence Inventory\nDomain: %s\nProducing execution ID: %d\n\n", safeSummary(domain), executionID)
	fmt.Fprintf(&report, "GPOs discovered: %d\nSYSVOL files retrieved: %d\nSYSVOL files with limitations: %d\nOverall evidence status: %s\n\n", len(manifest.GPOs), countManifestStatus(manifest.Files, "", "complete"), len(manifest.Files)-countManifestStatus(manifest.Files, "", "complete"), manifestStatus(manifest))
	report.WriteString("Per-GPO status:\n")
	for _, gpo := range manifest.GPOs {
		fmt.Fprintf(&report, "- %s: %s (listed=%d retrieved=%d failed=%d limited=%d)\n", gpo.GPOGUID, gpo.Status, gpo.Listed, gpo.Retrieved, gpo.Failed, gpo.Limited)
	}
	report.WriteString("\nAuthoritative evidence:\n- Enumeration/ActiveDirectory/GPO/GPO_metadata.json\n- Enumeration/ActiveDirectory/GPO/GPO_links.json\n- Enumeration/ActiveDirectory/GPO/GPO_evidence_manifest.json\n- Enumeration/ActiveDirectory/GPO/SYSVOL/<GPO-GUID>/\n\nLimitations:\n- Configured links are not proof of applicability.\n- Effective GPO applicability and client-side application were not verified.\n- WMI filter runtime results and effective security filtering were not calculated.\n")
	return atomicWrite(filepath.Join(resultsRoot, "GPO_EVIDENCE_SUMMARY.txt"), []byte(report.String()))
}

func safeSummary(value string) string {
	return strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 32 {
			return ' '
		}
		return r
	}, value)), " ")
}
func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp := path + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func collectLDAP(ctx context.Context, runtime *modules.Runtime) (Metadata, LinksDocument, []GPO, error) {
	attrs := []string{"objectGUID", "cn", "displayName", "distinguishedName", "gPCFileSysPath", "gPCMachineExtensionNames", "gPCUserExtensionNames", "flags", "versionNumber", "whenCreated", "whenChanged", "gPCWQLFilter"}
	meta := Metadata{SchemaVersion: 1, Domain: runtime.Domain, SourceDC: runtime.Target, Requested: attrs, GPOs: []GPO{}, Collection: Collection{Status: "complete", PageSize: 500, SourceDC: runtime.Target, CollectedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	links := LinksDocument{SchemaVersion: 1, Domain: runtime.Domain, SourceDC: runtime.Target, Sources: []LinkSource{}, Collection: meta.Collection}
	gpoBase := "CN=Policies,CN=System," + domainDN(runtime.Domain)
	gpoReq := ldap.NewSearchRequest(gpoBase, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=groupPolicyContainer)", attrs, nil)
	gpoResult, _, err := ldaptransport.Search(ctx, ldapConfig(runtime), runtime.LDAPOptions, gpoReq)
	if err != nil {
		return meta, links, nil, err
	}
	if len(gpoResult.Entries) > maxGPOs {
		meta.Collection.Status = "partial"
		meta.Collection.Detail = "maximum GPO count reached"
		gpoResult.Entries = gpoResult.Entries[:maxGPOs]
	}
	for _, entry := range gpoResult.Entries {
		gpo := parseGPO(entry, attrs)
		meta.GPOs = append(meta.GPOs, gpo)
	}
	meta.Collection.ObjectCount = len(meta.GPOs)
	linkAttrs := []string{"distinguishedName", "objectClass", "gPLink", "gPOptions"}
	linkReq := ldap.NewSearchRequest(domainDN(runtime.Domain), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(|(objectClass=domainDNS)(objectClass=organizationalUnit)(objectClass=site))", linkAttrs, nil)
	linkResult, _, linkErr := ldaptransport.Search(ctx, ldapConfig(runtime), runtime.LDAPOptions, linkReq)
	if linkErr != nil {
		meta.Collection.Status = "partial"
		meta.Collection.Detail = safeError(linkErr)
		links.Collection.Status = statusFor(linkErr)
		links.Collection.Detail = safeError(linkErr)
	} else {
		for _, entry := range linkResult.Entries {
			links.Sources = append(links.Sources, parseLinkSource(entry))
		}
	}
	links.Collection.ObjectCount = len(links.Sources)
	return meta, links, meta.GPOs, nil
}

func parseGPO(entry *ldap.Entry, attrs []string) GPO {
	// objectGUID identifies the directory object that stores the GPC. The
	// policy/SYSVOL GUID is the textual CN and must be used for the policy path.
	guid := normalizeGUID(entry.GetAttributeValue("cn"))
	objectGUID := entry.GetAttributeValue("objectGUID")
	if raw := entry.GetRawAttributeValue("objectGUID"); len(raw) > 0 {
		objectGUID = formatGUID(raw)
	}
	gpo := GPO{GUID: guid, ObjectGUID: objectGUID, OriginalGUID: entry.GetAttributeValue("cn"), DN: entry.DN, Attributes: map[string]attributeValue{}}
	for _, name := range attrs {
		values := entry.GetAttributeValues(name)
		status := "missing"
		if len(values) > 0 {
			status = "present"
			if len(values) == 1 && values[0] == "" {
				status = "empty"
			}
		}
		gpo.Attributes[name] = attributeValue{Status: status, Values: values}
	}
	return gpo
}

func parseLinkSource(entry *ldap.Entry) LinkSource {
	classes := entry.GetAttributeValues("objectClass")
	objectType := "unknown"
	for _, class := range classes {
		if class == "domainDNS" {
			objectType = "domain"
		}
		if class == "organizationalUnit" {
			objectType = "ou"
		}
		if class == "site" {
			objectType = "site"
		}
	}
	raw := entry.GetAttributeValue("gPLink")
	source := LinkSource{DN: entry.DN, ObjectType: objectType, RawGLink: rawAttribute(entry, "gPLink"), RawOptions: rawAttribute(entry, "gPOptions"), Links: parseLinks(raw)}
	return source
}

func rawAttribute(entry *ldap.Entry, name string) attributeValue {
	values := entry.GetAttributeValues(name)
	status := "missing"
	if len(values) > 0 {
		status = "present"
		if values[0] == "" {
			status = "empty"
		}
	}
	return attributeValue{Status: status, Values: values}
}

func parseLinks(raw string) []Link {
	if strings.TrimSpace(raw) == "" {
		return []Link{}
	}
	parts := strings.Split(raw, "]")
	links := make([]Link, 0, len(parts))
	order := 0
	for _, part := range parts {
		start := strings.Index(part, "LDAP://")
		if start < 0 {
			continue
		}
		token := strings.TrimPrefix(part[start:], "LDAP://")
		flags := 0
		if semi := strings.LastIndex(token, ";"); semi >= 0 {
			flags, _ = strconv.Atoi(token[semi+1:])
			token = token[:semi]
		}
		guid := extractGUID(token)
		link := Link{GPOGUID: guid, Raw: part, Order: intPtr(order)}
		order++
		enabled := flags&1 == 0
		enforced := flags&2 != 0
		link.Enabled, link.Enforced = &enabled, &enforced
		if guid == "" {
			link.Error = "referenced value did not contain a valid GPO GUID"
		}
		links = append(links, link)
	}
	return links
}

func collectSYSVOL(ctx context.Context, runtime *modules.Runtime, root string, gpos []GPO, manifest *Manifest) {
	if !validDomain(runtime.Domain) {
		for _, gpo := range gpos {
			manifest.GPOs = append(manifest.GPOs, failedSummary(gpo.GUID, "validation", "invalid domain", "", false, false))
		}
		return
	}
	authPath, err := writeAuthFile(runtime)
	if err != nil {
		for _, gpo := range gpos {
			manifest.GPOs = append(manifest.GPOs, failedSummary(gpo.GUID, "authentication", safeError(err), "", false, false))
		}
		return
	}
	defer os.Remove(authPath)
	var totalFiles, totalBytes int
	for _, gpo := range gpos {
		if err := ctx.Err(); err != nil {
			manifest.GPOs = append(manifest.GPOs, failedSummary(gpo.GUID, "cancellation", "collection cancelled", "", false, false))
			return
		}
		summary := GPOSummary{GPOGUID: gpo.GUID, ExpectedPath: `SYSVOL/` + runtime.Domain + `/Policies/` + bracedGUID(gpo.GUID)}
		if !guidPattern.MatchString(gpo.GUID) {
			summary.Status, summary.Stage, summary.ErrorCategory, summary.ErrorSummary = "failed", "guid_validation", "invalid_gpo_guid", "LDAP GPO identifier is not a valid GUID"
			manifest.GPOs = append(manifest.GPOs, summary)
			continue
		}
		remotePath, pathErr := validatedPolicyRelativePath(gpo, runtime.Domain)
		if pathErr != nil {
			summary.Status, summary.Stage, summary.ErrorCategory, summary.ErrorSummary = "failed", "path_validation", "invalid_or_mismatched_gpo_path", safeError(pathErr)
			manifest.GPOs = append(manifest.GPOs, summary)
			continue
		}
		tempRoot, tempErr := os.MkdirTemp("", "pwnflow-gpo-")
		if tempErr != nil {
			summary.Status, summary.Stage, summary.ErrorCategory, summary.ErrorSummary = "failed", "staging", "process_execution_failure", safeError(tempErr)
			manifest.GPOs = append(manifest.GPOs, summary)
			continue
		}
		operationCtx, cancel := context.WithTimeout(ctx, perGPOTimeout)
		command := fmt.Sprintf("cd %s; recurse; prompt OFF; mget *", remotePath)
		cmd := exec.CommandContext(operationCtx, "smbclient", "//"+runtime.Target+"/SYSVOL", "-A", authPath, "-c", command)
		cmd.Dir = tempRoot
		output, runErr := cmd.CombinedOutput()
		summary.RetrievalAttempted, summary.SourcePath = true, remotePath
		summary.Stage, summary.ErrorCategory, summary.ErrorSummary, summary.ListingCompleted = retrievalDiagnostic(operationCtx, runErr, output)
		gpoRoot := filepath.Join(tempRoot, runtime.Domain, "Policies", gpo.GUID)
		if _, statErr := os.Stat(gpoRoot); os.IsNotExist(statErr) {
			gpoRoot = tempRoot
		}
		storedRoot := filepath.Join(root, "SYSVOL", gpo.GUID)
		_ = os.MkdirAll(storedRoot, 0o700)
		walkErr := publishTree(ctx, gpoRoot, storedRoot, runtime, gpo.GUID, manifest, &totalFiles, &totalBytes)
		cancel()
		_ = os.RemoveAll(tempRoot)
		summary.Listed = countManifest(manifest.Files, gpo.GUID)
		summary.Retrieved = countManifestStatus(manifest.Files, gpo.GUID, "complete")
		summary.Limited = countManifestStatus(manifest.Files, gpo.GUID, "limited")
		summary.Failed = countManifestStatus(manifest.Files, gpo.GUID, "failed")
		if errors.Is(operationCtx.Err(), context.DeadlineExceeded) {
			summary.Status = "timed_out"
		} else if runErr != nil && summary.Retrieved == 0 {
			summary.Status = "failed"
		} else if walkErr != nil || summary.Limited > 0 || runErr != nil {
			summary.Status = "partial"
		} else if summary.Retrieved == 0 {
			summary.Status = "partial"
			summary.Stage, summary.ErrorCategory, summary.ErrorSummary, summary.ListingCompleted = "directory_listing", "empty_directory_listing", "directory listing completed with no files", true
		} else {
			summary.Status = "complete"
		}
		manifest.GPOs = append(manifest.GPOs, summary)
	}
}

func validatedPolicyRelativePath(gpo GPO, domain string) (string, error) {
	expected := domain + "/Policies/" + bracedGUID(gpo.GUID)
	attribute, ok := gpo.Attributes["gPCFileSysPath"]
	if !ok || len(attribute.Values) == 0 || strings.TrimSpace(attribute.Values[0]) == "" {
		return expected, nil
	}
	raw := strings.ReplaceAll(strings.TrimSpace(attribute.Values[0]), `\`, "/")
	raw = strings.TrimPrefix(raw, "//")
	parts := strings.Split(strings.Trim(raw, "/"), "/")
	if len(parts) != 5 || !strings.EqualFold(parts[0], domain) || !strings.EqualFold(parts[1], "sysvol") || !strings.EqualFold(parts[2], domain) || !strings.EqualFold(parts[3], "policies") || !strings.EqualFold(normalizeGUID(parts[4]), gpo.GUID) {
		return "", fmt.Errorf("gPCFileSysPath is outside the domain SYSVOL Policies root")
	}
	return expected, nil
}

func bracedGUID(value string) string {
	return "{" + normalizeGUID(value) + "}"
}

func failedSummary(guid, stage, detail, sourcePath string, attempted, listed bool) GPOSummary {
	return GPOSummary{GPOGUID: guid, ExpectedPath: "", Status: "failed", Stage: stage, ErrorCategory: classifyErrorCategory(detail), ErrorSummary: safeError(errors.New(detail)), SourcePath: sourcePath, RetrievalAttempted: attempted, ListingCompleted: listed}
}

func listingOutcome(summary GPOSummary) string {
	if summary.ListingCompleted {
		return "completed"
	}
	return "failed"
}

func valueOrUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func retrievalDiagnostic(operationCtx context.Context, runErr error, output []byte) (stage, category, summary string, listingCompleted bool) {
	if errors.Is(operationCtx.Err(), context.DeadlineExceeded) {
		return "directory_listing", "network_timeout", "SMB operation exceeded per-GPO timeout", false
	}
	if errors.Is(operationCtx.Err(), context.Canceled) {
		return "directory_listing", "cancellation", "SMB operation cancelled", false
	}
	diagnostic := safeError(errors.New(string(output)))
	if runErr == nil {
		return "directory_listing", "", "directory listing completed", true
	}
	category = classifyErrorCategory(diagnostic)
	return "directory_lookup", category, diagnosticOrFallback(diagnostic, runErr), false
}

func diagnosticOrFallback(diagnostic string, err error) string {
	if diagnostic != "" {
		if len(diagnostic) > 500 {
			return diagnostic[:500] + "..."
		}
		return diagnostic
	}
	return safeError(err)
}

func classifyErrorCategory(detail string) string {
	text := strings.ToLower(detail)
	switch {
	case strings.Contains(text, "logon failure"), strings.Contains(text, "nt_status_logon_failure"), strings.Contains(text, "authentication"):
		return "authentication_rejected"
	case strings.Contains(text, "access denied"), strings.Contains(text, "permission denied"), strings.Contains(text, "nt_status_access_denied"):
		return "permission_denied"
	case strings.Contains(text, "bad network name"), strings.Contains(text, "connection failed"), strings.Contains(text, "no route"):
		return "share_unavailable"
	case strings.Contains(text, "object name not found"), strings.Contains(text, "does not exist"), strings.Contains(text, "nt_status_object_name_not_found"):
		return "directory_not_found"
	case strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return "network_timeout"
	default:
		return "process_execution_failure"
	}
}

func writeAuthFile(runtime *modules.Runtime) (string, error) {
	file, err := os.CreateTemp("", "pwnflow-smb-auth-")
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		os.Remove(path)
		return "", err
	}
	_, err = fmt.Fprintf(file, "username = %s\npassword = %s\ndomain = %s\n", runtime.Username, runtime.Password, runtime.Domain)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
	}
	return path, err
}

func publishTree(ctx context.Context, sourceRoot, storedRoot string, runtime *modules.Runtime, guid string, manifest *Manifest, totalFiles, totalBytes *int) error {
	return filepath.WalkDir(sourceRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != sourceRoot && depth(sourceRoot, path) > maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return err
		}
		if err := validateRelativePath(rel); err != nil {
			return err
		}
		item := ManifestFile{GPOGUID: guid, Domain: runtime.Domain, SourceDC: runtime.Target, SourceShare: "SYSVOL", SourcePath: filepath.ToSlash(rel), CollectedAt: time.Now().UTC().Format(time.RFC3339Nano), Status: "complete"}
		if *totalFiles >= maxFilesTotal || countManifest(manifest.Files, guid) >= maxFilesPerGPO {
			item.Status, item.ErrorCategory = "limited", "file_count_limit"
			manifest.Files = append(manifest.Files, item)
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			item.Status, item.ErrorCategory = "failed", "stat"
			manifest.Files = append(manifest.Files, item)
			return nil
		}
		if info.Size() > maxFileBytes {
			item.Status, item.ErrorCategory = "limited", "file_size_limit"
			manifest.Files = append(manifest.Files, item)
			return nil
		}
		if *totalBytes+int(info.Size()) > maxTotalBytes {
			item.Status, item.ErrorCategory = "limited", "total_size_limit"
			manifest.Files = append(manifest.Files, item)
			return nil
		}
		destination := filepath.Join(storedRoot, filepath.FromSlash(filepath.ToSlash(rel)))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			item.Status, item.ErrorCategory = "failed", "mkdir"
			manifest.Files = append(manifest.Files, item)
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			item.Status, item.ErrorCategory = "failed", "read"
			manifest.Files = append(manifest.Files, item)
			return nil
		}
		hash, size := hashBytes(data)
		temp := destination + ".tmp"
		if err := os.WriteFile(temp, data, 0o600); err != nil {
			item.Status, item.ErrorCategory = "failed", "write"
			manifest.Files = append(manifest.Files, item)
			return nil
		}
		if err := os.Rename(temp, destination); err != nil {
			os.Remove(temp)
			item.Status, item.ErrorCategory = "failed", "publish"
			manifest.Files = append(manifest.Files, item)
			return nil
		}
		item.StoredPath, item.SHA256, item.Bytes = filepath.ToSlash(filepath.Join(outputRoot, "SYSVOL", guid, rel)), hash, size
		manifest.Files = append(manifest.Files, item)
		*totalFiles++
		*totalBytes += int(size)
		return nil
	})
}

func depth(root, path string) int {
	rel, _ := filepath.Rel(root, path)
	if rel == "." {
		return 0
	}
	return strings.Count(filepath.ToSlash(rel), "/") + 1
}
func countManifest(files []ManifestFile, guid string) int {
	count := 0
	for _, file := range files {
		if guid == "" || file.GPOGUID == guid {
			count++
		}
	}
	return count
}
func countManifestStatus(files []ManifestFile, guid, status string) int {
	count := 0
	for _, file := range files {
		if file.GPOGUID == guid && file.Status == status {
			count++
		}
	}
	return count
}
func validDomain(domain string) bool {
	if domain == "" || strings.ContainsAny(domain, `/\\`) {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || strings.Trim(label, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") != "" {
			return false
		}
	}
	return true
}

func normalizeGUID(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "{}")
	return strings.ToUpper(value)
}
func extractGUID(value string) string {
	start := strings.LastIndex(value, "{")
	end := strings.LastIndex(value, "}")
	if start < 0 || end <= start {
		return ""
	}
	candidate := value[start : end+1]
	if !guidPattern.MatchString(candidate) {
		return ""
	}
	return normalizeGUID(candidate)
}
func formatGUID(raw []byte) string {
	if len(raw) != 16 {
		return ""
	}
	return fmt.Sprintf("%08X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X", uint32(raw[0])|uint32(raw[1])<<8|uint32(raw[2])<<16|uint32(raw[3])<<24, raw[5], raw[4], raw[7], raw[6], raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15])
}
func intPtr(value int) *int { return &value }
func domainDN(domain string) string {
	parts := strings.Split(domain, ".")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			out = append(out, "DC="+ldap.EscapeFilter(strings.TrimSpace(part)))
		}
	}
	return strings.Join(out, ",")
}
func ldapConfig(runtime *modules.Runtime) config.Config {
	return config.Config{Target: runtime.Target, Domain: runtime.Domain, Username: runtime.Username, Password: runtime.Password}
}
func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temp := path + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temp, path)
}
func statusFor(err error) string {
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "timeout") {
		return "timed_out"
	}
	if strings.Contains(text, "denied") || strings.Contains(text, "access") {
		return "permission_denied"
	}
	return "failed"
}
func safeError(err error) string {
	return strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 32 {
			return ' '
		}
		return r
	}, err.Error())), " ")
}
func manifestStatus(manifest Manifest) string {
	if len(manifest.GPOs) == 0 {
		return "unknown"
	}
	for _, gpo := range manifest.GPOs {
		if gpo.Status != "complete" {
			return "partial"
		}
	}
	return "complete"
}

// The following helpers are kept small and independently testable. They are used
// by the future SMB adapter once the repository has a native authenticated SMB
// transport; this checkpoint deliberately never guesses remote file bytes.
func validateRelativePath(value string) error {
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return fmt.Errorf("unsafe relative path %q", value)
		}
	}
	clean := filepath.ToSlash(filepath.Clean(value))
	if clean == "." || strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") || strings.Contains(clean, ":") {
		return fmt.Errorf("unsafe relative path %q", value)
	}
	return nil
}
func hashBytes(data []byte) (string, int64) {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), int64(len(data))
}
func copyBounded(ctx context.Context, dst io.Writer, src io.Reader, limit int64) (int64, error) {
	return io.Copy(dst, io.LimitReader(src, limit+1))
}
