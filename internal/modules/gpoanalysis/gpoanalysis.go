package gpoanalysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	outputRoot    = "Enumeration/ActiveDirectory/GPO"
	schemaVersion = 1
)

type inputRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Status string `json:"status"`
}

type Attribute struct {
	Status string   `json:"status"`
	Values []string `json:"values,omitempty"`
}

type metadataDocument struct {
	Domain   string `json:"domain"`
	SourceDC string `json:"source_dc"`
	GPOs     []struct {
		GUID         string               `json:"guid"`
		ObjectGUID   string               `json:"object_guid"`
		OriginalGUID string               `json:"original_guid"`
		DN           string               `json:"distinguished_name"`
		Attributes   map[string]Attribute `json:"attributes"`
	} `json:"gpos"`
}

type linksDocument struct {
	Sources []struct {
		DN         string    `json:"distinguished_name"`
		ObjectType string    `json:"object_type"`
		RawOptions Attribute `json:"gPOptions"`
		Links      []struct {
			GPOGUID  string `json:"gpo_guid"`
			Raw      string `json:"raw"`
			Enabled  *bool  `json:"enabled"`
			Enforced *bool  `json:"enforced"`
			Order    *int   `json:"order"`
			Error    string `json:"error"`
		} `json:"links"`
	} `json:"sources"`
}

type manifestDocument struct {
	GPOs []struct {
		GPOGUID   string `json:"gpo_guid"`
		Status    string `json:"status"`
		Retrieved int    `json:"retrieved_files"`
		Failed    int    `json:"failed_files"`
		Limited   int    `json:"limited_files"`
	} `json:"gpos"`
	Files []struct {
		GPOGUID    string `json:"gpo_guid"`
		SourcePath string `json:"source_relative_path"`
		StoredPath string `json:"stored_relative_path"`
		SHA256     string `json:"sha256"`
		Bytes      int64  `json:"bytes"`
		Status     string `json:"status"`
	} `json:"files"`
}

type FileRecord struct {
	Path       string `json:"source_relative_path"`
	StoredPath string `json:"stored_relative_path,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Bytes      int64  `json:"bytes,omitempty"`
	Status     string `json:"status"`
	Category   string `json:"category"`
	Section    string `json:"section"`
}

type Relationship struct {
	GPOGUID           string `json:"gpo_guid"`
	GPOName           string `json:"gpo_name,omitempty"`
	SourceDN          string `json:"source_dn"`
	SourceType        string `json:"source_type"`
	TargetContainerDN string `json:"target_container_dn,omitempty"`
	Enabled           *bool  `json:"enabled,omitempty"`
	Enforced          *bool  `json:"enforced,omitempty"`
	Order             *int   `json:"link_order,omitempty"`
	Classification    string `json:"classification"`
	Applicability     string `json:"applicability"`
	Explanation       string `json:"explanation"`
	SourceArtifact    string `json:"source_artifact"`
}

type GPOAnalysis struct {
	GUID               string               `json:"gpo_guid"`
	ObjectGUID         string               `json:"directory_object_guid,omitempty"`
	DisplayName        string               `json:"display_name,omitempty"`
	DN                 string               `json:"distinguished_name"`
	FileSystemPath     string               `json:"gpc_file_sys_path,omitempty"`
	Attributes         map[string]Attribute `json:"attributes"`
	SYSVOLStatus       string               `json:"sysvol_status"`
	SYSVOLFiles        []FileRecord         `json:"sysvol_files"`
	WMIReference       Attribute            `json:"wmi_filter_reference"`
	WMIStatus          string               `json:"wmi_filter_status"`
	SecurityFiltering  string               `json:"security_filtering"`
	PrincipalPlacement string               `json:"principal_placement"`
	EvidencePaths      []string             `json:"evidence_paths"`
}

type Analysis struct {
	SchemaVersion                int            `json:"schema_version"`
	Domain                       string         `json:"domain"`
	SourceDC                     string         `json:"source_dc"`
	CollectionExecutionID        int64          `json:"collection_execution_id"`
	SupportingExecutionIDs       []int64        `json:"supporting_execution_ids"`
	AnalyzedAt                   string         `json:"analyzed_at"`
	Inputs                       []inputRef     `json:"inputs"`
	GPOs                         []GPOAnalysis  `json:"gpos"`
	Links                        []Relationship `json:"configured_relationships"`
	Limitations                  []string       `json:"limitations"`
	EffectiveApplicationVerified bool           `json:"effective_application_verified"`
}

// WriteArtifacts performs only local parsing of the completed GPO evidence bundle.
// It intentionally has no Runtime or network dependency.
func WriteArtifacts(resultsRoot, domain string, collectionExecutionID int64, now time.Time) error {
	directory := filepath.Join(resultsRoot, outputRoot)
	metadataPath := filepath.Join(directory, "GPO_metadata.json")
	linksPath := filepath.Join(directory, "GPO_links.json")
	manifestPath := filepath.Join(directory, "GPO_evidence_manifest.json")
	metadataData, err := os.ReadFile(metadataPath)
	if err != nil {
		return err
	}
	linksData, err := os.ReadFile(linksPath)
	if err != nil {
		return err
	}
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var metadata metadataDocument
	var links linksDocument
	var manifest manifestDocument
	if err := json.Unmarshal(metadataData, &metadata); err != nil {
		return fmt.Errorf("GPO metadata: %w", err)
	}
	if err := json.Unmarshal(linksData, &links); err != nil {
		return fmt.Errorf("GPO links: %w", err)
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("GPO manifest: %w", err)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	analysis := Analysis{
		SchemaVersion: schemaVersion, Domain: domain, SourceDC: metadata.SourceDC,
		CollectionExecutionID: collectionExecutionID, SupportingExecutionIDs: []int64{},
		AnalyzedAt: now.UTC().Format(time.RFC3339Nano), EffectiveApplicationVerified: false,
		Inputs: []inputRef{inputReference(metadataPath, metadataData), inputReference(linksPath, linksData), inputReference(manifestPath, manifestData)},
		Limitations: []string{
			"Configured links are not proof of effective client-side application.",
			"Security filtering, group expansion, WMI runtime results, loopback processing and replication state were not evaluated.",
			"No user or computer placement evidence was correlated in this local analysis; principal applicability remains unknown.",
		},
	}
	manifestByGUID := make(map[string]struct {
		Status string
		Files  []FileRecord
	})
	for _, summary := range manifest.GPOs {
		manifestByGUID[strings.ToUpper(summary.GPOGUID)] = struct {
			Status string
			Files  []FileRecord
		}{Status: summary.Status}
	}
	for _, file := range manifest.Files {
		entry := manifestByGUID[strings.ToUpper(file.GPOGUID)]
		status := file.Status
		if status == "complete" && file.StoredPath != "" && file.SHA256 != "" {
			storedPath := filepath.Join(resultsRoot, filepath.FromSlash(file.StoredPath))
			storedData, readErr := os.ReadFile(storedPath)
			if readErr != nil || hashBytes(storedData) != strings.ToLower(file.SHA256) {
				status = "hash_mismatch"
				analysis.Limitations = append(analysis.Limitations, "A preserved SYSVOL file did not match its manifest hash; that file is not treated as trustworthy.")
			}
		}
		entry.Files = append(entry.Files, FileRecord{Path: file.SourcePath, StoredPath: file.StoredPath, SHA256: file.SHA256, Bytes: file.Bytes, Status: status, Category: fileCategory(file.SourcePath), Section: fileSection(file.SourcePath)})
		manifestByGUID[strings.ToUpper(file.GPOGUID)] = entry
	}
	gpoNames := make(map[string]string)
	knownGPOs := make(map[string]bool)
	for _, gpo := range metadata.GPOs {
		name := first(gpo.Attributes["displayName"].Values)
		guid := strings.ToUpper(strings.Trim(gpo.GUID, "{}"))
		gpoNames[guid] = name
		knownGPOs[guid] = true
		entry := manifestByGUID[guid]
		wmi := gpo.Attributes["gPCWQLFilter"]
		wmiStatus := "not_present"
		if wmi.Status == "present" && len(wmi.Values) > 0 && strings.TrimSpace(wmi.Values[0]) != "" {
			wmiStatus = "reference_unresolved"
		}
		analysis.GPOs = append(analysis.GPOs, GPOAnalysis{GUID: guid, ObjectGUID: gpo.ObjectGUID, DisplayName: name, DN: gpo.DN, FileSystemPath: first(gpo.Attributes["gPCFileSysPath"].Values), Attributes: gpo.Attributes, SYSVOLStatus: valueOr(entry.Status, "unknown"), SYSVOLFiles: entry.Files, WMIReference: wmi, WMIStatus: wmiStatus, SecurityFiltering: "not_fully_evaluated", PrincipalPlacement: "unknown", EvidencePaths: []string{metadataPath, linksPath, manifestPath, filepath.Join(directory, "SYSVOL", guid)}})
	}
	for _, source := range links.Sources {
		for _, link := range source.Links {
			guid := strings.ToUpper(strings.Trim(link.GPOGUID, "{}"))
			classification, applicability, explanation := linkClassification(link.Enabled, link.Enforced, link.Error)
			if link.Error == "" && !knownGPOs[guid] {
				classification, applicability, explanation = "unresolved", "indeterminate", "The configured link references a GPO that was not present in the collected metadata."
			}
			analysis.Links = append(analysis.Links, Relationship{GPOGUID: guid, GPOName: gpoNames[guid], SourceDN: source.DN, SourceType: source.ObjectType, Enabled: link.Enabled, Enforced: link.Enforced, Order: link.Order, Classification: classification, Applicability: applicability, Explanation: explanation, SourceArtifact: linksPath})
			if source.ObjectType == "ou" {
				for _, child := range links.Sources {
					if child.ObjectType != "ou" || strings.EqualFold(child.DN, source.DN) || !isChildDN(child.DN, source.DN) {
						continue
					}
					childBlocks := optionBlocksInheritance(child.RawOptions)
					classification, applicability, explanation = "configured_inherited", "potentially_applicable", "Configured on a parent OU; effective filtering and client-side application remain unverified."
					if childBlocks && !boolValue(link.Enforced) {
						classification, applicability, explanation = "inheritance_blocked", "excluded_by_known_configuration", "Child OU gPOptions indicates block inheritance and the link is not enforced."
					}
					if boolValue(link.Enforced) && childBlocks {
						classification, applicability, explanation = "inheritance_exception", "potentially_applicable", "The link is enforced, so configured inheritance may cross the child OU block; effective application remains unverified."
					}
					analysis.Links = append(analysis.Links, Relationship{GPOGUID: guid, GPOName: gpoNames[guid], SourceDN: source.DN, SourceType: source.ObjectType, TargetContainerDN: child.DN, Enabled: link.Enabled, Enforced: link.Enforced, Order: link.Order, Classification: classification, Applicability: applicability, Explanation: explanation, SourceArtifact: linksPath})
				}
			}
		}
	}
	sort.Slice(analysis.GPOs, func(i, j int) bool { return analysis.GPOs[i].GUID < analysis.GPOs[j].GUID })
	data, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := atomicWrite(filepath.Join(directory, "GPO_applicability.json"), data); err != nil {
		return err
	}
	return writeReport(resultsRoot, domain, analysis)
}

func inputReference(path string, data []byte) inputRef {
	sum := sha256.Sum256(data)
	return inputRef{Path: path, SHA256: hex.EncodeToString(sum[:]), Status: "complete"}
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
func boolValue(value *bool) bool { return value != nil && *value }
func optionBlocksInheritance(value Attribute) bool {
	for _, item := range value.Values {
		if strings.TrimSpace(item) == "1" {
			return true
		}
	}
	return false
}
func isChildDN(child, parent string) bool {
	return strings.HasSuffix(strings.ToLower(child), ","+strings.ToLower(parent))
}
func linkClassification(enabled, enforced *bool, parseError string) (string, string, string) {
	if parseError != "" {
		return "unresolved", "indeterminate", "Link target could not be parsed from the preserved LDAP value."
	}
	if enabled != nil && !*enabled {
		return "configured_disabled", "excluded_by_known_configuration", "The configured link is disabled."
	}
	return "configured_direct", "confirmed_configured_relationship", "The GPO link is directly configured on this container; effective application is not verified."
}
func fileSection(path string) string {
	lower := strings.ToLower(filepath.ToSlash(path))
	if strings.HasPrefix(lower, "machine/") {
		return "Machine"
	}
	if strings.HasPrefix(lower, "user/") {
		return "User"
	}
	return "root"
}
func fileCategory(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, "gpt.ini"):
		return "GPT.INI"
	case strings.HasSuffix(lower, "registry.pol"):
		return "Registry.pol"
	case strings.HasSuffix(lower, ".xml"):
		return "Group Policy Preferences XML"
	case strings.Contains(lower, "script"):
		return "Scripts"
	case strings.Contains(lower, "security"):
		return "Security template/settings"
	default:
		return "Other policy file"
	}
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

func writeReport(resultsRoot, domain string, analysis Analysis) error {
	var report strings.Builder
	fmt.Fprintf(&report, "PwnFlow AD Group Policy Applicability Summary\nDomain: %s\nCollection execution ID: %d\nAnalysis time: %s\n\n", domain, analysis.CollectionExecutionID, analysis.AnalyzedAt)
	fmt.Fprintf(&report, "GPOs analyzed: %d\nConfigured relationships: %d\nEffective client-side application verified: no\n\n", len(analysis.GPOs), len(analysis.Links))
	counts := map[string]int{}
	for _, link := range analysis.Links {
		counts[link.Classification]++
	}
	report.WriteString("Relationship classifications:\n")
	for _, key := range []string{"configured_direct", "configured_inherited", "configured_disabled", "inheritance_blocked", "inheritance_exception", "unresolved"} {
		if counts[key] > 0 {
			fmt.Fprintf(&report, "- %s: %d\n", key, counts[key])
		}
	}
	report.WriteString("\nGPO inventory:\n")
	for _, gpo := range analysis.GPOs {
		fmt.Fprintf(&report, "- %s — %s | SYSVOL=%s files=%d | WMI=%s | security filtering=%s | principal placement=%s\n", gpo.GUID, valueOr(gpo.DisplayName, "unnamed"), gpo.SYSVOLStatus, len(gpo.SYSVOLFiles), gpo.WMIStatus, gpo.SecurityFiltering, gpo.PrincipalPlacement)
	}
	report.WriteString("\nConfigured links:\n")
	for _, link := range analysis.Links {
		fmt.Fprintf(&report, "- %s -> %s (%s) classification=%s applicability=%s: %s\n", link.SourceDN, valueOr(link.GPOName, link.GPOGUID), link.SourceType, link.Classification, link.Applicability, link.Explanation)
	}
	report.WriteString("\nAuthoritative artifacts:\n- Enumeration/ActiveDirectory/GPO/GPO_metadata.json\n- Enumeration/ActiveDirectory/GPO/GPO_links.json\n- Enumeration/ActiveDirectory/GPO/GPO_evidence_manifest.json\n- Enumeration/ActiveDirectory/GPO/GPO_applicability.json\n- Enumeration/ActiveDirectory/GPO/SYSVOL/<GPO-GUID>/\n\nLimitations:\n")
	for _, limitation := range analysis.Limitations {
		fmt.Fprintf(&report, "- %s\n", limitation)
	}
	report.WriteString("\nConfigured GPO relationships were analyzed from preserved evidence; effective client-side policy application was not verified.\n")
	return atomicWrite(filepath.Join(resultsRoot, "GPO_APPLICABILITY_SUMMARY.txt"), []byte(report.String()))
}
