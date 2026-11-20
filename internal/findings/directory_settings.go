package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/storage"
)

const (
	directorySettingsParserVersion = "directory-settings-v1"
	// DirectorySettingsTool is the source tool name of the AD Directory
	// Settings module.
	DirectorySettingsTool = "AD Directory Settings"
	directorySettingsJSON = "AD_directory_settings.json"
)

// directorySettingsReport mirrors the artifact the AD Directory Settings
// module writes. It is declared here so the Findings engine does not depend on
// the module package.
type directorySettingsReport struct {
	SchemaVersion int    `json:"schema_version"`
	Domain        string `json:"domain"`
	DSHeuristics  struct {
		Status, DN, Value string
	} `json:"ds_heuristics"`
	AnonymousLDAP struct {
		Status      string `json:"status"`
		Endpoint    string `json:"endpoint"`
		UserObjects int    `json:"user_objects"`
	} `json:"anonymous_ldap"`
	DNSZones []struct {
		Name           string `json:"name"`
		DN             string `json:"dn"`
		Partition      string `json:"partition"`
		ACLStatus      string `json:"acl_status"`
		WildcardStatus string `json:"wildcard_status"`
		WildcardRecord bool   `json:"wildcard_record"`
		ACEs           []struct {
			SID       string   `json:"sid"`
			Name      string   `json:"name"`
			Allow     bool     `json:"allow"`
			Rights    []string `json:"rights"`
			Inherited bool     `json:"inherited"`
		} `json:"aces"`
	} `json:"dns_zones"`
}

// directorySettingsArtifact maps the module's text output to the JSON
// artifact written beside it.
func directorySettingsArtifact(outputPath string) string {
	candidate := outputPath
	if !strings.EqualFold(filepath.Base(outputPath), directorySettingsJSON) {
		candidate = filepath.Join(filepath.Dir(outputPath), directorySettingsJSON)
	}
	if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
		return candidate
	}
	return ""
}

// AnalyzeDirectorySettings turns the AD Directory Settings report into
// Findings: anonymous LDAP configuration and behaviour, and who may create or
// change records in the AD-integrated DNS zones.
func AnalyzeDirectorySettings(ctx context.Context, artifactPath string, assessmentID, executionID int64, now time.Time) ([]storage.FindingInput, error) {
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		return nil, err
	}
	var report directorySettingsReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	if report.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported directory-settings schema %d", report.SchemaVersion)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	domain := strings.ToUpper(report.Domain)
	key := func(detector, identity string) string {
		hash := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s\x00%s", assessmentID, detector, strings.ToLower(domain), strings.ToLower(identity))))
		return "directory-settings:" + hex.EncodeToString(hash[:])
	}
	finding := func(detector, identity, typ, title, description, severity, ref string, evidence map[string]any) storage.FindingInput {
		evidence["domain"] = domain
		encoded, _ := json.Marshal(evidence)
		return storage.FindingInput{
			FindingKey: key(detector, identity), AssessmentID: assessmentID, SourceTool: DirectorySettingsTool, SourceExecution: executionID,
			FindingType: typ, Title: title, Description: description, Severity: severity, Confidence: "observed-directory-read",
			AffectedObjectID: strings.ToLower(fallbackString(identity, domain)), AffectedObject: fallbackString(identity, domain),
			EvidenceJSON: string(encoded), ArtifactPath: artifactPath, ArtifactRef: ref, ObservedAt: now, Status: "open", ParserVersion: directorySettingsParserVersion,
		}
	}
	var result []storage.FindingInput
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if value := report.DSHeuristics.Value; report.DSHeuristics.Status == "read" && len(value) >= 7 && value[6] == '2' {
		result = append(result, finding("anonymous-ldap-operations", domain, "ad_domain_config_anonymous_ldap_operations",
			fmt.Sprintf("Anonymous LDAP operations enabled (%s)", domain),
			"dSHeuristics on the Directory Service object sets fLDAPBlockAnonOps (character 7) to 2, which lets unauthenticated clients perform LDAP operations beyond the root DSE. What they can read still depends on object ACLs.",
			"medium", "/ds_heuristics", map[string]any{"ds_heuristics": value, "object": report.DSHeuristics.DN, "account": domain, "flag": "fLDAPBlockAnonOps=2"}))
	}

	switch report.AnonymousLDAP.Status {
	case "objects_readable":
		result = append(result, finding("anonymous-ldap-read", domain, "ad_domain_config_anonymous_ldap_read",
			fmt.Sprintf("Unauthenticated LDAP search returns user objects (%s)", domain),
			fmt.Sprintf("A search without any bind at %s returned user objects. Unauthenticated clients can enumerate accounts over LDAP. Only object classes were requested.", report.AnonymousLDAP.Endpoint),
			"high", "/anonymous_ldap", map[string]any{"endpoint": report.AnonymousLDAP.Endpoint, "status": report.AnonymousLDAP.Status, "user_objects": report.AnonymousLDAP.UserObjects}))
	case "base_readable":
		result = append(result, finding("anonymous-ldap-read", domain, "ad_domain_config_anonymous_ldap_read",
			fmt.Sprintf("Unauthenticated LDAP search answered (%s)", domain),
			fmt.Sprintf("A search without any bind at %s returned the domain head object. Anonymous LDAP operations are permitted; no user objects were returned to the probe, so object ACLs still restrict what is visible.", report.AnonymousLDAP.Endpoint),
			"medium", "/anonymous_ldap", map[string]any{"endpoint": report.AnonymousLDAP.Endpoint, "status": report.AnonymousLDAP.Status}))
	}

	// DNS zones: who may add or change records.
	var createZones, broadWrite []map[string]any
	delegated := map[string][]string{}
	for index, zone := range report.DNSZones {
		if zone.ACLStatus != "read" && zone.ACLStatus != "partial" {
			continue
		}
		denied := map[string]bool{}
		for _, ace := range zone.ACEs {
			if !ace.Allow {
				denied[strings.ToUpper(coreSID(ace.SID))] = true
			}
		}
		var creators, writers []string
		for _, ace := range zone.ACEs {
			if !ace.Allow || denied[strings.ToUpper(coreSID(ace.SID))] {
				continue
			}
			name := fallbackString(ace.Name, wellKnownReaderName(ace.SID))
			class := classifyReader(ace.SID)
			if strings.EqualFold(ace.Name, "DnsAdmins") {
				class = readerPrivileged
			}
			write := hasZoneWrite(ace.Rights)
			switch {
			case class == readerBroad && write:
				writers = append(writers, name+" ("+strings.Join(ace.Rights, ", ")+")")
			case class == readerBroad && containsFold(ace.Rights, "CreateChild"):
				creators = append(creators, name)
			case class == readerDelegated && (write || containsFold(ace.Rights, "CreateChild")):
				delegated[name] = appendUniqueString(delegated[name], zone.Name)
			}
		}
		ref := fmt.Sprintf("/dns_zones/%d", index)
		if len(writers) > 0 {
			broadWrite = append(broadWrite, map[string]any{"zone": zone.Name, "partition": zone.Partition, "principals": writers, "ref": ref})
		}
		if len(creators) > 0 {
			createZones = append(createZones, map[string]any{"zone": zone.Name, "partition": zone.Partition, "principals": uniqueStrings(creators), "wildcard_record": zone.WildcardRecord, "wildcard_status": zone.WildcardStatus, "ref": ref})
		}
	}
	if len(createZones) > 0 {
		names := make([]string, 0, len(createZones))
		withoutWildcard := 0
		for _, zone := range createZones {
			label := zone["zone"].(string)
			if !zone["wildcard_record"].(bool) {
				withoutWildcard++
				label += " (no wildcard record)"
			}
			names = append(names, label)
		}
		result = append(result, finding("dns-zone-record-creation", domain, "ad_domain_config_dns_record_creation",
			fmt.Sprintf("Any authenticated user can add DNS records (%s)", domain),
			fmt.Sprintf("A broad principal such as Authenticated Users holds CreateChild on %d AD-integrated DNS zone(s), so any domain account can register new names, including ones clients look up by default such as WPAD or a mistyped host. This is the Windows default; %d zone(s) have no wildcard record to absorb unknown names. No record was created.", len(createZones), withoutWildcard),
			"medium", createZones[0]["ref"].(string), map[string]any{"account": fmt.Sprintf("%d zone(s)", len(createZones)), "flag": "CreateChild for a broad principal", "affected_objects": names, "zones": createZones}))
	}
	for _, zone := range broadWrite {
		result = append(result, finding("dns-zone-broad-write", zone["zone"].(string), "ad_domain_config_dns_zone_broad_write",
			"Broad principal can modify DNS zone: "+zone["zone"].(string),
			"A broad principal holds write rights on the DNS zone object itself, beyond adding records. It may change or delete existing records or the zone's permissions. No change was attempted.",
			"high", zone["ref"].(string), map[string]any{"zone": zone["zone"], "partition": zone["partition"], "principals": zone["principals"]}))
	}
	if len(delegated) > 0 {
		principals := make([]string, 0, len(delegated))
		for name := range delegated {
			principals = append(principals, name)
		}
		sort.Strings(principals)
		affected := make([]string, 0, len(principals))
		for _, name := range principals {
			affected = append(affected, name+" → "+strings.Join(delegated[name], ", "))
		}
		result = append(result, finding("dns-zone-delegated-write", domain, "ad_domain_config_dns_zone_delegated_write",
			fmt.Sprintf("Delegated write access to DNS zones (%s)", domain),
			"Principals other than the built-in administrators and DnsAdmins can add or change records in these DNS zones. Confirm each delegation is intended; nested group membership was not expanded.",
			"low", "/dns_zones", map[string]any{"account": fmt.Sprintf("%d principal(s)", len(principals)), "flag": "delegated DNS write", "affected_objects": affected}))
	}
	return result, nil
}

func hasZoneWrite(rights []string) bool {
	for _, right := range rights {
		switch right {
		case "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "WriteProperty", "Delete":
			return true
		}
	}
	return false
}

func coreSID(sid string) string {
	if index := strings.Index(strings.ToUpper(sid), "S-1-"); index >= 0 {
		return sid[index:]
	}
	return sid
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}
