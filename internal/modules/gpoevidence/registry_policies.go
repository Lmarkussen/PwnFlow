package gpoevidence

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pwnflow/pwnflow/internal/modules"
)

const (
	registryPoliciesID       = "ad-gpo-registry-policies"
	registryPoliciesRoot     = "Enumeration/ActiveDirectory/GPO_Registry"
	registryPoliciesDocument = "registry_policies.json"
	registryPolicyTimeout    = 30 * time.Second
)

// RegistryPolicyFile names the two per-GPO files this module retrieves. Both
// hold registry settings only: Administrative Templates (Registry.pol) and
// Group Policy Preferences registry items (Registry.xml), which cannot carry
// a cpassword. gpoParser reads neither.
var registryPolicyFiles = []struct{ key, remote, local string }{
	{"registry_pol", `Machine\Registry.pol`, "Registry.pol"},
	{"gpp_registry", `Machine\Preferences\Registry\Registry.xml`, "Registry.xml"},
}

// RegistryPoliciesModule collects the registry-based computer settings of
// every GPO, which decide name-resolution, update and IPv6 behaviour, plus
// where each GPO is linked. Unlike the full GPO evidence collection it
// retrieves no scripts and no other preference files.
type RegistryPoliciesModule struct{}

// RegistryPolicyFileStatus is the retrieval result of one file.
type RegistryPolicyFileStatus struct {
	Status string `json:"status"` // retrieved, absent, failed, limited
	File   string `json:"file,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// RegistryPolicyLink is one container a GPO is linked to.
type RegistryPolicyLink struct {
	Container string `json:"container"`
	Type      string `json:"type"`
	Enabled   bool   `json:"enabled"`
	Enforced  bool   `json:"enforced"`
}

// RegistryPolicyGPO is one GPO in the document.
type RegistryPolicyGPO struct {
	GUID                     string                              `json:"guid"`
	Name                     string                              `json:"name"`
	ComputerSettingsDisabled bool                                `json:"computer_settings_disabled"`
	Links                    []RegistryPolicyLink                `json:"links"`
	Files                    map[string]RegistryPolicyFileStatus `json:"files"`
}

// RegistryPoliciesDocument is what the analyzer reads.
type RegistryPoliciesDocument struct {
	SchemaVersion int                 `json:"schema_version"`
	Domain        string              `json:"domain"`
	SourceDC      string              `json:"source_dc"`
	Status        string              `json:"status"` // complete, partial, failed
	Detail        string              `json:"detail,omitempty"`
	CollectedAt   string              `json:"collected_at"`
	GPOs          []RegistryPolicyGPO `json:"gpos"`
}

func (RegistryPoliciesModule) ID() string   { return registryPoliciesID }
func (RegistryPoliciesModule) Name() string { return "GPO Registry Settings" }
func (RegistryPoliciesModule) ToolFamily() modules.ToolFamily {
	return modules.ToolFamilyActiveDirectory
}
func (RegistryPoliciesModule) Category() modules.Category {
	return modules.CategoryConfigurationAuditing
}
func (RegistryPoliciesModule) Tool() string               { return RegistryPoliciesTool }
func (RegistryPoliciesModule) Protocol() modules.Protocol { return modules.ProtocolLDAP }
func (RegistryPoliciesModule) Description() string {
	return "Reads every GPO's links over LDAP and only its Machine\\Registry.pol and Group Policy Preferences Registry.xml from SYSVOL, which hold the computer settings for LLMNR, NetBIOS, mDNS, WSUS and IPv6. No scripts or other policy files are retrieved."
}
func (RegistryPoliciesModule) Prerequisites() []string {
	return []string{"Authorized LDAP access and smbclient for SYSVOL"}
}
func (RegistryPoliciesModule) RequiredPrivileges() []string { return nil }
func (RegistryPoliciesModule) OutputFile() string {
	return filepath.Join(registryPoliciesRoot, "collection.log")
}
func (RegistryPoliciesModule) Sensitivity() modules.Sensitivity { return modules.SensitivityStandard }
func (RegistryPoliciesModule) ReadOnly() bool                   { return true }
func (RegistryPoliciesModule) SecondaryConnections() []string {
	return []string{"configured domain controller LDAP and its SYSVOL share only"}
}
func (RegistryPoliciesModule) OptionKeys() []string { return nil }

// RegistryPoliciesTool is the source tool name Findings carry.
const RegistryPoliciesTool = "GPO Registry Settings"

func (m RegistryPoliciesModule) Check(ctx context.Context, runtime *modules.Runtime) error {
	return Module{}.Check(ctx, runtime)
}

func (m RegistryPoliciesModule) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	if err := m.Check(ctx, runtime); err != nil {
		return err
	}
	root := filepath.Join(runtime.ResultsRoot, registryPoliciesRoot)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	document := RegistryPoliciesDocument{SchemaVersion: 1, Domain: runtime.Domain, SourceDC: runtime.Target, Status: "complete", CollectedAt: time.Now().UTC().Format(time.RFC3339Nano), GPOs: []RegistryPolicyGPO{}}
	metadata, links, gpos, err := collectLDAP(ctx, runtime)
	switch {
	case err != nil:
		document.Status, document.Detail = "failed", safeError(err)
	case metadata.Collection.Status != "complete" || links.Collection.Status != "complete":
		document.Status, document.Detail = "partial", fallbackDetail(metadata.Collection.Detail, links.Collection.Detail)
	}
	if err == nil {
		document.GPOs = collectRegistryPolicies(ctx, runtime, root, gpos, links)
		for _, gpo := range document.GPOs {
			for _, file := range gpo.Files {
				if file.Status == "failed" || file.Status == "limited" {
					document.Status = "partial"
				}
			}
		}
	}
	if writeErr := writeJSON(filepath.Join(root, registryPoliciesDocument), document); writeErr != nil {
		return writeErr
	}
	retrieved := 0
	for _, gpo := range document.GPOs {
		for _, file := range gpo.Files {
			if file.Status == "retrieved" {
				retrieved++
			}
		}
	}
	fmt.Fprintf(sink, "GPO registry settings: GPOs=%d files retrieved=%d status=%s\n", len(document.GPOs), retrieved, document.Status)
	if err != nil {
		return err
	}
	if document.Status != "complete" {
		return fmt.Errorf("GPO registry settings collection partial: %s", fallbackDetail(document.Detail, "a policy file could not be read"))
	}
	return ctx.Err()
}

func fallbackDetail(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func collectRegistryPolicies(ctx context.Context, runtime *modules.Runtime, root string, gpos []GPO, links LinksDocument) []RegistryPolicyGPO {
	linked := map[string][]RegistryPolicyLink{}
	for _, source := range links.Sources {
		for _, link := range source.Links {
			guid := normalizeGUID(link.GPOGUID)
			if guid == "" {
				continue
			}
			linked[guid] = append(linked[guid], RegistryPolicyLink{Container: source.DN, Type: source.ObjectType, Enabled: link.Enabled == nil || *link.Enabled, Enforced: link.Enforced != nil && *link.Enforced})
		}
	}
	authPath, authErr := writeAuthFile(runtime)
	if authErr == nil {
		defer os.Remove(authPath)
	}
	result := make([]RegistryPolicyGPO, 0, len(gpos))
	for _, gpo := range gpos {
		entry := RegistryPolicyGPO{GUID: gpo.GUID, Name: firstAttribute(gpo, "displayName", gpo.GUID), Links: linked[normalizeGUID(gpo.GUID)], Files: map[string]RegistryPolicyFileStatus{}}
		if entry.Links == nil {
			entry.Links = []RegistryPolicyLink{}
		}
		var flags int
		fmt.Sscanf(firstAttribute(gpo, "flags", "0"), "%d", &flags)
		entry.ComputerSettingsDisabled = flags&2 != 0
		remotePath, pathErr := validatedPolicyRelativePath(gpo, runtime.Domain)
		for _, file := range registryPolicyFiles {
			switch {
			case !guidPattern.MatchString(gpo.GUID) || pathErr != nil:
				entry.Files[file.key] = RegistryPolicyFileStatus{Status: "failed", Detail: "GPO path failed validation"}
			case authErr != nil:
				entry.Files[file.key] = RegistryPolicyFileStatus{Status: "failed", Detail: safeError(authErr)}
			case !validDomain(runtime.Domain):
				entry.Files[file.key] = RegistryPolicyFileStatus{Status: "failed", Detail: "invalid domain"}
			default:
				entry.Files[file.key] = fetchRegistryPolicyFile(ctx, runtime, authPath, remotePath, gpo.GUID, root, file.remote, file.local)
			}
		}
		result = append(result, entry)
	}
	return result
}

// fetchRegistryPolicyFile retrieves one file of one GPO; a file the GPO does
// not have is the common case and is recorded as absent.
func fetchRegistryPolicyFile(ctx context.Context, runtime *modules.Runtime, authPath, remotePath, guid, root, remote, local string) RegistryPolicyFileStatus {
	temp, err := os.MkdirTemp("", "pwnflow-gpo-registry-")
	if err != nil {
		return RegistryPolicyFileStatus{Status: "failed", Detail: safeError(err)}
	}
	defer os.RemoveAll(temp)
	operation, cancel := context.WithTimeout(ctx, registryPolicyTimeout)
	defer cancel()
	remoteDir := strings.ReplaceAll(remotePath, "/", `\`)
	cmd := exec.CommandContext(operation, "smbclient", "//"+runtime.Target+"/SYSVOL", "-A", authPath, "-c", fmt.Sprintf(`get "%s\%s" "%s"`, remoteDir, remote, local))
	cmd.Dir = temp
	output, runErr := cmd.CombinedOutput()
	text := string(output)
	if strings.Contains(text, "NT_STATUS_OBJECT_NAME_NOT_FOUND") || strings.Contains(text, "NT_STATUS_OBJECT_PATH_NOT_FOUND") || strings.Contains(text, "NT_STATUS_NO_SUCH_FILE") {
		return RegistryPolicyFileStatus{Status: "absent"}
	}
	downloaded := filepath.Join(temp, local)
	info, statErr := os.Stat(downloaded)
	if runErr != nil || statErr != nil {
		detail := "retrieval failed"
		if errors.Is(operation.Err(), context.DeadlineExceeded) {
			detail = "retrieval timed out"
		} else if category := classifyErrorCategory(text); category != "" {
			detail = category
		}
		return RegistryPolicyFileStatus{Status: "failed", Detail: detail}
	}
	if info.Size() > maxFileBytes {
		return RegistryPolicyFileStatus{Status: "limited", Detail: "file_size_limit"}
	}
	data, err := os.ReadFile(downloaded)
	if err != nil {
		return RegistryPolicyFileStatus{Status: "failed", Detail: safeError(err)}
	}
	relative := filepath.Join(guid, local)
	stored := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(stored), 0o700); err != nil {
		return RegistryPolicyFileStatus{Status: "failed", Detail: safeError(err)}
	}
	if err := atomicWrite(stored, data); err != nil {
		return RegistryPolicyFileStatus{Status: "failed", Detail: safeError(err)}
	}
	return RegistryPolicyFileStatus{Status: "retrieved", File: filepath.ToSlash(relative)}
}

func firstAttribute(gpo GPO, name, fallback string) string {
	if attribute, ok := gpo.Attributes[name]; ok && len(attribute.Values) > 0 && strings.TrimSpace(attribute.Values[0]) != "" {
		return strings.TrimSpace(attribute.Values[0])
	}
	return fallback
}
