package trustinventory

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/go-ldap/ldap/v3"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/ldaptransport"
	"github.com/pwnflow/pwnflow/internal/modules"
)

const moduleID = "ad-trust-inventory"

type Module struct{}

func (Module) ID() string                     { return moduleID }
func (Module) Name() string                   { return "Active Directory Trust Inventory" }
func (Module) ToolFamily() modules.ToolFamily { return modules.ToolFamilyActiveDirectory }
func (Module) Category() modules.Category     { return modules.CategoryEnumeration }
func (Module) Tool() string                   { return "LDAP" }
func (Module) Protocol() modules.Protocol     { return modules.ProtocolLDAP }
func (Module) Description() string {
	return "Collects trustedDomain topology attributes from the configured domain only."
}
func (Module) Prerequisites() []string {
	return []string{"An authorized domain controller with LDAP access"}
}
func (Module) RequiredPrivileges() []string { return nil }
func (Module) OutputFile() string {
	return filepath.Join("Enumeration", "ActiveDirectory", "AD_trust_inventory.json")
}
func (Module) Sensitivity() modules.Sensitivity { return modules.SensitivityStandard }
func (Module) ReadOnly() bool                   { return true }
func (Module) SecondaryConnections() []string   { return nil }

type Collection struct {
	Status      string `json:"status"`
	Source      string `json:"source"`
	ObjectCount int    `json:"object_count"`
	Detail      string `json:"detail,omitempty"`
}

type Inventory struct {
	SchemaVersion int        `json:"schema_version"`
	Domain        string     `json:"domain"`
	Collection    Collection `json:"collection"`
	Trusts        []Trust    `json:"trusts"`
}

type Trust struct {
	DistinguishedName    string   `json:"distinguished_name,omitempty"`
	CN                   string   `json:"cn,omitempty"`
	Name                 string   `json:"name,omitempty"`
	Partner              string   `json:"partner,omitempty"`
	FlatName             string   `json:"flat_name,omitempty"`
	SecurityIdentifier   string   `json:"security_identifier,omitempty"`
	DirectionRaw         *int64   `json:"direction_raw,omitempty"`
	Direction            string   `json:"direction"`
	TypeRaw              *int64   `json:"type_raw,omitempty"`
	TrustType            string   `json:"trust_type"`
	AttributesRaw        *int64   `json:"attributes_raw,omitempty"`
	AttributeFlags       []string `json:"attribute_flags"`
	UnknownAttributeBits []string `json:"unknown_attribute_bits,omitempty"`
	WhenCreated          string   `json:"when_created,omitempty"`
	WhenChanged          string   `json:"when_changed,omitempty"`
	InterpretationStatus string   `json:"interpretation_status"`
}

func (Module) Check(ctx context.Context, runtime *modules.Runtime) error {
	if runtime == nil || runtime.Target == "" || runtime.Domain == "" || runtime.Username == "" {
		return fmt.Errorf("target, domain and username are required")
	}
	return ctx.Err()
}

func (m Module) Run(ctx context.Context, runtime *modules.Runtime, sink modules.OutputSink) error {
	if err := m.Check(ctx, runtime); err != nil {
		return err
	}
	request := ldap.NewSearchRequest(domainDN(runtime.Domain), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=trustedDomain))",
		[]string{"cn", "name", "distinguishedName", "flatName", "trustPartner", "securityIdentifier", "trustDirection", "trustType", "trustAttributes", "whenCreated", "whenChanged"}, nil)
	result, _, searchErr := ldaptransport.Search(ctx, ldapConfig(runtime), runtime.LDAPOptions, request)
	inventory := Inventory{SchemaVersion: 1, Domain: runtime.Domain, Collection: Collection{Status: "complete", Source: "ldap_trusted_domain"}, Trusts: []Trust{}}
	if searchErr != nil {
		inventory.Collection.Status = collectionStatus(searchErr)
		inventory.Collection.Detail = safeError(searchErr)
	} else {
		inventory.Trusts = ParseEntries(result.Entries)
		inventory.Collection.ObjectCount = len(inventory.Trusts)
	}
	if err := writeArtifacts(runtime.ResultsRoot, inventory); err != nil {
		return err
	}
	text := formatText(inventory)
	if _, err := sink.Write([]byte(text)); err != nil {
		return err
	}
	if searchErr != nil {
		return searchErr
	}
	return nil
}

func ldapConfig(runtime *modules.Runtime) config.Config {
	return config.Config{Target: runtime.Target, Domain: runtime.Domain, Username: runtime.Username, Password: runtime.Password}
}

func domainDN(domain string) string {
	parts := strings.Split(domain, ".")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			result = append(result, "DC="+ldap.EscapeFilter(strings.TrimSpace(part)))
		}
	}
	return strings.Join(result, ",")
}

func ParseEntries(entries []*ldap.Entry) []Trust {
	result := make([]Trust, 0, len(entries))
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		trust := Trust{DistinguishedName: entry.DN, CN: attr(entry, "cn"), Name: attr(entry, "name"), Partner: attr(entry, "trustPartner"), FlatName: attr(entry, "flatName"), SecurityIdentifier: binaryValue(entry, "securityIdentifier"), WhenCreated: attr(entry, "whenCreated"), WhenChanged: attr(entry, "whenChanged"), Direction: "unknown", TrustType: "unknown", AttributeFlags: []string{}, InterpretationStatus: "configuration_only"}
		if value, ok := intAttribute(entry, "trustDirection"); ok {
			trust.DirectionRaw = &value
			trust.Direction = direction(value)
		}
		if value, ok := intAttribute(entry, "trustType"); ok {
			trust.TypeRaw = &value
			trust.TrustType = trustType(value)
		}
		if value, ok := intAttribute(entry, "trustAttributes"); ok {
			trust.AttributesRaw = &value
			trust.AttributeFlags, trust.UnknownAttributeBits = attributeFlags(value)
		}
		result = append(result, trust)
	}
	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i].DistinguishedName) < strings.ToLower(result[j].DistinguishedName)
	})
	return result
}

func attr(entry *ldap.Entry, name string) string {
	return strings.TrimSpace(entry.GetAttributeValue(name))
}

func binaryValue(entry *ldap.Entry, name string) string {
	values := entry.GetRawAttributeValues(name)
	if len(values) == 0 {
		return ""
	}
	return "0x" + hex.EncodeToString(values[0])
}

func intAttribute(entry *ldap.Entry, name string) (int64, bool) {
	value := strings.TrimSpace(entry.GetAttributeValue(name))
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	return parsed, err == nil
}

func direction(value int64) string {
	switch value {
	case 0:
		return "disabled_or_no_direction"
	case 1:
		return "inbound"
	case 2:
		return "outbound"
	case 3:
		return "bidirectional"
	default:
		return "unknown"
	}
}
func trustType(value int64) string {
	switch value {
	case 1:
		return "downlevel"
	case 2:
		return "windows_ad"
	case 3:
		return "mit"
	case 4:
		return "dce"
	default:
		return "unknown"
	}
}

var trustFlags = []struct {
	bit  uint64
	name string
}{
	{0x1, "non_transitive"}, {0x2, "uplevel_only"}, {0x4, "quarantined_domain"}, {0x8, "forest_transitive"},
	{0x10, "cross_organization"}, {0x20, "within_forest"}, {0x40, "treat_as_external"}, {0x80, "uses_rc4_encryption"},
	{0x100, "uses_aes_keys"}, {0x400, "pim_trust"}, {0x800, "cross_organization_no_tgt_delegation"}, {0x80000000, "primary"},
}

func attributeFlags(raw int64) ([]string, []string) {
	value := uint64(raw)
	if raw < 0 {
		value = uint64(uint32(raw))
	}
	var flags []string
	known := uint64(0)
	for _, flag := range trustFlags {
		if value&flag.bit != 0 {
			flags = append(flags, flag.name)
			known |= flag.bit
		}
	}
	unknown := value &^ known
	var unknownBits []string
	for bit := uint(0); bit < 64; bit++ {
		if unknown&(uint64(1)<<bit) != 0 {
			unknownBits = append(unknownBits, fmt.Sprintf("0x%x", uint64(1)<<bit))
		}
	}
	return flags, unknownBits
}

func collectionStatus(err error) string {
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "timeout"):
		return "timeout"
	case strings.Contains(text, "denied"), strings.Contains(text, "insufficient access"):
		return "permission_denied"
	case strings.Contains(text, "connection"), strings.Contains(text, "network"):
		return "unavailable"
	default:
		return "partial"
	}
}
func safeError(err error) string {
	text := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, err.Error())
	return strings.Join(strings.Fields(text), " ")
}

func writeArtifacts(root string, inventory Inventory) error {
	data, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	jsonPath := filepath.Join(root, "Enumeration", "ActiveDirectory", "AD_trust_inventory.json")
	textPath := filepath.Join(root, "Enumeration", "ActiveDirectory", "AD_trust_inventory.txt")
	if err := atomicWrite(jsonPath, data); err != nil {
		return err
	}
	return atomicWrite(textPath, []byte(formatText(inventory)))
}

func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".trust-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(data)
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
	return os.Rename(name, path)
}

func formatText(inventory Inventory) string {
	var b strings.Builder
	b.WriteString("ACTIVE DIRECTORY TRUST INVENTORY\n\n")
	fmt.Fprintf(&b, "DOMAIN: %s\nSTATUS: %s\nTRUST OBJECTS: %d\n\n", inventory.Domain, strings.ToUpper(inventory.Collection.Status), len(inventory.Trusts))
	for _, trust := range inventory.Trusts {
		b.WriteString("TRUST: " + trust.Partner + "\n")
		fmt.Fprintf(&b, "  Flat Name: %s\n  Direction: %s\n  Trust Type: %s\n  Transitivity: not established\n  Authentication: not established\n", trust.FlatName, trust.Direction, trust.TrustType)
		if trust.DirectionRaw != nil {
			fmt.Fprintf(&b, "  Raw Direction: %d\n", *trust.DirectionRaw)
		}
		if trust.TypeRaw != nil {
			fmt.Fprintf(&b, "  Raw Type: %d\n", *trust.TypeRaw)
		}
		if trust.AttributesRaw != nil {
			fmt.Fprintf(&b, "  Raw Attributes: %d\n", *trust.AttributesRaw)
		}
		b.WriteString("  Interpretation: configuration only\n\n")
	}
	if inventory.Collection.Detail != "" {
		b.WriteString("DETAIL: " + inventory.Collection.Detail + "\n")
	}
	return b.String()
}

var _ modules.Module = Module{}
