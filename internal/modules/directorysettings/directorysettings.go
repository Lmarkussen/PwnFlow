// Package directorysettings reads forest- and domain-wide directory settings
// that the RustHound-CE collection does not carry: dSHeuristics, whether an
// unauthenticated LDAP search is answered, and the access-control lists of the
// AD-integrated DNS zones. Every read is an LDAP search with the assessment
// credentials, except the anonymous probe, which sends no credentials at all.
// Nothing is written to the directory.
package directorysettings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-ldap/ldap/v3"
	"github.com/pwnflow/pwnflow/internal/config"
	"github.com/pwnflow/pwnflow/internal/ldaptransport"
	"github.com/pwnflow/pwnflow/internal/modules"
)

const (
	moduleID = "ad-directory-settings"
	// ToolName is the source tool recorded for executions; the Findings engine
	// dispatches on it.
	ToolName   = "AD Directory Settings"
	outputDir  = "Enumeration/ActiveDirectory"
	outputText = "AD_directory_settings.txt"
	// JSONName is the structured artifact written beside the text output.
	JSONName = "AD_directory_settings.json"
	// maxResolvedSIDs bounds the name lookup for ACL principals.
	maxResolvedSIDs = 100
	// sdFlagsControl asks the server for the DACL only, which an ordinary
	// account may read; the full descriptor needs SACL access.
	sdFlagsOID = "1.2.840.113556.1.4.801"
)

// sdFlagsDACL is the BER encoding of SEQUENCE { INTEGER 4 } (DACL_SECURITY_INFORMATION).
var sdFlagsDACL = string([]byte{0x30, 0x03, 0x02, 0x01, 0x04})

type Module struct{}

func (Module) ID() string                     { return moduleID }
func (Module) Name() string                   { return "AD Directory Settings" }
func (Module) ToolFamily() modules.ToolFamily { return modules.ToolFamilyActiveDirectory }
func (Module) Category() modules.Category     { return modules.CategoryEnumeration }
func (Module) Tool() string                   { return ToolName }
func (Module) Protocol() modules.Protocol     { return modules.ProtocolLDAP }
func (Module) Description() string {
	return "Reads directory settings the RustHound collection does not carry: dSHeuristics from the configuration partition, " +
		"whether the domain controller answers an LDAP search without any credentials, and the DACLs of the AD-integrated DNS zones " +
		"(who may create or change records, and whether a wildcard record exists). Read-only LDAP searches; the anonymous probe sends no credentials."
}
func (Module) Prerequisites() []string {
	return []string{"An authorized domain controller with LDAP access"}
}
func (Module) RequiredPrivileges() []string     { return nil }
func (Module) OutputFile() string               { return filepath.Join(outputDir, outputText) }
func (Module) Sensitivity() modules.Sensitivity { return modules.SensitivityStandard }
func (Module) ReadOnly() bool                   { return true }
func (Module) SecondaryConnections() []string   { return nil }

// Report is the structured artifact the Findings engine reads.
type Report struct {
	SchemaVersion int            `json:"schema_version"`
	Domain        string         `json:"domain"`
	CollectedAt   time.Time      `json:"collected_at"`
	NamingContext NamingContexts `json:"naming_contexts"`
	DSHeuristics  Setting        `json:"ds_heuristics"`
	AnonymousLDAP Probe          `json:"anonymous_ldap"`
	DNSZones      []DNSZone      `json:"dns_zones"`
	// PasswordSettings holds the fine-grained password policies (PSOs) the
	// credentials can see. By default only Domain Admins can read them, so
	// an empty list does not show that none exist.
	PasswordSettings PasswordSettings `json:"password_settings"`
	Errors           []string         `json:"errors,omitempty"`
}

type NamingContexts struct {
	Default       string `json:"default"`
	Configuration string `json:"configuration"`
	RootDomain    string `json:"root_domain"`
}

// Setting is one attribute read: Status is "read", "not_set" or "error".
type Setting struct {
	Status string `json:"status"`
	DN     string `json:"dn,omitempty"`
	Value  string `json:"value,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Probe records the unauthenticated LDAP search. Status is "refused",
// "base_readable" (the domain head was returned), "objects_readable" (user
// objects were returned), "unreachable" or "error".
type Probe struct {
	Status      string `json:"status"`
	Endpoint    string `json:"endpoint,omitempty"`
	UserObjects int    `json:"user_objects,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

// PasswordSettings is the result of reading the Password Settings Container.
type PasswordSettings struct {
	Status   string `json:"status"` // read, none_visible, error
	Detail   string `json:"detail,omitempty"`
	Policies []PSO  `json:"policies"`
}

// PSO is one fine-grained password policy. Durations are in minutes; -1
// means forever or never, and a nil field was not returned.
type PSO struct {
	Name                  string   `json:"name"`
	DN                    string   `json:"dn"`
	Precedence            *int64   `json:"precedence,omitempty"`
	MinimumLength         *int64   `json:"minimum_password_length,omitempty"`
	History               *int64   `json:"password_history_length,omitempty"`
	ComplexityEnabled     *bool    `json:"complexity_enabled,omitempty"`
	ReversibleEncryption  *bool    `json:"reversible_encryption_enabled,omitempty"`
	LockoutThreshold      *int64   `json:"lockout_threshold,omitempty"`
	LockoutDurationMin    *int64   `json:"lockout_duration_minutes,omitempty"`
	ObservationWindowMin  *int64   `json:"lockout_observation_window_minutes,omitempty"`
	MaximumPasswordAgeDay *int64   `json:"maximum_password_age_days,omitempty"`
	AppliesTo             []string `json:"applies_to"`
}

type DNSZone struct {
	Name           string `json:"name"`
	DN             string `json:"dn"`
	Partition      string `json:"partition"`
	ACLStatus      string `json:"acl_status"`
	ACLDetail      string `json:"acl_detail,omitempty"`
	ACEs           []ACE  `json:"aces"`
	WildcardStatus string `json:"wildcard_status"`
	WildcardRecord bool   `json:"wildcard_record"`
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
	report := Collect(ctx, runtime, searcher{runtime: runtime})
	if err := writeJSON(filepath.Join(runtime.ResultsRoot, outputDir, JSONName), report); err != nil {
		return err
	}
	_, err := sink.Write([]byte(formatText(report)))
	return err
}

// directory abstracts the LDAP reads so the collection logic can be tested
// without a server.
type directory interface {
	Search(ctx context.Context, request *ldap.SearchRequest) (*ldap.SearchResult, error)
	AnonymousSearch(ctx context.Context, request *ldap.SearchRequest) (*ldap.SearchResult, string, error)
}

type searcher struct{ runtime *modules.Runtime }

func (s searcher) Search(ctx context.Context, request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	cfg := config.Config{Target: s.runtime.Target, Domain: s.runtime.Domain, Username: s.runtime.Username, Password: s.runtime.Password}
	result, _, err := ldaptransport.Search(ctx, cfg, s.runtime.LDAPOptions, request)
	return result, err
}

// AnonymousSearch dials plain LDAP and searches without binding, which is
// what an unauthenticated client can do.
func (s searcher) AnonymousSearch(ctx context.Context, request *ldap.SearchRequest) (*ldap.SearchResult, string, error) {
	endpoint := net.JoinHostPort(s.runtime.Target, "389")
	if err := ctx.Err(); err != nil {
		return nil, endpoint, err
	}
	conn, err := ldap.DialURL("ldap://"+endpoint, ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}))
	if err != nil {
		return nil, endpoint, err
	}
	defer conn.Close()
	conn.SetTimeout(5 * time.Second)
	result, err := conn.Search(request)
	return result, endpoint, err
}

// Collect performs the reads. Each part records its own outcome, so one
// refused search does not hide the others.
func Collect(ctx context.Context, runtime *modules.Runtime, dir directory) Report {
	report := Report{SchemaVersion: 1, Domain: runtime.Domain, CollectedAt: time.Now().UTC(), DNSZones: []DNSZone{}}
	report.NamingContext = NamingContexts{Default: domainDN(runtime.Domain)}

	rootDSE := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)",
		[]string{"defaultNamingContext", "configurationNamingContext", "rootDomainNamingContext"}, nil)
	if result, err := dir.Search(ctx, rootDSE); err == nil && len(result.Entries) > 0 {
		entry := result.Entries[0]
		report.NamingContext.Default = fallback(entry.GetAttributeValue("defaultNamingContext"), report.NamingContext.Default)
		report.NamingContext.Configuration = entry.GetAttributeValue("configurationNamingContext")
		report.NamingContext.RootDomain = entry.GetAttributeValue("rootDomainNamingContext")
	} else if err != nil {
		report.Errors = append(report.Errors, "root DSE: "+safeError(err))
	}
	if report.NamingContext.RootDomain == "" {
		report.NamingContext.RootDomain = report.NamingContext.Default
	}
	if report.NamingContext.Configuration == "" {
		report.NamingContext.Configuration = "CN=Configuration," + report.NamingContext.RootDomain
	}

	report.DSHeuristics = readDSHeuristics(ctx, dir, report.NamingContext.Configuration)
	report.AnonymousLDAP = probeAnonymous(ctx, dir, report.NamingContext.Default)
	report.DNSZones, report.Errors = readDNSZones(ctx, dir, report.NamingContext, report.Errors)
	resolveNames(ctx, dir, report.NamingContext.Default, report.DNSZones)
	report.PasswordSettings = readPasswordSettings(ctx, dir, report.NamingContext.Default)
	return report
}

// readPasswordSettings reads the PSOs in the domain's Password Settings
// Container.
func readPasswordSettings(ctx context.Context, dir directory, base string) PasswordSettings {
	attributes := []string{"name", "msDS-PasswordSettingsPrecedence", "msDS-MinimumPasswordLength", "msDS-PasswordHistoryLength",
		"msDS-PasswordComplexityEnabled", "msDS-PasswordReversibleEncryptionEnabled", "msDS-LockoutThreshold",
		"msDS-LockoutDuration", "msDS-LockoutObservationWindow", "msDS-MaximumPasswordAge", "msDS-PSOAppliesTo"}
	request := ldap.NewSearchRequest("CN=Password Settings Container,CN=System,"+base, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=msDS-PasswordSettings)", attributes, nil)
	result, err := dir.Search(ctx, request)
	settings := PasswordSettings{Policies: []PSO{}}
	switch {
	case err != nil && ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
		settings.Status, settings.Detail = "none_visible", "the Password Settings Container was not returned"
		return settings
	case err != nil:
		settings.Status, settings.Detail = "error", safeError(err)
		return settings
	case len(result.Entries) == 0:
		settings.Status, settings.Detail = "none_visible", "no PSO was returned; by default only Domain Admins can read PSOs, so this does not show that none exist"
		return settings
	}
	settings.Status = "read"
	for _, entry := range result.Entries {
		pso := PSO{Name: entry.GetAttributeValue("name"), DN: entry.DN, AppliesTo: []string{}}
		pso.Precedence = ldapInt(entry, "msDS-PasswordSettingsPrecedence")
		pso.MinimumLength = ldapInt(entry, "msDS-MinimumPasswordLength")
		pso.History = ldapInt(entry, "msDS-PasswordHistoryLength")
		pso.ComplexityEnabled = ldapBool(entry, "msDS-PasswordComplexityEnabled")
		pso.ReversibleEncryption = ldapBool(entry, "msDS-PasswordReversibleEncryptionEnabled")
		pso.LockoutThreshold = ldapInt(entry, "msDS-LockoutThreshold")
		pso.LockoutDurationMin = ldapInterval(entry, "msDS-LockoutDuration", 600000000)
		pso.ObservationWindowMin = ldapInterval(entry, "msDS-LockoutObservationWindow", 600000000)
		pso.MaximumPasswordAgeDay = ldapInterval(entry, "msDS-MaximumPasswordAge", 864000000000)
		for _, dn := range entry.GetAttributeValues("msDS-PSOAppliesTo") {
			name := dn
			if parsed, parseErr := ldap.ParseDN(dn); parseErr == nil && len(parsed.RDNs) > 0 && len(parsed.RDNs[0].Attributes) > 0 {
				name = parsed.RDNs[0].Attributes[0].Value
			}
			pso.AppliesTo = append(pso.AppliesTo, name)
		}
		settings.Policies = append(settings.Policies, pso)
	}
	return settings
}

func ldapInt(entry *ldap.Entry, name string) *int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(entry.GetAttributeValue(name)), 10, 64)
	if err != nil {
		return nil
	}
	return &value
}

func ldapBool(entry *ldap.Entry, name string) *bool {
	switch strings.ToUpper(strings.TrimSpace(entry.GetAttributeValue(name))) {
	case "TRUE":
		value := true
		return &value
	case "FALSE":
		value := false
		return &value
	}
	return nil
}

// ldapInterval converts a negative 100-nanosecond interval to whole units;
// the minimum int64 (forever/never) and 0 for durations mean -1.
func ldapInterval(entry *ldap.Entry, name string, unit int64) *int64 {
	raw := ldapInt(entry, name)
	if raw == nil {
		return nil
	}
	if *raw == math.MinInt64 {
		value := int64(-1)
		return &value
	}
	value := -*raw / unit
	return &value
}

func readDSHeuristics(ctx context.Context, dir directory, configuration string) Setting {
	dn := "CN=Directory Service,CN=Windows NT,CN=Services," + configuration
	request := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"dSHeuristics"}, nil)
	result, err := dir.Search(ctx, request)
	if err != nil {
		return Setting{Status: "error", DN: dn, Detail: safeError(err)}
	}
	if len(result.Entries) == 0 {
		return Setting{Status: "error", DN: dn, Detail: "the Directory Service object was not returned"}
	}
	value := result.Entries[0].GetAttributeValue("dSHeuristics")
	if value == "" {
		return Setting{Status: "not_set", DN: dn}
	}
	return Setting{Status: "read", DN: dn, Value: value}
}

func probeAnonymous(ctx context.Context, dir directory, base string) Probe {
	request := ldap.NewSearchRequest(base, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=*)", []string{"objectClass"}, nil)
	result, endpoint, err := dir.AnonymousSearch(ctx, request)
	probe := Probe{Endpoint: endpoint}
	switch {
	case err != nil && ldap.IsErrorWithCode(err, ldap.LDAPResultOperationsError):
		probe.Status, probe.Detail = "refused", "the server requires a bind before searching"
		return probe
	case err != nil && isNetworkError(err):
		probe.Status, probe.Detail = "unreachable", safeError(err)
		return probe
	case err != nil:
		probe.Status, probe.Detail = "refused", safeError(err)
		return probe
	case len(result.Entries) == 0:
		probe.Status, probe.Detail = "refused", "the search returned no entries"
		return probe
	}
	probe.Status = "base_readable"
	users := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 5, 5, false,
		"(&(objectCategory=person)(objectClass=user))", []string{"objectClass"}, nil)
	if result, _, err := dir.AnonymousSearch(ctx, users); (err == nil || ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded)) && result != nil && len(result.Entries) > 0 {
		probe.Status, probe.UserObjects = "objects_readable", len(result.Entries)
	}
	return probe
}

func readDNSZones(ctx context.Context, dir directory, names NamingContexts, errs []string) ([]DNSZone, []string) {
	partitions := []struct{ label, base string }{
		{"DomainDnsZones", "DC=DomainDnsZones," + names.Default},
		{"ForestDnsZones", "DC=ForestDnsZones," + names.RootDomain},
		{"Domain (legacy)", "CN=MicrosoftDNS,CN=System," + names.Default},
	}
	zones := []DNSZone{}
	for _, partition := range partitions {
		request := ldap.NewSearchRequest(partition.base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=dnsZone)", []string{"name", "nTSecurityDescriptor"},
			[]ldap.Control{ldap.NewControlString(sdFlagsOID, true, sdFlagsDACL)})
		result, err := dir.Search(ctx, request)
		if err != nil {
			if !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				errs = append(errs, partition.label+" zones: "+safeError(err))
			}
			continue
		}
		for _, entry := range result.Entries {
			name := entry.GetAttributeValue("name")
			if name == "" || name == "RootDNSServers" || strings.HasPrefix(name, "..") {
				continue
			}
			zone := DNSZone{Name: name, DN: entry.DN, Partition: partition.label, ACEs: []ACE{}}
			raw := entry.GetRawAttributeValue("nTSecurityDescriptor")
			if len(raw) == 0 {
				zone.ACLStatus, zone.ACLDetail = "unreadable", "the server did not return the security descriptor"
			} else if aces, err := parseDACL(raw); err != nil {
				zone.ACLStatus, zone.ACLDetail, zone.ACEs = "partial", err.Error(), append(zone.ACEs, aces...)
			} else {
				zone.ACLStatus, zone.ACEs = "read", append(zone.ACEs, aces...)
			}
			wildcard := ldap.NewSearchRequest(entry.DN, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 1, 0, false,
				"(&(objectClass=dnsNode)(name=\\2a))", []string{"name"}, nil)
			if found, err := dir.Search(ctx, wildcard); err != nil {
				zone.WildcardStatus = "error"
			} else {
				zone.WildcardStatus, zone.WildcardRecord = "read", len(found.Entries) > 0
			}
			zones = append(zones, zone)
		}
	}
	sort.Slice(zones, func(i, j int) bool { return strings.ToLower(zones[i].DN) < strings.ToLower(zones[j].DN) })
	return zones, errs
}

// resolveNames looks up the account names of the domain SIDs in the zone
// ACLs with one search. Well-known SIDs are named by the Findings engine.
func resolveNames(ctx context.Context, dir directory, base string, zones []DNSZone) {
	unique := map[string]bool{}
	var filters []string
	for _, zone := range zones {
		for _, ace := range zone.ACEs {
			if !strings.HasPrefix(ace.SID, "S-1-5-21-") || unique[ace.SID] || len(filters) >= maxResolvedSIDs {
				continue
			}
			if value, ok := sidFilterValue(ace.SID); ok {
				unique[ace.SID] = true
				filters = append(filters, "(objectSid="+value+")")
			}
		}
	}
	if len(filters) == 0 {
		return
	}
	request := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(|"+strings.Join(filters, "")+")", []string{"sAMAccountName", "objectSid"}, nil)
	result, err := dir.Search(ctx, request)
	if err != nil {
		return
	}
	names := map[string]string{}
	for _, entry := range result.Entries {
		if sid, err := formatSID(entry.GetRawAttributeValue("objectSid")); err == nil {
			names[sid] = entry.GetAttributeValue("sAMAccountName")
		}
	}
	for zoneIndex := range zones {
		for aceIndex := range zones[zoneIndex].ACEs {
			if name := names[zones[zoneIndex].ACEs[aceIndex].SID]; name != "" {
				zones[zoneIndex].ACEs[aceIndex].Name = name
			}
		}
	}
}

func domainDN(domain string) string {
	var parts []string
	for _, part := range strings.Split(domain, ".") {
		if part = strings.TrimSpace(part); part != "" {
			parts = append(parts, "DC="+part)
		}
	}
	return strings.Join(parts, ",")
}

func fallback(value, other string) string {
	if strings.TrimSpace(value) == "" {
		return other
	}
	return value
}

func isNetworkError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "connection refused") || strings.Contains(text, "no route") || strings.Contains(text, "i/o timeout")
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

func writeJSON(path string, report Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".directory-settings-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(append(data, '\n'))
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

func formatText(report Report) string {
	var b strings.Builder
	b.WriteString("AD DIRECTORY SETTINGS\n\n")
	fmt.Fprintf(&b, "DOMAIN: %s\nCONFIGURATION: %s\n\n", report.Domain, report.NamingContext.Configuration)
	fmt.Fprintf(&b, "dSHeuristics: %s", strings.ToUpper(report.DSHeuristics.Status))
	if report.DSHeuristics.Value != "" {
		fmt.Fprintf(&b, " (%s)", report.DSHeuristics.Value)
	}
	if report.DSHeuristics.Detail != "" {
		fmt.Fprintf(&b, " - %s", report.DSHeuristics.Detail)
	}
	fmt.Fprintf(&b, "\nANONYMOUS LDAP SEARCH: %s", strings.ToUpper(report.AnonymousLDAP.Status))
	if report.AnonymousLDAP.Detail != "" {
		fmt.Fprintf(&b, " - %s", report.AnonymousLDAP.Detail)
	}
	fmt.Fprintf(&b, "\n\nDNS ZONES: %d\n", len(report.DNSZones))
	for _, zone := range report.DNSZones {
		fmt.Fprintf(&b, "  %s [%s] ACL:%s wildcard:%v\n", zone.Name, zone.Partition, zone.ACLStatus, zone.WildcardRecord)
		for _, ace := range zone.ACEs {
			decision := "allow"
			if !ace.Allow {
				decision = "deny"
			}
			fmt.Fprintf(&b, "    %s %s %s\n", decision, fallback(ace.Name, ace.SID), strings.Join(ace.Rights, ","))
		}
	}
	for _, message := range report.Errors {
		b.WriteString("ERROR: " + message + "\n")
	}
	return b.String()
}

var _ modules.Module = Module{}
