package modules

import (
	"context"
	"fmt"
	"sort"
	"time"
)

type ToolFamily string

const (
	ToolFamilyNetExec         ToolFamily = "NetExec"
	ToolFamilyADCS            ToolFamily = "AD CS"
	ToolFamilyActiveDirectory ToolFamily = "Active Directory"
	ToolFamilySCCM            ToolFamily = "SCCM"
	ToolFamilyNetwork         ToolFamily = "Network"
)

func ToolFamilies() []ToolFamily {
	return []ToolFamily{ToolFamilyNetExec, ToolFamilyADCS, ToolFamilyActiveDirectory, ToolFamilySCCM, ToolFamilyNetwork}
}

type Category string

const (
	CategoryEnumeration         Category = "Enumeration"
	CategoryCredentialAuditing  Category = "Credential Auditing"
	CategoryCredentialDumping   Category = "Credential Dumping"
	CategoryPrivilegeEscalation Category = "Privilege Escalation"
)

func Categories() []Category {
	return []Category{CategoryEnumeration, CategoryCredentialAuditing, CategoryCredentialDumping, CategoryPrivilegeEscalation}
}

type Protocol string

const (
	ProtocolNA    Protocol = "N/A"
	ProtocolLDAP  Protocol = "LDAP"
	ProtocolSMB   Protocol = "SMB"
	ProtocolWinRM Protocol = "WINRM"
	ProtocolWMI   Protocol = "WMI"
	ProtocolMSSQL Protocol = "MSSQL"
	ProtocolSSH   Protocol = "SSH"
	ProtocolFTP   Protocol = "FTP"
	ProtocolRDP   Protocol = "RDP"
	ProtocolVNC   Protocol = "VNC"
	ProtocolNFS   Protocol = "NFS"
)

// Protocols lists every protocol PwnFlow can drive through NetExec. The order is
// the navigation order, and it mirrors NetExec's own protocol set so a protocol
// present in the installed build also exists in the taxonomy.
func Protocols() []Protocol {
	return []Protocol{
		ProtocolLDAP, ProtocolSMB, ProtocolWinRM, ProtocolWMI, ProtocolMSSQL,
		ProtocolSSH, ProtocolFTP, ProtocolRDP, ProtocolVNC, ProtocolNFS,
	}
}

// CategoriesForFamily describes the navigation taxonomy, including inactive
// future categories that have no executable modules yet.
func CategoriesForFamily(family ToolFamily) []Category {
	switch family {
	case ToolFamilyNetExec:
		// NetExec is an enumeration and auditing integration. Its registrations
		// read the target or export material for offline auditing, so the
		// navigation offers the two categories those belong to and no
		// exploitation category with nothing legitimate in it.
		return []Category{CategoryEnumeration, CategoryCredentialAuditing, CategoryCredentialDumping}
	case ToolFamilyADCS:
		return []Category{CategoryEnumeration, Category("Configuration Auditing"), CategoryPrivilegeEscalation}
	case ToolFamilyActiveDirectory:
		return []Category{CategoryEnumeration, Category("Permissions Auditing"), CategoryPrivilegeEscalation}
	case ToolFamilySCCM:
		return []Category{CategoryEnumeration}
	case ToolFamilyNetwork:
		return []Category{Category("Host Discovery"), Category("Service Enumeration"), Category("Security Auditing")}
	default:
		return nil
	}
}

// ProtocolsForScope returns only protocols represented by the registered
// modules in a family/category. Empty scopes use N/A instead of stale values.
func ProtocolsForScope(registered []Module, family ToolFamily, category Category) []Protocol {
	seen := make(map[Protocol]bool)
	protocols := make([]Protocol, 0, 2)
	for _, module := range registered {
		if module.ToolFamily() == family && module.Category() == category && module.Protocol() != ProtocolNA && !seen[module.Protocol()] {
			seen[module.Protocol()] = true
			protocols = append(protocols, module.Protocol())
		}
	}
	if len(protocols) == 0 {
		return []Protocol{ProtocolNA}
	}
	return protocols
}

type Sensitivity string

const (
	SensitivityStandard  Sensitivity = "standard"
	SensitivitySensitive Sensitivity = "sensitive"
)

// Status is the display status of a registered module in the module list.
//
// It answers two different questions the operator has to be able to tell apart
// before pressing a key:
//
//   - StatusAvailable means there is nothing to warn about. PwnFlow shows no
//     suffix at all for it, because a suffix that says "fine" is noise on every
//     row of the list.
//   - StatusAdminRequired means the module needs elevated rights on the target -
//     local administrator, domain administrator, or another special right the
//     reason names. It is informational and never blocks execution: a module can
//     still return useful partial results without those rights.
//   - StatusUnavailable means the module cannot run at all in this environment:
//     a missing dependency, a build of the external tool that does not support
//     it, or configuration the operator has not supplied. It takes precedence
//     over StatusAdminRequired.
type Status uint8

const (
	StatusAvailable Status = iota
	StatusAdminRequired
	StatusUnavailable
)

// StatusProvider lets a module report its display status and, when it is not
// plainly available, the reason for that. Implementations are asked while the
// frame is drawn, so they may only read data that was gathered off the render
// path: no process spawns, no network, no filesystem work.
type StatusProvider interface {
	Status(*Runtime) Status
	StatusReason(*Runtime) string
}

// Endpoint is one SCCM-related system discovered during an assessment.
//
// Address is the validated IP address a prober can be pointed at; it is empty
// when discovery produced only a name that did not resolve, in which case the
// record is still kept so the operator can see what was found. Role and Source
// carry the provenance needed to explain why an address is in the list, and
// Domain scopes the record to the assessment it was discovered in. Credentials
// are never part of an endpoint.
type Endpoint struct {
	Address      string
	Hostname     string
	Role         string
	Source       string
	Domain       string
	DiscoveredAt time.Time
}

// EndpointStore persists and reports endpoints discovered by the current
// assessment. Discovery state is scoped by domain so a run can never consume
// another assessment's results.
type EndpointStore interface {
	RecordEndpoints(ctx context.Context, endpoints []Endpoint) error
	Endpoints(ctx context.Context, domain string) ([]Endpoint, error)
}

// DetailRefresher is implemented by modules whose Module Information needs work that
// is far too expensive to repeat while a frame is being drawn: a dependency probe, a
// revision check, a store read. DetailLines then only reads what this stored, and the
// TUI calls it off the render path.
type DetailRefresher interface {
	RefreshDetails(ctx context.Context, runtime *Runtime)
}

// ElevationPolicy is the operator's decision about running a module's external tool
// through sudo. The TUI asks for it before a batch starts; a module consults it at
// run time and never elevates itself, and a module that never asks is unaffected.
type ElevationPolicy interface {
	ElevationApproved(moduleID string) bool
}

// ElevationRequester is implemented by modules whose external tool needs privileges
// the process may not have. The TUI asks the operator for approval before such a
// module runs; the module itself never prompts, so the decision is always explicit
// and taken once per requested run.
type ElevationRequester interface {
	ElevationRequired() (bool, string)
}

type Runtime struct {
	Target, Domain, Username, Password, ResultsRoot string
	// ModuleOptions carries operator-supplied options for individual modules,
	// keyed by module ID and then by the option key the integration declared. It
	// exists so a module that needs a value the operator alone can supply - a
	// search term, a registry path, a listener address - is configured from the
	// operator's runtime configuration instead of being registered with a dummy
	// placeholder argument.
	ModuleOptions map[string]map[string]string
	// Endpoints is the assessment's discovery store. It is optional: a runtime
	// built without one still runs modules, which then report that discovery
	// cannot be persisted or read.
	Endpoints EndpointStore
	// Elevation carries the operator's approval for a module that needs elevated
	// execution. It is optional: a runtime without it means no module may elevate.
	Elevation ElevationPolicy
}

type OutputSink interface{ Write([]byte) (int, error) }

// ModuleOption returns the operator-supplied value for one option of one module.
// A runtime built without a module-options map answers "not supplied" for every
// key, which is what makes a module that requires one report itself unavailable
// rather than run with a guess.
func (r *Runtime) ModuleOption(moduleID, key string) (string, bool) {
	if r == nil || len(r.ModuleOptions) == 0 {
		return "", false
	}
	options, ok := r.ModuleOptions[moduleID]
	if !ok {
		return "", false
	}
	value, ok := options[key]
	if !ok || value == "" {
		return "", false
	}
	return value, true
}

type Module interface {
	ID() string
	Name() string
	ToolFamily() ToolFamily
	Category() Category
	Tool() string
	Protocol() Protocol
	Description() string
	Prerequisites() []string
	RequiredPrivileges() []string
	OutputFile() string
	Sensitivity() Sensitivity
	ReadOnly() bool
	SecondaryConnections() []string
	Check(context.Context, *Runtime) error
	Run(context.Context, *Runtime, OutputSink) error
}

// ExecutionPolicy is implemented by integrations that intentionally keep a
// registered module out of execution until a separate workflow is approved.
type ExecutionPolicy interface {
	ExecutionEnabled() bool
	AvailabilityReason() string
}

type CommandPreviewProvider interface {
	CommandPreview(*Runtime) string
}

// OptionDeclarer is implemented by modules that accept operator-supplied
// options. PwnFlow checks the operator's configuration against it at startup so
// a mistyped option key is reported instead of being silently dropped.
type OptionDeclarer interface {
	OptionKeys() []string
}

// OptionWarnings reports configured module options that no registration will
// use: an unknown module ID, or an option key the module does not declare.
// Passing an unknown `-o` key would do nothing at all on the target, so the
// operator has to see it rather than discover it later.
func OptionWarnings(registered []Module, options map[string]map[string]string) []string {
	if len(options) == 0 {
		return nil
	}
	byID := make(map[string]Module, len(registered))
	for _, module := range registered {
		byID[module.ID()] = module
	}
	ids := make([]string, 0, len(options))
	for id := range options {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	warnings := make([]string, 0)
	for _, id := range ids {
		module, ok := byID[id]
		if !ok {
			warnings = append(warnings, fmt.Sprintf("no registered module has the id %q; its options are ignored", id))
			continue
		}
		declarer, ok := module.(OptionDeclarer)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("%s does not accept module options; its options are ignored", id))
			continue
		}
		declared := make(map[string]bool)
		for _, key := range declarer.OptionKeys() {
			declared[key] = true
		}
		keys := make([]string, 0, len(options[id]))
		for key := range options[id] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if !declared[key] {
				warnings = append(warnings, fmt.Sprintf("%s does not use the option %s; it is ignored", id, key))
			}
		}
	}
	return warnings
}

// DependencyKeyProvider is implemented by modules whose availability is gated by
// a dependency registry entry with a different ID, such as a tool that
// contributes several modules under one installed program.
type DependencyKeyProvider interface {
	DependencyKey() string
}

// BatchPrerequisiteProvider is implemented by modules that must run after other
// modules in the same batch, such as a prober that consumes a discovery module's
// freshly written results. The named modules are matched by their IDs.
type BatchPrerequisiteProvider interface {
	BatchPrerequisites() []string
}

// DetailProvider is implemented by modules that expose their fixed configuration
// in the Module Information pane, such as a pinned collection method or the
// expected output directory. Lines must be cheap to compute and free of
// secrets: the TUI renders them on every frame.
type DetailProvider interface {
	DetailLines(*Runtime) []string
}
