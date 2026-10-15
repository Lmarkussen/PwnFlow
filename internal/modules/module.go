package modules

import "context"

type ToolFamily string

const (
	ToolFamilyNetExec         ToolFamily = "NetExec"
	ToolFamilyADCS            ToolFamily = "AD CS"
	ToolFamilyActiveDirectory ToolFamily = "Active Directory"
	ToolFamilyNetwork         ToolFamily = "Network"
)

func ToolFamilies() []ToolFamily {
	return []ToolFamily{ToolFamilyNetExec, ToolFamilyADCS, ToolFamilyActiveDirectory, ToolFamilyNetwork}
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
	ProtocolNA   Protocol = "N/A"
	ProtocolLDAP Protocol = "LDAP"
	ProtocolSMB  Protocol = "SMB"
)

func Protocols() []Protocol { return []Protocol{ProtocolLDAP, ProtocolSMB} }

// CategoriesForFamily describes the navigation taxonomy, including inactive
// future categories that have no executable modules yet.
func CategoriesForFamily(family ToolFamily) []Category {
	switch family {
	case ToolFamilyNetExec:
		return []Category{CategoryEnumeration, CategoryCredentialAuditing, CategoryCredentialDumping, CategoryPrivilegeEscalation}
	case ToolFamilyADCS:
		return []Category{CategoryEnumeration, Category("Configuration Auditing"), CategoryPrivilegeEscalation}
	case ToolFamilyActiveDirectory:
		return []Category{CategoryEnumeration, Category("Permissions Auditing"), CategoryPrivilegeEscalation}
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

type Runtime struct{ Target, Domain, Username, Password, ResultsRoot string }
type OutputSink interface{ Write([]byte) (int, error) }
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

// DependencyKeyProvider is implemented by modules whose availability is gated by
// a dependency registry entry with a different ID, such as a tool that
// contributes several modules under one installed program.
type DependencyKeyProvider interface {
	DependencyKey() string
}

// DetailProvider is implemented by modules that expose their fixed configuration
// in the Module Information pane, such as a pinned collection method or the
// expected output directory. Lines must be cheap to compute and free of
// secrets: the TUI renders them on every frame.
type DetailProvider interface {
	DetailLines(*Runtime) []string
}
