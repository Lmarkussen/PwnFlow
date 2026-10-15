package netexec

import (
	"strings"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// Gate reasons. A gated registration is listed with its requirement, shows
// UNAVAILABLE, and refuses to run. They exist for modules that change state on
// the target, execute code there, or export credential material: those must be
// selected deliberately instead of being swept up by a category-wide run, and
// they need a decision the operator has not been asked for yet.
const (
	gateStateChange    = "execution gated: this module changes state on the target"
	gateExecution      = "execution gated: this module executes code or delivers a payload on the target"
	gateCoercion       = "execution gated: this module coerces target authentication or writes lure files to shares"
	gateCredentialDump = "execution gated: this module extracts credential material and needs an approved sensitive-artifact workflow"
	gateKerberosTicket = "execution gated: exported Kerberos ticket material needs an approved sensitive-artifact workflow"
)

// entry is the authoring form of a registration. It keeps the tables readable:
// every field an operator has to understand is visible on one line of the table.
type entry struct {
	// id is the stable PwnFlow identifier. It is the key selection, output
	// paths, and module information use.
	id string
	// name is what the operator reads in the module list.
	name string
	// description explains the effect, the target type, and the privilege the
	// module needs, in the operator's terms.
	description string
	category    modules.Category
	protocol    modules.Protocol
	// args are the native protocol flags.
	args []string
	// module is the `-M` value, empty for a native command.
	module string
	// options are the module option keys accepted from the operator through
	// --module-options; required lists the subset without which the module
	// cannot do anything, and they were taken from the module's own --options.
	options  []string
	required []string
	// admin names the elevated target-side right, empty when the module needs
	// nothing beyond valid credentials.
	admin string
	// gated is one of the gate reasons above, empty for an executable module.
	gated string
	// sensitive marks a module whose output is credential material.
	sensitive bool
	// output overrides the derived artifact name. It is set for registrations
	// that already write into an existing assessment tree, so upgrading PwnFlow
	// never orphans collected evidence.
	output string
}

func (e entry) definition() Definition {
	description := e.description
	if description == "" {
		description = e.name + " through NetExec " + string(e.protocol) + "."
	}
	sensitivity := modules.SensitivityStandard
	if e.sensitive {
		sensitivity = modules.SensitivitySensitive
	}
	output := e.output
	if output == "" {
		output = artifactName(e)
	}
	prerequisites := []string{"nxc executable"}
	if e.module != "" {
		prerequisites = append(prerequisites, "nxc "+protocolCommand(e.protocol)+" -M "+e.module)
	}
	privileges := []string(nil)
	if e.admin != "" {
		privileges = []string{e.admin}
	}
	return Definition{
		IDValue: e.id, NameValue: e.name, DescriptionValue: description,
		ToolValue: "NetExec (nxc)", ToolFamilyValue: modules.ToolFamilyNetExec,
		CategoryValue: e.category, ProtocolValue: e.protocol,
		Arguments: e.args, ModuleName: e.module,
		OptionKeys: e.options, RequiredOptions: e.required,
		OutputValue: output, PrerequisiteValues: prerequisites,
		RequiredPrivilegeValues: privileges,
		AdminRequiredValue:      e.admin != "",
		AdminReasonValue:        e.admin,
		GatedReasonValue:        e.gated,
		SensitivityValue:        sensitivity,
		// Every registration in the tables is non-destructive: the modules that
		// do write, coerce, or execute are gated, and a gated module is listed
		// under the category whose name says what it is.
		ReadOnlyValue: e.gated == "" || e.gated == gateCredentialDump || e.gated == gateKerberosTicket,
	}
}

// artifactName derives the persisted output name from the NetExec module name
// where there is one, so the artifact says which `-M` module produced it.
func artifactName(e entry) string {
	source := e.module
	if source == "" {
		source = strings.TrimPrefix(e.id, strings.ToLower(string(e.protocol))+"-")
	}
	source = strings.NewReplacer("-", "_", " ", "_", "/", "_").Replace(source)
	return strings.ToUpper(string(e.protocol)) + "_" + source + ".txt"
}

func definitions(entries []entry) []Definition {
	result := make([]Definition, 0, len(entries))
	for _, item := range entries {
		result = append(result, item.definition())
	}
	return result
}

// admin reasons, phrased as the right the target must grant.
const (
	adminLocal  = "local administrator on the target"
	adminDomain = "domain administrator or equivalent directory rights"
	adminDC     = "local administrator on the domain controller"
	adminRemote = "local administrator with remote registry or service access"
)

func level(category modules.Category, protocol modules.Protocol, entries []entry) []modules.Module {
	for index := range entries {
		entries[index].category = category
		entries[index].protocol = protocol
	}
	return buildModules(definitions(entries))
}

// moduleEntries filters a protocol's table down to the `-M` registrations, which
// is the list the coverage tests compare against `nxc <protocol> -L`.
func moduleEntries(entries []entry) map[string]bool {
	names := make(map[string]bool)
	for _, item := range entries {
		if item.module != "" {
			names[item.module] = true
		}
	}
	return names
}
