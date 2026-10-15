package netexec

import (
	"strings"

	"github.com/pwnflow/pwnflow/internal/modules"
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
	// optionDefaults and dynamicOptions pre-fill module options that have an
	// obvious starting point, so the module is usable without the operator
	// configuring anything first.
	optionDefaults map[string]string
	dynamicOptions map[string]func(*modules.Runtime) string
	// dynamicArgs contribute runtime-dependent arguments.
	dynamicArgs func(*modules.Runtime) []string
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
		OptionDefaults: e.optionDefaults, DynamicOptions: e.dynamicOptions,
		DynamicArgs: e.dynamicArgs,
		OutputValue: output, PrerequisiteValues: prerequisites,
		RequiredPrivilegeValues: privileges,
		AdminRequiredValue:      e.admin != "",
		AdminReasonValue:        e.admin,
		SensitivityValue:        sensitivity,
		// Every registration in the tables reads: it asks the target for
		// information, or exports authentication material for offline auditing.
		// Nothing here writes to the target, runs code on it, or starts a
		// listener, which is why no registration needs a deeper guard than the
		// category it is filed under.
		ReadOnlyValue: true,
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
