package netexec

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// TestDumpInventoryTables renders the registration tables as Markdown when
// PWNFLOW_DUMP_INVENTORY is set. It exists so docs/netexec-inventory.md can be
// regenerated from the registry instead of transcribed by hand.
func TestDumpInventoryTables(t *testing.T) {
	if strings.TrimSpace(os.Getenv("PWNFLOW_DUMP_INVENTORY")) == "" {
		t.Skip("set PWNFLOW_DUMP_INVENTORY=1 to print the inventory tables")
	}
	byModule := map[modules.Protocol]map[string]Module{}
	native := map[modules.Protocol][]Module{}
	for _, raw := range RegisteredModules() {
		entry := raw.(Module)
		if entry.ModuleName() == "" {
			native[entry.Protocol()] = append(native[entry.Protocol()], entry)
			continue
		}
		if byModule[entry.Protocol()] == nil {
			byModule[entry.Protocol()] = map[string]Module{}
		}
		byModule[entry.Protocol()][entry.ModuleName()] = entry
	}
	for _, protocol := range modules.Protocols() {
		fmt.Printf("\n### %s\n\n", protocol)
		if len(native[protocol]) > 0 {
			fmt.Printf("| native flag | registration | category | privilege |\n|---|---|---|---|\n")
			sort.Slice(native[protocol], func(i, j int) bool { return native[protocol][i].ID() < native[protocol][j].ID() })
			for _, entry := range native[protocol] {
				fmt.Printf("| %s | %s | %s | %s |\n", strings.Join(entry.definition.Arguments, " "), entry.ID(), entry.Category(), privilege(entry))
			}
		}
		modulesHere := byModule[protocol]
		if len(modulesHere) > 0 {
			names := make([]string, 0, len(modulesHere))
			for name := range modulesHere {
				names = append(names, name)
			}
			sort.Strings(names)
			fmt.Printf("\n| -M module | registration | category | privilege | options |\n|---|---|---|---|---|\n")
			for _, name := range names {
				entry := modulesHere[name]
				fmt.Printf("| %s | %s | %s | %s | %s |\n", name, entry.ID(), entry.Category(), privilege(entry), strings.Join(entry.definition.OptionKeys, ", "))
			}
		}
	}
}

func privilege(entry Module) string {
	switch {
	case !entry.ExecutionEnabled():
		return "gated"
	case entry.definition.AdminRequiredValue:
		return "ADMIN-REQ"
	default:
		return "-"
	}
}
