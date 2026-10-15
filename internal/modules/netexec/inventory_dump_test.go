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
	// A machine-readable line per module with declared options, so the declared
	// keys can be compared with `nxc <protocol> -M <module> --options`.
	counts := map[string]int{}
	for _, raw := range RegisteredModules() {
		entry := raw.(Module)
		counts[string(entry.Protocol())+" "+string(entry.Category())]++
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Printf("COUNT %s %d\n", key, counts[key])
	}
	names := make([]string, 0, len(byModule))
	for protocol, entries := range byModule {
		for name := range entries {
			names = append(names, string(protocol)+" "+name)
		}
	}
	sort.Strings(names)
	for _, qualified := range names {
		for protocol, entries := range byModule {
			name := strings.TrimPrefix(qualified, string(protocol)+" ")
			if name == qualified {
				continue
			}
			entry, ok := entries[name]
			if !ok {
				continue
			}
			fmt.Printf("OPTIONS %s %s %s\n", protocol, name, strings.Join(entry.definition.OptionKeys, ","))
		}
	}
}

func privilege(entry Module) string {
	switch {
	case entry.definition.AdminRequiredValue:
		return "ADMIN-REQ"
	default:
		return "-"
	}
}
