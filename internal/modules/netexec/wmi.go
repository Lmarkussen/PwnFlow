package netexec

import "github.com/pwnflow/pwnflow/internal/modules"

// WMI keeps the two capabilities that are WMI's own: the credential check, and
// the shadow-copy listing, which is a native WMI query with no SMB equivalent.
//
// The modules WMI shares with SMB - bitlocker, enum_dns, get_netconnections,
// ioxidresolver, spooler, zerologon, ntds-dump-raw - are registered once, under
// SMB, so the same check does not appear twice in the menu. The native
// --wmi-query flag takes an operator-supplied WQL statement and the -x/-X flags
// run code on the target; both are documented rather than registered.

func WMIEnumerationModules() []modules.Module {
	return level(modules.CategoryEnumeration, modules.ProtocolWMI, []entry{
		{
			id: "wmi-auth-check", name: "WMI Authentication Check",
			description: "Authenticates over DCOM/RPC and prints the result without running anything. It establishes whether the channel a later WMI module needs is available to the account.",
			output:      "WMI_auth_check.txt",
		},
		{
			id: "wmi-list-snapshots", name: "List Volume Shadow Copies",
			description: "Lists the volume shadow copies present on the target through the --list-snapshots native flag. A host without shadow copies answers with an empty list, which is itself the result.",
			args:        []string{"--list-snapshots"}, output: "WMI_list_snapshots.txt",
		},
	})
}
