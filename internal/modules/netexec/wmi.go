package netexec

import "github.com/pwnflow/pwnflow/internal/modules"

// WMI is a read-heavy protocol with three low-privilege checks, three
// administrator-level enumeration modules, and a dumping path. The native
// --wmi-query flag takes an operator-supplied query, so it is documented in the
// inventory rather than registered: PwnFlow's option mechanism passes module
// options, which a native flag does not accept.

func WMIEnumerationModules() []modules.Module {
	return level(modules.CategoryEnumeration, modules.ProtocolWMI, []entry{
		{
			id: "wmi-auth-check", name: "WMI Authentication Check",
			description: "Authenticates over DCOM/RPC and prints the result without running anything. It establishes whether the channel a later WMI module needs is available to the account.",
			output:      "WMI_auth_check.txt",
		},
		{
			id: "wmi-ioxidresolver", name: "Detect Additional Interfaces",
			description: "Identifies hosts that answer on more interfaces than the target address through -M ioxidresolver.",
			module:      "ioxidresolver",
		},
		{
			id: "wmi-list-snapshots", name: "List Volume Shadow Copies",
			description: "Lists the volume shadow copies present on the target through the --list-snapshots native flag. A host without shadow copies answers with an empty list, which is itself the result.",
			args:        []string{"--list-snapshots"}, output: "WMI_list_snapshots.txt",
		},
		{
			id: "wmi-spooler", name: "Check Print Spooler",
			description: "Detects whether the print spooler is running through -M spooler, the precondition for printer coercion.",
			module:      "spooler",
		},
		{
			id: "wmi-zerologon", name: "Check Zerologon (CVE-2020-1472)",
			description: "Checks whether a domain controller is vulnerable to Zerologon through -M zerologon. Detection only.",
			module:      "zerologon",
		},
		{
			id: "wmi-bitlocker", name: "Enumerate BitLocker Status",
			description: "Reports whether BitLocker is enabled through -M bitlocker. Needs " + adminLocal + ".",
			module:      "bitlocker", admin: adminLocal,
		},
		{
			id: "wmi-enum-dns", name: "Enumerate DNS Zones",
			description: "Dumps DNS zones from an AD DNS server through -M enum_dns. Needs " + adminLocal + ".",
			module:      "enum_dns", admin: adminLocal,
		},
		{
			id: "wmi-get-netconnections", name: "Enumerate Network Connections",
			description: "Queries active network connections through -M get_netconnections. Needs " + adminLocal + ".",
			module:      "get_netconnections", admin: adminLocal,
		},
	})
}

func WMIPrivilegeEscalationModules() []modules.Module {
	return level(modules.CategoryPrivilegeEscalation, modules.ProtocolWMI, []entry{
		{
			id: "wmi-rdp-toggle", name: "Enable or Disable RDP",
			description: "Turns the RDP service on or off through -M rdp. " + gateStateChange + "; needs " + adminLocal + ".",
			module:      "rdp", gated: gateStateChange, admin: adminLocal, sensitive: true,
		},
	})
}

func WMICredentialDumpingModules() []modules.Module {
	return level(modules.CategoryCredentialDumping, modules.ProtocolWMI, []entry{
		{
			id: "wmi-ntds-dump-raw", name: "Dump NTDS, SAM and SYSTEM (raw)",
			description: "Reads ntds.dit, SAM, and SYSTEM through the raw drive with -M ntds-dump-raw. " + gateCredentialDump + "; needs " + adminDC + ".",
			module:      "ntds-dump-raw", gated: gateCredentialDump, admin: adminDC, sensitive: true,
		},
	})
}
