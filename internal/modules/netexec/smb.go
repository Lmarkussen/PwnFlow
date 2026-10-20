package netexec

import (
	"path/filepath"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// SMB keeps the plain `nxc smb <target>` shape: no LDAP transport flags are
// passed, and the domain is supplied with `-d` because SMB authentication
// against a domain-joined host needs it.
//
// SMB covers what only SMB can see - a host's shares, sessions, local groups,
// endpoint protection, and its security configuration - plus the vulnerability
// checks that are SMB checks. Domain-wide data (users, groups, computers,
// password policy) is read over LDAP instead, so it appears once: see
// docs/netexec-inventory.md for the mapping.

// SMBEnumerationModules are read-only. The rows marked ADMIN-REQ still run
// without those rights and report the refusal, which is a result in itself.
func SMBEnumerationModules() []modules.Module {
	return level(modules.CategoryEnumeration, modules.ProtocolSMB, []entry{
		{
			id: "smb-server-info", name: "SMB Server Information",
			description: "Authenticates and reports the host name, operating system build, SMB signing state, and SMBv1 state - the baseline before any share work.",
			output:      "SMB_server_info.txt",
		},
		{
			id: "smb-shares", name: "SMB Shares",
			description: "Enumerates shares and the permissions the authenticated account has on each one.",
			args:        []string{"--shares"}, output: "SMB_shares.txt",
		},
		{
			id: "smb-spider-plus", name: "SMB Spider Plus",
			description: "Recursively inventories metadata from readable SMB shares without downloading file contents. Automatic runs use approved current-batch NetworkHound TCP/445 results; manual runs may provide exact SMB_ENDPOINTS.",
			module:      "spider_plus", runtimeOnly: []string{"SMB_ENDPOINTS"},
			forcedOptions: map[string]func(*modules.Runtime) string{"OUTPUT_FOLDER": spiderOutputFolder},
		},
		{
			id: "smb-disks", name: "SMB Disks",
			description: "Enumerates local disks through --disks.",
			args:        []string{"--disks"}, output: "SMB_disks.txt",
		},
		{
			id: "smb-local-groups", name: "Local Groups",
			description: "Enumerates local groups and their members through --local-groups. Remote SAMR queries for local group membership need " + adminLocal + ".",
			args:        []string{"--local-groups"}, admin: adminLocal, output: "SMB_local_groups.txt",
		},
		{
			id: "smb-sessions", name: "SMB Sessions",
			description: "Enumerates active SMB sessions through --smb-sessions. The session table is only readable with " + adminLocal + ".",
			args:        []string{"--smb-sessions"}, admin: adminLocal, output: "SMB_sessions.txt",
		},
		{
			id: "logged-on-users", name: "Logged-on Users",
			description: "Lists interactive sessions through --loggedon-users, which shows which accounts are signed in and where " + adminLocal + " is available.",
			args:        []string{"--loggedon-users"}, admin: adminLocal, output: "SMB_loggedon_users.txt",
		},
		{
			id: "registry-sessions", name: "Registry Sessions",
			description: "Reads the registry session table through --reg-sessions, an alternative view of logged-on users that needs " + adminRemote + ".",
			args:        []string{"--reg-sessions"}, admin: adminRemote, output: "SMB_registry_sessions.txt",
		},
		{
			id: "terminal-sessions", name: "Terminal Sessions",
			description: "Lists RDP/terminal sessions through --qwinsta, which needs " + adminLocal + ".",
			args:        []string{"--qwinsta"}, admin: adminLocal, output: "SMB_terminal_sessions.txt",
		},
		{
			id: "running-processes", name: "Running Processes",
			description: "Lists processes with --tasklist, including the accounts that own them. Needs " + adminLocal + ".",
			args:        []string{"--tasklist"}, admin: adminLocal, output: "SMB_running_processes.txt",
		},
		{
			id: "smb-enum-av", name: "Enumerate Endpoint Protection",
			description: "Gathers the endpoint protection products installed on the target through -M enum_av, which is what decides how a later stage may have to be adapted.",
			module:      "enum_av",
		},
		{
			id: "smb-enum-ca", name: "Find AD CS CAs via RPC",
			description: "Hunts for certificate authorities through unauthenticated RPC endpoints with -M enum_ca. It complements the LDAP AD CS search, which reads the directory instead of the RPC endpoints.",
			module:      "enum_ca",
		},
		{
			id: "smb-gpp-privileges", name: "Extract GPO-Assigned Privileges",
			description: "Extracts privileges assigned through Group Policy objects and resolves the SIDs through LDAP with -M gpp_privileges.",
			module:      "gpp_privileges", options: []string{"NO_LDAP"},
		},
		{
			id: "smb-ioxidresolver", name: "Detect Additional Interfaces",
			description: "Identifies hosts that answer on more interfaces than the target address through -M ioxidresolver.",
			module:      "ioxidresolver", options: []string{"DIFFERENT"},
		},
		{
			id: "smb-ms17-010", name: "Check MS17-010 (EternalBlue)",
			description: "Checks whether the target is vulnerable to MS17-010 through -M ms17-010. Detection only; the module is marked as lab-only upstream and is never exploited from here.",
			module:      "ms17-010",
		},
		{
			id: "smb-nopac", name: "Check noPac (CVE-2021-42278/42287)",
			description: "Checks whether a domain controller is vulnerable to the noPac impersonation chain through -M nopac using a normal domain account.",
			module:      "nopac",
		},
		{
			id: "smb-ntlm-reflection", name: "Check NTLM Reflection (CVE-2025-33073)",
			description: "Checks whether the operating system is vulnerable to the NTLM reflection attack through -M ntlm_reflection.",
			module:      "ntlm_reflection",
		},
		{
			id: "smb-printnightmare", name: "Check PrintNightmare",
			description: "Checks whether the target is vulnerable to PrintNightmare through -M printnightmare. Detection only.",
			module:      "printnightmare", options: []string{"PORT"},
		},
		{
			id: "smb-remove-mic", name: "Check CVE-2019-1040 (Drop MIC)",
			description: "Checks whether the target accepts NTLM authentication messages without the MIC through -M remove-mic.",
			module:      "remove-mic", options: []string{"PORT"},
		},
		{
			id: "smb-sccm-recon6", name: "Check SCCM Site Role",
			description: "Checks whether the target is an SCCM distribution point or primary site server through -M sccm-recon6 (RECON-6), which reads the site role from the host's registry representation.",
			module:      "sccm-recon6",
		},
		{
			id: "smb-smbghost", name: "Check SMBGhost (CVE-2020-0796)",
			description: "Reports the SMB dialect and compression capability that indicate SMBGhost through -M smbghost.",
			module:      "smbghost",
		},
		{
			id: "smb-spooler", name: "Check Print Spooler",
			description: "Detects whether the print spooler service is running through -M spooler, the precondition for printer coercion paths.",
			module:      "spooler", options: []string{"PORT"},
		},
		{
			id: "smb-webdav", name: "Check WebClient Service",
			description: "Checks whether the WebClient service is running through -M webdav.",
			module:      "webdav", options: []string{"MSG"},
		},
		{
			id: "smb-zerologon", name: "Check Zerologon (CVE-2020-1472)",
			description: "Checks whether a domain controller is vulnerable to Zerologon through -M zerologon. Detection only.",
			module:      "zerologon",
		},
		{
			id: "smb-bitlocker", name: "Enumerate BitLocker Status",
			description: "Reports whether BitLocker is enabled on the target's volumes through -M bitlocker. Enumerating recovery information needs " + adminLocal + ".",
			module:      "bitlocker", admin: adminLocal,
		},
		{
			id: "smb-enum-dns", name: "Enumerate DNS Zones",
			description: "Dumps DNS zones from an AD DNS server through -M enum_dns. Reading zone data needs " + adminLocal + ".",
			module:      "enum_dns", admin: adminLocal,
		},
		{
			id: "smb-enum-interfaces", name: "Enumerate Interfaces via Registry",
			description: "Reads interface names, addresses, masks, and gateways from the remote registry through -M enum_interfaces, the module that superseded the --interfaces flag. Needs " + adminRemote + ".",
			module:      "enum_interfaces", admin: adminRemote,
		},
		{
			id: "smb-get-netconnections", name: "Enumerate Network Connections",
			description: "Queries active network connections through -M get_netconnections, which uses WMI on the target. Needs " + adminLocal + ".",
			module:      "get_netconnections", admin: adminLocal,
		},
		{
			id: "smb-hyperv-host", name: "Find Hyper-V Host",
			description: "Reads the registry value that names the Hyper-V host of a virtual machine through -M hyperv-host. Needs " + adminRemote + ".",
			module:      "hyperv-host", admin: adminRemote,
		},
		{
			id: "smb-install-elevated", name: "Check AlwaysInstallElevated",
			description: "Checks the AlwaysInstallElevated policy through -M install_elevated, a local privilege-escalation precondition. Needs " + adminRemote + " to read the policy keys.",
			module:      "install_elevated", admin: adminRemote,
		},
		{
			id: "smb-keepass-discover", name: "Discover KeePass Files",
			description: "Searches the target for KeePass databases and processes through -M keepass_discover. It locates files; it does not open them. Needs " + adminLocal + ".",
			module:      "keepass_discover", admin: adminLocal,
		},
		{
			id: "smb-lockscreendoors", name: "Detect Lock Screen Backdoors",
			description: "Checks the file descriptions of accessibility binaries for lock-screen backdoors through -M lockscreendoors. Needs " + adminLocal + ".",
			module:      "lockscreendoors", admin: adminLocal,
		},
		{
			id: "smb-ntlmv1", name: "Check NTLMv1 Compatibility Level",
			description: "Reads LmCompatibilityLevel through -M ntlmv1 to report whether NTLMv1 is still permitted. Needs " + adminRemote + ".",
			module:      "ntlmv1", admin: adminRemote,
		},
		{
			id: "smb-presence", name: "Trace Domain Admin Presence",
			description: "Traces where domain and enterprise administrators are signed in through -M presence. Needs " + adminLocal + " to read the session tables.",
			module:      "presence", admin: adminLocal,
		},
		{
			id: "smb-reg-query", name: "Query Registry Key",
			description: "Reads one registry key through -M reg-query, defaulting to the key that names the operating system. Only the read path is exposed here, never the module's write capability. Needs " + adminRemote + ".",
			module:      "reg-query", options: []string{"PATH", "KEY"},
			optionDefaults: map[string]string{"PATH": `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`},
			admin:          adminRemote,
		},
		{
			id: "smb-runasppl", name: "Check RunAsPPL",
			description: "Reads the RunAsPPL registry value through -M runasppl, which reports whether LSASS protection is enabled. Needs " + adminRemote + ".",
			module:      "runasppl", admin: adminRemote,
		},
		{
			id: "smb-uac", name: "Check UAC Status",
			description: "Checks the local UAC configuration through -M uac. Needs " + adminRemote + ".",
			module:      "uac", admin: adminRemote,
		},
		{
			id: "smb-wcc", name: "Run Windows Configuration Check",
			description: "Checks security configuration items through -M wcc and writes its report into the assessment tree, unless the operator points -o OUTPUT elsewhere. Needs " + adminLocal + ".",
			module:      "wcc", options: []string{"OUTPUT_FORMAT", "OUTPUT", "QUIET"},
			dynamicOptions: map[string]func(*modules.Runtime) string{
				"OUTPUT": wccReportPath,
			},
			admin: adminLocal,
		},
	})
}

// SMBCredentialDumpingModules read secrets that a file share or an SMB read
// exposes. They need no code execution on the target and no listener: Group
// Policy Preferences decrypt with a published key, and the share walker only
// lists metadata.
func SMBCredentialDumpingModules() []modules.Module {
	return level(modules.CategoryCredentialDumping, modules.ProtocolSMB, []entry{
		{
			id: "smb-gpp-autologin", name: "GPP Autologin Credentials",
			description: "Reads registry.xml from SYSVOL through -M gpp_autologin to recover autologon credentials pushed by Group Policy Preferences.",
			module:      "gpp_autologin", sensitive: true,
		},
		{
			id: "smb-gpp-password", name: "GPP Passwords",
			description: "Decrypts the cpassword values that Group Policy Preferences pushed through -M gpp_password. The decryption key is published, so this only needs read access to SYSVOL.",
			module:      "gpp_password", sensitive: true,
		},
		{
			id: "smb-aws-credentials", name: "Search for AWS Credentials",
			description: "Searches shares for AWS credential files through -M aws-credentials. Reads only; nothing is written to the target.",
			module:      "aws-credentials", sensitive: true,
		},
	})
}

// wccReportPath keeps a module's report file inside the assessment tree, so a run
// never writes into the working directory.
func wccReportPath(runtime *modules.Runtime) string {
	if runtime.ResultsRoot == "" {
		return ""
	}
	return filepath.Join(runtime.ResultsRoot, "Enumeration", "NetExec", "SMB_wcc_report.json")
}
