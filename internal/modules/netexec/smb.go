package netexec

import "github.com/pwnflow/pwnflow/internal/modules"

// SMB keeps the plain `nxc smb <target>` shape: no LDAP transport flags are
// passed, and the domain is supplied with `-d` because SMB authentication
// against a domain-joined host needs it. The registrations below were checked
// against `nxc smb --help` and `nxc smb -L` from the installed 1.5.1 build. The
// retired SMB modules (petitpotam, printerbug, shadowcoerce, dfscoerce,
// efsr_spray, firefox) are deliberately absent.

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
			id: "smb-disks", name: "SMB Disks",
			description: "Enumerates local disks through --disks.",
			args:        []string{"--disks"}, output: "SMB_disks.txt",
		},
		{
			id: "smb-domain-users", name: "Domain Users via SMB",
			description: "Enumerates domain users through the SAMR/SMB path with --users.",
			args:        []string{"--users"}, output: "SMB_domain_users.txt",
		},
		{
			id: "smb-domain-groups", name: "Domain Groups via SMB",
			description: "Enumerates domain groups through the SAMR/SMB path with --groups.",
			args:        []string{"--groups"}, output: "SMB_domain_groups.txt",
		},
		{
			id: "smb-local-groups", name: "Local Groups",
			description: "Enumerates local groups and their members through --local-groups. Remote SAMR queries for local group membership need " + adminLocal + ".",
			args:        []string{"--local-groups"}, admin: adminLocal, output: "SMB_local_groups.txt",
		},
		{
			id: "smb-domain-computers", name: "Domain Computers via SMB",
			description: "Enumerates computer accounts through the SAMR/SMB path with --computers.",
			args:        []string{"--computers"}, output: "SMB_domain_computers.txt",
		},
		{
			id: "smb-password-policy", name: "SMB Password Policy",
			description: "Reads the password and lockout policy with --pass-pol, which bounds any later authentication testing.",
			args:        []string{"--pass-pol"}, output: "SMB_password_policy.txt",
		},
		{
			id: "smb-rid-brute", name: "SMB RID Brute",
			description: "Enumerates accounts by walking RID values through --rid-brute when SAMR lookups are available. It works without elevated rights but is loud in target logs.",
			args:        []string{"--rid-brute"}, output: "SMB_rid_brute.txt",
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
			id: "network-interfaces", name: "Network Interfaces",
			description: "Enumerates network interfaces through the --interfaces native query, which needs " + adminRemote + ". The equivalent -M enum_interfaces module is registered separately.",
			args:        []string{"--interfaces"}, admin: adminRemote, output: "SMB_network_interfaces.txt",
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
			description: "Hunts for certificate authorities through unauthenticated RPC endpoints with -M enum_ca.",
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
			description: "Checks whether the target accepts NTLM authentication messages without the MIC through -M remove-mic, a relay precondition.",
			module:      "remove-mic", options: []string{"PORT"},
		},
		{
			id: "smb-sccm-recon6", name: "Check SCCM Site Role",
			description: "Checks whether the target is an SCCM distribution point or primary site server through -M sccm-recon6 (RECON-6), which reads the site role from the registry representation.",
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
			description: "Checks whether the WebClient service is running through -M webdav, the precondition for HTTP-based coercion.",
			module:      "webdav", options: []string{"MSG"},
		},
		{
			id: "smb-zerologon", name: "Check Zerologon (CVE-2020-1472)",
			description: "Checks whether a domain controller is vulnerable to Zerologon through -M zerologon. Detection only; the exploit path is gated separately.",
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
			description: "Reads interface names, addresses, masks, and gateways from the remote registry through -M enum_interfaces, the module that replaced the --interfaces flag. Needs " + adminRemote + ".",
			module:      "enum_interfaces", admin: adminRemote,
		},
		{
			id: "smb-get-netconnections", name: "Enumerate Network Connections",
			description: "Queries active network connections through -M get_netconnections. Needs " + adminLocal + " for the WMI query.",
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
			description: "Searches the target for KeePass databases and processes through -M keepass_discover. Needs " + adminLocal + ".",
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
			description: "Reads one registry key through -M reg-query. The operator names the path with --module-options; only the read path is exposed here, never the module's write capability. Needs " + adminRemote + ".",
			module:      "reg-query", options: []string{"PATH", "KEY"}, required: []string{"PATH"}, admin: adminRemote,
		},
		{
			id: "smb-runasppl", name: "Check RunAsPPL",
			description: "Reads the RunAsPPL registry value through -M runasppl, which decides whether LSASS protection would block a later dump. Needs " + adminRemote + ".",
			module:      "runasppl", admin: adminRemote,
		},
		{
			id: "smb-test-connection", name: "Ping Host",
			description: "Pings the target from its own perspective through -M test_connection. The operator names the host to ping with --module-options. Needs " + adminLocal + ".",
			module:      "test_connection", options: []string{"HOST"}, required: []string{"HOST"}, admin: adminLocal,
		},
		{
			id: "smb-uac", name: "Check UAC Status",
			description: "Checks the local UAC configuration through -M uac. Needs " + adminRemote + ".",
			module:      "uac", admin: adminRemote,
		},
		{
			id: "smb-wcc", name: "Run Windows Configuration Check",
			description: "Checks security configuration items through -M wcc and writes its report to the path the operator supplies with --module-options. Needs " + adminLocal + ".",
			module:      "wcc", options: []string{"OUTPUT_FORMAT", "OUTPUT", "QUIET"}, required: []string{"OUTPUT"}, admin: adminLocal,
		},
	})
}

// SMBCredentialDumpingModules access credential material through SMB. The
// discovery modules are read-only against the target; the extraction modules
// are gated because their output is credential material that needs an approved
// artifact workflow, and several of them also modify the target.
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
		{
			id: "smb-spider-plus", name: "Spider Shares and Record Metadata",
			description: "Walks shares recursively through -M spider_plus and records file metadata to the folder the operator supplies with --module-options. It lists and records only; file contents are not downloaded.",
			module:      "spider_plus", options: []string{"OUTPUT_FOLDER", "SHARE", "EXCLUDE_DIRS", "DEPTH", "PATTERN", "REGEX", "CONTENT", "ONLY_FILES", "SILENT"},
			required: []string{"OUTPUT_FOLDER"}, sensitive: true,
		},
		{
			id: "smb-dpapi-hash", name: "Dump DPAPI Hashes",
			description: "Dumps DPAPI masterkey-backed hashes through -M dpapi_hash. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "dpapi_hash", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-eventlog-creds", name: "Extract Credentials from Event Logs",
			description: "Extracts credentials that process-creation and Sysmon events recorded through -M eventlog_creds. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "eventlog_creds", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-iis", name: "Extract IIS Application Pool Credentials",
			description: "Reads IIS application pool configuration with appcmd through -M iis to recover account passwords. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "iis", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-keepass-trigger", name: "Trigger KeePass Export",
			description: "Creates a KeePass trigger that exports the database in cleartext through -M keepass_trigger. " + gateCredentialDump + "; it modifies the target's KeePass configuration and needs " + adminLocal + ".",
			module:      "keepass_trigger", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-lsassy", name: "Dump LSASS with lsassy",
			description: "Dumps LSASS and parses the result remotely through -M lsassy. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "lsassy", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-handlekatz", name: "Dump LSASS with handlekatz",
			description: "Dumps LSASS with handlekatz and parses it with pypykatz through -M handlekatz. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "handlekatz", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-nanodump", name: "Dump LSASS with nanodump",
			description: "Dumps LSASS with nanodump and parses it with pypykatz through -M nanodump. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "nanodump", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-procdump", name: "Dump LSASS with procdump",
			description: "Dumps LSASS with procdump64 and parses it with pypykatz through -M procdump. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "procdump", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-masky", name: "Recover Domain Credentials via ADCS",
			description: "Requests domain user credentials through an AD CS certificate and a KDC through -M masky. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "masky", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-mobaxterm", name: "Dump MobaXterm Credentials",
			description: "Dumps MobaXterm credentials through the remote registry or a NTUSER.dat export with -M mobaxterm. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "mobaxterm", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-mremoteng", name: "Dump mRemoteNG Credentials",
			description: "Decrypts mRemoteNG connection passwords through -M mremoteng. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "mremoteng", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-msol", name: "Dump MSOL Account Credentials",
			description: "Dumps the MSOL account credentials from the Entra ID Connect local database through -M msol. " + gateCredentialDump + "; needs " + adminLocal + " on the sync server.",
			module:      "msol", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-ntds-dump-raw", name: "Dump NTDS, SAM and SYSTEM (raw)",
			description: "Reads ntds.dit, SAM, and SYSTEM by accessing the raw drive through -M ntds-dump-raw. " + gateCredentialDump + "; needs " + adminDC + ".",
			module:      "ntds-dump-raw", gated: gateCredentialDump, admin: adminDC, sensitive: true,
		},
		{
			id: "smb-ntdsutil", name: "Dump NTDS with ntdsutil",
			description: "Dumps the directory database with ntdsutil through -M ntdsutil. " + gateCredentialDump + "; needs " + adminDC + ".",
			module:      "ntdsutil", gated: gateCredentialDump, admin: adminDC, sensitive: true,
		},
		{
			id: "smb-powershell-history", name: "Extract PowerShell History",
			description: "Reads PowerShell command history for every user and flags sensitive commands through -M powershell_history. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "powershell_history", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-putty", name: "Collect PuTTY Private Keys",
			description: "Reads the registry for saved PuTTY SSH private keys and downloads them through -M putty. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "putty", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-rdcman", name: "Dump RDCMan Credentials",
			description: "Dumps Remote Desktop Connection Manager credentials through -M rdcman. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "rdcman", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-reg-winlogon", name: "Collect Winlogon Autologon Credentials",
			description: "Collects autologon credentials stored in the registry through -M reg-winlogon. " + gateCredentialDump + "; needs " + adminRemote + ".",
			module:      "reg-winlogon", gated: gateCredentialDump, admin: adminRemote, sensitive: true,
		},
		{
			id: "smb-security-questions", name: "Collect Security Questions",
			description: "Reads the security questions and answers stored for users on the target through -M security-questions. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "security-questions", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-teams-localdb", name: "Dump Teams SSO Cookie",
			description: "Reads the cleartext SSO cookie from the local Microsoft Teams database through -M teams_localdb. " + gateCredentialDump + "; it stops Teams processes on the target, so it is a state change as well.",
			module:      "teams_localdb", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-veeam", name: "Dump Veeam Credentials",
			description: "Extracts credentials from the local Veeam SQL database through -M veeam. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "veeam", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-vnc-passwords", name: "Loot VNC Passwords",
			description: "Loots passwords from VNC server and client configurations through -M vnc. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "vnc", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-wam", name: "Dump Token Broker Cache",
			description: "Dumps access tokens from the Windows Token Broker cache through -M wam. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "wam", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-wdigest", name: "Enable WDigest Dumping",
			description: "Creates the UseLogonCredential registry value so that WDigest caches cleartext passwords through -M wdigest. " + gateCredentialDump + "; it changes the target's registry and needs " + adminLocal + ".",
			module:      "wdigest", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-wifi", name: "Read Wireless Keys",
			description: "Reads the keys of all wireless interfaces through -M wifi. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "wifi", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-winscp", name: "Extract WinSCP Credentials",
			description: "Finds WinSCP.ini files in the registry and default locations and extracts credentials through -M winscp. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "winscp", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-notepad", name: "Extract Notepad Tab State",
			description: "Extracts content from Windows Notepad tab-state files through -M notepad. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "notepad", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-notepad-plus-plus", name: "Extract Notepad++ Unsaved Files",
			description: "Extracts unsaved Notepad++ buffers through -M notepad++. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "notepad++", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-recent-files", name: "Extract Recently Modified Files",
			description: "Extracts recently modified files from user profiles through -M recent_files. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "recent_files", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-recyclebin", name: "Export Recycle Bins",
			description: "Lists and exports the recycle bin of each user through -M recyclebin. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "recyclebin", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-snipped", name: "Download Snipping Tool Screenshots",
			description: "Downloads screenshots taken with the Snipping Tool through -M snipped. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "snipped", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-sam", name: "Dump SAM",
			description: "Dumps local SAM hashes through the --sam native flag. " + gateCredentialDump + "; needs " + adminLocal + ".",
			args:        []string{"--sam"}, gated: gateCredentialDump, admin: adminLocal, sensitive: true,
			output: "SMB_sam.txt",
		},
		{
			id: "smb-lsa", name: "Dump LSA Secrets",
			description: "Dumps LSA secrets through the --lsa native flag. " + gateCredentialDump + "; needs " + adminLocal + ".",
			args:        []string{"--lsa"}, gated: gateCredentialDump, admin: adminLocal, sensitive: true,
			output: "SMB_lsa.txt",
		},
		{
			id: "smb-ntds", name: "Dump NTDS.dit",
			description: "Dumps directory hashes through the --ntds native flag. " + gateCredentialDump + "; needs " + adminDC + ".",
			args:        []string{"--ntds"}, gated: gateCredentialDump, admin: adminDC, sensitive: true,
			output: "SMB_ntds.txt",
		},
		{
			id: "smb-dpapi", name: "Dump DPAPI Secrets",
			description: "Dumps DPAPI-protected Credential Manager secrets through the --dpapi native flag. " + gateCredentialDump + "; needs " + adminLocal + ".",
			args:        []string{"--dpapi"}, gated: gateCredentialDump, admin: adminLocal, sensitive: true,
			output: "SMB_dpapi.txt",
		},
		{
			id: "smb-sccm-secrets", name: "Dump SCCM Secrets",
			description: "Dumps SCCM secrets such as network access accounts from the target through the --sccm native flag. " + gateCredentialDump + "; needs " + adminLocal + ".",
			args:        []string{"--sccm"}, gated: gateCredentialDump, admin: adminLocal, sensitive: true,
			output: "SMB_sccm.txt",
		},
	})
}

// SMBPrivilegeEscalationModules change state, coerce authentication, or execute
// code. All are gated: they must never be swept into a batch, and enabling one
// is an explicit operator decision.
func SMBPrivilegeEscalationModules() []modules.Module {
	return level(modules.CategoryPrivilegeEscalation, modules.ProtocolSMB, []entry{
		{
			id: "smb-add-computer", name: "Add or Delete Domain Computer",
			description: "Creates or deletes a domain computer account through -M add-computer. " + gateStateChange + ".",
			module:      "add-computer", gated: gateStateChange, sensitive: true,
		},
		{
			id: "smb-change-password", name: "Change or Reset Passwords",
			description: "Changes or resets user passwords through -M change-password. " + gateStateChange + ".",
			module:      "change-password", gated: gateStateChange, sensitive: true,
		},
		{
			id: "smb-backup-operator", name: "Backup Operator to NTDS",
			description: "Uses membership of the Backup Operators group to dump NTDS through -M backup_operator. " + gateCredentialDump + ".",
			module:      "backup_operator", gated: gateCredentialDump, sensitive: true,
		},
		{
			id: "smb-coerce-plus", name: "Coerce Authentication",
			description: "Tests the target against every known coercion vector through -M coerce_plus with the listener the operator configures. " + gateCoercion + ".",
			module:      "coerce_plus", options: []string{"LISTENER", "TECHNIQUE"}, gated: gateCoercion, sensitive: true,
		},
		{
			id: "smb-timeroast", name: "Timeroast",
			description: "Requests password hashes of computer and trust accounts through NTP authentication with -M timeroast. " + gateCoercion + ".",
			module:      "timeroast", gated: gateCoercion, sensitive: true,
		},
		{
			id: "smb-drop-sc", name: "Drop searchConnector-ms",
			description: "Writes a searchConnector-ms file into every writable share through -M drop-sc to capture a user's authentication. " + gateCoercion + ".",
			module:      "drop-sc", options: []string{"URL", "CLEANUP"}, gated: gateCoercion, sensitive: true,
		},
		{
			id: "smb-drop-library-ms", name: "Drop .library-ms (CVE-2025-24054)",
			description: "Writes a .library-ms file that exploits CVE-2025-24054 into writable shares through -M drop-library-ms to capture NTLMv2 hashes. " + gateCoercion + ".",
			module:      "drop-library-ms", options: []string{"NAME", "CLEANUP"}, gated: gateCoercion, sensitive: true,
		},
		{
			id: "smb-scuffy", name: "Drop SCF Lure",
			description: "Writes .scf files whose icon property points at the operator's SMB listener into writable shares through -M scuffy. " + gateCoercion + ".",
			module:      "scuffy", options: []string{"URL", "CLEANUP"}, gated: gateCoercion, sensitive: true,
		},
		{
			id: "smb-slinky", name: "Drop Shortcut Lure",
			description: "Writes Windows shortcut files that point at the operator's listener into writable shares through -M slinky. " + gateCoercion + ".",
			module:      "slinky", options: []string{"URL", "CLEANUP"}, gated: gateCoercion, sensitive: true,
		},
		{
			id: "smb-impersonate", name: "Impersonate Logged-on Token",
			description: "Impersonates a logged-on user's token to run a command as them through -M impersonate. " + gateExecution + "; needs " + adminLocal + ".",
			module:      "impersonate", gated: gateExecution, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-process-injection", name: "Run Command via Process Injection",
			description: "Runs a command as a logged-on user through process injection with -M pi. " + gateExecution + "; needs " + adminLocal + ".",
			module:      "pi", gated: gateExecution, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-schtask-as", name: "Scheduled Task as User",
			description: "Runs a command as a logged-on user through a scheduled task with -M schtask_as. " + gateExecution + "; needs " + adminLocal + ".",
			module:      "schtask_as", gated: gateExecution, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-hash-spider", name: "Recursive LSASS Dump via BloodHound",
			description: "Walks BloodHound's local-administrator data to dump LSASS recursively through -M hash_spider. " + gateCredentialDump + ".",
			module:      "hash_spider", gated: gateCredentialDump, sensitive: true,
		},
		{
			id: "smb-rdp-toggle", name: "Enable or Disable RDP",
			description: "Turns the RDP service on or off through -M rdp. " + gateStateChange + "; needs " + adminLocal + ".",
			module:      "rdp", gated: gateStateChange, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-remote-uac", name: "Enable or Disable Remote UAC",
			description: "Changes the remote UAC restriction through -M remote-uac. " + gateStateChange + "; needs " + adminLocal + ".",
			module:      "remote-uac", gated: gateStateChange, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-shadowrdp", name: "Enable or Disable Shadow RDP",
			description: "Changes the shadow-RDP configuration through -M shadowrdp. " + gateStateChange + "; needs " + adminLocal + ".",
			module:      "shadowrdp", gated: gateStateChange, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-empire-exec", name: "Execute Empire Launcher",
			description: "Generates an Empire launcher and runs it on the target through -M empire_exec. " + gateExecution + "; needs " + adminLocal + " and a configured Empire instance.",
			module:      "empire_exec", gated: gateExecution, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-met-inject", name: "Inject Meterpreter Stager",
			description: "Downloads and injects the Meterpreter stager through -M met_inject. " + gateExecution + "; needs " + adminLocal + ".",
			module:      "met_inject", gated: gateExecution, admin: adminLocal, sensitive: true,
		},
		{
			id: "smb-web-delivery", name: "Metasploit Web Delivery",
			description: "Starts a Metasploit web-delivery payload through -M web_delivery. " + gateExecution + "; needs a configured Metasploit RPC instance.",
			module:      "web_delivery", gated: gateExecution, sensitive: true,
		},
	})
}
