package netexec

import (
	"slices"
	"strings"
	"testing"

	"github.com/pwnflow/pwnflow/internal/modules"
)

// The tables below are the module catalogue of the installed NetExec build, as
// read from `nxc <protocol> -L`. They are the offline half of the coverage
// proof: the live half is the lab run recorded in docs/netexec-inventory.md.
//
// Keeping them here means a registration can never drift into naming a module
// the executable does not advertise, and a module the executable does advertise
// can never be silently dropped from the registry.
var advertisedModules = map[modules.Protocol][]string{
	modules.ProtocolLDAP: {
		"adcs", "badsuccessor", "certipy-find", "daclread", "dns-nonsecure", "dump-computers",
		"entra-id", "find-computer", "get-desc-users", "get-info-users", "get-network",
		"get-unixUserPassword", "get-userPassword", "groupmembership", "laps", "maq",
		"obsolete", "pre2k", "pso", "raisechild", "sccm", "subnets", "user-desc", "whoami",
	},
	modules.ProtocolSMB: {
		"add-computer", "aws-credentials", "backup_operator", "bitlocker", "change-password",
		"coerce_plus", "dpapi_hash", "drop-library-ms", "drop-sc", "empire_exec", "enum_av",
		"enum_ca", "enum_dns", "enum_interfaces", "eventlog_creds", "get_netconnections",
		"gpp_autologin", "gpp_password", "gpp_privileges", "handlekatz", "hash_spider",
		"hyperv-host", "iis", "impersonate", "install_elevated", "ioxidresolver",
		"keepass_discover", "keepass_trigger", "lockscreendoors", "lsassy", "masky",
		"met_inject", "mobaxterm", "mremoteng", "ms17-010", "msol", "nanodump", "nopac",
		"notepad", "notepad++", "ntds-dump-raw", "ntdsutil", "ntlmv1", "ntlm_reflection",
		"pi", "powershell_history", "presence", "printnightmare", "procdump", "putty",
		"rdcman", "rdp", "recent_files", "recyclebin", "reg-query", "reg-winlogon",
		"remote-uac", "remove-mic", "runasppl", "sccm-recon6", "schtask_as", "scuffy",
		"security-questions", "shadowrdp", "slinky", "smbghost", "snipped", "spider_plus",
		"spooler", "teams_localdb", "test_connection", "timeroast", "uac", "veeam", "vnc",
		"wam", "wcc", "web_delivery", "webdav", "wdigest", "wifi", "winscp", "zerologon",
	},
	modules.ProtocolWinRM: {"aws-credentials", "ntds-dump-raw"},
	modules.ProtocolWMI: {
		"bitlocker", "enum_dns", "get_netconnections", "ioxidresolver", "ntds-dump-raw",
		"rdp", "spooler", "zerologon",
	},
	modules.ProtocolMSSQL: {
		"empire_exec", "enable_cmdshell", "enum_impersonate", "enum_links", "enum_logins",
		"exec_on_link", "link_enable_cmdshell", "link_xpcmd", "met_inject", "mssql_coerce",
		"mssql_priv", "nanodump", "test_connection", "web_delivery",
	},
	modules.ProtocolSSH: {"aws-credentials"},
	modules.ProtocolFTP: {},
	modules.ProtocolRDP: {},
	modules.ProtocolVNC: {},
	modules.ProtocolNFS: {},
}

// retiredModules are still printed by `-L` but marked "[REMOVED]": the command
// exists in the menu and cannot run. They must never be registered, and the
// status has to be discovered from the listing rather than assumed.
var retiredModules = map[modules.Protocol][]string{
	modules.ProtocolLDAP: {"enum_trusts", "group-mem", "ldap-checker"},
	modules.ProtocolSMB: {
		"petitpotam", "printerbug", "shadowcoerce", "dfscoerce", "efsr_spray", "firefox",
	},
}

// excludedModules are advertised and usable, and deliberately not registered.
// Each one carries a short reason code, so the omission is auditable instead of
// silent, and docs/netexec-inventory.md holds the same list with the prose.
//
// PwnFlow is an enumeration and assessment framework: a module is registered
// only when its primary purpose is to read something from the target with the
// operator's own credentials. Everything that executes code, changes state,
// coerces authentication, dumps credentials, or needs a listener is left out.
var excludedModules = map[string]string{
	// LDAP.
	"ldap:user-desc":              "duplicate: get-desc-users is the canonical description query and exposes the same user attribute with filtering options",
	"ldap:certipy-find":           "duplicate: the AD CS family runs certipy find",
	"ldap:pso":                    "duplicate: the --pso native query is registered",
	"ldap:computers":              "duplicate: -M dump-computers returns the OS and FQDN as well",
	"ldap:trusted-for-delegation": "duplicate: --find-delegation reports delegation relationships in full",
	"ldap:pre2k":                  "exploitation: creates computer accounts and requests tickets",
	"ldap:raisechild":             "exploitation: abuses a parent-domain trust",
	// SMB: domain data that LDAP reads better, and native duplicates.
	"smb:users":           "duplicate: LDAP --users reads the same dataset over LDAPS",
	"smb:groups":          "duplicate: LDAP --groups reads the same dataset over LDAPS",
	"smb:computers":       "duplicate: LDAP dump-computers reports the same accounts with OS detail",
	"smb:pass-pol":        "duplicate: LDAP --pass-pol reads the domain policy over LDAPS",
	"smb:rid-brute":       "duplicate: LDAP --users enumerates the same accounts without a RID walk",
	"smb:test_connection": "needs-operator-value: pings a host the operator names, which is a probe rather than target enumeration",
	"smb:spider_plus":     "duplicate: the option surface is a file collector, and the crawl duplicates the operator's dedicated share tooling",
	"smb:sam":             "credential-dump: local account hashes",
	"smb:lsa":             "credential-dump: LSA secrets",
	"smb:ntds":            "credential-dump: directory database hashes",
	"smb:dpapi":           "credential-dump: DPAPI secrets",
	"smb:sccm":            "credential-dump: SCCM network access accounts",
	// SMB: credential extraction beyond a plain read.
	"smb:dpapi_hash":         "credential-dump: masterkey-backed hashes",
	"smb:eventlog_creds":     "credential-dump: credentials recorded in event logs",
	"smb:iis":                "credential-dump: application pool credentials",
	"smb:keepass_trigger":    "exploitation: modifies the target's KeePass configuration",
	"smb:lsassy":             "credential-dump: LSASS dump",
	"smb:handlekatz":         "credential-dump: LSASS dump",
	"smb:nanodump":           "credential-dump: LSASS dump",
	"smb:procdump":           "credential-dump: LSASS dump",
	"smb:hash_spider":        "credential-dump: recursive LSASS dump",
	"smb:masky":              "credential-dump: certificate-backed account takeover",
	"smb:mobaxterm":          "credential-dump: saved session credentials",
	"smb:mremoteng":          "credential-dump: saved connection passwords",
	"smb:msol":               "credential-dump: Entra ID Connect service account",
	"smb:ntds-dump-raw":      "credential-dump: directory database files",
	"smb:ntdsutil":           "credential-dump: directory database dump",
	"smb:powershell_history": "credential-dump: command history",
	"smb:putty":              "credential-dump: saved private keys",
	"smb:rdcman":             "credential-dump: saved connection credentials",
	"smb:reg-winlogon":       "credential-dump: autologon credentials",
	"smb:security-questions": "credential-dump: account recovery answers",
	"smb:teams_localdb":      "credential-dump: single sign-on cookie, and it stops Teams processes",
	"smb:veeam":              "credential-dump: backup product credentials",
	"smb:vnc":                "credential-dump: VNC passwords",
	"smb:wam":                "credential-dump: token broker cache",
	"smb:wdigest":            "exploitation: changes the target's registry to cache cleartext",
	"smb:wifi":               "credential-dump: wireless keys",
	"smb:winscp":             "credential-dump: saved session credentials",
	"smb:notepad":            "credential-dump: editor state files",
	"smb:notepad++":          "credential-dump: unsaved editor buffers",
	"smb:recent_files":       "credential-dump: recently modified files",
	"smb:recyclebin":         "credential-dump: deleted files",
	"smb:snipped":            "credential-dump: screenshots",
	// SMB: exploitation and state change.
	"smb:add-computer":    "exploitation: creates or deletes a domain computer account",
	"smb:backup_operator": "credential-dump: directory database via Backup Operators",
	"smb:change-password": "exploitation: changes account passwords",
	"smb:coerce_plus":     "exploitation: coerces authentication to an operator listener",
	"smb:timeroast":       "exploitation: requests account hashes over NTP",
	"smb:drop-sc":         "exploitation: writes lure files into shares",
	"smb:drop-library-ms": "exploitation: writes a CVE-2025-24054 lure into shares",
	"smb:scuffy":          "exploitation: writes SCF lure files into shares",
	"smb:slinky":          "exploitation: writes shortcut lure files into shares",
	"smb:impersonate":     "exploitation: runs code as a logged-on user",
	"smb:pi":              "exploitation: process injection",
	"smb:schtask_as":      "exploitation: runs a scheduled task as another user",
	"smb:rdp":             "exploitation: enables or disables RDP",
	"smb:remote-uac":      "exploitation: changes the remote UAC policy",
	"smb:shadowrdp":       "exploitation: changes the shadow-RDP policy",
	"smb:empire_exec":     "exploitation: payload delivery through Empire",
	"smb:met_inject":      "exploitation: Meterpreter stager injection",
	"smb:web_delivery":    "exploitation: Metasploit web-delivery payload",
	// WinRM.
	"winrm:aws-credentials": "duplicate: registered under SMB",
	"winrm:ntds-dump-raw":   "credential-dump: directory database files",
	"winrm:sam":             "credential-dump: local account hashes",
	"winrm:lsa":             "credential-dump: LSA secrets",
	"winrm:dpapi":           "credential-dump: DPAPI secrets",
	// WMI: the same checks SMB already offers, plus dumps and exploitation.
	"wmi:ioxidresolver":      "duplicate: registered under SMB",
	"wmi:spooler":            "duplicate: registered under SMB",
	"wmi:zerologon":          "duplicate: registered under SMB",
	"wmi:bitlocker":          "duplicate: registered under SMB",
	"wmi:enum_dns":           "duplicate: registered under SMB",
	"wmi:get_netconnections": "duplicate: registered under SMB",
	"wmi:ntds-dump-raw":      "credential-dump: directory database files",
	"wmi:rdp":                "exploitation: enables or disables RDP",
	// MSSQL.
	"mssql:test_connection":      "needs-operator-value: pings a host the operator names",
	"mssql:nanodump":             "credential-dump: LSASS dump on the SQL host",
	"mssql:enable_cmdshell":      "exploitation: reconfigures the instance to run commands",
	"mssql:link_enable_cmdshell": "exploitation: reconfigures a linked instance",
	"mssql:link_xpcmd":           "exploitation: runs commands through a linked server",
	"mssql:exec_on_link":         "exploitation: executes SQL on a linked server",
	"mssql:mssql_priv":           "exploitation: follows SQL privileges to code execution",
	"mssql:mssql_coerce":         "exploitation: coerces SQL authentication to an operator listener",
	"mssql:empire_exec":          "exploitation: payload delivery through Empire",
	"mssql:met_inject":           "exploitation: Meterpreter stager injection",
	"mssql:web_delivery":         "exploitation: Metasploit web-delivery payload",
	// SSH.
	"ssh:aws-credentials": "duplicate: registered under SMB",
}

func TestEveryAdvertisedModuleIsAccountedFor(t *testing.T) {
	registered := make(map[string]map[string]bool)
	for _, module := range RegisteredModules() {
		entry := module.(Module)
		if entry.ModuleName() == "" {
			continue
		}
		protocol := string(entry.Protocol())
		if registered[protocol] == nil {
			registered[protocol] = make(map[string]bool)
		}
		if registered[protocol][entry.ModuleName()] {
			t.Fatalf("module %s is registered twice under %s", entry.ModuleName(), protocol)
		}
		registered[protocol][entry.ModuleName()] = true
	}
	for protocol, names := range advertisedModules {
		for _, name := range names {
			key := strings.ToLower(string(protocol)) + ":" + name
			if _, excluded := excludedModules[key]; excluded {
				if registered[string(protocol)][name] {
					t.Fatalf("%s is documented as excluded but is registered", key)
				}
				continue
			}
			if !registered[string(protocol)][name] {
				t.Fatalf("advertised module %s is neither registered nor documented as excluded", key)
			}
		}
	}
}

func TestNoRegistrationNamesAnUnadvertisedOrRetiredModule(t *testing.T) {
	for _, module := range RegisteredModules() {
		entry := module.(Module)
		if entry.ModuleName() == "" {
			continue
		}
		advertised := advertisedModules[entry.Protocol()]
		if !sortedContains(advertised, entry.ModuleName()) {
			t.Fatalf("%s registers %s, which the installed %s build does not advertise",
				entry.ID(), entry.ModuleName(), entry.Protocol())
		}
		if sortedContains(retiredModules[entry.Protocol()], entry.ModuleName()) {
			t.Fatalf("%s registers the retired module %s", entry.ID(), entry.ModuleName())
		}
	}
}

func TestRetiredAndSupersededRegistrationsAreAbsent(t *testing.T) {
	absent := map[string]bool{
		// Retired NetExec modules.
		"ldap-checker": true, "enum_trusts": true, "group-mem": true,
		"petitpotam": true, "printerbug": true, "shadowcoerce": true,
		"dfscoerce": true, "efsr_spray": true, "firefox": true,
		// Exploitation, coercion, payload delivery, and credential extraction.
		"pre2k": true, "raisechild": true, "add-computer": true, "change-password": true,
		"coerce_plus": true, "timeroast": true, "drop-sc": true, "drop-library-ms": true,
		"scuffy": true, "slinky": true, "impersonate": true, "pi": true, "schtask_as": true,
		"remote-uac": true, "shadowrdp": true, "empire_exec": true, "met_inject": true,
		"web_delivery": true, "lsassy": true, "nanodump": true, "procdump": true,
		"handlekatz": true, "wdigest": true, "keepass_trigger": true, "ntdsutil": true,
		"ntds-dump-raw": true, "mssql_priv": true, "mssql_coerce": true, "exec_on_link": true,
		"link_xpcmd": true, "link_enable_cmdshell": true, "enable_cmdshell": true,
		// The retired PwnFlow registrations.
		"bloodhound": true, "organizational-units": true,
	}
	for _, module := range RegisteredModules() {
		entry := module.(Module)
		if absent[entry.ID()] || absent[entry.ModuleName()] {
			t.Fatalf("obsolete registration %q (module %q) is still registered", entry.ID(), entry.ModuleName())
		}
		for _, argument := range entry.definition.Arguments {
			if argument == "--bloodhound" || argument == "--collection" {
				t.Fatalf("%s still builds the retired BloodHound collection command", entry.ID())
			}
			if argument == "--ldaps" {
				t.Fatalf("%s invents an unsupported --ldaps option", entry.ID())
			}
		}
		if strings.Contains(entry.OutputFile(), "BloodHound") {
			t.Fatalf("%s still writes into the retired BloodHound output path", entry.ID())
		}
	}
}

// The cleaned registry holds nothing whose purpose is to exploit, coerce, run
// code, or wait for a callback, and nothing whose configuration would need an
// attacker-controlled endpoint.
func TestNoExploitOrListenerRegistrationsRemain(t *testing.T) {
	listenerOptions := map[string]bool{
		"LISTENER": true, "CALLBACK": true, "URL": true, "HOST": true,
		"TECHNIQUE": true, "LHOST": true, "LPORT": true, "PAYLOAD": true,
		"RC_HOST": true, "REMOTE_HOST": true,
	}
	for _, module := range RegisteredModules() {
		entry := module.(Module)
		if entry.Category() == modules.CategoryPrivilegeEscalation {
			t.Fatalf("%s is filed under Privilege Escalation; NetExec registers enumeration and auditing only", entry.ID())
		}
		for _, key := range entry.definition.OptionKeys {
			if listenerOptions[key] {
				t.Fatalf("%s accepts the option %s, which configures attack infrastructure", entry.ID(), key)
			}
		}
		for _, argument := range entry.definition.Arguments {
			switch argument {
			case "-x", "-X", "--put-file", "--get-file", "--taskkill", "--ntds", "--sam", "--lsa", "--dpapi":
				t.Fatalf("%s builds the exploitation or dumping flag %s", entry.ID(), argument)
			}
		}
	}
}

// NetExec offers the categories its registrations belong to, and no category that
// exists only to hold exploitation.
func TestNetExecCategoriesAreEnumerationAndAuditing(t *testing.T) {
	want := []modules.Category{modules.CategoryEnumeration, modules.CategoryCredentialAuditing, modules.CategoryCredentialDumping}
	got := modules.CategoriesForFamily(modules.ToolFamilyNetExec)
	if len(got) != len(want) {
		t.Fatalf("NetExec categories = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("NetExec categories = %v, want %v", got, want)
		}
	}
}

func TestModuleIdentifiersAreUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, module := range RegisteredModules() {
		if seen[module.ID()] {
			t.Fatalf("module identifier %q is registered twice", module.ID())
		}
		seen[module.ID()] = true
	}
}

// The cleanup removed the registrations that ran the same query twice - the SMB
// SAMR variants of the domain queries, and the modules WMI shares with SMB - and
// this keeps them from coming back: no two registrations may build the same
// command for the same target data.
func TestNoTwoRegistrationsRunTheSameCommand(t *testing.T) {
	signatures := map[string]string{}
	for _, module := range RegisteredModules() {
		entry := module.(Module)
		signature := strings.Join(append([]string{protocolCommand(entry.Protocol()), entry.ModuleName()}, entry.definition.Arguments...), " ")
		if signature == "" {
			continue
		}
		if previous, ok := signatures[signature]; ok {
			t.Fatalf("%s and %s both build %q; one of them is a duplicate", previous, entry.ID(), signature)
		}
		signatures[signature] = entry.ID()
	}
}

func TestModuleOptionsAreDeclaredConsistently(t *testing.T) {
	for _, module := range RegisteredModules() {
		entry := module.(Module)
		declared := make(map[string]bool)
		for _, key := range entry.definition.OptionKeys {
			if !strings.EqualFold(key, strings.ToUpper(key)) || strings.ContainsAny(key, " -=") {
				t.Fatalf("%s declares the option key %q, which is not a NetExec option name", entry.ID(), key)
			}
			if declared[key] {
				t.Fatalf("%s declares the option key %q twice", entry.ID(), key)
			}
			declared[key] = true
		}
		for _, key := range entry.definition.RequiredOptions {
			if !declared[key] {
				t.Fatalf("%s requires option %s without declaring it", entry.ID(), key)
			}
		}
		if len(entry.definition.Arguments) == 0 && entry.ModuleName() == "" && entry.definition.DynamicArgs == nil &&
			!strings.HasSuffix(entry.ID(), "-auth-check") && entry.ID() != "smb-server-info" {
			t.Fatalf("%s runs nothing: it has neither a native flag nor a module", entry.ID())
		}
	}
}

// Option keys were read from the installed module's own --options output. These
// are the ones the registry depends on, so a rename in the executable fails the
// test instead of silently dropping the option.
func TestDeclaredOptionKeysMatchTheInstalledModules(t *testing.T) {
	want := map[string][]string{
		"get-info-users":  {"FILTER"},
		"get-desc-users":  {"FILTER", "PASSWORDPOLICY", "MINLENGTH"},
		"find-computer":   {"TEXT"},
		"groupmembership": {"USER"},
		"daclread":        {"TARGET", "TARGET_DN", "PRINCIPAL", "ACTION", "ACE_TYPE", "RIGHTS", "RIGHTS_GUID"},
		"laps":            {"COMPUTER"},
		"sccm":            {"BASE_DN", "REC_RESOLVE"},
		"get-network":     {"ALL", "ONLY_HOSTS"},
		"ioxidresolver":   {"DIFFERENT"},
		"reg-query":       {"PATH", "KEY"},
		"wcc":             {"OUTPUT_FORMAT", "OUTPUT", "QUIET"},
	}
	found := make(map[string][]string)
	for _, module := range RegisteredModules() {
		entry := module.(Module)
		if entry.ModuleName() != "" && len(entry.definition.OptionKeys) > 0 {
			found[entry.ModuleName()] = entry.definition.OptionKeys
		}
	}
	for name, keys := range want {
		got, ok := found[name]
		if !ok {
			t.Fatalf("module %s declares no options; the installed module advertises %v", name, keys)
		}
		if strings.Join(got, ",") != strings.Join(keys, ",") {
			t.Fatalf("module %s declares %v, want %v", name, got, keys)
		}
	}
}

func sortedContains(values []string, wanted string) bool {
	return slices.Contains(values, wanted)
}
