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
// Each one carries the reason, so the omission is auditable instead of silent.
var excludedModules = map[string]string{
	"ldap:certipy-find": "duplicates the AD CS family's certipy find integration and writes its own artifact files",
	"ldap:pso":          "duplicates the --pso native query, which is already registered as fine-grained-password-policy",
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

func TestModuleIdentifiersAreUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, module := range RegisteredModules() {
		if seen[module.ID()] {
			t.Fatalf("module identifier %q is registered twice", module.ID())
		}
		seen[module.ID()] = true
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
		if len(entry.definition.Arguments) == 0 && entry.ModuleName() == "" &&
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
		"spider_plus":     {"OUTPUT_FOLDER", "SHARE", "EXCLUDE_DIRS", "DEPTH", "PATTERN", "REGEX", "CONTENT", "ONLY_FILES", "SILENT"},
		"reg-query":       {"PATH", "KEY"},
		"test_connection": {"HOST"},
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
