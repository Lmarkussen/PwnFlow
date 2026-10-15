package netexec

import "github.com/pwnflow/pwnflow/internal/modules"

// MSSQL splits into three low-privilege SQL enumeration modules and a large
// privilege-escalation set built on linked servers and xp_cmdshell. The native
// -q/--query flag takes an operator-supplied statement and is documented rather
// than registered; --database without a name lists databases and is read-only.

func MSSQLEnumerationModules() []modules.Module {
	return level(modules.CategoryEnumeration, modules.ProtocolMSSQL, []entry{
		{
			id: "mssql-auth-check", name: "MSSQL Authentication Check",
			description: "Authenticates to the SQL Server instance and prints the result, including the server version the login may read.",
			output:      "MSSQL_auth_check.txt",
		},
		{
			id: "mssql-databases", name: "List Databases",
			description: "Lists the databases visible to the login through the --database native flag.",
			args:        []string{"--database"}, output: "MSSQL_databases.txt",
		},
		{
			id: "mssql-enum-logins", name: "Enumerate SQL Logins",
			description: "Enumerates SQL, domain, and local logins through -M enum_logins, which shows which principals can reach the instance.",
			module:      "enum_logins",
		},
		{
			id: "mssql-enum-links", name: "Enumerate Linked Servers",
			description: "Enumerates linked SQL servers and their login configuration through -M enum_links, the map a linked-server attack path builds on.",
			module:      "enum_links",
		},
		{
			id: "mssql-enum-impersonate", name: "Enumerate Impersonation Rights",
			description: "Enumerates logins with IMPERSONATE rights through -M enum_impersonate, a read-only view of who may act as whom.",
			module:      "enum_impersonate",
		},
		{
			id: "mssql-test-connection", name: "Ping Host from SQL Server",
			description: "Pings a host from the SQL Server's own perspective through -M test_connection; the operator names the host with --module-options. Needs " + adminLocal + " on the SQL host.",
			module:      "test_connection", options: []string{"HOST"}, required: []string{"HOST"}, admin: adminLocal,
		},
	})
}

// MSSQLPrivilegeEscalationModules all change state or execute code on the SQL
// Server. They are gated, and each one names the technique it needs.
func MSSQLPrivilegeEscalationModules() []modules.Module {
	return level(modules.CategoryPrivilegeEscalation, modules.ProtocolMSSQL, []entry{
		{
			id: "mssql-enable-cmdshell", name: "Enable or Disable xp_cmdshell",
			description: "Turns xp_cmdshell on or off through -M enable_cmdshell. " + gateStateChange + "; needs a sysadmin login.",
			module:      "enable_cmdshell", gated: gateStateChange, admin: adminDomain, sensitive: true,
		},
		{
			id: "mssql-link-enable-cmdshell", name: "Enable xp_cmdshell on Linked Server",
			description: "Turns xp_cmdshell on or off on a linked server through -M link_enable_cmdshell. " + gateStateChange + "; needs a login that may reconfigure the link.",
			module:      "link_enable_cmdshell", gated: gateStateChange, sensitive: true,
		},
		{
			id: "mssql-link-xpcmd", name: "Run Command on Linked Server",
			description: "Runs xp_cmdshell commands on a linked SQL server through -M link_xpcmd. " + gateExecution + "; needs a sysadmin login on the link.",
			module:      "link_xpcmd", gated: gateExecution, sensitive: true,
		},
		{
			id: "mssql-exec-on-link", name: "Execute Command on Linked Server",
			description: "Executes SQL commands on a linked server through -M exec_on_link. " + gateExecution + "; needs the login to reach the link.",
			module:      "exec_on_link", gated: gateExecution, sensitive: true,
		},
		{
			id: "mssql-priv", name: "Enumerate and Exploit MSSQL Privileges",
			description: "Enumerates the login's SQL privileges and can follow them to code execution through -M mssql_priv. " + gateExecution + ".",
			module:      "mssql_priv", gated: gateExecution, sensitive: true,
		},
		{
			id: "mssql-coerce", name: "Coerce SQL Authentication",
			description: "Runs SQL commands that make the server authenticate to the operator's listener through -M mssql_coerce. " + gateCoercion + ".",
			module:      "mssql_coerce", options: []string{"LISTENER"}, gated: gateCoercion, sensitive: true,
		},
		{
			id: "mssql-nanodump", name: "Dump LSASS with nanodump",
			description: "Dumps LSASS on the SQL host with nanodump and parses it with pypykatz through -M nanodump. " + gateCredentialDump + "; needs " + adminLocal + ".",
			module:      "nanodump", gated: gateCredentialDump, admin: adminLocal, sensitive: true,
		},
		{
			id: "mssql-empire-exec", name: "Execute Empire Launcher",
			description: "Generates an Empire launcher and runs it through a SQL path with -M empire_exec. " + gateExecution + "; needs a configured Empire instance.",
			module:      "empire_exec", gated: gateExecution, sensitive: true,
		},
		{
			id: "mssql-met-inject", name: "Inject Meterpreter Stager",
			description: "Downloads and injects the Meterpreter stager through -M met_inject. " + gateExecution + "; needs " + adminLocal + ".",
			module:      "met_inject", gated: gateExecution, admin: adminLocal, sensitive: true,
		},
		{
			id: "mssql-web-delivery", name: "Metasploit Web Delivery",
			description: "Starts a Metasploit web-delivery payload through -M web_delivery. " + gateExecution + "; needs a configured Metasploit RPC instance.",
			module:      "web_delivery", gated: gateExecution, sensitive: true,
		},
	})
}
