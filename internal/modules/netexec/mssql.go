package netexec

import "github.com/pwnflow/pwnflow/internal/modules"

// MSSQL keeps the SQL enumeration that answers "what can this login reach": the
// databases it sees, the logins, the linked servers, and the impersonation rights
// it holds. The escalation half of the protocol - xp_cmdshell, linked-server
// command execution, coercion, and the payload modules - is exploitation rather
// than enumeration and is not registered.
//
// The native -q/--query flag takes an operator-supplied statement, and the
// --rid-brute walk duplicates the login enumeration loudly, so neither is
// registered; both are documented in docs/netexec-inventory.md.

func MSSQLEnumerationModules() []modules.Module {
	return level(modules.CategoryEnumeration, modules.ProtocolMSSQL, []entry{
		{
			id: "mssql-auth-check", name: "MSSQL Authentication Check",
			description: "Authenticates to the SQL Server instance and prints the result, including the server version the login may read.",
			options:     []string{"TARGET"}, required: []string{"TARGET"},
			inputUsage: map[string]string{"TARGET": "the explicitly approved SQL Server host or host:port"},
			output:     "MSSQL_auth_check.txt",
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
			description: "Enumerates linked SQL servers and their login configuration through -M enum_links, the map any later linked-server work would build on.",
			module:      "enum_links",
		},
		{
			id: "mssql-enum-impersonate", name: "Enumerate Impersonation Rights",
			description: "Enumerates logins with IMPERSONATE rights through -M enum_impersonate, a read-only view of who may act as whom.",
			module:      "enum_impersonate",
		},
	})
}
