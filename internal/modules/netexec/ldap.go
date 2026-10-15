package netexec

import (
	"github.com/pwnflow/pwnflow/internal/modules"
)

// LDAP runs over LDAPS: the transport spec appends `--port 636`, which is how
// the installed NetExec selects ldaps://, and every registration below inherits
// it. The registrations were checked against `nxc ldap --help` and
// `nxc ldap -L` from the installed 1.5.1 build; the retired LDAP modules
// (enum_trusts, group-mem, ldap-checker) are deliberately absent.

// LDAPEnumerationModules are read-only directory queries that need no elevated
// rights on the target: a valid domain account is enough.
func LDAPEnumerationModules() []modules.Module {
	return level(modules.CategoryEnumeration, modules.ProtocolLDAP, []entry{
		{
			id: "domain-users", name: "Enumerate Domain Users",
			description: "Lists every domain user object with its attributes through the --users native query.",
			args:        []string{"--users"}, output: "LDAP_domain_users.txt",
		},
		{
			id: "active-users", name: "Enumerate Active Users",
			description: "Lists users by last logon information through --active-users, which separates accounts that have actually signed in from stale ones.",
			args:        []string{"--active-users"}, output: "LDAP_active_users.txt",
		},
		{
			id: "domain-groups", name: "Enumerate Domain Groups",
			description: "Lists domain groups through the --groups native query.",
			args:        []string{"--groups"}, output: "LDAP_domain_groups.txt",
		},
		{
			id: "domain-sid", name: "Get Domain SID",
			description: "Reads the domain SID with --get-sid, which later queries and ACL comparisons need.",
			args:        []string{"--get-sid"}, output: "LDAP_domain_sid.txt",
		},
		{
			id: "password-policy", name: "Enumerate Domain Password Policy",
			description: "Dumps the domain password and lockout policy through --pass-pol so lockout thresholds are known before any authentication testing.",
			args:        []string{"--pass-pol"}, output: "LDAP_password_policy.txt",
		},
		{
			id: "fine-grained-password-policy", name: "Enumerate Fine-Grained Password Policy",
			description: "Reads password settings objects (PSOs) through --pso: account-specific policy that overrides the domain default.",
			args:        []string{"--pso"}, output: "LDAP_fine_grained_password_policy.txt",
		},
		{
			id: "admin-count", name: "Enumerate AdminCount Accounts",
			description: "Lists accounts with adminCount=1, the historical marker of protected high-privilege objects.",
			args:        []string{"--admin-count"}, output: "LDAP_admin_count.txt",
		},
		{
			id: "password-not-required", name: "Find Password-Not-Required Accounts",
			description: "Finds accounts flagged PASSWD_NOTREQD, which may be usable without a password.",
			args:        []string{"--password-not-required"}, output: "LDAP_password_not_required.txt",
		},
		{
			id: "delegation", name: "Enumerate Delegation Relationships",
			description: "Finds accounts and computers trusted for delegation through --find-delegation.",
			args:        []string{"--find-delegation"}, output: "LDAP_delegation.txt",
		},
		{
			id: "domain-controllers", name: "Enumerate Domain Controllers",
			description: "Lists domain controllers through --dc-list, which identifies the hosts a later stage may target.",
			args:        []string{"--dc-list"}, output: "LDAP_domain_controllers.txt",
		},
		{
			id: "maq", name: "Check Machine Account Quota",
			description: "Reads the ms-DS-MachineAccountQuota attribute through -M maq: how many computer accounts a normal user may create.",
			module:      "maq", output: "LDAP_machine_account_quota.txt",
		},
		{
			id: "adcs", name: "Find AD CS Enrollment Services",
			description: "Searches the directory for PKI enrollment services and certificate template names through -M adcs.",
			module:      "adcs",
		},
		{
			id: "badsuccessor", name: "Check BadSuccessor (dMSA)",
			description: "Tests whether the domain is vulnerable to the BadSuccessor delegated managed service account attack through -M badsuccessor. Read-only check.",
			module:      "badsuccessor",
		},
		{
			id: "dns-nonsecure", name: "Find Nonsecure DNS Zones",
			description: "Detects DNS zones that accept nonsecure dynamic updates through -M dns-nonsecure, a common record-hijack path.",
			module:      "dns-nonsecure",
		},
		{
			id: "dump-computers", name: "Dump Computer OS Information",
			description: "Dumps the FQDN and operating system of every computer in the domain through -M dump-computers, which is strictly more informative than the plain computer list.",
			module:      "dump-computers",
		},
		{
			id: "entra-id", name: "Find Entra ID Sync Server",
			description: "Identifies the host running Entra ID Connect through -M entra-id, which marks a high-value credential target for later stages.",
			module:      "entra-id",
		},
		{
			id: "get-network", name: "Query Domain DNS Records",
			description: "Queries all DNS records of the domain with their IPs through -M get-network. -o ALL/ONLY_HOSTS narrow the listing.",
			module:      "get-network", options: []string{"ALL", "ONLY_HOSTS"},
		},
		{
			id: "groupmembership", name: "Query Group Membership",
			description: "Queries the groups a user belongs to through -M groupmembership, which is how nested group membership becomes visible. It defaults to the account PwnFlow authenticated with; -o USER names another account.",
			module:      "groupmembership", options: []string{"USER"},
			dynamicOptions: map[string]func(*modules.Runtime) string{
				"USER": func(runtime *modules.Runtime) string { return runtime.Username },
			},
		},
		{
			id: "obsolete", name: "Find Obsolete Operating Systems",
			description: "Extracts computer accounts running unsupported operating systems through -M obsolete.",
			module:      "obsolete",
		},
		{
			id: "sccm", name: "Find SCCM Infrastructure in AD",
			description: "Finds the Configuration Manager infrastructure published in the directory through -M sccm, including management points and site systems.",
			module:      "sccm", options: []string{"BASE_DN", "REC_RESOLVE"},
		},
		{
			id: "subnets", name: "Enumerate Sites and Subnets",
			description: "Retrieves the AD sites and subnets through -M subnets, which maps the network layout the target addresses belong to.",
			module:      "subnets",
		},
		{
			id: "whoami", name: "Describe Authenticated User",
			description: "Resolves the authenticated account's directory details through -M whoami, including group membership and account flags.",
			module:      "whoami",
		},
		{
			id: "daclread", name: "Read Object DACL",
			description:    "Reads the discretionary access control list of one object through -M daclread. PwnFlow asks for the object when you run it; daclread reads one object at a time and never recurses.",
			module:         "daclread",
			options:        []string{"TARGET", "TARGET_DN", "PRINCIPAL", "ACTION", "ACE_TYPE", "RIGHTS", "RIGHTS_GUID"},
			required:       []string{"ACTION", "TARGET"},
			optionDefaults: map[string]string{"ACTION": "read"},
			inputUsage: map[string]string{
				"TARGET": "the object whose DACL to read, by sAMAccountName",
			},
		},
		{
			id: "find-computer", name: "Find Computers by Text",
			description: "Searches computer names and operating systems for a text fragment through -M find-computer. PwnFlow asks for the text when you run it.",
			module:      "find-computer",
			options:     []string{"TEXT"},
			required:    []string{"TEXT"},
			inputUsage: map[string]string{
				"TEXT": "the text to search for in computer names and operating systems",
			},
		},
	})
}

// LDAPCredentialDumpingModules read secrets out of the directory. They are
// read-only against the target, but their output is credential material, so
// they are not part of an enumeration run.
func LDAPCredentialDumpingModules() []modules.Module {
	return level(modules.CategoryCredentialDumping, modules.ProtocolLDAP, []entry{
		{
			id: "get-info-users", name: "Get AD-User Info",
			description: "Reads the info field of every user through -M get-info-users; the field frequently holds a password left by an administrator.",
			module:      "get-info-users", options: []string{"FILTER"}, sensitive: true,
			output: "LDAP_get_users_info.txt",
		},
		{
			id: "get-desc-users", name: "Get AD-User Description",
			description: "Reads the description field of every user through -M get-desc-users; the field frequently holds a password left by an administrator.",
			module:      "get-desc-users", options: []string{"FILTER", "PASSWORDPOLICY", "MINLENGTH"}, sensitive: true,
			output: "LDAP_get_users_description.txt",
		},
		{
			id: "user-desc", name: "Get User Descriptions",
			description: "Reads user descriptions through -M user-desc, the module that reports description content verbatim.",
			module:      "user-desc", sensitive: true,
		},
		{
			id: "get-userPassword", name: "Get userPassword Attribute",
			description: "Reads the userPassword attribute of directory objects through -M get-userPassword. Finding anything requires read access to that attribute.",
			module:      "get-userPassword", sensitive: true,
		},
		{
			id: "get-unixUserPassword", name: "Get unixUserPassword Attribute",
			description: "Reads the unixUserPassword attribute through -M get-unixUserPassword, which is populated when the directory holds Unix-integrated accounts.",
			module:      "get-unixUserPassword", sensitive: true,
		},
		{
			id: "laps", name: "Read LAPS Passwords",
			description: "Reads local administrator passwords stored by LAPS through -M laps. Only the passwords the authenticated account may read come back; the module names that limit itself.",
			module:      "laps", options: []string{"COMPUTER"}, sensitive: true,
		},
		{
			id: "gmsa", name: "Enumerate GMSA Passwords",
			description: "Reads the managed password of group managed service accounts through the --gmsa native query. Reading a gMSA password requires the directory right granted to the principal.",
			args:        []string{"--gmsa"}, sensitive: true,
		},
	})
}
