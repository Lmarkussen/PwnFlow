package netexec

import "github.com/pwnflow/pwnflow/internal/modules"

func SMBEnumerationModules() []modules.Module {
	definitions := []Definition{
		definition("smb-server-info", "SMB Server Information", modules.CategoryEnumeration, modules.ProtocolSMB, nil, "SMB_server_info.txt"),
		definition("smb-shares", "SMB Shares", modules.CategoryEnumeration, modules.ProtocolSMB, []string{"--shares"}, "SMB_shares.txt"),
		definition("smb-disks", "SMB Disks", modules.CategoryEnumeration, modules.ProtocolSMB, []string{"--disks"}, "SMB_disks.txt"),
		definition("smb-domain-users", "Domain Users via SMB", modules.CategoryEnumeration, modules.ProtocolSMB, []string{"--users"}, "SMB_domain_users.txt"),
		definition("smb-domain-groups", "Domain Groups via SMB", modules.CategoryEnumeration, modules.ProtocolSMB, []string{"--groups"}, "SMB_domain_groups.txt"),
		definition("smb-local-groups", "Local Groups", modules.CategoryEnumeration, modules.ProtocolSMB, []string{"--local-groups"}, "SMB_local_groups.txt"),
		definition("smb-domain-computers", "Domain Computers via SMB", modules.CategoryEnumeration, modules.ProtocolSMB, []string{"--computers"}, "SMB_domain_computers.txt"),
		definition("smb-password-policy", "SMB Password Policy", modules.CategoryEnumeration, modules.ProtocolSMB, []string{"--pass-pol"}, "SMB_password_policy.txt"),
		definition("smb-sessions", "SMB Sessions", modules.CategoryEnumeration, modules.ProtocolSMB, []string{"--smb-sessions"}, "SMB_sessions.txt"),
		definition("logged-on-users", "Logged-on Users", modules.CategoryEnumeration, modules.ProtocolSMB, []string{"--loggedon-users"}, "SMB_loggedon_users.txt"),
		definition("registry-sessions", "Registry Sessions", modules.CategoryEnumeration, modules.ProtocolSMB, []string{"--reg-sessions"}, "SMB_registry_sessions.txt"),
		definition("terminal-sessions", "Terminal Sessions", modules.CategoryEnumeration, modules.ProtocolSMB, []string{"--qwinsta"}, "SMB_terminal_sessions.txt"),
		definition("network-interfaces", "Network Interfaces", modules.CategoryEnumeration, modules.ProtocolSMB, []string{"--interfaces"}, "SMB_network_interfaces.txt"),
		definition("running-processes", "Running Processes", modules.CategoryEnumeration, modules.ProtocolSMB, []string{"--tasklist"}, "SMB_running_processes.txt"),
	}
	for index := range definitions {
		if definitions[index].IDValue == "smb-local-groups" || definitions[index].IDValue == "smb-sessions" || definitions[index].IDValue == "logged-on-users" || definitions[index].IDValue == "registry-sessions" || definitions[index].IDValue == "terminal-sessions" || definitions[index].IDValue == "running-processes" {
			definitions[index].RequiredPrivilegeValues = []string{"administrator privileges may be required"}
		}
	}
	return buildModules(definitions)
}

// EnumerationModules returns the deterministic executable-candidate order used by the registry.
func EnumerationModules() []modules.Module {
	result := append([]modules.Module{}, LDAPEnumerationModules()...)
	return append(result, SMBEnumerationModules()...)
}
