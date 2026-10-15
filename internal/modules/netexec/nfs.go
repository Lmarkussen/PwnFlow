package netexec

import "github.com/pwnflow/pwnflow/internal/modules"

// NFS exports are enumerated without credentials, so the transport spec passes
// neither username nor password. The installed build advertises no modules for
// NFS. The native --ls/--get-file/--put-file flags take operator-supplied paths
// and are documented rather than registered.

func NFSEnumerationModules() []modules.Module {
	return level(modules.CategoryEnumeration, modules.ProtocolNFS, []entry{
		{
			id: "nfs-auth-check", name: "NFS Service Check",
			description: "Contacts the target's portmapper and reports what the NFS service answers. It needs no credentials and changes nothing.",
			output:      "NFS_service_check.txt",
		},
		{
			id: "nfs-shares", name: "List NFS Exports",
			description: "Lists the exported file systems through the --shares native flag, including the hosts each export allows.",
			args:        []string{"--shares"}, output: "NFS_shares.txt",
		},
	})
}
