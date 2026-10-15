package netexec

import "github.com/pwnflow/pwnflow/internal/modules"

// FTP has no domain and no modules in the installed build. The listing flag
// takes an optional directory, so `--ls` with no argument lists the session's
// default directory; the file transfer flags (--get/--put) take operator-supplied
// names and are documented rather than registered.

func FTPEnumerationModules() []modules.Module {
	return level(modules.CategoryEnumeration, modules.ProtocolFTP, []entry{
		{
			id: "ftp-auth-check", name: "FTP Authentication Check",
			description: "Authenticates to the FTP service and prints the result, including the banner the service returns.",
			output:      "FTP_auth_check.txt",
		},
		{
			id: "ftp-list", name: "List Directory",
			description: "Lists the files, including hidden ones, in the session's directory through the --ls native flag. Reads only.",
			args:        []string{"--ls"}, output: "FTP_listing.txt",
		},
	})
}
