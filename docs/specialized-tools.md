# Specialist tool integrations

The registry records these upstream revisions checked during Prompt 069. The
modules use only the modes listed here; no other upstream mode is exposed.

| Tool | Revision | Registered mode | Boundary | License evidence |
|---|---|---|---|---|
| SCCMSecrets | `5488158d097a7f76b879e0e5db7d9e123380fd7a` (`master`) | Offline placeholder only | `policies` and `files` stay disabled: they can register/impersonate SCCM clients or retrieve protected deployment content. | Upstream repository did not expose a machine-readable license file during audit; review before redistribution. |
| mssqlrelay | `1e03c96f0d05f7aed0abd89186bfe58e1a4f54c4` (`main`) | `check` | One configured MSSQL target. `checkall`, `relay`, coercion and command execution are not registered. | MIT (`LICENSE`). |
| MSSqlPwner | `c791b84431345064f52f86ca01d33ec00f24909a` (`main`) | `enumerate` | Linked-server and impersonation enumeration only. `exec`, `ntlm-relay`, interactive and direct-query modes are not registered. | Upstream repository did not expose a machine-readable license file during audit; review before redistribution. |
| gpoParser | `5cfe7aa3556f7c9263620515a33f4ef7afb88c1b` (`main`) | `local`, `remote` | `local` requires explicit SYSVOL and LDAP-export paths; `remote` targets the configured DC. `enrich` is not registered because it writes to Neo4j. | MIT (`LICENSE`). |
| ghostSPN | `f5df2cd072d9c3ba81b01590e433b21449d91394` (`main`) | bounded JSON audit | Configured DC/domain only; JSON output is preferred. Optional DNS expansion is not enabled by the module. | Upstream repository did not expose a machine-readable license file during audit; review before redistribution. |

The five tool dependencies are optional. A missing executable makes only its
own module unavailable; it does not block unrelated modules. No live assessment
was run as part of this integration.

## Installation and verification

`./install.sh` verifies all twelve dependencies when run without flags. The
pipx-backed tools are installed from Git URLs using isolated environments and
are resolved from both `PATH` and `~/.local/bin`, so a noninteractive PwnFlow
launch does not depend on shell startup files. The installer runs every
selected dependency attempt, prints a complete summary, and returns nonzero if
any selected attempt fails.

On the Prompt 070 Kali verification, the installed entry points were:

- `/home/kali/.local/bin/mssqlrelay` — upstream `1.1`.
- `/home/kali/.local/bin/mssqlpwner` — upstream `1.3.2`.
- `/home/kali/.local/bin/gpoParser` — upstream `1.0.0`.
- `/home/kali/.local/bin/ghostspn` — upstream `0.1.0`.
- `/home/kali/.local/share/pwnflow/tools/SCCMSecrets/.venv/bin/python3` plus `SCCMSecrets.py`.

The installer verified each with its actual help entry point. No live target,
LDAP, DNS, relay, SQL, SCCM registration, or GPO remote operation was run.
