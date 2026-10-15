# PwnFlow

**A focused Bubble Tea workbench for authorized Active Directory enumeration.**

PwnFlow gives an operator one target-aware interface for planning, configuring,
running, and reviewing read-oriented AD assessment modules. It keeps each tool's
native command builder and evidence layout while adding consistent availability,
approval, cancellation, redaction, and SQLite history handling.

## What it provides

- A responsive terminal UI with direct access to small tool families and useful
  protocol navigation for NetExec.
- Registry-wide selection (`Space`), selected execution (`R`), and a global plan
  (`A`) with per-operation input and approval gates.
- Buffered output, lossless findings, restrictive artifact permissions, and
  per-assessment SQLite history.
- Operator-controlled local sudo handoff for PXEThief; PwnFlow never receives
  or transports the sudo password.
- Watcher output with selected-module abort (`x`), immutable execution identity,
  partial-artifact preservation, and process-group cleanup.

## Supported families

| Family | Integrations |
| --- | --- |
| NetExec | LDAP, SMB, WINRM, WMI, MSSQL, SSH, FTP, RDP, VNC, NFS; credential auditing and dumping |
| Network | NetworkHound topology and scoped validation; RelayKing targeted and domain audit |
| SCCM | SCCMhunter discovery and PXEThief |
| AD CS | Certipy find-only collection |
| Active Directory | RustHound-CE LDAP-only collection |

The browser presents NetExec by protocol. The other families present their
registered modules directly, without an unnecessary category or `N/A` protocol
folder.

## Quick start

```bash
git clone git@github.com:Lmarkussen/PwnFlow.git
cd PwnFlow
./install.sh
make build
./bin/pwnflow --target <DC> --domain <DOMAIN> --username <USER>
```

The unqualified `./install.sh` checks and installs all declared dependencies.
Use `--with-*` selectors only when a targeted installation is wanted. PwnFlow
does not install tools at startup. Kali Linux is the supported installation
target.

For development:

```bash
make test
make vet
make check
```

## Controls

| Key | Action |
| --- | --- |
| `↑`/`↓`, `Tab` | Navigate rows, panes, and module lists |
| `Space` | Toggle a module in the registry-wide selection |
| `Enter` | Run the highlighted module |
| `R` | Run the selected modules |
| `A` | Plan the complete eligible registry |
| `I` | Configure an input-required module |
| `Ctrl+W` | Open the execution watcher |
| `x` | Ask to abort the selected running execution |
| `Ctrl+C`, `q` | Cancel or quit with confirmation when work is active |

## Documentation

- [Operator guide](docs/operator-guide.md) — installation, module behavior,
  scope notes, sudo handling, and troubleshooting details.
- [NetExec inventory](docs/netexec-inventory.md) — registered protocols,
  capabilities, options, and validation notes.
- [Enumeration tool candidates](docs/enumeration-tool-candidates.md) — current
  research, overlap analysis, and prioritized additions; no tools are integrated
  by that document.
- [RustHound artifact schema](docs/rusthound-artifact-schema.md) — the observed
  JSON/ACL shape and the limits of local findings analysis.

## Security and authorization

PwnFlow is target-agnostic and does not grant authorization. Run it only against
systems and domains you are explicitly authorized to assess. NetworkHound's
upstream project is distributed under a non-commercial license; PwnFlow does not
vendor or redistribute it. The installer fetches the upstream checkout when that
dependency is selected. Review upstream licenses and terms before use.

Passwords are prompted for in the terminal where possible, are redacted from
operator-facing previews and stored findings, and are not written to SQLite.
NetExec's native password argument is an unavoidable process-visibility caveat;
use an isolated assessment host and restrict process visibility accordingly.

## Credits

PwnFlow integrates and credits NetExec, RustHound-CE, Certipy, SCCMhunter,
PXEThief, NetworkHound, RelayKing, and the upstream projects used by them.
See the [operator guide](docs/operator-guide.md) for the detailed upstream
attribution and license notes.
