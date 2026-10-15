# PwnFlow

PwnFlow is a Go-based Active Directory enumeration orchestrator for authorized assessments. Version 0.1 launches a dark, green-accented Bubble Tea TUI after validating LDAP connectivity and credentials, and provides protocol-scoped NetExec LDAP and SMB enumeration.

Unless `--password` is explicitly supplied, startup prompts for a password in raw terminal mode and displays one `*` per entered character. Backspace, Enter, and Ctrl+C are supported; terminal settings are restored on every exit path. Supplying passwords on command lines can expose them through process inspection and should be avoided on shared systems.

## Security model

Passwords are read from a hidden terminal prompt, are never stored in SQLite or result metadata, and are redacted from streamed output and files. NetExec currently requires its password argument for this operation; this unavoidable process-inspection limitation is documented here and the command is never passed through a shell. Use an isolated assessment host and restrict process visibility.

## Build and run

```bash
git clone git@github.com:Lmarkussen/PwnFlow.git
cd PwnFlow
./scripts/install.sh
make build
./bin/pwnflow --help
```

The development workflow is provided by the root `Makefile`:

```bash
make run ARGS="--target 10.1.10.40 --domain sccm.lab --username audituser"
make test
make check
make install PREFIX="$HOME/.local"
make uninstall PREFIX="$HOME/.local"
```

`make build VERSION=0.1.1` overrides the embedded version. `make clean` removes only `bin/`; it never removes assessment results or SQLite databases. `scripts/install.sh` is the only dependency installer. It runs independently in a normal Kali terminal; PwnFlow never installs packages, invokes sudo, or shows an installer screen at runtime. The default invocation checks and installs the supported dependencies: NetExec, the BloodHound CE application package, the BloodHound CE Python ingestor, and RustHound-CE (including Cargo/build prerequisites when needed). Existing functional tools are skipped. Use `--with-netexec`, `--with-bloodhound-ce`, `--with-bloodhound-python`, `--with-bloodhound` (both BloodHound components), or `--with-rusthound-ce` for selective installation. Kali Linux is the only supported installation target.

The standalone installer uses native sudo authentication only when a privileged operation is needed, scoped noninteractive APT/dpkg settings, pipx for Python CLI tools, and Cargo for RustHound-CE. It never starts BloodHound, Neo4j, or PostgreSQL. Re-run `./scripts/install.sh` when adding tools; dependency detection is read-only inside PwnFlow and missing required dependencies show this command: `cd /home/kali/PwnFlow && ./scripts/install.sh`.

Development and validation are restricted to the authorized lab target `10.1.10.40` and domain `sccm.lab`. PwnFlow rejects other target/domain combinations, and build/test/check targets do not connect to assessment infrastructure.

The application root is resolved from the executable location (or the nearest `go.mod` during development), not the current working directory. Results are written to `results/<domain>/Enumeration/NetExec/`, with prior output under `history/`, and metadata in `enumeration.db`.

The active executable scope is NetExec → Enumeration. LDAP and SMB are separate protocol scopes, so their arguments are never mixed. Credential Auditing remains visible with disabled sensitive Kerberos modules. RustHound-CE is registered separately under Active Directory → Enumeration with a scope-restricted status; it is not a NetExec module and is never included in NetExec YOLO mode. Credential Dumping, Privilege Escalation, Reporting, AD CS, and Network remain visible as inactive taxonomy entries until their workflows are implemented. `A` runs every available module in the selected NetExec Enumeration protocol scope and never expands the authorized target scope.

NetExec LDAP and SMB capabilities are checked locally at execution time with `nxc <protocol> --help`; NetExec LDAP plugin modules are checked with `nxc ldap -L`. Unsupported options are marked unavailable rather than substituted. The current installed Kali lab version was inspected locally as NetExec 1.5.1. No capability check supplies a target or initiates enumeration.

Controls: Navigation uses `↑/↓` to select a row and `←/→` to change its value. Modules use `↑/↓`, `Space`, `Enter`, `R`, and `A` for YOLO mode. Output uses arrows, `PgUp`/`PgDn`, `Home`, and `End`. `Tab` cycles Navigation → Modules → Output; `Ctrl+W` opens the operator-controlled watcher; `Esc` closes it; `?` shows help; `Q` quits when idle.

## Development

```bash
go test ./...
go vet ./...
```

The LDAP preflight intentionally requires TCP/389 and a real NTLMSSP LDAP bind, matching NetExec's LDAP authentication behavior. It does not treat an open port as successful authentication or silently downgrade TLS/signing requirements. Simple-bind identities are normalized to the UPN form `username@domain` when that mechanism is used.

### Optional BloodHound components

PwnFlow registers NetExec BloodHound capability metadata separately from the
BloodHound CE application and the `bloodhound-ce-python` ingestor. The standalone installer does not start services or install these optional components.
To explicitly request the optional installer routines, run one component at a
time (or use `--with-bloodhound` for both):

```bash
./scripts/install.sh --with-bloodhound-ce
./scripts/install.sh --with-bloodhound-python
```

BloodHound collection remains disabled because unrestricted collection methods
may contact hosts beyond the authorized DC. AS-REP Roasting and Kerberoasting
remain registered under NetExec → Credential Auditing → LDAP, but their
sensitive artifact workflows are disabled. No ticket material is written to
ordinary enumeration logs, and PwnFlow does not crack or automatically reuse
credentials. The NetExec `--bloodhound`/`--collection` capability is checked
locally, but the collection module remains unavailable until a confined
single-host workflow exists. The CE application, Python ingestor, and NetExec
collection capability are separate dependencies; the installer never starts a
BloodHound service or binds it to a network interface.

BloodHound CE Python installation is pipx-first. PwnFlow checks both
`bloodhound-ce-python` and `bloodhound-python` as exposed command names, runs
their help capability check, and refreshes the current process PATH after
installation. `pipx ensurepath` configures future shells without PwnFlow
editing bash, zsh, or fish startup files; the user-local pipx bin directory is
also made available immediately. The CE application uses its official
application method and is never installed through pipx.

RustHound-CE is an independent BloodHound CE collector. Request it explicitly
with `./scripts/install.sh --with-rusthound-ce`; the installer checks Cargo,
the required local build dependencies, and operator consent before running
`cargo install rusthound-ce`. Existing functional installations are preserved.
RustHound-CE collection remains Scope Restricted until its secondary
destination behavior can be confined to the authorized DC.

## Emergency terminal recovery

If an older or unresponsive PwnFlow process traps the terminal, use another
shell or SSH session to stop only that process:

```bash
pkill -TERM -x pwnflow
```

If the shell still appears corrupted after the process exits, restore the
terminal with `stty sane` or `reset`. In tmux, `Ctrl+B`, then `D` detaches the
client; PwnFlow does not change the tmux prefix or install tmux keybindings.
