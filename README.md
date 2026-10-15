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

`make build VERSION=0.1.1` overrides the embedded version. `make clean` removes only `bin/`; it never removes assessment results or SQLite databases. `scripts/install.sh` is the only dependency installer. It runs independently in a normal Kali terminal; PwnFlow never installs packages, invokes sudo, or shows an installer screen at runtime. The default invocation checks and installs the supported dependencies: NetExec and RustHound-CE (including Cargo/build prerequisites when needed). Existing functional tools are skipped. Use `--with-netexec` or `--with-rusthound-ce` for selective installation. Kali Linux is the only supported installation target.

The standalone installer uses native sudo authentication only when a privileged operation is needed, scoped noninteractive APT/dpkg settings, and Cargo for RustHound-CE. It never installs, starts, or configures a service, and it leaves an existing BloodHound CE application untouched. Re-run `./scripts/install.sh` when adding tools; dependency detection is read-only inside PwnFlow and missing required dependencies show this command: `cd /home/kali/PwnFlow && ./scripts/install.sh`.

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

### BloodHound CE and RustHound-CE

PwnFlow registers NetExec BloodHound capability metadata separately from the
BloodHound CE application and from RustHound-CE. BloodHound CE is the separate
graph application used to import and visualize collected directory data; the
standalone installer does not install, start, or configure it, so install
BloodHound CE with its official application procedure and keep it bound to a
local interface. An existing BloodHound CE installation is still detected
read-only (Debian package `bloodhound`) and keeps working for importing
RustHound-CE output. The retired `--with-bloodhound-ce`,
`--with-bloodhound-python`, and `--with-bloodhound` flags now stop with an
explanation instead of running; the installer no longer manages these
components in either direction.

BloodHound collection remains disabled because unrestricted collection methods
may contact hosts beyond the authorized DC. AS-REP Roasting and Kerberoasting
remain registered under NetExec → Credential Auditing → LDAP, but their
sensitive artifact workflows are disabled. No ticket material is written to
ordinary enumeration logs, and PwnFlow does not crack or automatically reuse
credentials. The NetExec `--bloodhound`/`--collection` capability is checked
locally, but the collection module remains unavailable until a confined
single-host workflow exists. PwnFlow checks `bloodhound-ce-python` and the
legacy `bloodhound-python` as exposed command names only for read-only
detection; the installer does not install either collector.

RustHound-CE is the supported BloodHound CE collector. Request it explicitly
with `./scripts/install.sh --with-rusthound-ce`; the installer checks Cargo,
the required local build dependencies, and operator consent before running
`cargo install rusthound-ce`. Existing functional installations are preserved.

The PwnFlow module under Active Directory → Enumeration always passes
`-c LdapOnly` and pins the domain and DC address to `sccm.lab`/`10.1.10.40`,
so the CLI's default `All` collection is never selected and the module cannot be
redirected by a caller. JSON artifacts are written to
`results/sccm.lab/Enumeration/RustHoundCE/artifacts/<run timestamp>/` so a later
run never overwrites an earlier one, while the sanitized terminal log stays
separate under `results/sccm.lab/Enumeration/RustHoundCE/`. Execution history
keeps status, exit code, artifact path, and a redacted error summary only.

RustHound-CE 2.5.25 accepts the LDAP password only as a command-line value.
That native `-p` argument is used for this private single-operator lab, by
operator decision; the password therefore exists briefly in the collector's
process arguments, exactly as NetExec's does. It is never rendered in the
Module Information command preview (`-p [REDACTED]`, and the same for
`--ldappassword`, `-H/--hashes`, and `--pfx-pass`), never streamed to the
output pane or the persisted log (the runner redacts by value, so both flag
forms are covered), never stored in SQLite or the execution history, and never
appended to an error message. No credential is committed to Git.

RustHound-CE runs only behind a process-specific egress boundary, and PwnFlow
verifies that boundary itself instead of assuming it. On startup, and again
immediately before every collection, `internal/confinement` attempts a TCP
connection to a loopback address nothing listens on:

- the connect stalls until the deadline, or fails with `EPERM` - a cgroup filter
  dropped or rejected the packet, so a boundary is enforced, the module is
  executable, and Enter runs it;
- the connect is refused by the local stack (`ECONNREFUSED`), or a listener
  answers - the local stack handled it, so no boundary exists: the module reports
  `Execution: blocked - Scope Restricted`, names the missing mechanism, and Enter
  declines instead of collecting.

Loopback is used deliberately: it never leaves the host, so the check cannot
contact another system, while `IPAddressDeny=any` denies it just like any other
destination. An unfiltered loopback connect is answered in microseconds, so a
stall is a reliable signature of a dropping filter; both signatures were observed
on the assessment host and are covered by tests. Any outcome the check cannot
classify fails closed. Because the probe runs in the collector's own cgroup, its
verdict applies to the collector, not just to PwnFlow.

### Confined launch

Loading a cgroup BPF program needs privilege, so PwnFlow does not create the
filter; it requires one. The unprivileged systemd user manager accepts
`IPAddressAllow`/`IPAddressDeny` as unit properties but does not enforce them on
this host (`kernel.unprivileged_bpf_disabled=2`), which is exactly why a property
being accepted is not treated as proof. The boundary therefore has to come from
the system manager, which does have the privilege:

```bash
sudo systemd-run --pty --collect \
  --property=User=kali --property=WorkingDirectory=/home/kali/PwnFlow \
  --property=IPAddressAllow=10.1.10.40 --property=IPAddressDeny=any \
  /home/kali/PwnFlow/bin/pwnflow \
  --target 10.1.10.40 --domain sccm.lab --username <operator>
```

That unit confines the process tree - so NetExec runs inside it too, which keeps
every collection on the authorized DC - and it disappears when PwnFlow exits.
Nothing global is configured: no firewall rule, no persistent unit, no service.
DNS is denied along with every other destination, including Tailscale MagicDNS,
so anything that needs name resolution fails visibly rather than leaving the
boundary. Confirm the state the operator sees with `pwnflow`'s Module Information
line: it reports `Execution: enabled - egress confined to 10.1.10.40` only when
the probe passed.

Cargo performs every install build in a temporary directory under `TMPDIR`, and
Kali mounts `/tmp` as a tmpfs sized at roughly half of RAM — too small for
RustHound-CE's optimized release build. The installer therefore builds in
`$HOME/.cache/pwnflow/cargo-tmp`, reports that directory and its free space
before compiling, and refuses to start a build when the filesystem has less
than 2 GiB free. An explicitly configured `TMPDIR` is used when it is a writable
directory with enough room and is never replaced silently; when it is unusable
the installer stops and explains how to correct it.

## Emergency terminal recovery

If an older or unresponsive PwnFlow process traps the terminal, use another
shell or SSH session to stop only that process:

```bash
pkill -TERM -x pwnflow
```

If the shell still appears corrupted after the process exits, restore the
terminal with `stty sane` or `reset`. In tmux, `Ctrl+B`, then `D` detaches the
client; PwnFlow does not change the tmux prefix or install tmux keybindings.
