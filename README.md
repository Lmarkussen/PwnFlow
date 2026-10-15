# PwnFlow

PwnFlow is a Go-based Active Directory enumeration orchestrator for authorized assessments. Version 0.1 launches a dark, green-accented Bubble Tea TUI after validating LDAP connectivity and credentials, and provides protocol-scoped NetExec LDAP and SMB enumeration.

Unless `--password` is explicitly supplied, startup prompts for a password in raw terminal mode and displays one `*` per entered character. Backspace, Enter, and Ctrl+C are supported; terminal settings are restored on every exit path. Supplying passwords on command lines can expose them through process inspection and should be avoided on shared systems.

## Security model

Passwords are read from a hidden terminal prompt, are never stored in SQLite or result metadata, and are redacted from streamed output and files. NetExec currently requires its password argument for this operation; this unavoidable process-inspection limitation is documented here and the command is never passed through a shell. Use an isolated assessment host and restrict process visibility.

## Build and run

```bash
git clone git@github.com:Lmarkussen/PwnFlow.git
cd PwnFlow
./install.sh
make build
./bin/pwnflow --help
```

The development workflow is provided by the root `Makefile`:

```bash
make run ARGS="--target 198.51.100.10 --domain corp.example --username audituser"
make test
make check
make install PREFIX="$HOME/.local"
make uninstall PREFIX="$HOME/.local"
```

`make build VERSION=0.1.1` overrides the embedded version. `make clean` removes only `bin/`; it never removes assessment results or SQLite databases. `install.sh` in the repository root is the only dependency installer. It runs independently in a normal Kali terminal; PwnFlow never installs packages, invokes sudo, or shows an installer screen at runtime. The default invocation checks and installs the supported dependencies: NetExec and RustHound-CE (including Cargo/build prerequisites when needed). Existing functional tools are skipped. Use `--with-netexec` or `--with-rusthound-ce` for selective installation. Kali Linux is the only supported installation target.

The standalone installer uses native sudo authentication only when a privileged operation is needed, scoped noninteractive APT/dpkg settings, and Cargo for RustHound-CE. It never installs, starts, or configures a service, and it leaves an existing BloodHound CE application untouched. Re-run `./install.sh` when adding tools; dependency detection is read-only inside PwnFlow and missing required dependencies show this command: `./install.sh`.

PwnFlow is a general-purpose framework: the target, domain, and credentials are supplied by the operator at startup, so any assessment configuration is accepted. PwnFlow holds no built-in scope and never substitutes a development value. What it validates is input shape and path safety - a target must be a plain address or host name rather than something that looks like a command option, and the domain must be a safe single path component - so unusual input cannot escape `results/`. Authorization for the assessment itself is the operator's responsibility. The test suite is fully offline: build/test/check targets never connect to assessment infrastructure.

The application root is resolved from the executable location (or the nearest `go.mod` during development), not the current working directory. Results are written to `results/<domain>/Enumeration/NetExec/`, with prior output under `history/`, and metadata in `enumeration.db`.

The active executable scope is NetExec → Enumeration. LDAP and SMB are separate protocol scopes, so their arguments are never mixed. Credential Auditing remains visible with disabled sensitive Kerberos modules. RustHound-CE is registered separately under Active Directory → Enumeration with a scope-restricted status; it is not a NetExec module and is never included in NetExec YOLO mode. Credential Dumping, Privilege Escalation, Reporting, AD CS, and Network remain visible as inactive taxonomy entries until their workflows are implemented. `A` runs every available module in the selected NetExec Enumeration protocol scope and never expands the authorized target scope.

NetExec LDAP and SMB capabilities are checked locally at execution time with `nxc <protocol> --help`; NetExec LDAP plugin modules are checked with `nxc ldap -L`. Unsupported options are marked unavailable rather than substituted. The current installed Kali lab version was inspected locally as NetExec 1.5.1. No capability check supplies a target or initiates enumeration.

Controls: Navigation uses `↑/↓` to select a row and `←/→` to change its value. Modules use `↑/↓`, `Space`, `Enter`, `R`, and `A` for YOLO mode. Output uses arrows, `PgUp`/`PgDn`, `Home`, and `End`. `Tab` cycles Navigation → Modules → Output; `Ctrl+W` opens the operator-controlled watcher; `Esc` closes it; `?` shows help; `Q` quits when idle.

## Development

```bash
go test ./...
go vet ./...
```

The LDAP preflight performs a real NTLMSSP bind with your credentials before the
TUI starts, and it never treats an open port as successful authentication.
Because domains may require LDAP signing/integrity — which an unsigned bind
cannot satisfy and which is reported as result code 8 — the preflight negotiates
the transport through `internal/ldaptransport`:

1. plain LDAP on 389, as before;
2. LDAPS on 636 when the server demands integrity or the plain endpoint cannot be
   reached — a TLS channel satisfies the signing requirement, so the same
   credentials bind;
3. StartTLS on 389, only when LDAPS itself is unreachable.

Wrong credentials are never retried: an authentication failure stops at the first
attempt instead of repeating invalid logins. Each attempt is bounded to one per
transport, and when every attempt fails the error explains the LDAP and LDAPS
attempts separately. Failures stay distinct — connectivity, TLS/certificate,
authentication, signing/integrity, protocol — so a signing requirement is never
reported as bad credentials. The transport that carried the bind is printed when
it was not plain LDAP. Certificates are verified against the normal trust store;
if the target's certificate cannot be validated, the opt-in
`--insecure-skip-verify` skips verification explicitly and is reported back,
rather than being applied silently. Simple-bind identities are normalized to the
UPN form `username@domain` when that mechanism is used.

### TLS identity for IP targets

Domain controller certificates normally carry the controller's DNS name, not an
IP SAN, so verifying a connection made to an address fails with "cannot validate
certificate for <ip> because it doesn't contain any IP SANs". PwnFlow separates the
two concerns: it always connects to the target you supplied, and it verifies the
certificate against a name it can justify for that address.

- A host name target is verified as given, with no lookups at all.
- An address target is resolved to its reverse DNS name. A candidate is only used
  when it is a valid host name, sits inside the AD domain you supplied, and
  resolves forward back to that same address. Candidates are normalized and
  ordered, so the choice does not depend on resolver order.
- Nothing else is consulted: no SRV records, no sibling controller, no
  certificate-advertised name. A reverse record on its own is never treated as
  proof of identity, and no name is ever invented.
- If no name can be confirmed, the connection address is verified instead and the
  failure says so, naming the address and what discovery found.

The connection destination never changes because of discovery, and verification
is never disabled to make a mismatch go away. Trust is a separate problem: if the
DC certificate is issued by an internal CA that Kali does not trust, discovering
the host name does not fix the chain, and the diagnostic says which of the
following applies — missing IP SAN, certificate not valid for a name, unknown
issuing authority, expired certificate, failed TLS handshake, or a refused bind.
`--insecure-skip-verify` remains the explicit, operator-approved escape hatch for
lab testing and is reported whenever it is in effect.

### Certificate trust decisions

A chain that does not reach a trusted authority is a trust problem, not an
identity problem, so PwnFlow asks rather than guessing. When the presented
certificate is signed by an unknown authority — and only then — startup shows the
certificate and offers three choices:

```
[!] The certificate presented by <target> (<identity>) is not trusted:
      Subject:   CN=domain controller
      Issuer:    CN=Lab Issuing CA
      Valid:     <notBefore> .. <notAfter> (N days remaining)
      SHA-256:   AA:BB:CC:…
      Problem:   x509: certificate signed by unknown authority
    [t] trust and remember this certificate for this target
    [s] accept this certificate for this session only
    [r] reject and exit (default)
```

- An affirmative answer that is not given is a rejection: an empty line, end of
  input, an unrecognised answer, or a run without an interactive terminal all
  refuse the certificate, and a non-interactive run is told to re-run in a
  terminal or to use `--insecure-skip-verify` deliberately.
- `t` stores non-secret metadata — target, certificate identity, SHA-256
  fingerprint, subject, issuer, expiry — in
  `$XDG_CONFIG_HOME/pwnflow/trusted-certificates.json` (or
  `~/.config/pwnflow/trusted-certificates.json`), created `0600` inside a `0700`
  directory. Credentials are never part of a decision or the store.
- An approval is scoped to the target and certificate identity and matched by
  fingerprint, so the same controller is not asked again; a certificate that has
  changed since it was approved triggers a fresh decision instead of being
  accepted silently. `s` accepts for the current run only.
- Approving an unknown authority can never approve a bad certificate. Host name,
  validity window, and server-auth usage are verified before the question is
  asked, so an expired, wrongly named, or client-only certificate is refused
  outright without an offer to trust it.
- Nothing is written to Kali's CA store, no sudo, APT, or installer is invoked,
  and standard chain verification stays the preferred path: a certificate the
  host already trusts connects without any prompt.

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
with `./install.sh --with-rusthound-ce`; the installer checks Cargo,
the required local build dependencies, and operator consent before running
`cargo install rusthound-ce`. Existing functional installations are preserved.

The PwnFlow module under Active Directory → Enumeration always passes
`-c LdapOnly` together with the target and domain supplied to PwnFlow at startup
(`-d <domain> -i <target>`), so the CLI's default `All` collection is never
selected and the command always matches the operator's configuration. JSON
artifacts are written to
`results/<domain>/Enumeration/RustHoundCE/artifacts/<run timestamp>/` so a later
run never overwrites an earlier one, while the sanitized terminal log stays
separate under `results/<domain>/Enumeration/RustHoundCE/`. Execution history
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

RustHound-CE starts with everything else: `./bin/pwnflow --target <target>
--domain <domain> --username <user>` is the whole workflow, with no launcher
wrapper, no root privileges, no network namespace, and no firewall configuration.
The module shows `READY` once the collector is installed, and Enter runs it
against the target and domain you supplied.

`-c LdapOnly` plus your chosen target and domain narrow what the collector asks
for; they are **not** a network boundary, and Module Information says so
explicitly (`Network scope: LdapOnly against the supplied target; not
kernel-enforced`). In particular, name resolution follows the host resolver and
LDAP referrals are RustHound's own behaviour, so nothing here claims that a
collection cannot reach beyond the target you named. Treat the module as an
operator-scoped collector whose authorization you own.

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
