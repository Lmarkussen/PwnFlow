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

`make build VERSION=0.1.1` overrides the embedded version. `make clean` removes only `bin/`; it never removes assessment results or SQLite databases. `install.sh` in the repository root is the only dependency installer. It runs independently in a normal Kali terminal; PwnFlow never installs packages, invokes sudo, or shows an installer screen at runtime. The default invocation checks and installs **every** supported dependency: NetExec, RustHound-CE (including Cargo/build prerequisites when needed), Certipy for AD CS enumeration, the SCCM tooling SCCMhunter and PXEThief, and the network assessment tools NetworkHound and RelayKing. Existing functional tools are skipped, whichever name they are exposed under. `--with-netexec`, `--with-rusthound-ce`, `--with-certipy`, `--with-sccmhunter`, `--with-pxethief`, `--with-networkhound` and `--with-relayking` remain available as selective conveniences. Kali Linux is the only supported installation target.

The standalone installer uses native sudo authentication only when a privileged operation is needed, scoped noninteractive APT/dpkg settings, and Cargo for RustHound-CE. It never installs, starts, or configures a service, and it leaves an existing BloodHound CE application untouched. Re-run `./install.sh` when adding tools; dependency detection is read-only inside PwnFlow and missing required dependencies show this command: `./install.sh`.

PwnFlow is a general-purpose framework: the target, domain, and credentials are supplied by the operator at startup, so any assessment configuration is accepted. PwnFlow holds no built-in scope and never substitutes a development value. What it validates is input shape and path safety - a target must be a plain address or host name rather than something that looks like a command option, and the domain must be a safe single path component - so unusual input cannot escape `results/`. Authorization for the assessment itself is the operator's responsibility. The test suite is fully offline: build/test/check targets never connect to assessment infrastructure.

The application root is resolved from the executable location (or the nearest `go.mod` during development), not the current working directory. Results are written to `results/<domain>/Enumeration/NetExec/`, with prior output under `history/`, and metadata in `enumeration.db`.

The browser presents NetExec by protocol and keeps its Credential Auditing and Credential Dumping categories. Network, SCCM, AD CS, and Active Directory present their registered modules directly, without an intermediary category or `N/A` protocol folder. LDAP and SMB remain separate protocol scopes, so their arguments are never mixed.

Offline RustHound ACL analysis and the structured findings storage API are
documented in [the artifact schema note](rusthound-artifact-schema.md). Findings
processing is explicit and read-only; it does not replace BloodHound CE's graph
analysis or automatically process partial artifacts at startup.

`Space` selection is registry-wide: a module selected in one tool family, category, or protocol stays selected while you navigate, and the modules pane header shows the running total. `Enter` runs only the highlighted module. `Ctrl+R` runs the selected eligible modules as a single batch, whatever scope is visible; an unavailable selection is reported and skipped rather than run. `Ctrl+A` runs the fixed Default Enumeration profile regardless of the family, category, protocol, focus, scroll position, or selection on screen; it never means “run the whole registry.”

`Ctrl+A` reports requested, eligible, authorization-required, skipped, executed, and analysis counts separately. It collects required values before execution and keeps credential-access, remote-admin, local-sudo, missing-input, and wider-scope entries visible with their reason. Declining a specific authorization continues the eligible remainder; it does not make the profile appear complete.

LDAP-based modules prefer LDAPS. NetExec LDAP modules therefore pass `--port 636`, which is how the installed NetExec selects `ldaps://` for its LDAP protocol, while its SMB modules keep their defaults. Certipy `find` passes `-ldap-scheme ldaps -ldap-port 636`, and RustHound-CE passes `--ldaps`; none of these is downgraded to unsigned LDAP at runtime, and none requires extra certificate configuration. PwnFlow's own certificate trust decisions apply to its Go LDAP preflight only: each external tool verifies - or, for its own historical reasons, does not verify - the domain controller's certificate on its own, and PwnFlow neither changes nor claims to change that.

NetExec coverage follows the installed executable protocol by protocol: LDAP, SMB, WINRM, WMI, MSSQL, SSH, FTP, RDP, VNC, and NFS, each with its own transport, credential and domain flags, its native enumeration commands, and the `-M` modules that protocol advertises. A module is registered under the protocol that advertises it - so a capability that SMB and WMI both offer appears once - and the registry is compared against `nxc <protocol> --help` and `nxc <protocol> -L` by a test, so a registration can neither name a module the build does not advertise nor drop one it does without a recorded reason. The retired BloodHound collection registration and the LDAP modules the build marks `[REMOVED]` are gone. `docs/netexec-inventory.md` records the full matrix, what each module needs, which duplicates were removed and what replaced them, and which parts ran against an authorized lab.

Capabilities are probed once, off the render path, and cached: navigation and Module Information never wait on `nxc`, and the probe sends no target and initiates no enumeration. A module the installed build cannot run shows `UNAVAILABLE` with the reason, and execution refuses it as well. A module that needs a value from you shows `INPUT-REQ` and asks for it, so being unconfigured never looks like being unsupported. A module that needs elevated rights **on the target** shows `ADMIN-REQ` with the specific right named in Module Information; the label never blocks a run, because a module can still produce a useful partial result without those rights. Available modules carry no suffix at all - there is no ready label. The current installed lab version was inspected as NetExec 1.5.1.

Modules that need a value only the operator can supply - a registry path, a search text, the user a group query should name - take it from `--module-options <registration>.<KEY>=VALUE`, repeatable:

```bash
./bin/pwnflow --target <target> --domain <domain> --username <user> \
  --module-options smb-reg-query.PATH='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion' \
  --module-options smb-reg-query.KEY=ProductName
```

Where a module has an obvious starting point PwnFlow supplies it - `groupmembership` defaults to the account you authenticated with, `smb-reg-query` to the registry key that names the operating system, `smb-wcc` to a report inside the assessment tree, and `daclread` to the read action - and your value always wins. An option key no registration uses is reported at startup instead of being silently dropped.

### Local sudo, and what PwnFlow does with it

Some tools need privileges the PwnFlow process does not have - PXEThief cannot craft its DHCP packets without `CAP_NET_RAW`. PwnFlow asks before the batch starts, in the amber confirmation, naming the modules that need it:

```
Default Enumeration includes tools requiring local sudo privileges (pxethief): PXEThief discovery requires
Linux raw-socket privileges (CAP_NET_RAW), which this process does not have.
Authenticate with sudo before starting? [y/N]
```

Only `y` approves. Approval releases the terminal through Bubble Tea's external-process handoff, so **sudo reads the password itself**; PwnFlow never receives, stores, caches, logs or forwards it. There is no `sudo -S`, no password in an environment variable or in `argv`, no temporary password file, no askpass helper, no passwordless sudoers rule, no capability handed to an interpreter, and no elevation of the whole PwnFlow process - a test walks the repository for exactly those patterns.

What the handoff leaves behind is sudo's own cached authorization, which has a lifetime (15 minutes by default) and, on a default sudo (`timestamp_type=tty`), is keyed to the terminal. PwnFlow therefore does not assume it lasts: before every privileged invocation it asks sudo, noninteractively (`sudo -n -v`), whether the cache is still valid. A valid cache is reused, so a batch with several privileged invocations prompts once. An expired one pauses the batch *before* that invocation and asks you to authenticate again; declining skips the privileged work - PwnFlow never retries a privileged tool unprivileged - and the rest of the batch continues. Sudo is never allowed to prompt from the background worker.

Local sudo is not the same thing as `ADMIN-REQ`, which describes rights **on the remote target or domain**. Approving sudo authorizes local elevation for the batch that asked; it does not authorize credential access, coercion, or any other operation, each of which keeps its own approval.

### Default Enumeration

`Ctrl+A` runs the fixed **Default Enumeration** profile, not the whole
registry. It includes the selected NetExec LDAP checks (password-not-required,
delegation, DNS, obsolete operating systems, SCCM, authenticated-user info,
AS-REP and Kerberos material) and the selected SMB checks (server/session and
logged-on-user observations, NTLM reflection, GPP/AWS/user attributes, LAPS
and gMSA), all registered Certipy AD CS enumeration, RustHound-CE, SCCMhunter,
PXEThief, and the eligible Network assessments. Remote-admin, credential
material, local-sudo, missing-input and wider-scope operations remain explicitly
gated; declined items are recorded and the eligible remainder continues.

Masscan is deliberately excluded from this profile. Run it manually with
`Enter` after entering and approving its target and port inputs.

### Network assessment: NetworkHound

NetworkHound (<https://github.com/MorDavid/NetworkHound>, Mor David) is installed as an upstream checkout with its own virtual environment under `~/.local/share/pwnflow/tools/NetworkHound`. It is distributed under a **non-commercial license**, so PwnFlow neither vendors nor redistributes its source: `./install.sh` fetches the upstream checkout and the runtime drives the installed copy.

Two capabilities are registered directly under Network, and the difference between them is the point:

| Module | What it does | Scope |
|---|---|---|
| **AD Network Topology** | Reads computer objects through the configured domain controller over LDAP, resolves their names through the same server, and writes BloodHound-compatible OpenGraph JSON | The domain controller only. NetworkHound's `--port-scan`, `--valid-http`, `--valid-smb`, `--ssl`, `--shadow-it` and `--networks` are not requested, so no discovered computer is contacted |
| **Scoped Network & Service Validation** | Runs the port and service validation against a network scope **you supply for that run** - CIDR blocks, address ranges and single addresses | Exactly the addresses you name. Nothing is derived from Active Directory, and no credential is passed, because NetworkHound's manual mode ignores the LDAP options |

The scoped scan asks for its scope before the batch starts (`INPUT-REQ`, answered with Enter or pre-set with `--module-options networkhound-scope-validation.NETWORKS=198.51.100.0/29`), validates it - a host name is refused, because a name would resolve to addresses you did not name - and appears in the plan approval list, so a global run never starts a network sweep on its own. `--valid-http`, `--valid-smb` and certificate detail (`--ssl`) are opt-in per option; the shadow-IT subnet sweep is not registered at all.

Each run writes into its own directory (`results/<domain>/Enumeration/NetworkHound/artifacts/<module>-<timestamp>/`), so no run overwrites another, and the files are tightened to owner-only after the tool writes them. Nothing is uploaded to a BloodHound server.

### Network assessment: RelayKing

RelayKing (<https://github.com/depthsecurity/RelayKing-Depth>, Depth Security) is installed the same way, as an upstream checkout with its own virtual environment under `~/.local/share/pwnflow/tools/RelayKing`. Its entry point prints its usage and then exits non-zero, which the installer and the dependency probe both accept, judging the tool by the options its help documents.

Two registrations cover the two ways the tool is meant to be used, both directly under Network:

| Module | Profile | Scope |
|---|---|---|
| **Relay Exposure Assessment (Targeted)** | `-vv --protocols smb,ldap,ldaps,mssql,http,https --threads 10 -o plaintext,json --proto-portscan --ntlmv1 --gen-relay-list <run>/relaytargets.txt`, with `--output-file <run>/relayking-scan` | The single host you configured, named at the end of the command. Reads the domain NTLMv1 policy through the domain controller; enumerates nothing else |
| **Relay Exposure Audit (Full Domain)** | The same profile plus `--audit` | Enumerates the domain's computers with your low-privilege credentials and contacts each one. It is held for an explicit approval, so a global run never begins a domain-wide scan on its own |

The detection profile is the one upstream recommends: signing and channel-binding checks for SMB, LDAP and LDAPS, HTTP/HTTPS authentication protection, MSSQL relay settings, the fast port pre-scan (`--proto-portscan`) and the domain NTLMv1 policy check (`--ntlmv1`). The protocols upstream still marks as work in progress - SMTP, IMAP, WINRM - are refused rather than presented as supported, and the protocol list is selectable per option (`--module-options relayking-target-assessment.PROTOCOLS=smb,ldaps`).

**Not registered, on purpose:** `--coerce` and `--coerce-all` make the target authenticate to a listener you would have to run, and `--ntlmv1-all` reads each host's registry with administrative rights. Those are attack and administrative operations, not exposure assessment, and they are not exposed as PwnFlow registrations. CIDR, range and target-file modes are excluded too: a registration scans the host or the domain it was configured with, never a scope assembled at run time.

Each run writes both reports and the relay target list into its own directory (`results/<domain>/Enumeration/RelayKing/artifacts/<module>-<timestamp>/`), owner-only after the tool writes them.

When a module needs a value that has no sensible default - the object whose DACL to read, the text to search computers for - pressing `Enter` (or `I`, to configure it without running it) opens an input prompt that explains the field and validates the answer. A value entered this way is used for the rest of the assessment and by any batch that includes the module, including a global run, which collects every value it needs before it starts rather than interrupting itself halfway. `Esc` during a prompt skips that one module and the rest of the plan still runs; `Ctrl+C` abandons the plan. Values live in the running session only, so they cannot reach another assessment, and automation can keep supplying them up front with `--module-options`.

PwnFlow is an enumeration and assessment framework, so the NetExec registry holds reads: directory, host, share, service, and configuration enumeration; the credential checks for each protocol; and the credential material a plain read exposes, which lives in `Credential Dumping` rather than `Enumeration`. AS-REP roasting and Kerberoasting are registered under LDAP in `Credential Auditing`: they use the directory protocol and your credentials, change nothing on the target, and write the crackable material into the assessment tree for you to audit offline - PwnFlow never cracks it, and it never runs them for you. Exploitation, coercion, relay execution, payload delivery, remote command execution, credential dumping that needs code execution, and anything that configures a listener are not registered at all, so an enumeration scope cannot reach them even by accident.

Module Information explains a registration before you run it: the transport, the NetExec module or native flag, the options (yours and the defaults), and whether the target has to grant an administrator right.

Controls: Navigation uses `↑/↓` to select a row and `←/→` to change its value. Modules use `↑/↓`, `PgUp`/`PgDn`, `Home`/`End`, `Space` to select, `Enter` to run the highlighted module, `I` to fill in a value a module needs, `Ctrl+R` to run the selection, and `Ctrl+A` to run Default Enumeration; the module list scrolls with the selection, and its header shows the window (`ENUMERATION MODULES // 9-21/24`) when the list is longer than the pane. While a prompt is open, `Enter` answers it, `Esc` skips that one module, and `Ctrl+C` abandons the plan. Output uses arrows, `PgUp`/`PgDn`, `Home`, and `End`. `Tab` cycles Navigation → Modules → Output; `Ctrl+W` opens the operator-controlled watcher; `Esc` closes it; `?` shows help; `Q` quits when idle.

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

The NetExec BloodHound collection module is no longer registered: its
collection methods may contact hosts beyond the authorized DC, so it is absent
from the registry rather than present and disabled. AS-REP Roasting and
Kerberoasting remain registered under NetExec → Credential Auditing → LDAP, but
their sensitive artifact workflows are disabled. No ticket material is written
to ordinary enumeration logs, and PwnFlow does not crack or automatically reuse
credentials. PwnFlow checks `bloodhound-ce-python` and the
legacy `bloodhound-python` as exposed command names only for read-only
detection; the installer does not install either collector.

RustHound-CE is the supported BloodHound CE collector. Request it explicitly
with `./install.sh --with-rusthound-ce`; the installer checks Cargo,
the required local build dependencies, and operator consent before running
`cargo install rusthound-ce`. Existing functional installations are preserved.

The PwnFlow module under Active Directory always passes
`-c LdapOnly` together with the target and domain supplied to PwnFlow at startup
(`-d <domain> -i <target> --ldaps`), so the CLI's default `All` collection is
never selected, the command always matches the operator's configuration, and
the collection runs over LDAPS on port 636. JSON
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
Once the collector is installed the row carries no status suffix, and Enter runs
it against the target and domain you supplied. Rows only carry a suffix when
there is something to say: `ADMIN-REQ` when the module needs elevated rights on
the *target*, and `UNAVAILABLE` when it cannot run at all.

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

### SCCM discovery and PXE testing

SCCM is a tool family of its own: **SCCM** directly carries SCCMhunter and
PXEThief. Install them with `./install.sh --with-sccmhunter` and
`./install.sh --with-pxethief`, or run `./install.sh` to check and install
everything. Both are source checkouts with their own virtual environment under
`$PWNFLOW_TOOLS_DIR` (default `~/.local/share/pwnflow/tools`), and PwnFlow invokes
that environment's interpreter by path, so **no virtualenv activation is needed** in
Bash, Zsh, or Fish.

PXEThief is pinned to `pull/11` (`8ca8a79`, AES-256 media variable support), not the
default branch. The installer clones the repository, fetches
`pull/11/head:pr-11`, checks that branch out, records the revision, and reuses an
already-verified checkout rather than reinstalling it. If the pull request cannot be
fetched, the installer reports the git error and never substitutes another revision.

**SCCMhunter** runs `find` and then `show -all` over LDAPS against the domain
controller supplied to PwnFlow, reads the tool's own database for structured records,
and stores what it found — address, host name, SCCM role, and provenance — in the
assessment's SQLite history, scoped to the assessment domain. Each run gets its own
isolated data directory, so a run never reads another assessment's results, and the
Module Information pane reports the stored endpoint count by role.

**PXEThief** resolves that endpoint list when it runs, so selecting both modules and
pressing `R` discovers first and probes afterwards. With no usable endpoint stored,
Default Enumeration records PXEThief as awaiting SCCMhunter discovery and does not
broadcast. An explicitly approved manual PXEThief run may use mode 1, which
**broadcasts a DHCP discover on the local network** and follows the PXE server it
finds; mode 1 also honours the
operator's own `settings.ini`, including its automatic blank-password exploitation
setting, so it is only ever an operator-initiated action. With endpoints stored, one
`pxethief.py 2 <address>` invocation runs per endpoint — separately, never combined,
and a failure on one endpoint does not stop the others.

Results are kept apart: discovery output and preserved tables under
`results/<domain>/Enumeration/SCCMHunter/`, and one directory per endpoint under
`results/<domain>/Enumeration/PXEThief/`. Endpoints that resolve outside the
assessment domain, or that have no usable address, are never probed, and the
addresses in the list are not a network boundary.

PXEThief crafts DHCP packets with Scapy, so it needs **Linux raw-socket privileges**
(`CAP_NET_RAW`) in the process that runs it. PwnFlow reports whether the capability is
present in Module Information and, when it is missing, names it in the failure
summary instead of leaving you with a Python traceback. It never elevates itself: the
virtual environment's interpreter is a link to the system Python, so granting the
capability to it is not an option PwnFlow offers. When you intend to use PXEThief,
give the session the capability explicitly and only for as long as you need it:

```bash
sudo setpriv --ambient-caps=+net_raw --inh-caps=+net_raw ./bin/pwnflow \
  --target <DC> --domain <domain> --username <user>
```

That runs PwnFlow with the one capability, not as root: no systemd unit, no network
namespace, and no firewall change are involved, and a normal `./bin/pwnflow` start is
unaffected. If you prefer per-command elevation, run the PXEThief invocation yourself
under `sudo` with a rule scoped to that exact interpreter and script; PwnFlow will
keep using the unprivileged interpreter and report the requirement rather than
elevating on its own.


### AD CS enumeration with Certipy

Certipy's AD CS tool is registered directly under AD CS as three
read-only modules: **AD CS Discovery** (`certipy find`), **Enabled Certificate
Templates** (`find -enabled`), and **Potentially Vulnerable Certificate
Templates** (`find -vulnerable`). Kali's `certipy-ad` package and a pipx
installation of the same tool are both detected, and whichever is found has to
report the AD CS tool's own banner and document the arguments PwnFlow passes
before it is accepted; an unrelated program that happens to be called `certipy`
is reported instead of being run.

Request the dependency explicitly with `./install.sh --with-certipy`, which
installs or reuses the `certipy-ad` package. The installer simulates the APT
transaction and asks for confirmation before applying it, never upgrades or
replaces a Certipy that is already installed but unusable, and reports the
result in the installation summary.

Every module passes `-dc-only` together with the target, domain, and credentials
supplied to PwnFlow at startup, so the collection stays on the configured domain
controller: certificate authorities, templates, and their configuration are read
over LDAP, and CA registry retrieval, Web Enrollment checks, and member-machine
contact are skipped. The transport is pinned to LDAPS (`-ldap-scheme ldaps
-ldap-port 636`) and is never downgraded to unsigned LDAP, which is the
condition a signing-requiring controller would otherwise reject. `-dc-only` and
the pinned flags express the intended scope; DNS resolution and LDAP referral
handling remain Certipy's own behaviour, and Module Information states that they
are not a network boundary.

Certipy's native `-u`/`-p` credentials are used for this private
single-operator lab, by operator decision, so the password exists briefly in the
collector's process arguments exactly as NetExec's does. It is redacted from the
Module Information preview, from streamed output and persisted logs, and from
the SQLite execution history, where only status, exit code, artifact path, and a
redacted error summary are recorded. JSON and text reports are written to
`results/<domain>/Enumeration/Certipy/artifacts/<run timestamp>/` with a
per-run prefix, so a later run never overwrites an earlier one, and they stay
separate from the sanitized terminal log under
`results/<domain>/Enumeration/Certipy/`.

## Emergency terminal recovery

If an older or unresponsive PwnFlow process traps the terminal, use another
shell or SSH session to stop only that process:

```bash
pkill -TERM -x pwnflow
```

If the shell still appears corrupted after the process exits, restore the
terminal with `stty sane` or `reset`. In tmux, `Ctrl+B`, then `D` detaches the
client; PwnFlow does not change the tmux prefix or install tmux keybindings.

### Specialist dependency repair

Run `./install.sh` without flags to verify or install every supported dependency.
The specialist Python tools use isolated pipx environments; the installer also
checks `~/.local/bin` so PwnFlow can resolve them from a normal noninteractive
launch. A failed specialist does not prevent later specialist attempts; the
final summary reports every outcome and exits nonzero if any selected attempt
failed. Live relay, SQL command execution, SCCM client registration, and GPO
Neo4j enrichment remain outside automatic execution.

### Network assessment: Masscan

Masscan is registered directly under **Network** and is manual-only: global `A`
(Default Enumeration) skips it because it is an active raw-packet scan. Press `Enter` on
Masscan to open the normal orange input flow and enter one IPv4 target, CIDR, or
explicit IPv4 range. The port list below is fixed and is not an interactive input:

`21,22,23,25,53,80,110,111,135,139,389,443,445,593,623,636,993,995,1433,1521,1723,2049,2083,2086,3306,3389,5000,5432,5601,5985,5986,6379,8000,8008,8080-8090,8181,8443,8444,8888,9000,9090,9200,9443,10000,27017`

PwnFlow validates the requested target syntax and shows the fixed rate of 4000
packets per second before the existing local sudo preflight. A manually entered
target does not require `AUTHORIZED_SCOPE`; when that optional restriction is
configured, the target must remain inside it. Configure it, for example, with
`--module-options masscan.AUTHORIZED_SCOPE=198.51.100.0/24`. Optional exclusions
can be supplied with `masscan.EXCLUDE`. Masscan always uses the existing local
sudo approval and timestamp flow; PwnFlow never stores the sudo password.

Each run writes the original grepable output to
`results/<domain>/Enumeration/Masscan/artifacts/<timestamp>/masscan.log` and
keeps the execution transcript in the normal module artifact. Open ports are
shown as Network observations under **Port Discovery**, not as vulnerabilities.
No live scan is performed by installation or dependency checks.

### Findings history reset

To remove derived Findings history for one assessment while preserving the
original result artifacts, stop PwnFlow and run the deliberately confirmed
maintenance command from the project root:

```bash
./bin/pwnflow --target TARGET --domain DOMAIN --username MAINTENANCE_USER \
  --reset-findings --confirm-reset-findings
```

This clears findings, evidence links, and queued analysis jobs for that
assessment only. It does not require a password or LDAP connection, and it
does not delete executions, configuration, schema metadata, or raw evidence.
Create and verify an external database backup before using it.
