# Enumeration Tool Candidates

Research snapshot: 2026-10-15. This is a source-level audit, not a live lab
validation. No candidate was installed, executed, or integrated into PwnFlow.

## Executive recommendation

1. **go-windapsearch** — the clearest small addition for targeted LDAP queries
   that PwnFlow does not currently expose as first-class modules: DNS names and
   zones, protected/admin objects, recursive privileged users, and unconstrained
   delegation. Its JSON output and single-binary Go distribution fit PwnFlow's
   bounded runner model. Maintenance is slow (last upstream push: 2021-03-25),
   so integration should begin with a pinned source review and a compatibility
   probe.
2. **LDAPDomainDump** — useful if operators want a conventional, human-readable
   LDAP evidence bundle: HTML, JSON, and greppable output include trusts, policy,
   users, groups, computers, and group relationships. It overlaps RustHound's
   LDAP collection substantially, so it is a candidate for an optional export
   profile, not another default full-domain run.
3. **enum4linux-ng** — worthwhile only for a deliberately bounded SMB/RPC
   profile. Its parsed YAML/JSON output and RPC coverage add value where NetExec
   does not expose an equivalent result, but it wraps multiple Samba clients and
   can enumerate shares, services, printers, password policy, and RID ranges.
   Defaults and target-side effects require a module-specific allowlist.

**Do not integrate linWinPwn as a module.** It is an orchestration shell script,
not a single bounded collector, and its `--auto` mode includes password spraying,
roasting/cracking, exploit checks, coercion/service checks, and domain-wide target
fan-out. PwnFlow already owns the safe subset more explicitly.

## Existing coverage

PwnFlow currently registers 101 modules in five families: NetExec, Network,
SCCM, AD CS, and Active Directory. Existing integrations include NetExec LDAP/
SMB/WinRM/WMI/MSSQL/SSH/FTP/RDP/VNC/NFS, RustHound-CE LDAP-only collection,
Certipy find-only AD CS collection, SCCMhunter, PXEThief, NetworkHound, and
RelayKing. The comparison below treats an existing module as covered only when
its current command builder and scope are actually present in the repository.

| Capability | Current PwnFlow | Candidates / gap | Assessment |
| --- | --- | --- | --- |
| LDAP users, groups, computers | NetExec LDAP, RustHound-CE | LDAPDomainDump, windapsearch | Covered; candidates mainly add alternate exports or focused queries |
| Domain trusts and relationships | RustHound graph collection; NetExec LDAP coverage varies by registration | LDAPDomainDump explicitly writes `domain_trusts`; windapsearch has LDAP metadata/custom queries | **Potential export gap**, verify whether a dedicated trust artifact is needed |
| DNS names/zones from AD | NetExec LDAP inventory has DNS-related registrations | windapsearch `dns-names` and `dns-zones` | **Distinct focused gap** |
| Delegation / protected objects | NetExec inventory includes delegation-oriented checks; RustHound collects graph edges | windapsearch `unconstrained`, `admin-objects`, `privileged-users` | **Focused query gap**, especially operator-readable findings |
| SMB/RPC users, groups, shares, services, policy | NetExec protocol registry covers much of this | enum4linux-ng parses Samba RPC and exports structured YAML/JSON | Mostly duplicative; possible bounded RPC evidence profile |
| LDAPS/TLS LDAP collection | RustHound pins LDAPS; Certipy pins LDAPS; NetExec LDAP pins port 636 | windapsearch `--secure` skips certificate verification; LDAPDomainDump documents LDAP/NTLM/SIMPLE but not a PwnFlow-safe TLS policy | Covered where strict transport matters; candidates need TLS review |
| AD CS | Certipy find-only | linWinPwn calls Certipy/certi.py | Covered; no addition |
| SCCM/PXE | SCCMhunter and PXEThief | linWinPwn invokes SCCMhunter/SCCMSecrets | Covered; SCCMSecrets would need separate scope review |
| Network exposure and service checks | NetworkHound scoped validation and RelayKing | linWinPwn composes several checks and broad target lists | Covered by explicit profiles; wrapper is too broad |
| Kerberos exposure / roasting | NetExec AS-REP and Kerberoasting registrations | linWinPwn, windapsearch `user-spns` | Covered for PwnFlow's existing credential-auditing policy; do not duplicate |

## linWinPwn audit

**Source:** [lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) — MIT,
active upstream repository, Bash orchestrator. The README advertises interactive
and `--auto` modes, LDAPS, forced Kerberos, multiple credential forms, and target
selection. The source entry points are `linWinPwn.sh`, `install.sh`, and
`MENUS.md`; the project is a wrapper around many separately installed tools.

The README's authenticated path includes DNS extraction, BloodHound collection,
NetExec, enum4linux-ng, LDAPDomainDump, bloodyAD, SCCMhunter, GPOParser, Certipy,
Kerbrute, share enumeration, and service/coercion checks. The unauthenticated path
also lists RID brute force, Kerbrute spraying, Pre2k checks, AS-REP roasting,
Kerberoasting, DNS update checks, and vulnerability checks. It explicitly lists
password cracking with John and rockyou in automated workflows.

| linWinPwn area | PwnFlow disposition |
| --- | --- |
| NetExec, BloodHound/RustHound, Certipy, SCCMhunter, NetworkHound-like checks | Already covered or intentionally narrower |
| LDAPDomainDump and enum4linux-ng orchestration | Candidate components assessed separately below |
| DNS extraction | Partly covered; focused DNS names/zones remain a plausible addition |
| Trust/delegation/GPO details | Partly covered through LDAP/graph output; dedicated operator-readable artifacts may help |
| Anonymous enumeration | Not a default PwnFlow credential model; would require an explicit bounded module and scope decision |
| RID brute force, spraying, roasting/cracking, exploit checks, coercion | Intrusive or credential-auditing behavior; do not import through `--auto` |
| `--targets All`, auto-config, tunnels/proxychains | Incompatible with PwnFlow's explicit target and no-broad-scan boundary |

The label “enumeration only” is therefore insufficient evidence for execution.
Any future component must be copied into a dedicated command profile, with exact
arguments, target fan-out rules, output paths, and approval state tested first.

## Candidate review

### enum4linux-ng

- **Upstream:** [cddmp/enum4linux-ng](https://github.com/cddmp/enum4linux-ng),
  GPL-3.0, active; the repository reports release `v1.3.10`.
- **Install/runtime:** Python script plus Samba clients (`nmblookup`, `net`,
  `rpcclient`, `smbclient`); Kali packaging or a pinned checkout should be
  verified before integration, not assumed from this audit.
- **Authentication:** anonymous/guest-style operation plus username/password,
  NTLM hash, and Kerberos ticket options documented upstream.
- **Collection/output:** RPC users/groups/members/shares/services/password policy,
  OS/printer information, optional RID cycling, LDAP/LDAPS domain information,
  and SMB dialect/signing checks; YAML or JSON export.
- **Scope/safety:** one configured target is possible, but `-A`, `-C`, shares,
  RID cycling, and service enumeration are separate behaviors that must not be
  bundled without an allowlist. It requires no local sudo in the documented
  normal path, but relies on external Samba binaries.
- **Overlap:** high with NetExec. The distinctive value is parsed multi-file
  export and a Samba/RPC evidence shape, not another broad SMB wrapper.

### LDAPDomainDump

- **Upstream:** [dirkjanm/ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump),
  MIT, not archived; last upstream push reported as 2025-04-06.
- **Install/runtime:** Python 3.6+, `ldap3`, and `dnspython`; PyPI or source
  install is documented upstream. No local privilege is required.
- **Authentication/TLS:** anonymous or username/password; NTLM and SIMPLE
  authentication types are documented. The upstream usage exposes a DC/DNS
  server option, but PwnFlow would need to validate certificate behavior before
  claiming safe LDAPS support.
- **Collection/output:** users, groups, computers, password policy, trusts,
  memberships, OS groupings, and raw attributes as HTML, JSON, and tab-delimited
  files; optional BloodHound 1.x conversion.
- **Scope/safety:** a single configured LDAP server is a good bounded shape, but
  resolving every computer name can add DNS load. Disable broad resolution or
  make it an explicit option if integrated.
- **Overlap:** high with RustHound-CE for LDAP collection; strongest distinct
  value is a readable trust/policy/object evidence bundle.

### go-windapsearch

- **Upstream:** [ropnop/go-windapsearch](https://github.com/ropnop/go-windapsearch),
  BSD-3-Clause, not archived but slow-maintenance (last push 2021-03-25).
- **Install/runtime:** Go binary; upstream documents building from source and
  provides a standalone CLI. No local privilege is required.
- **Authentication/TLS:** anonymous, simple username/password, NTLM/hash, and
  `--secure` LDAPS are documented. Upstream notes that `--secure` does not verify
  TLS certificates, so PwnFlow must not expose it unchanged as a “verified LDAPS”
  mode.
- **Collection/output:** modular LDAP queries for users, groups, computers, DNS
  names/zones, GPOs, domain metadata, protected/admin objects, privileged users,
  SPNs, and unconstrained delegation; text, file output, or JSON.
- **Scope/safety:** naturally bounded to one LDAP server and selected module;
  custom filters and full-attribute output need input validation and artifact
  redaction review.
- **Overlap:** medium overall and low for focused DNS/delegation/admin-object
  queries. This is the best first candidate for a small, non-duplicative addition.

## Integration gate

Before selecting any candidate, require an offline command contract and a harmless
fixture test for: dependency detection, exact authentication/LDAPS flags, one
configured target only, no listener/callback, output ownership and permissions,
credential redaction, cancellation, and an explicit availability label. Live
validation must remain limited to the authorized scope and must not use automated
or domain-wide modes by default.
