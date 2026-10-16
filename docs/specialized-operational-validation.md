# Specialized operational validation

This document records the Prompt 071 validation of the six registered
specialist entries. Validation is based on the installed upstream source
revisions and harmless argument/help checks; no relay, coercion, SQL command
execution, SCCM client registration, protected-policy retrieval, GPO write, or
Neo4j enrichment was performed.

## Installed contract

| Module | Installed entry point | Upstream revision/version | PwnFlow command | Artifact | Parser/category |
|---|---|---|---|---|---|
| `ghostspn-audit` | `/home/kali/.local/bin/ghostspn` | `0.1.0`, `f5df2cd072d9c3ba81b01590e433b21449d91394` | `--server DC --domain DOMAIN --username USER --password PASSWORD --output FILE.json` | ghostSPN JSON rows | `ghostSPN` / Active Directory / SPN Hygiene |
| `gpoparser-local` | `/home/kali/.local/bin/gpoParser` | `1.0.0`, `5cfe7aa3556f7c9263620515a33f4ef7afb88c1b` | `local SYSVOL LDAP_EXPORT -o FILE.json` | gpoParser cache JSON | `gpoParser` / Active Directory / Group Policy |
| `gpoparser-remote` | `/home/kali/.local/bin/gpoParser` | `1.0.0`, `5cfe7aa3556f7c9263620515a33f4ef7afb88c1b` | `remote -s DC -d DOMAIN -u USER -p PASSWORD -o FILE.json` | gpoParser cache JSON | `gpoParser` / Active Directory / Group Policy |
| `mssqlrelay-check` | `/home/kali/.local/bin/mssqlrelay` | `1.1`, `1e03c96f0d05f7aed0abd89186bfe58e1a4f54c4` | `check -target TARGET -u USER@DOMAIN -p PASSWORD -windows-auth` | stdout log | `mssqlrelay` / Network / MSSQL Security |
| `mssqlpwner-enumerate` | `/home/kali/.local/bin/mssqlpwner` | `1.3.2`, `c791b84431345064f52f86ca01d33ec00f24909a` | `DOMAIN/USER:PASSWORD@TARGET -windows-auth enumerate` | stdout log | `MSSqlPwner` / Network / MSSQL Security |
| `sccmsecrets-offline` | isolated SCCMSecrets Python environment | `5488158d097a7f76b879e0e5db7d9e123380fd7a` | disabled | none | intentionally not dispatched |

The `ghostSPN` and `gpoParser` commands write their structured result to the
JSON artifact. PwnFlow stores captured stdout beside it as a `.log` file and
never overwrites the structured artifact. This prevents the previous
execution/output collision.

## Safety audit

`mssqlrelay check` is the only registered mssqlrelay mode. `checkall` and
`relay` are not registered. `MSSqlPwner enumerate` uses the upstream
read-only discovery queries for server information, principals, roles,
databases, linked servers and impersonation relationships. Its command
execution, relay, direct-query, interactive and write-capable modules are not
registered. `gpoParser enrich` is not registered because it writes to Neo4j.
ghostSPN DNS checks are not enabled, so its module does not initiate optional
DNS expansion. SCCMSecrets `files` and `policies` remain disabled because they
can download deployment material, register clients, impersonate clients, or
retrieve protected policy content.

## Source validation and findings

ghostSPN 0.1.0 emits rows containing `spn`, `hostname`, `account_sam`,
`account_dn`, `dns_status`, `exploitability`, and `reason`. The parser now uses
those fields and only creates an observation for an explicit exploitability
row; a normal SPN or malformed JSON creates no finding. It retains the full
row as evidence and does not reinterpret the result as Kerberoasting or
compromise.

gpoParser local/remote saves a cache containing `ous`, `gpos`, `sid_cache`, and
`dn_cache`. The parser walks structured values for explicit `cpassword`, local
group, and Remote Desktop evidence, with a text fallback for supported
transcripts. It does not infer effective policy scope without source linkage.

mssqlrelay output is parsed only when it explicitly reports `Encryption: not
enforced`; the finding is described as a configuration/relay-prerequisite
observation, not successful relay. MSSqlPwner relationship lines are retained
as informational observations and do not assert an executable escalation path.

SCCMSecrets remains **Option C — unsupported offline execution** for this
checkpoint. The installed upstream script is functional for help display, but
its supported workflows are not a safe PwnFlow offline parser contract. The
entry remains visible as execution-disabled so the operator is not misled into
believing that installation enables a safe artifact workflow. Existing PXE and
SCCM findings remain the supported offline evidence path.

## Validation status

All five enabled command builders have exact-argument unit coverage and parser
fixtures use the installed ghostSPN/gpoParser source schemas. Local build,
tests, vet, race-focused package tests, installer checks, and `git diff --check`
are required before release. Kali validation uses harmless `--help` and
offline fixtures first. Live LDAP/GPO/MSSQL tests are intentionally omitted
unless the upstream implementation and target scope can be independently
verified without side effects; no Default Enumeration run is part of this checkpoint.

Original assessment results and the SQLite database are outside source sync
and are preserved during Kali deployment.
