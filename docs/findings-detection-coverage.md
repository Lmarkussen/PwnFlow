# Findings Detection Coverage

This matrix describes what PwnFlow can prove from finalized local artifacts. A
collection being successful does not mean that its security conditions were
parsed or that a finding exists. PwnFlow never treats an unsupported check as
clean.

## Coverage states

- **Collection**: the relevant module produced a finalized artifact.
- **Parser**: PwnFlow can read the artifact format without changing it.
- **Detection**: the parser has a conservative rule for the condition.
- **Finding**: at least one artifact record met that rule.

## Current matrix

| Condition | Collection source | Parser / evidence required | Detection state | Limits |
|---|---|---|---|---|
| Kerberoastable account | RustHound `users` or NetExec LDAP | Enabled user with `hasspn`/SPNs; disabled users excluded | Supported | SPN presence does not prove a ticket was requested or cracked |
| Kerberoast material collected | NetExec `LDAP_kerberoasting/kerberoast.txt` | `$krb5tgs$` material line | Supported | Material is counted and referenced; raw material stays in the restricted artifact |
| AS-REP roastable account | RustHound `users` | `dontreqpreauth` or UAC `0x400000`, with enabled state | Supported | Unknown enabled state is informational; no material is inferred |
| AS-REP material collected | NetExec `LDAP_asreproast/asreproast.txt` | `$krb5asrep$` material line | Supported | Empty output and status messages are not findings |
| Direct AD ACL control | RustHound schema-v6 object `Aces` | `PrincipalSID`, `RightName`, target object, inheritance fields | Supported | Direct ACE only; no transitive membership, deny ordering, or attack-path calculation |
| Potential Shadow Credentials | RustHound `AddKeyCredentialLink` ACE | Direct right on an account/object | Supported | Potential control only; no credential was added or used |
| Replication-right observation | RustHound replication ACEs | Individual `GetChanges*` rights | Supported | Full DCSync is not claimed without complete effective-right context |
| Delegation configuration | RustHound user/computer properties | Explicit delegation properties | Partial | Configuration is reported conservatively; exploitability is not inferred |
| LDAP signing | NetExec LDAP security output | Explicit proof signing is not required | Not assessed unless explicit evidence exists | LDAPS success and bind errors are insufficient |
| LDAPS channel binding | A targeted supported artifact | Explicit channel-binding result | Not assessed | TLS success, certificate state and simple bind are insufficient |
| SMB signing | NetExec SMB security output | Explicit signing-required state | Partial | Enabled is not equivalent to required |
| NTLM relay exposure | RelayKing structured output | Explicit classified relay path | Supported | Does not claim exploitation or make every NTLM endpoint vulnerable |
| AD CS template weakness | Certipy structured output | Explicit vulnerability classification | Supported | Enabled templates alone are not findings |
| PXE/SCCM credential exposure | PXEThief logs/XML/boot variables | Populated credential-bearing variable | Supported | Password values remain only in original restricted artifacts |
| SCCM inventory | SCCMhunter structured output | Verified role/service records | Observation only | Infrastructure presence is not a vulnerability |
| Network topology | NetworkHound structured output | Validated topology/service record | Observation only | Discovery is not a security condition |

## RustHound artifact facts

The installed collection used RustHound-CE 2.5.25 with schema version 6 and
`--ldaps -c LdapOnly`. User objects expose fields such as `enabled`,
`dontreqpreauth`, `hasspn`, `serviceprincipalnames`, `unconstraineddelegation`,
`trustedtoauth` and `allowedtodelegate`. ACL arrays expose direct records such
as `PrincipalSID`, `PrincipalType`, `RightName`, `IsInherited` and
`InheritanceHash`. These are evidence records, not BloodHound-derived attack
paths.

RustHound's LDAP-only export does not provide a complete security descriptor:
ACE ordering, deny evaluation, every object-specific GUID and effective access
may be absent. Group membership is retained as membership data and is not
silently expanded into direct permission findings.

## Historical analysis

Automatic processing is limited to the finalized execution artifact. Explicit
offline reanalysis can submit an existing execution through the durable analysis
queue. Repeated submissions use stable assessment/execution/artifact identity;
source files are opened read-only and are never rewritten. Parser failures are
stored as analysis failures or partial results rather than being represented as
zero findings.

Synthetic fixtures cover positive and negative Kerberoast/AS-REP material and
RustHound identity cases. No live assessment secrets or collection files are
committed.
