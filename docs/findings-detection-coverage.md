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
| Kerberoastable account | RustHound `users` | Enabled user with `hasspn`/SPNs; disabled users excluded | Supported | SPN presence does not prove a ticket was requested or cracked |
| Kerberoast material collected | NetExec `LDAP_kerberoasting/kerberoast.txt` | `$krb5tgs$` material line | Supported | Material is counted and referenced; raw material stays in the restricted artifact |
| AS-REP roastable account | RustHound `users` | `dontreqpreauth` or UAC `0x400000`, with enabled state | Supported | Unknown enabled state is informational; no material is inferred |
| AS-REP material collected | NetExec `LDAP_asreproast/asreproast.txt` | `$krb5asrep$` material line | Supported | Empty output and status messages are not findings |
| Direct AD ACL control | RustHound schema-v6 object `Aces` | `PrincipalSID`, `RightName`, target object, inheritance fields | Supported | Direct ACE only; no transitive membership, deny ordering, or attack-path calculation |
| Potential Shadow Credentials | RustHound `AddKeyCredentialLink` ACE | Direct right on an account/object | Supported | Potential control only; no credential was added or used |
| Replication-right observation | RustHound replication ACEs | Individual `GetChanges*` rights | Supported | Full DCSync is not claimed without complete effective-right context |
| Delegation configuration | RustHound user/computer properties | Explicit delegation properties | Partial | Configuration is reported conservatively; exploitability is not inferred |
| Non-expiring passwords | RustHound `users` | Enabled users with `pwdneverexpires`, grouped per domain | Supported | Password strength and real age not assessed |
| Reversible encryption / DES-only | RustHound `users` | `encryptedtextpwdallowed` / `usedeskeyonly` on enabled users | Supported | Whether a reversibly stored password exists is not verified |
| sIDHistory | RustHound users/computers/groups | Populated `sidhistory`; same-domain privileged RID raises severity | Supported | Token construction and trust-boundary SID filtering not evaluated |
| Readable password attributes | RustHound `users` | Populated `userpassword`/`unixpassword`/`unicodepassword`/`sfupassword` | Supported | Attribute names only; the value stays in the restricted artifact |
| krbtgt password age | RustHound `users` | `pwdlastset` of RID 502, measured at collection time | Supported | Reported from 180 days; medium from 365 |
| Privileged users without delegation protection | RustHound users + Protected Users group | `admincount`, `sensitive`, direct RID 525 membership | Supported | adminCount may be stale; nested membership not expanded |
| Stale enabled accounts | RustHound users/computers | `lastlogontimestamp` older than 90 days, or never with `whencreated` older than 90 days | Supported | lastLogonTimestamp replicates lazily |
| LAPS coverage | RustHound `computers` | Enabled non-DC Windows computers with `haslaps=false` | Supported | An unreadable expiration attribute looks absent |
| Anonymous LDAP (configuration and behaviour) | AD Directory Settings | `dSHeuristics` read from the Directory Service object; a search with no bind against the domain head and user objects | Supported | Only object classes are requested by the probe |
| DNS zone ACLs (ADIDNS) | AD Directory Settings | Zone DACL read with the SD-flags control: CreateChild or write for broad or delegated principals; wildcard record presence | Supported | Deny ACEs for the same principal suppress the zone; nested membership not expanded; no record is created |
| Pre-Windows 2000 Compatible Access | RustHound `groups` | Members of S-1-5-32-554; high with Anonymous Logon or Everyone | Supported | Anonymous access itself is tested by the null-session and LDAP probes |
| Kerberos encryption types | RustHound users/computers | `supportedencryptiontypes`: DES, RC4 without AES, SPN users without a value | Supported | The domain-wide default encryption type is not read |
| SMB null/guest session and SMBv1 | NetExec SMB banner | `(Null Auth:True)`, `(Guest Auth:True)`, `(SMBv1:True)` | Supported | The banner alone does not show what a null session can read |
| Anonymous SMB enumeration | NetExec `smb-null-session` | Users, password policy or readable shares returned to an empty user name and password | Supported | Only counts are recorded; user rows stay in the original artifact |
| Domain functional level / anonymous LDAP | RustHound `domains` | `functionallevel`; `dsheuristics` character 7 | Partial | RustHound-CE reads `dSHeuristics` from the domain object, but the attribute lives on the Directory Service object in the configuration partition, so the anonymous-LDAP condition is rarely observable. Anonymous bind is not attempted |
| Password not required | RustHound `users` | `passwordnotreqd`; disabled accounts informational | Supported | A blank password is not proven; no authentication is attempted |
| LAPS password readers | RustHound `computers` ACEs | `ReadLAPSPassword`, grouped per domain with each reader's computers | Supported | Nested membership not expanded; no password is read |
| gMSA password readers | RustHound `users` ACEs | `ReadGMSAPassword` per gMSA | Supported | Nested membership not expanded; no password is read |
| Writable objects, BloodyAD vs RustHound | BloodyAD writable output and the RustHound writable-object report | Same distinguished name in both | Correlation note | Shown on the BloodyAD Finding; the two remain separate Findings |
| Nonsecure DNS dynamic updates | NetExec `dns-nonsecure` | Zone listed under a "[+] … allowing nonsecure dynamic updates" header | Supported | No record is created or changed |
| Unsupported operating systems | NetExec `obsolete` | Enabled computers with an unsupported Windows release, grouped per domain | Supported | `operatingSystem` is self-reported and may be stale; hosts are not contacted |
| Readable password attributes (reader) | NetExec `get-userPassword` / `get-unixUserPassword` | Explicit `User: … <attribute>:` lines; records which assessment account could read the attribute | Supported | The value stays in the original artifact; the header alone is not evidence because the module prints it for referral-only results |
| Trust SID filtering / TGT delegation | RustHound `domains` `Trusts` | Raw `TrustAttributes` and `TrustDirection` | Supported | Within-forest trusts excluded; trusted domain not contacted |
| LDAP signing | NetExec LDAP banner `(signing:None)` | NetExec's unsigned-bind probe | Tool-reported, not verified | NetExec prints the same value when its probe fails (for example with NTLM disabled); explicit policy proof is still not assessed |
| LDAPS channel binding | NetExec LDAP banner `(channel binding:…)` | `Never` (medium) or `When Supported` (low) | Tool-reported, not verified | `Never` is also NetExec's value when its probe fails; `No TLS cert` and `Unknown` produce no Finding |
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
