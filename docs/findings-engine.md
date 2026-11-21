# Findings Engine

PwnFlow analyzes finalized local artifacts; it does not add a network collector or replace BloodHound CE.

## Lifecycle

A terminal module execution is recorded first, then creates one durable `analysis_jobs` row. A bounded background worker marks the job `PENDING`, `ANALYZING`, and then `COMPLETE`, `PARTIAL`, `FAILED`, or `NOT SUPPORTED`. The batch remains visibly in its findings-processing phase until queued work drains. Repeated completion events are keyed by assessment, execution, source tool, and artifact path.

Only the newest run-scoped RustHound, Certipy, or RelayKing artifact is selected automatically. Historical artifacts are not rescanned at startup. The original output remains untouched; parser errors are stored on the job and do not change the underlying module result.

## Detection boundary

RustHound findings are direct exported ACE observations. PwnFlow does not expand group membership, calculate effective permissions, infer BloodHound attack paths, or claim that a shadow credential was added. `AddKeyCredentialLink` is reported as a potential condition, and replication rights remain a narrow observation unless the collected evidence proves more.

Certipy findings require an explicit vulnerability classification. RelayKing findings require an explicit classified relay path. Informational inventory output is not automatically a vulnerability. LDAP signing and channel-binding state comes from two sources. NetExec's LDAP banner is labelled tool-reported, not verified, because NetExec prints the same value when its own probe fails. The Group Policy settings gpoParser collects are the explicit policy evidence: the value the GPOs linked to the Domain Controllers OU configure, resolved by enforced, linked and inherited precedence. A successful LDAPS connection is not evidence of signing enforcement.

Certipy reports are associated with the module-specific native artifact nearest the execution log timestamp, rather than the newest JSON anywhere under the shared artifacts directory. This preserves CA-level evidence from broad discovery runs and prevents a template-only report from being reused for another execution. A CA Web Enrollment observation without an explicit Certipy ESC classification remains an observation, not an ESC8 finding.

NetExec's existing `LDAP_password_policy.txt` and `LDAP_machine_account_quota.txt` artifacts also support domain-default policy observations. The engine recognizes the reported minimum password length, a zero/non-expiring `maxPwdAge`, and positive `ms-DS-MachineAccountQuota` values. These findings require an attributable domain identity, use stable assessment/domain/detector keys, and preserve the source line as evidence. Domain defaults are not asserted to apply to every account; fine-grained password policy scope is a stated limitation rather than an inferred override.

## Operator view

Press `F` for the cached Findings view. Use `/` for text search, `1`, `2`, `3`, or `0` for severity filters, and `Enter` for evidence-backed detail. Compact rows never include recovered passwords or other plaintext secrets; original restricted artifacts remain the authoritative lossless record.

The Findings browser is available from a normal assessment and from
`--findings`. Both modes use the same persisted Findings and source-aware detail
renderer. `E — Original Evidence` opens the referenced artifact through a
results-root boundary check; it does not rewrite the retained artifact.

Critical Findings are an in-memory, read-only projection over source Findings.
The projection separates `CONFIRMED CRITICAL` from `POTENTIAL CRITICAL — NOT
VERIFIED`, groups each state by attack-path family, and keeps stable links to
supporting Finding IDs and execution provenance. The navigation hierarchy is
`Critical Findings → state → family → Finding`. Opening a row reuses the
original Finding renderer, so source-specific Certipy, ACL, Kerberos, PXEThief,
credential, and protocol evidence remains available rather than being replaced
by a generic summary. The projection does not write database rows or change
specialist-category Findings.

Confirmed rules require evidence that the condition was exercised, not only
configured:

| Rule | Source Finding | Confirms |
|---|---|---|
| `CRIT-NETEXEC-PWN3D` | `netexec_privileged_access` | Administrative access on the tested target |
| `CRIT-PXETHIEF-CREDENTIAL-DISCLOSURE` | `sccm_task_sequence_credentials_exposed` | Recovered task-sequence credential material |
| `CRIT-LDAP-PASSWORD-ATTRIBUTE-READ` | `ad_account_password_attribute_readable` | A populated userPassword/unixUserPassword value returned to the assessment account; the value is withheld and not tested |
| `CRIT-ADCS-ESC1`, `CRIT-ADCS-ESC8` | Certipy ESC Findings | Every structured prerequisite of the ESC path verified |
| `CRIT-AD-DCSYNC` | Replication-rights overview | Complete, verified evidence of GetChanges and GetChangesAll on the domain root for an inappropriate principal |
| `CRIT-AD-TIER0-CONTROL` | Privileged ACL evidence | Complete evidence of an allowed GenericAll, WriteDacl or WriteOwner by an inappropriate principal over the domain root or a Tier Zero group |

Attack paths stitch current Findings into multi-step chains, grouped first under
"Attack Paths": coercing the domain controller and relaying to AD CS web
enrollment (ESC8); coercing it to an unconstrained-delegation principal;
coercing a WebClient host over HTTP and relaying to LDAP that does not require
signing or channel binding (with MachineAccountQuota when present); registering
a name through ADIDNS and relaying the authentication it attracts to the
strongest observed target (AD CS web enrollment, then LDAP without signing,
then SMB without signing); taking a privileged account's credentials from a
host where PwnFlow's credentials are local administrator and that account is
signed in; poisoning LLMNR/NBT-NS or taking over DNS through DHCPv6 (mitm6)
and relaying to the strongest observed target; serving a malicious update from
WSUS over HTTP after a DHCPv6 DNS takeover; and a recovered or readable
credential of a privileged account. Each step names the
Finding it relies on, and a chain stays potential with its unverified
conditions listed.

Potential paths keep the condition and list what is not verified. Besides
unverified ESC, ACL, replication, delegation, relay and SMB-signing evidence,
they include: LAPS passwords readable by a broad group; a gMSA readable by a
broad group, or a privileged gMSA readable by a delegated principal; a
privileged SID of the object's own domain in sIDHistory; relaxed SID filtering
on a trust; broad write on a DNS zone; NetExec-reported or Group
Policy-configured LDAP signing or LDAPS channel binding not enforced; and the
Print Spooler or WebClient service answering on the domain controller. Conditions that hold in almost every domain
by default, such as any authenticated user adding DNS records, and information
disclosure without a privilege path, such as anonymous enumeration, stay in
their categories and are not projected.

Findings are upserted on a stable key, so a re-observed Finding keeps its row
and moves its last-seen time and source execution forward. A Finding is
reported as not re-observed when a later, completed and analyzed execution of
its source module started after it was last seen, or when its source module is
no longer registered. Presentation (Findings view, Critical projection,
report) leaves such Findings out by default; the rows themselves are kept.

The automatic enumeration plan is an explicit, protected list of 44 modules.
GhostSPN is the additive audit immediately after Kerberoasting. The plan is
separate from manually selected modules and from offline artifact analysis;
`--reanalyze-latest` analyzes retained supported artifacts and never starts a
collector.
