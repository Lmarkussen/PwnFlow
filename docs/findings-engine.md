# Findings Engine

PwnFlow analyzes finalized local artifacts; it does not add a network collector or replace BloodHound CE.

## Lifecycle

A terminal module execution is recorded first, then creates one durable `analysis_jobs` row. A bounded background worker marks the job `PENDING`, `ANALYZING`, and then `COMPLETE`, `PARTIAL`, `FAILED`, or `NOT SUPPORTED`. The batch remains visibly in its findings-processing phase until queued work drains. Repeated completion events are keyed by assessment, execution, source tool, and artifact path.

Only the newest run-scoped RustHound, Certipy, or RelayKing artifact is selected automatically. Historical artifacts are not rescanned at startup. The original output remains untouched; parser errors are stored on the job and do not change the underlying module result.

## Detection boundary

RustHound findings are direct exported ACE observations. PwnFlow does not expand group membership, calculate effective permissions, infer BloodHound attack paths, or claim that a shadow credential was added. `AddKeyCredentialLink` is reported as a potential condition, and replication rights remain a narrow observation unless the collected evidence proves more.

Certipy findings require an explicit vulnerability classification. RelayKing findings require an explicit classified relay path. Informational inventory output is not automatically a vulnerability. LDAP signing and channel-binding findings remain unsupported until an artifact explicitly proves the policy condition; a successful LDAPS connection is not evidence of signing enforcement.

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

The automatic enumeration plan is an explicit, protected list of 45 modules.
GhostSPN is the additive audit immediately after Kerberoasting. The plan is
separate from manually selected modules and from offline artifact analysis;
`--reanalyze-latest` analyzes retained supported artifacts and never starts a
collector.
