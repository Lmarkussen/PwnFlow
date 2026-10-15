# Findings Engine

PwnFlow analyzes finalized local artifacts; it does not add a network collector or replace BloodHound CE.

## Lifecycle

A terminal module execution is recorded first, then creates one durable `analysis_jobs` row. A bounded background worker marks the job `PENDING`, `ANALYZING`, and then `COMPLETE`, `PARTIAL`, `FAILED`, or `NOT SUPPORTED`. The batch remains visibly in its findings-processing phase until queued work drains. Repeated completion events are keyed by assessment, execution, source tool, and artifact path.

Only the newest run-scoped RustHound, Certipy, or RelayKing artifact is selected automatically. Historical artifacts are not rescanned at startup. The original output remains untouched; parser errors are stored on the job and do not change the underlying module result.

## Detection boundary

RustHound findings are direct exported ACE observations. PwnFlow does not expand group membership, calculate effective permissions, infer BloodHound attack paths, or claim that a shadow credential was added. `AddKeyCredentialLink` is reported as a potential condition, and replication rights remain a narrow observation unless the collected evidence proves more.

Certipy findings require an explicit vulnerability classification. RelayKing findings require an explicit classified relay path. Informational inventory output is not automatically a vulnerability. LDAP signing and channel-binding findings remain unsupported until an artifact explicitly proves the policy condition; a successful LDAPS connection is not evidence of signing enforcement.

## Operator view

Press `F` for the cached Findings view. Use `/` for text search, `1`, `2`, `3`, or `0` for severity filters, and `Enter` for evidence-backed detail. Compact rows never include recovered passwords or other plaintext secrets; original restricted artifacts remain the authoritative lossless record.
