# Findings Quality Audit

This audit was performed against the operator's existing Kali assessment database
without changing the database or raw artifacts. The aggregate contained 1,429
rows and 1,429 distinct finding keys.

## Aggregate counts

| Source/type | Severity | Count | Interpretation |
|---|---:|---:|---|
| RustHound direct `GenericAll` | medium/high | 369 | Direct ACE observations; high rows have directly marked sensitive targets |
| RustHound direct `WriteDacl` | medium/high | 392 | Direct ACE observations; high rows have directly marked sensitive targets |
| RustHound direct `WriteOwner` | medium/high | 392 | Direct ACE observations; high rows have directly marked sensitive targets |
| RustHound direct `GenericWrite` | informational | 151 | Broad control observation, not independently asserted Shadow Credentials |
| RustHound `AddKeyCredentialLink` | informational | 62 | Explicit potential key-credential control; no credential insertion claim |
| RustHound replication fragments | informational | 7 | Individual rights only; not a DCSync conclusion |
| Other RustHound ACL rights | informational | 3 | AddMember, ForceChangePassword and WriteSPN observations |
| Certipy vulnerable templates | medium | 41 | Explicit Certipy classifications |
| PXEThief credential exposures | high | 4 | Recovered credential-bearing task-sequence values |
| Kerberoastable accounts | medium | 3 | Enabled SPN-bearing directory users |
| AS-REP roastable accounts/material | medium | 2 | Configuration and collected material |
| Delegation configuration | medium/info | 3 | Explicit properties, not exploitability conclusions |

Source totals were RustHound-CE 1,383, Certipy 41, PXEThief 4 and NetExec 1.
The high count is not caused by parser reruns alone: the stable key includes
assessment, principal, target, right and canonical ACE data, so different direct
relationships remain distinct. Repeated copies of the same ACE and repeated
processing of the same artifact are idempotent through the stable key and
`finding_evidence` key.

## Classification policy

The Findings view now derives a presentation classification without deleting or
rewriting persisted records:

- **Findings** (default): non-informational security conditions, plus ACL
  relationships marked high or explicitly titled as affecting a privileged
  object.
- **Observations**: informational ACL, delegation and partial-right records.
- **All**: the complete persisted evidence-backed set.

This is intentionally not a severity alias. An informational observation can
still be relevant context, and a high-severity condition remains visible even if
it has multiple supporting ACEs.

The existing RustHound rule emits Shadow Credentials only for an explicit
`AddKeyCredentialLink` ACE. A `GenericWrite` ACE is retained as one direct ACL
observation and is not duplicated into a Shadow Credentials finding. Direct
ACE evidence remains separate from effective access, group expansion, deny
ordering and BloodHound-derived attack paths.

## Deduplication and provenance

Finding IDs remain stable and assessment-scoped. Distinct principal/right/target
relationships are not merged merely because names match. Repeated ingestion
updates the finding and retains evidence records; source execution IDs,
artifact paths and structural references remain available in the detail view.
No raw artifact, execution row or finding row was deleted for this audit.

No database migration was needed for this presentation-only classification
change, so no live database backup or rollback operation was performed. Any
future persistent reclassification must first create a permissions-preserving
SQLite backup and run an explicit transactional migration with rollback tests.
