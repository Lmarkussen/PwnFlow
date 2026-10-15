# RustHound-CE Artifact Schema

This note records the RustHound-CE export inspected on the authorized Kali
workstation on 2026-10-15. It is a format audit only; no live collection was
started for this note and no assessment artifact is committed here.

## Observed export

- **Collector:** RustHound-CE `v2.5.25`.
- **Invocation:** PwnFlow's fixed `--ldaps -c LdapOnly` profile.
- **Metadata:** every JSON document is an object with `meta` and `data` keys.
  `meta` contains `collectorversion`, numeric schema `version` (`6` in the
  inspected export), `type`, `methods`, and `count`.
- **Files:** the observed collection emitted separate JSON files for users,
  groups, computers, domains, OUs, containers, GPOs, certificate templates,
  enterprise/root/AIA CAs, issuance policies, and NT auth stores. No ZIP was
  present in the inspected PwnFlow artifact directory, but the parser accepts a
  ZIP containing the same JSON files without extracting it.
- **ACLs:** `data[*].Aces` is an array of direct relationship records. Observed
  ACE fields are `PrincipalSID`, `PrincipalType`, `RightName`, `IsInherited`,
  `InheritanceHash`, and the owner-rights flags. The inspected collection had
  ACL arrays on groups, users, computers, domains, containers, OUs, GPOs, and
  certificate templates.
- **Object identity:** `data[*].ObjectIdentifier` is retained as the stable
  object identifier. Human-readable names come from `Properties` when present;
  unresolved principals retain their original SID.
- **Membership:** group `Members` arrays are separate object relationships and
  are not converted into direct ACEs by the ACL analyzer.

## Supported analysis

`internal/findings` reads bounded JSON files, directories, and ZIP entries. It
records only rights that the export explicitly supplies and that the parser
recognizes: `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `AddMember`,
`ForceChangePassword`, `AddAllowedToAct`, `AddKeyCredentialLink`, `WriteSPN`,
and the relevant replication rights (`GetChanges`, `GetChangesAll`, and
`GetChangesInFilteredSet`). Each finding retains the source artifact path and a
JSON pointer such as `/data/0/Aces/0`.

The analyzer resolves principal SIDs to collected object names when possible,
but preserves the SID and marks an unresolved principal honestly. It separates
distinct ACEs using the canonical ACE content in the deterministic finding key;
it does not collapse permissions merely because they affect the same object.

## Limits

- An observed ACE is not an effective privilege and is not an attack path.
- The parser does not expand group membership, calculate transitive access, or
  infer BloodHound post-processing edges.
- `IsInherited` is reported as collected. Full DACL ordering, object-specific
  GUID interpretation, inheritance evaluation, and security-descriptor details
  unavailable in the export remain unmodeled.
- A missing `Aces` field produces no fabricated relationship. Unknown
  `RightName` values are skipped rather than guessed.
- `LdapOnly` still does not collect SMB, RPC, SYSVOL, local session, or other
  member-machine data. BloodHound CE remains the graph and attack-path tool.
- AD CS object files are parsed as object types when their ACL arrays are
  present; Certipy's vulnerability decisions remain a separate parser concern.

## Synthetic shape

The committed tests use fictional identifiers only:

```json
{
  "meta": {"collectorversion": "RustHound-CE v2.5.25", "version": 6, "type": "groups"},
  "data": [{
    "ObjectIdentifier": "S-1-5-21-EXAMPLE-512",
    "Properties": {"name": "Domain Admins", "highvalue": true},
    "Aces": [{
      "PrincipalSID": "S-1-5-21-EXAMPLE-1101",
      "PrincipalType": "User",
      "RightName": "GenericAll",
      "IsInherited": false
    }]
  }]
}
```

The sample demonstrates the representation only. It does not claim that every
RustHound version emits every field or that the relationship is exploitable.
