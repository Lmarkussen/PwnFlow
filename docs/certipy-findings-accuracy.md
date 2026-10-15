# Certipy Findings Accuracy

PwnFlow consumes the structured Certipy `find` JSON artifact under
`Certificate Templates`. A template entry may contain a `[!] Vulnerabilities`
field, but template inventory, enabled state, enrollment permissions and
numeric map keys are not vulnerability evidence by themselves.

## Actionable rule

The parser emits an actionable AD CS finding only when the vulnerability field
contains an explicit ESC entry, such as `ESC1: ...` or a structured map keyed
by `ESC1`. ESC identifiers are extracted from vulnerability entries and
normalized to uppercase. Text elsewhere in the artifact, filenames and
numeric template keys do not qualify.

The resulting identity is assessment + source object name + ESC identifier.
Repeated evidence therefore updates one canonical finding while retaining its
artifact/evidence provenance through the storage layer. Different ESC
identifiers and different affected objects remain separate. If the source key
is numeric, the title uses `affected template identity unresolved` rather than
inventing a template name.

Titles use the form `Certipy reported ESCn — <object>`. They describe a
Certipy-reported potential condition, not successful certificate abuse or a
complete attack path. ESC1, ESC4, ESC8, ESC13 and ESC15 currently receive the
high policy tier; other explicit ESC identifiers receive medium pending more
context.

## Historical records

Legacy `adcs_template_vulnerability` rows are retained for auditability and
raw evidence access, but the TUI classifies them as observations unless their
stored title contains an explicit ESC identifier. They are not counted in the
actionable Findings view. Pressing `P` queues the latest saved Certipy
execution for offline reanalysis; it never starts Certipy or contacts a host.
The parser version is `certipy-v2`, allowing queued jobs to be retried after
parser changes.

No live Certipy output or assessment database is committed to this repository.
The committed tests use synthetic template names and fictional evidence.
