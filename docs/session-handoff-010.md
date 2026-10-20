# PwnFlow Session Handoff — Codex 010

## Identity and scope

PwnFlow is an enumeration, safe-validation, evidence-analysis and reporting application. It is not an exploitation or post-exploitation framework.

- Development repository: `/home/lars/code/PwnFlow`
- Remote: `git@github.com:Lmarkussen/PwnFlow.git`
- Kali source-copy: `/home/kali/PwnFlow`
- Kali executable: `/home/kali/PwnFlow/bin/pwnflow`
- Kali host: `kali@100.72.35.81`
- Current development/origin commit: `77822647fd6ed32617b346cbb06d3f99dd2159ce` before Codex 010 changes
- Kali is deliberately non-Git; source-manifest hashes are the deployment parity check.

Only the authorized disposable lab is in scope: `sccm.lab`, DC `10.1.10.40`, SCCM/PXE `10.1.10.41`, MSSQL/member server `10.1.10.42`, and workstation `10.1.10.43`. Do not expand scope, authenticate elsewhere, or run full enumeration without explicit operator authorization.

## Milestones and acceptance

Implemented and locally validated: P1, P2, P3 (hard pass), accepted TUI navigation, SPHunter, RustHound-backed AD writable-object analysis, NetworkHound-driven FTP validation, NetworkHound-driven SMB Spider Plus targeting, artifact ownership normalization, and the 009F Spider Plus scheduling fix.

Deployed and offline-verified: the 009F build was deployed to Kali at commit `77822647fd6ed32617b346cbb06d3f99dd2159ce` with binary SHA-256 recorded in the deployment report. 009F live operator acceptance remains pending; no new live crawl was run after that fix.

Operator accepted: prior Finder/Watcher/Tool Runner navigation and Findings layout behavior. Pending operator acceptance: Codex 010 Easter egg and the post-009F Spider Plus runtime behavior.

The comprehensive Findings-quality review remains deferred. No P3 reopening, SPHunter/bloodyAD expansion, or unrelated redesign is authorized by this handoff.

## Default Enumeration

The authoritative 43-entry profile is `internal/tui/plan.go`, in `defaultEnumerationModuleIDs`. The original 39 entries remain unchanged; additive entries are position 40 `sphunter-tenant-discovery`, position 41 `ad-writable-objects`, position 42 `ftp-anonymous-access`, and position 43 `smb-spider-plus`. Profile tests are in `internal/tui/default_enumeration_test.go`.

Default Enumeration is one operator-approved configured plan. It does not prompt separately for Spider Plus targets or Spider Plus traversal approval. Spider Plus still retains its module approval policy for manual execution. Automatic Spider Plus uses only current-batch NetworkHound TCP/445 evidence, the configured scope, metadata-only options, cancellation, and the ten-minute wall-clock cap.

## NetworkHound workflows

### FTP Anonymous Access

NetworkHound scope validation publishes a current-batch artifact. FTP Anonymous Access consumes only confirmed in-scope TCP/21 endpoints. It performs the single `anonymous:password` check per endpoint, does not list/download/upload files, and creates Findings only for confirmed successful authentication. Rejected, skipped, timeout and indeterminate results remain execution evidence.

### SMB Spider Plus

NetworkHound scope validation publishes `network_scope.json`. `networkhound.OpenSMBEndpoints` extracts literal in-scope addresses whose `open_ports` contains TCP/445, then deduplicates them. Spider Plus does not perform a second port scan and does not prompt for targets during Ctrl+A. Manual `SMB_ENDPOINTS` overrides remain available subject to scope checks.

Spider Plus invokes one `nxc smb <host> -M spider_plus` process per discovered host. `DOWNLOAD_FLAG` is not exposed/enabled; output is execution-scoped and the original metadata JSON remains separate from the Watcher summary. No Finding is created merely because a share or file exists.

## 009F runtime investigation and resolution

The latest Kali artifact was read-only inspected. NetworkHound supplied four TCP/445 targets: `10.1.10.40` through `10.1.10.43`. The Spider Plus execution began at `21:48:15.004`, was cancelled at `21:49:54.873`, and recorded `99,868 ms`. Its transcript reached target `1/4`; it was not a completed four-host run. The operator's approximately 20-second manual result was a single-host comparison.

The root cause was PwnFlow's serial per-host loop, not a hidden parser or UI delay. Commit `7782264` changed execution to bounded concurrency (maximum four workers), synchronized shared output, added per-host progress/timing, and preserved the ten-minute global timeout and cancellation. Regression tests cover multi-host overlap, ordering, cancellation and timeout cleanup.

## Evidence ownership

PwnFlow normalizes newly created execution artifact trees to the invoking operator's ownership/access policy through `internal/artifacts/ownership.go`. This addresses future artifacts created by privileged child processes without using world-writable permissions or unrestricted recursive ownership changes.

Historical root-owned files may still exist in older results trees. They were not rewritten automatically. Any remediation must be a separately approved, narrowly scoped operation that preserves sensitive-file restrictions, database integrity and evidence provenance.

## AD and Findings

RustHound evidence feeds existing ACL, privileged-identity, tiering, replication-rights, GPO and writable-object analysis. AD Writable Objects is a PwnTools execution module but its Finding category is `Active Directory ACLs → AD Writable Objects`; PwnTools is not a Findings category. FTP Anonymous Access uses the designated PwnTools Findings category. Historical records are preserved and category/count behavior is tested.

Observed ACL relationships are not asserted as proven effective access. Reports retain source execution/artifact provenance and caveats about deny precedence, inheritance, object-specific applicability, membership completeness and absent schema context. No directory modification is performed to validate a relationship.

## TUI behavior

Finder root Left is a strict no-op; nested Left navigates to the parent and Esc remains the explicit Finder exit. Ctrl+W, Ctrl+F and Ctrl+A are routed globally from intended Main/Tool Runner states. Watcher and Finder preserve selection/focus state, and active enumeration keeps read-only browsing available.

Codex 010 adds an embedded full-screen Easter egg. The exact source artwork is preserved at `internal/tui/assets/easter_asc.asc` and embedded by `internal/tui/easter.go`; it does not depend on `/home/lars/easter_asc.asc` at runtime. Ctrl+= opens it from idle Main/Tool Runner. Bubble Tea 1.3 has no dedicated `KeyCtrlEqual`, so the handler accepts the named `ctrl+=` representation and the legacy control-byte representation exposed as `tea.KeyCtrlCloseBracket`; plain `=` is not consumed. Lowercase or uppercase Q closes the Easter egg without invoking the global quit path. Active enumeration, prompts, Watcher and Findings are not interrupted.

## Validation and deployment rule

For accepted changes: modify narrowly → run `bash -n install.sh`, `make build`, `make test`, `make vet`, required race tests and `git diff --check` → review diff → commit/push → verify origin parity → transfer only the validated source manifest to Kali with backups → rebuild `/home/kali/PwnFlow/bin/pwnflow` → compare source hashes and record binary SHA-256 → run offline smoke tests → request operator acceptance. Never launch live enumeration automatically and never overwrite results, `enumeration.db`, configuration or historical evidence.

## Known limitations and next actions

- Codex 010 Easter egg still requires operator visual/keyboard acceptance on the deployed Kali terminal.
- 009F Spider Plus still requires a fresh operator-controlled live comparison after deployment; no live crawl was started automatically.
- Kali has no embedded VCS revision because it is a non-Git source-copy build; source manifest parity is authoritative.
- Historical root-owned evidence is intentionally untouched pending a separately approved remediation plan.
- SPHunter, bloodyAD expansion, comprehensive Findings audit, Telnet authentication, password spraying, exploitation and arbitrary SMB content scanning remain deliberately excluded.
