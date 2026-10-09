# RVI capture and analysis roadmap

Status: the core RVI-only implementation is ready for review. Physical-device capture, saved-file workflow, and generated packet/session/original-byte performance checks pass; controlled PTR transport is now verified on loopback. The approved feature-branch integration with current main is resolved and locally validated. Native browsing and candidate-specific hosted CodeQL acceptance remain pending. This is the canonical implementation and validation checklist.

## Scope and reviewed baseline

- Target: `RVI-Sentinel-Swift`, branch `codex/rvi-packet-analysis`. The initial implementation base was `9bdd458`; the current local HEAD is `1f4cde7`, published PR #2 is `bb4d607`, and current GitHub main is `ecfed3a` (read-only refresh on 2026-10-09). An explicit authorized fetch restored the source checkout's remote-tracking ref. Publication uses the isolated `codex/rvi-packet-publication` worktree; the canonical checkout's HEAD and unrelated work remain preserved.
- Read-only reference: `RVI-Correlator`, branch `codex/security-remediation`, HEAD `12c62bba8bbe6aeb99493d93e748fb24ac640f15`.
- Both roots are confirmed by the workspace registry. At the initial source study, applicable global and Codex ancestor instructions were read and no project/component instructions were found. The subsequently added repository `AGENTS.md` and current user-supplied instructions now apply; no nested override was found.
- Reviewed on 2026-10-07. Screenshots describe desired behavior; source code establishes implementation details. No private captures, device operations, privileged commands, or active DNS queries were used for this study.
- Keep device RVI capture, saved-file analysis, and native Swift/SwiftUI navigation. Exclude Mac PKTAP collection, cross-device matching, correlation scores, direct-peer analysis, unified logs, and additional collection mechanisms.

## Findings and decision

The initial gap was decoder/model/UI support. Sentinel records Apple PCAPNG using `tcpdump -P` and analyzes originals in place; no import conversion was found that strips metadata. It now retains compact packet records alongside existing aggregate inventories, negotiates recorded process/effective-process/interface/direction fields, and provides native packet/session views. The capture workflow is retained. [S1–S6]

Correlator obtains labels such as `maild` from the source capture's decoded `frame.darwin.process_info.*` options or `pktap.*` headers. It is not deriving iPhone labels from Mac correlations. These are recorded labels, not independently verified device process identity. The installed TShark 4.6.9 field catalog exposes all four Apple process/effective-process fields, direction, interface, PKTAP equivalents, raw TCP sequence/acknowledgment, and captured length. Availability in a decoder does not establish presence in a particular capture. [C1–C3, W1–W2]

### Pipeline comparison

| Stage | RVI-Correlator | RVI-Sentinel Swift | Consequence |
| --- | --- | --- | --- |
| Capture | Device RVI runs `/usr/sbin/tcpdump -i <rvi> -s 0 -U -n -P --apple-pcapng -w -`; output is the original device PCAPNG. Its live service also collects Mac/log sources. [C1, C12] | PCAPNG is the UI default. Writer uses `-i <rvi> -s 0 -U -n -P -Z <user> -w <destination>`; classic PCAP uses `-y RAW`. Existing setup, preflight, validation, hash, and cleanup remain. [S1] | `-P` and `--apple-pcapng` are aliases in the installed Apple tcpdump manual. No capture-flag change is presently justified. Classic RAW PCAP cannot carry Apple PCAPNG process options; absence must remain explicit. |
| Copy/import | Live finalization copies original bytes, checks source before/after and copied hash/size, then renames. Offline import reads the selected original directly and checks hash before/after decoding. [C4, C2] | Selected files are read directly; there is no import conversion. Capture and analysis already compute SHA-256; analysis now checks SHA-256 before/after decoding and rejects changed sources. [S1, S3, S4] | Keep original containers. Add changed-source detection and an explicit original-reference contract; do not add conversion or managed copies merely to obtain labels. |
| Decoder | `-n -2 -r … -T json --no-duplicate-keys` requests per-frame process/interface/direction, endpoints, streams, raw TCP values, and hostname fields. A separate structured DNS pass preserves RR relationships. [C2, C8] | Field negotiation uses installed `-G fields`; bounded TSV streaming uses `-n` and preserves supported per-frame metadata. Structured DNS preserves RR ownership. [S2, S3] | Sentinel now uses a bounded streaming `-n` pass with optional metadata/raw TCP fields and a structured DNS pass. Current lookup is an explicit inspector action. |
| Models | Artifact identity, per-frame observations, original/adjusted times, and decoded fields remain available. [C2, C3] | `DecodedPacket` remains transient. Typed per-frame records, exact decoded epochs, artifact identity, and bounded sessions augment existing aggregates. Endpoint process ownership remains unavailable because an IP can serve several processes. [S2, S5] | Add packet-scoped recorded metadata and stable artifact/frame identities. Do not assign a single process owner to a shared IP endpoint. |
| Timeline/inspector | Selectable chronological rows and inspector expose fields, source frame, process labels, interface/direction, and navigation. [C5] | Analysis retains aggregate tabs and adds a paged chronological timeline, filters, inspector, and scoped sessions. [S6] | Reuse existing decoded fields and native Analysis navigation before requesting more collection. |
| Sessions | Direction-independent five-tuple plus artifact, interface, process context, and TShark stream; incomplete/ambiguous packets remain outside groups. [C6] | Pure TCP/UDP grouping retains member frame IDs within the artifact/stream/interface/process context; incomplete and conflicting records remain on the timeline. [S2, S5] | Build a pure RVI-only grouping path after packet retention; streams and ports alone are insufficient. |
| Hostnames | Supporting frame IDs and evidence origin; structured A/AAAA/CNAME records, TTL/client/artifact scope, and separately triggered current lookup. [C7–C9] | Direct packet names and structured DNS resource records retain source frames. DNS links apply client/interface/time/TTL/replacement scope; earlier stream names are labeled inferred and unpaired when request role is unavailable. Current PTR stays separate. [S5, S7] | Improve linkage and correctness instead of rebuilding hostname detection. |
| Original bytes/integrity | Single-frame `jsonraw` inspection verifies artifact hash before/after and only highlights byte ranges whose hex matches saved bytes. [C10] | The inspector supports reveal/open and bounded, on-demand original bytes/ranges after matching SHA-256 and frame identity before/after extraction. [S1, S6] | Reuse hashing/reveal behavior. Add bounded, on-demand original-byte inspection later. |
| Scale | 50,000-frame batches and bounded process/data budgets; later batches restart TShark over growing prefixes. UI/search also scan retained arrays. [C11] | Bounded streaming, progress every 5,000 packets, and existing detail caps remain. Packet queries are paged/off-main. Generated 50k/100k optimized native decoder/query tests pass; scrolling and visual acceptance remain pending. [S3, S5] | Preserve streaming; add compact, bounded packet indexing and paged UI. Correlator's limits are not responsiveness evidence. |

### Reference behaviors to adapt carefully

- Correlator's `rebuild` requires both iPhone and Mac imports before deriving sessions/hostname investigation; its live finalization also requires both capture sources. Adapt independent analysis functions, not its coordinator or complete live service. [C12]
- Correlator's canonical ordering time truncates fractional seconds to microseconds even though the original epoch text survives. Sentinel currently converts timestamps to floating-point `Date`. Preserve source precision explicitly; do not copy either representation as the exact timestamp contract. Display timezone changes do not alter original capture time. Clock-offset controls are outside this RVI-only scope. [C2, S5]
- Correlator only fills session process display labels for Mac packets. Sentinel's RVI sessions must display/search their own recorded labels. Its timeline search also lacks some requested interface/PID/both-endpoint filters. [C5, C6]
- Sentinel's former flattened DNS Cartesian pairing is removed. Only structured owner/RDATA pairs establish direct answer/address records. Questions, certificate names, and request-role-ambiguous authorities remain unpaired; inferred conversation names do not identify a peer. [S5]
- Correlator's structured DNS importer supports A, AAAA, and CNAME relationships; it is not complete mDNS/DNS-SD service reconstruction. Preserve unpaired PTR/service observations rather than inventing address associations. [C8]
- Correlator's active DNS implementation retries request errors and uses blocking process I/O. Adopt its separate present-day provenance, with explicit bounds/cancellation and no indiscriminate retries. [C9]

## Ranked additions

Effort is relative implementation complexity, not a time estimate. Resource/performance controls are prerequisites throughout, with final measured acceptance in M6.

| Rank | Addition and user value | Implementation status / remaining work | Effort / main risk | Dependency / verification |
| --- | --- | --- | --- | --- |
| 1 | Recorded process/effective-process, interface, direction, and retained packet identity: expose useful evidence already saved. | Implemented typed metadata, optional field negotiation, exact decoded epochs, and explicit provenance/unknown/conflict states. Container-declared timestamp resolution is not inferred from decoder digits. [S2, S5; C2, C3] | Medium; unsupported fields, absent metadata, conflicting sources, PID reuse. | M1. Real TShark metadata-rich and metadata-free files; physical-device label availability separately. |
| 2 | Searchable packet timeline and inspector: explain what happened packet by packet. | Implemented retained records, bounded paging, raw TCP fields, filters, native inspector and original actions. Final visual selection/scrolling acceptance remains pending. [S2, S6; C5] | Medium–high; retention cost, timestamp ordering, incorrect field pairing. | M1 → M2. Stable selection, equal-time ordering, IPv4/IPv6, both endpoints, unknown labels, cancellation. |
| 3 | TCP/UDP sessions with packet ↔ session ↔ timeline navigation. | Implemented scoped pure grouping and session/focused timeline/packet return controls. Full native traversal remains pending. [S2; C6] | Medium; merging distinct flows or hiding incomplete packets. | M1/M2 → M3. Reversed directions, same tuple/different context, ambiguous encapsulation, and complete membership counts. |
| 4 | Packet/flow hostname provenance: explain each name and its supporting evidence. | Implemented structured records, supporting frames, TTL/client/interface scope, and conservative unpaired certificate/authority evidence. [S5, S7; C7, C8] | Medium–high; false name/address or historical associations. | M1; UI after M2/M3, implemented in M4 before any session name inference is exposed. Multi-answer DNS, CNAME, TTL, negative responses, opposing TLS directions. |
| 5 | Optional current reverse DNS: useful enrichment with a clear separate result. | Ordinary analysis is passive. Explicit current PTR UI/connector, parser checks, and real loopback-resolver integration pass; native lookup interaction remains pending. [S3, S5, S12; C9] | Medium; behavior change, network disclosure, confusing lookup time with packet time. | M4. Passive analysis invokes no resolver; separately validate success, no-answer, invalid input, timeout, and cancellation. |
| 6 | Original capture integrity and raw packet bytes: make each displayed record traceable. | Implemented typed pending/verified/failed status, before/after hash checks, source/frame references and bounded byte/range inspection. Generated large-capture byte costs are measured; native byte UI acceptance remains pending. [S1, S3, S6; C4, C10] | Medium; stale source, whole-file hashing cost, confusing container metadata with frame bytes. | Identity/state in M1, reveal in M2, verified raw inspection in M5. Changed/missing/growing/truncated originals and byte equality. |
| 7 | Responsive analysis at screenshot-scale and beyond. | Generated 50k/100k optimized native decoder, filter, selection and cancellation tests pass. Physical/native scrolling and DNS-heavy workloads have separate acceptance. [S3, S5; C11] | Medium; retaining complete dictionaries/payloads or repeated rescans. | Design in M1; measure each UI milestone and close M6. At least 50,000 and 100,000 packets, with host/tool/capture context recorded. |

## Implementation shape

- Keep `CaptureCoordinator`, existing `TSharkAnalyzer` capability negotiation, and aggregate analysis results. Do not replace Sentinel's collector with Correlator's privileged multi-source service.
- Introduce a typed artifact reference, exact capture timestamp, packet record, recorded-process metadata, capture direction, session key, and hostname support reference. The artifact records source provenance: Sentinel live device RVI, user-declared imported RVI, or unknown. Apple process options in an arbitrary imported file do not establish iPhone origin. Keep domain transformations pure; external decoding/file/lookup work stays behind narrow I/O boundaries.
- Use compact packet records and a bounded indexed query boundary. Page results into native SwiftUI `Table`/inspector views; fetch original bytes and verified field ranges on demand. Do not place every raw field dictionary or payload in `AppState`. Establish explicit record/byte budgets; exceeding a supported limit is a specific failure, never silent truncation. Add disk-backed indexing only if measured supported captures require it.
- Keep original decoded epoch text plus validated integral seconds/fraction for exact comparison. Container-declared resolution remains unknown unless separately established. Sort by exact capture time then frame number; display local timezone separately. A source frame number is unique only inside its artifact.
- Model recorded process labels separately from `ProcessAttribution`. Preserve label origin and unknown/unsupported/not-present states. If PCAPNG and PKTAP metadata disagree, surface the conflict; do not silently substitute one.
- Preserve original frame bytes and explicit ambiguity diagnostics for inspection; do not retain complete raw decoder dictionaries per packet. Derive endpoints/sessions only when one transport/IP pairing is established. Keep ungroupable records visible on the timeline.
- Reuse current summary, protocol details, interfaces, baselines, and export behavior. Version any required serialized changes and preserve old documents. Packet browsing must not silently expand report exports with payloads, private paths, or new evidence inventories.

## Milestones and TODO

### M0 — source study and baseline (complete)

- [x] Confirm canonical roots, instruction scope, branches/revisions, and existing dirty work.
- [x] Trace capture/copy/import/decode/models/UI and locate existing Sentinel equivalents.
- [x] Verify required optional field names against installed TShark 4.6.9 and official references.
- [x] Record prioritized additions, dependencies, acceptance criteria, and live-validation limits in this file.

### M1 — preserve packet identity and recorded metadata

Affected: `AnalysisModels.swift`, `Models.swift`, `TSharkAnalyzer.swift`, `PacketAnalysis.swift`, `AppState.swift`; new cohesive packet/timestamp/index model files as needed. Depends on M0.

- [x] Add optional `frame.darwin.process_info.{pid,pname,epid,epname}`, `frame.packet_flags_direction`, `pktap.{pid,cmdname,epid,ecmdname,ifname,flags}`, `tcp.seq_raw`, `tcp.ack_raw`, and `frame.cap_len` through the existing field catalog.
- [x] Retain compact per-frame records with artifact/frame identity and explicit source provenance, exact decoded epoch values, with container-declared resolution unknown unless separately established, protocol stack, validated endpoint/stream fields, recorded process/effective-process metadata, interface, direction, and field-support status. Distinguish live RVI provenance from an importer's declaration or unknown origin; field presence alone must never produce an iPhone attribution.
- [x] Validate field values/ranges and repeated-layer ambiguity. Keep missing labels unknown and PID 0 unavailable; PID/name pairs are not process lifetime identifiers.
- [x] Preserve aggregate outputs while adding a bounded packet index/query boundary. Specify cancellation, decoder deadlines, record/row/diagnostic/resource bounds, and explicit failure behavior for the added path.
- [x] Reuse streaming SHA-256; add typed pending/verified/failed integrity states and before/after original-file verification. Do not return completed evidence for a changed source.
- [x] Preserve existing serialized export/baseline contracts or version a necessary schema change explicitly; do not add packet payload export.

Acceptance: metadata-rich input exposes only its own recorded labels; ordinary RAW PCAP remains usable with unknown labels/direction; missing optional decoder fields are distinguished from absent capture data; unequal sub-microsecond timestamps remain distinct; all decoded frames have stable references; source bytes remain unchanged; resource-limit/cancellation failures are explicit. Existing aggregate totals remain equivalent for the same passive fields.

Verification: real installed TShark against isolated known PCAP/PCAPNG inputs, optional-field negotiation, malformed/repeated-layer/invalid-value cases, timestamp precision, changed-source denial, aggregate equivalence, and initial 50,000-packet resource measurements. Manufactured format fixtures establish parser behavior only; real iPhone metadata requires the physical validation in M6.

### M2 — native packet timeline and inspector

Affected: `AnalysisView.swift`, `AppState.swift`, `Models.swift` accessibility identifiers; new cohesive packet list/inspector views. Depends on M1.

- [x] Add a paged chronological packet view inside Analysis, retaining existing summary tabs.
- [x] Support search by recorded process/name/PID, source and destination IPv4/IPv6/port, directly recorded packet names, and protocol; add explicit protocol/interface/direction filters and accurate total/shown counts. Until M4 completes correct associations, do not use existing aggregate hostname-to-IP mappings for packet/session search or labels.
- [x] Show exact original epoch, formatted local time and decoded representation, explicitly distinguishing it from container-declared resolution, artifact/frame ID, wire/captured lengths, protocol stack, endpoints, relative versus raw TCP values, flags, process/effective process, interface, and direction.
- [x] Add stable selection and navigation/accessibility IDs; keep filter/sort state while inspecting or returning from a packet.
- [x] Reuse Finder reveal for analysis originals and show actionable missing/changed-file states. Explain recorded labels as metadata without repeating verbose explanations in every row.

Acceptance: every decoded packet, including ungroupable records, is reachable; tied timestamps have deterministic frame order; PID and both-endpoint searches work; absent labels are clear; selection survives filtering and inspector return; protocol-detail aggregates retain their existing relative sequence/ACK labels.

Verification: native UI interaction using stable IDs, deterministic sorting/filter checks, IPv6/unknown-value display, all-row reachability, and 50,000-packet load/filter/scroll measurements. A successful build alone does not establish UI interaction.

### M3 — RVI-only sessions and navigation

Affected: packet/index model, new pure session grouping and session views, `AnalysisView.swift`, `AppState.swift`. Depends on M1/M2.

- [x] Group direction-independent TCP/UDP endpoint pairs only within one artifact, stream, interface, and recorded process/effective-process context.
- [x] Display endpoints, transport/stream, first/last exact times, packet count, interface, and recorded RVI process labels. Keep PID reuse and missing labels from becoming identity claims.
- [x] Keep incomplete five-tuples, missing stream IDs, and ambiguous/encapsulated layers on the timeline without guessed session membership.
- [x] Implement session → focused timeline → packet → return navigation with stable IDs and restored selection/filter state. Make every session member accessible, not merely a preview subset.
- [x] Leave inferred hostname associations absent until M4; do not import correlation/log/peer-link fields into the session model.

Acceptance: opposite packet directions join the same eligible session; identical tuples from different artifacts/interfaces/streams/process contexts do not merge; session counts equal their distinct member frames; unknown/ambiguous records remain visible; complete navigation works with only an RVI input.

Verification: real decoder integration plus minimal grouping cases for reversed endpoints, context changes, absent fields, repeated layers, all-member traversal, and native navigation IDs. No Mac capture is required or requested.

### M4 — hostname evidence and optional current lookup

Affected: `PacketAnalysis.swift`, `Models.swift`, `TSharkAnalyzer.swift`, packet/session views; a narrow lookup connector; relevant `README.md`, compatibility guidance, and existing hostname/lookup assertions. Depends on M1/M2; session presentation also depends on M3.

- [x] Decode structured DNS resource records with owner/type/value/TTL/frame identity instead of Cartesian-product pairing of flattened response arrays. Bound the additional pass and avoid per-packet capture rescans.
- [x] Attach supporting frame/stream IDs to captured DNS/mDNS/PTR/service observations, TLS/QUIC SNI, HTTP authorities, and certificate names. Validate certificate peer/direction context; keep unsupported or unpaired names explicitly unpaired.
- [x] Separate directly recorded names from inferred within-stream or DNS-answer associations. Scope inferred DNS links by artifact/client/address family/time, TTL, CNAME chain, and later replacement/negative responses; retain conflicting candidates and reasons.
- [x] Ensure DNS questions alone never label a later endpoint. Do not claim full DNS-SD reconstruction or infer why an encrypted/late capture lacks names.
- [x] Make ordinary analysis passive (`-n`) and remove automatic `-N nN` enrichment from its data contract. Update associated UI text, coverage/export declarations, docs, and meaningful existing assertions consistently.
- [x] Add an explicit current PTR lookup for a selected validated IP. Store requested/completed times, query, result/status, TTL where available, and provenance separately from packet timestamps and captured evidence.
- [x] Bound lookup execution/output and support cancellation; distinguish no-answer/NXDOMAIN from operation failure. Do not retry invalid input, authorization, or decoder/schema failures.

Acceptance: multi-answer packets cannot cross-associate unrelated owners/addresses; expired/replaced answers do not label later flows; client-bound certificate traffic does not assign a server name to the client; passive analysis makes no resolver request; current lookup never becomes historical evidence or overwrites captured names.

Verification: real TShark DNS/mDNS/CNAME/TLS-direction integration using isolated known data and frame linkage/TTL/negative-answer cases; actual system `dig` with a bounded, loopback-only resolver for the lookup connector. Native user-triggered lookup, configured-resolver display, and cancellation still require UI acceptance. Controlled reserved-data transport proves no physical-device hostname identity. [S12]

### M5 — verified original packet bytes

Affected: existing hash/process boundaries; new raw-packet decoder model and inspector UI; packet artifact references. Depends on M1/M2; independent of inferred hostname/session links.

- [x] Decode only the selected original frame on demand with TShark `jsonraw`, explicit deadline/output/frame-byte bounds, and cancellation. Do not retain all payloads during initial analysis.
- [x] Require a completed matching artifact; verify source hash before/after extraction and reject missing, changed, growing, or wrong-artifact evidence.
- [x] Validate one-frame response shape, captured length, raw hex, offset/range bounds, and byte equality before highlighting a field. Keep PCAPNG option metadata, synthesized/reassembled fields, and unverifiable ranges explicitly unmapped.
- [x] Provide bounded hex windows and selected-field explanation with reveal-original/return navigation. Keep bytes out of existing exports by default.
- [x] Measure whole-file rehash/dissection cost at 50,000/100,000 packets using first, middle, and last frames. Verify each extracted frame against the generated bytes and preserve the capture digest. Measurements below include both integrity checks and both TShark processes. Any caching must preserve verified artifact identity and changed-source detection, rather than relying solely on modification time.

Acceptance: shown bytes equal the selected saved frame; verified highlights match exact byte slices; container process labels are not falsely presented as packet-byte ranges; pending/failed integrity, truncation, source mutation, and missing originals fail with specific recovery guidance.

Verification: real-TShark exact-byte/range integration, wrong/changed/missing/growing capture denial, raw JSON/hex/range boundary cases, and native navigation/performance. Source is unchanged before/after.

### M6 — integration, performance, and physical evidence

Affected: existing test targets, native interaction validation, compatibility evidence/docs only where validated behavior changes. Depends on M1–M5; resource measurements start in M1.

- [x] Run required native build/tests after final code edits, preserving meaningful existing tests. Compatibility tool/guidance is unchanged, so its separate checks are not required for this implementation. Executed/skipped/blocked scopes are recorded below.
- [x] Reconcile PR #2's feature branch with current main in the isolated publication worktree under fresh commit/integration/push approval. The verified conflict is `.github/workflows/native-macos.yml`: current main already contains every-PR triggers, pinned checkout, disabled persisted credentials, timeouts, a read-only token, and the required Homebrew Wireshark/TShark setup. The native workflow now equals current main intact, alongside its Swift/Actions analysis/upload workflow. Unrelated local compatibility work is preserved. The approved operation updates only PR #2's feature branch; it does not merge PR #2 into main.
- [ ] Verify successful Swift and Actions CodeQL extraction/analysis and separate Code scanning uploads for the candidate revision or its applicable test-merge revision. Inspect full artifact SARIF invocation notifications, including compiler/extraction diagnostics labeled `level: none`; report exclusions and unavailable imported-module semantic coverage. Successful file counts or zero unresolved AST nodes do not establish complete imported-framework semantics. Source analysis must remain read-only with `upload: never` and `upload-database: false`; successful results for main or another PR do not establish candidate coverage.
- [x] Benchmark generated 50,000 and 100,000 packets with the real decoder: total analysis time, separately repeated session construction, process RSS high-water mark, pure packet filter/selection and session queries, and caller/explicit cancellation. Record host/tool versions and distinguish generated inputs from physical-device evidence.
- [x] Verify pure packet filter/selection and session-query p95 ≤300 ms and cancellation acknowledgment ≤1 s on those generated datasets. The 200,000-record/256-MiB estimated-storage limits are explicit failure ceilings, not measured capacity claims.
- [ ] Measure full native filter/selection/scrolling interaction and session navigation latency. Apply the same latency targets to the native UI and record host/tool/input context. Pure session construction/query and original-byte extraction costs are measured separately below; they do not establish interaction latency.
- [x] Confirm the decoder uses a fixed number of passes rather than rescanning growing prefixes per batch; retain compact records and fetch raw bytes only for an explicit selected-frame request.
- [ ] Verify native main-thread responsiveness and repeated packet-detail selection/release memory behavior.
- [x] Run an authorized bounded PCAPNG capture through Sentinel's existing UI workflow; verify requested duration, finalization, original format, readable packet count, independent SHA-256 agreement, and temporary RVI removal. The user operated capture controls after native automation disconnected; observation of saved output and process/interface state verified completion.
- [x] Validate available process/effective-process/interface/direction fields against the device-source file using independent passive TShark inspection. Recorded process names/PIDs, interface, and direction were present; effective-process labels were absent. These remain capture metadata rather than independently verified process identity.
- [x] Confirm the completed physical capture opens for local analysis and displays Summary and Packets & Sessions results. The user confirmed these results are visible; automated UI verification remains blocked.
- [ ] Verify completed physical-capture reopening, packet/session traversal, and inspector navigation in the UI.
- [x] Execute the real current-PTR connector against a controlled loopback resolver: IPv4/IPv6 answers, no-answer/NXDOMAIN, observed-query timeout/cancellation, request/completion ordering, decoder reuse, rejected-input/no-query behavior, and unchanged generated capture hashes/re-decoded captured hostname evidence pass. Tests use only reserved IPs and `.test` names, never forward queries, and do not change DNS settings. The UI retains its configured resolver; its user-triggered behavior remains unverified. [S12]
- [x] Exercise real decoder integration with metadata-free classic RAW PCAP, malformed evidence, missing/changed originals, and existing aggregate/baseline/report checks. Original bytes remain unchanged in successful tests.
- [ ] Complete native reopen/navigation and moved/growing/truncated-original interaction checks, including the existing baseline and report workflows.

Acceptance: all applicable checks and required native interactions pass; supported capacity and latency are measured; saved-file versus physical/live verification are separately stated; unresolved device/metadata/service gaps remain explicit. No new Mac collection or correlation is introduced.

Required native commands from the Sentinel root:

```sh
xcodebuild -project RVISentinel.xcodeproj -scheme RVISentinel -configuration Debug -derivedDataPath DerivedData CODE_SIGNING_ALLOWED=NO build test
```

The controlled-PTR integration runs in the ordinary native suite. To isolate it without querying a private capture endpoint or changing system DNS:

```sh
xcodebuild -project RVISentinel.xcodeproj -scheme RVISentinel -configuration Debug -derivedDataPath DerivedData CODE_SIGNING_ALLOWED=NO SWIFT_TREAT_WARNINGS_AS_ERRORS=YES test -only-testing:RVISentinelTests/CurrentDNSLookupIntegrationTests
```

If compatibility tooling/guidance changes, follow the existing CI commands:

```sh
swift test --package-path Tools/Compatibility
swift run --package-path Tools/Compatibility check-compatibility docs/compatibility-evidence.json docs/COMPATIBILITY.md
```

## Verification status and source references

Source, generated-capture decoding, and an authorized physical-device capture have separate verification results below. Current checks are dated; the original physical capture and user-operated UI observations remain historical unless explicitly revalidated. Native automation verified the stable Analysis entry, file chooser, capture selection, passive analysis start, busy controls, and pending integrity, then its connection closed before completed results could be inspected. The user subsequently started a 120-second capture in Sentinel's UI and confirmed that Summary and Packets & Sessions results are visible after local analysis. Saved-file validation, independent hashes, passive metadata decoding, and RVI removal passed. Timeline/inspector/session traversal and scrolling remain unverified. Active PTR transport was exercised only through an explicitly selected loopback resolver with reserved generated data; no private capture endpoint was queried. Generated format tests alone do not establish actual iPhone metadata availability. `PhysicalWorkflowTests` now passes against the completed device-source file, covering analysis, baseline comparison/update, local exports, and redacted diagnostics; it does not create/capture/remove an RVI. [S8]

### Executed local checks

| Check | Outcome | Scope |
| --- | --- | --- |
| Native Debug `build test`, `SWIFT_TREAT_WARNINGS_AS_ERRORS=YES`, supplied physical capture enabled | Passed: 90 tests, 3 skips, 0 failures (2026-10-09) | Full app/test sources, Swift 6 complete concurrency; real TShark metadata/classic/DNS/mDNS/HTTP/raw-byte integrations, bounded process/file failures, timestamps, queries/sessions, and supplied physical-file analysis/baseline/export/diagnostic workflow. Three opt-in performance tests are executed separately in Release mode. The local working tree includes one pre-existing, unstaged PCAPNG test. Total wall time includes a confirmed host sleep interval; this suite is correctness evidence, not a latency measurement. |
| Optimized Release `test` build, command-scoped testability and Swift warnings as errors | Passed (2026-10-09) | Final sources; release project settings remain unchanged. |
| Opt-in optimized packet performance tests | Passed: 3 tests, 0 skips/failures (2026-10-09) | Final 50k/100k decode, separate session construction, packet/session queries, and first/middle/last original-byte measurements, with exact generated-byte equality and unchanged capture hashes. Both caller/explicit cancellation checks after 5,000 decoded packets acknowledged within 1 second and returned no completed result. |
| Hosted Native macOS check on published `bb4d607` | Passed | [Candidate native run](https://github.com/hideouts-io/RVI-Sentinel-Swift/actions/runs/37861284312). This does not verify the newer uncommitted benchmark changes or device/UI behavior. |
| Candidate integration with current main | Resolved and locally validated (2026-10-09); hosted checks pending | The nine-file checkpoint `eaa6ea0` integrates main `ecfed3a` in the isolated publication worktree. Only the native workflow conflicted; its resolution equals current main and retains every-PR checks, pinned Actions, disabled persisted credentials, timeouts, and the Wireshark/TShark prerequisite. Actual merged-tree Debug build/test passed: 89 tests, 3 performance skips, 0 failures, with the supplied physical file enabled. No integration into main is authorized or performed. |
| Isolated prospective integration candidate | Passed: 89 tests, 3 skips, 0 failures (2026-10-09) | Exported published `bb4d607` plus main `ecfed3a`'s four workflow/policy files and the nine reviewed task-owned files, excluding unrelated compatibility tooling, artwork, scheme changes, and the pre-existing unstaged test. Required Debug build/test passed with the supplied physical file enabled; workflow YAML syntax parsed. This is local preparation, not hosted CI, CodeQL, or execution of the decoder-provisioning step. |
| Candidate Swift/Actions CodeQL and Code scanning uploads | Not verified; refreshed 2026-10-09 | No analysis was found for PR #2's published candidate or its PR refs, and its test-merge revision is unavailable while conflicting. Current main's [run](https://github.com/hideouts-io/RVI-Sentinel-Swift/actions/runs/37902160466) passed both analyses, both uploads, and the upload gate. All full-artifact SARIF notifications were reviewed, including `level: none`; no compiler diagnostic notifications were present. Main extracted 25 app source files; its 12 test files are outside the application-build extraction. Main's scan does not cover the packet branch's 16 additional app source files or newer uncommitted work, and does not establish complete imported-framework semantics. No existing local CodeQL CLI/bundle was discovered; local candidate analysis was not run. Candidate-specific hosted analysis and uploads await an authorized branch update. |
| Cancellation-test harness cleanup | Passed: focused and full-suite verification (2026-10-09) | Two full Debug runs stalled inside the existing test's synchronous `Process.waitUntilExit`, after ownership checks; the standalone original test passed. The test now registers the existing asynchronous termination stream before launch, retains verification failures through cleanup, and records cleanup failures. Application decoder cancellation is unchanged; no assertion or timeout was weakened. |
| `git diff --check` and final read-only source review | Passed | Whitespace/scope and metadata/session/time/lookup/raw-byte/cancellation contracts; not runtime UI proof. |
| Preservation snapshot | Passed (2026-10-09) | All 543 unrelated Sentinel files and 181 Correlator files match this pass's initial SHA-256 snapshot. One initially unrelated decoder test became task-owned solely for the reproduced cleanup correction. Primary HEAD/index, Correlator HEAD/status, the other task's worktree HEAD, and the original private capture hash are unchanged. The local compatibility workflow/tooling/docs, artwork, scheme/README edits, and pre-existing packet test remain outside the nine-file focused update. |
| Compatibility package `swift test --package-path Tools/Compatibility` | Historical pass: 7 tests, 0 failures (2026-10-08); not rerun | Existing local compatibility tooling remains unchanged and is excluded from the feature candidate. The separate compatibility-document checker was not run. |
| Physical RVI capture and independent file validation | Historical device pass (2026-10-08); original SHA-256 rechecked 2026-10-09 | User-started Sentinel UI capture, bounded capture command, valid Apple PCAPNG, readable packets and recorded metadata, matching independent hashes, and verified absence of the temporary RVI. Private capture data and identifiers remain outside the repository. |
| Controlled current-PTR integration | Passed: 3 tests, 0 skips/failures (2026-10-09) | Actual `/usr/bin/dig` and a bounded ephemeral UDP resolver bound only to `127.0.0.1`; IPv4/IPv6 answers, no-answer/NXDOMAIN, request/completion ordering, observed-query deadline/cancellation, decoder reuse, invalid-address/port rejection without a query, and captured-evidence preservation. The explicit typed dependency leaves the UI caller system-configured. Zone identifiers and embedded NUL are rejected before `inet_pton`/process launch. If `~/.digrc` exists, these tests skip before querying rather than altering user configuration. |
| Native timeline/session/byte/current-lookup UI | Blocked; manual results pending (2026-10-09) | Native reconnect returned “Sky Computer Use native pipe closed before response.” The existing running app was preserved and focused manual results were requested. Task-owned metadata and 100,000-packet captures were prepared outside the repository; passive TShark confirmed their expected fields/count. Builds, connector tests, and pure queries do not establish these native interactions. |

### Remaining observable acceptance

- Native browsing: load the generated metadata fixture or an authorized saved RVI file; select **Packets & Sessions**, search `maild`/`343`, exercise protocol/interface/direction filters and both endpoints, select a row, then traverse Sessions → focused Timeline → packet → Return to Session. Confirm all members, exact epochs, unknown labels, restored selection/filter state, paging, and responsive scrolling at 100,000 packets. Use the existing stable accessibility IDs for automation.
- Byte inspection: select a packet and request original bytes; check bounded windows and verified field ranges, then move/change the task-owned test original and confirm a specific error. Rehash/dissection latency on 50,000/100,000-packet input is measured below; native responsiveness and memory after repeated selection/cancellation remain pending. Do not alter a user's original evidence for this check.
- Current DNS UI: explicitly initiate a lookup for a controlled, nonprivate endpoint under separately authorized resolver conditions. Verify displayed request/completion time, separate present-day provenance, errors/cancellation, and unchanged captured names. The real connector is validated locally; no UI resolver override was added, system DNS settings remain unchanged, and private capture endpoints must not be sent to external resolvers without specific authorization.
- Physical RVI UI: reopen the completed authorized device-source capture and verify native timeline, inspector, session navigation, and original-byte actions. Capture finalization, cleanup, format/hash, optional metadata, and supplied-file workflow checks have passed; those checks do not establish native navigation.

### Reproducible optimized measurements

The measurements below were refreshed on 2026-10-09 after the final code/test edits. The generated RAW inputs contain 50,000/100,000 loopback UDP frames, one eligible session, and no process labels. They are format fixtures written to temporary files; no packets are transmitted. Measurements use macOS 27.0 (26A428), Xcode 27, Swift 6 complete concurrency, and TShark 4.6.9. Analysis time includes tool probes, hashes, decoding, indexing, and session construction. The separate session-construction observation repeats grouping over retained chronological records and checks exact session equality. Packet/session-query latency measures pure queries, not native rendering or user interaction. RSS is the test process's high-water mark after analysis, repeated grouping, queries, and three original-byte inspections, including benchmark scratch allocations; it excludes the separate TShark child's RSS and is not incremental per-capture usage.

```sh
TEST_RUNNER_RVI_SENTINEL_RUN_PACKET_PERFORMANCE=1 xcodebuild -project RVISentinel.xcodeproj -scheme RVISentinel -configuration Release -derivedDataPath DerivedDataRelease CODE_SIGNING_ALLOWED=NO ENABLE_TESTABILITY=YES SWIFT_TREAT_WARNINGS_AS_ERRORS=YES test -only-testing:RVISentinelTests/PacketPerformanceTests
```

`ENABLE_TESTABILITY=YES` is a command-scoped flag for the existing `@testable` tests in an optimized build; project release settings are unchanged. Test-owned build artifacts are kept outside the review diff after verification. Native Debug build/test commands remain the required integration checks above.

| Generated packets | Total analysis seconds | Filter p95 ms (20 queries) | Single-record query p95 ms (20 queries) | Estimated retained record bytes | Test-process RSS high-water bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| 50,000 | 4.011 | 117.490 | 16.803 | 74,700,000 | 279,691,264 |
| 100,000 | 6.981 | 239.098 | 34.875 | 149,400,000 | 474,382,336 |

| Generated packets | Separate session construction ms | Session-query p95 ms (20 queries) |
| --- | ---: | ---: |
| 50,000 | 119.576 | 96.614 |
| 100,000 | 234.017 | 228.767 |

| Generated packets | First-frame inspection ms | Middle-frame inspection ms | Last-frame inspection ms |
| --- | ---: | ---: | ---: |
| 50,000 | 226.511 | 381.780 (frame 25,001) | 587.489 |
| 100,000 | 257.263 | 610.383 (frame 50,001) | 1061.625 |

Each inspection measurement includes before/after whole-file hashes, frame-identity decoding, selected-frame raw dissection, and response validation. The additional test-side preservation hash and byte assertions occur outside the timed interval. These are three individual generated-input observations per size, not percentiles or native interaction measurements. Late-frame inspection incurs two TShark prefix reads and can take about one second on this input; the existing asynchronous loading/cancellation UI still needs runtime validation. No digest caching or integrity relaxation was introduced.

These optimized packet/session-query measurements pass the ≤300-ms target. Original-byte extraction is measured separately and is not an instant-query claim. The single-session workload does not establish many-session browsing capacity. The measurements do not establish UI rendering/scrolling latency, DNS-heavy throughput, large-payload frame inspection, repeated-selection release behavior, or support at the failure ceilings. The native suite passes separately with the supplied physical capture enabled; the three opt-in tests run explicitly in Release mode.

The pure DNS resolver additionally returned 1,000 associations from 1,000 repeated answer refreshes plus 1,000 flows in 0.01224 seconds in an optimized temporary harness. This validates the indexed refresh path on synthetic typed inputs, not real DNS-heavy capture throughput or physical-device behavior. Equal timestamps use frame ordering; later answers cannot name earlier packets.

Sentinel references:

- **S1:** [CaptureCoordinator.capture / makeAuthorizedCapturePlan / sha256](Sources/RVISentinel/CaptureCoordinator.swift#L167), command at line 497 and hash at line 600; [PCAPNG default and completion view](Sources/RVISentinel/DeviceCaptureView.swift#L6).
- **S2:** [TSharkField](Sources/RVISentinel/AnalysisModels.swift#L57), [DecodedPacket](Sources/RVISentinel/AnalysisModels.swift#L189), and [NativeAnalysisResult](Sources/RVISentinel/AnalysisModels.swift#L268).
- **S3:** [TSharkAnalyzer.analyze](Sources/RVISentinel/TSharkAnalyzer.swift#L31), [passive tsharkArguments](Sources/RVISentinel/TSharkAnalyzer.swift#L160), and [BoundedDecoder](Sources/RVISentinel/BoundedDecoder.swift#L88).
- **S4:** [prepareCompletedCaptureForAnalysis](Sources/RVISentinel/AppState.swift#L206), [chooseAnalysisCapture](Sources/RVISentinel/AppState.swift#L218), and [startAnalysis](Sources/RVISentinel/AppState.swift#L248).
- **S5:** [AnalysisAccumulator.consume](Sources/RVISentinel/PacketAnalysis.swift#L59), [aggregate hostname evidence](Sources/RVISentinel/PacketAnalysis.swift#L277), [structured owner/RDATA pairing](Sources/RVISentinel/PacketAnalysis.swift#L303), [packet decoding](Sources/RVISentinel/PacketDecoding.swift#L26), and [relative TCP detail labels](Sources/RVISentinel/ProtocolDetails.swift#L33).
- **S6:** [AnalysisView](Sources/RVISentinel/AnalysisView.swift#L4), [PacketBrowserView](Sources/RVISentinel/PacketBrowserView.swift#L28), and [PacketInspectorView](Sources/RVISentinel/PacketInspectorView.swift#L4). Stable packet/session controls have `analysis.packet.*`, `analysis.session.*`, and `analysis.timeline.*` accessibility IDs.
- **S7:** [EvidenceProvenance / HostnameEvidence / ProcessAttribution](Sources/RVISentinel/Models.swift#L192); [versioned report model](Sources/RVISentinel/ExportModels.swift#L75).
- **S8:** [decoder integration tests](Tests/RVISentinelTests/AnalyzerPacketIntegrationTests.swift#L6), [DNS/raw evidence integration](Tests/RVISentinelTests/PacketEvidenceIntegrationTests.swift#L8), [generated performance tests](Tests/RVISentinelTests/PacketPerformanceTests.swift#L5), [supplied-file physical workflow](Tests/RVISentinelTests/PhysicalWorkflowTests.swift#L6), [documented native commands](README.md#L378), [compatibility CI commands](.github/workflows/native-macos.yml#L39), and [macOS 14 / Swift 6 configuration](project.yml#L4).
- **S9:** [PacketCaptureArtifact / exact decoded PacketTimestamp / PacketRecord](Sources/RVISentinel/PacketModels.swift#L28), [bounded packet index and queries](Sources/RVISentinel/PacketIndex.swift#L25), [makePacketSessions](Sources/RVISentinel/PacketSessions.swift#L51), and [session queries](Sources/RVISentinel/PacketBrowsing.swift#L10).
- **S10:** [structured DNS read/decode](Sources/RVISentinel/CapturedDNSRecords.swift#L66), [resolveCapturedHostnames](Sources/RVISentinel/CapturedHostnames.swift#L28), [TTL/client/interface/replacement scope](Sources/RVISentinel/CapturedHostnames.swift#L201), and [explicit lookupCurrentPTR / typed resolver dependency](Sources/RVISentinel/CurrentDNSLookup.swift#L56).
- **S12:** [real current-PTR transport tests](Tests/RVISentinelTests/CurrentDNSLookupIntegrationTests.swift#L19) and [bounded loopback-only resolver](Tests/RVISentinelTests/CurrentDNSLoopbackResolver.swift#L40). Test queries use reserved addresses and `.test` names; no query is forwarded. The native lookup caller retains the system-configured resolver.
- **S11:** [hashCaptureBytes](Sources/RVISentinel/CaptureEvidenceHash.swift#L24), [inspectOriginalPacket](Sources/RVISentinel/OriginalPacketBytes.swift#L60), and [raw-byte view](Sources/RVISentinel/PacketRawBytesView.swift#L4).

Read-only Correlator references:

- **C1:** [runCapture / device tcpdump arguments](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CaptureWorker/main.swift#L123), device writer at line 156.
- **C2:** [packetFields / parseEpochMicroseconds / decodeGrowingCapture / importCapture](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorCore/Import.swift#L4), precision at line 56, batching at line 96, static identity/hash at line 142.
- **C3:** [Observation process/interface/direction](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorCore/Models.swift#L38); [timestamp resolution description](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorCore/CaptureClock.swift#L3).
- **C4:** [publishCaptureFiles](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorCore/ProtectedCapture.swift#L257).
- **C5:** [TimelineView](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorApp/InvestigationViews.swift#L120), packet inspector at line 346; [timeline search](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorApp/ContentView.swift#L94); [field explanations](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorApp/FieldCatalog.swift#L8).
- **C6:** [sessionKey / packetSessions](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorCore/PacketSession.swift#L43), RVI display-label gap at line 83; [endpoint ambiguity](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorCore/PacketEndpoint.swift#L14); [session navigation](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorApp/SessionViews.swift#L15).
- **C7:** [resolveHostnames and evidence scope](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorCore/HostnameEvidence.swift#L39).
- **C8:** [structured DNS resource-record decoding](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorCore/DNSRecords.swift#L57).
- **C9:** [ActiveDNSLookup](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorApp/ActiveDNSLookup.swift#L23); [separate lookup UI](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorApp/EvidenceExplanationViews.swift#L53).
- **C10:** [inspectRawPacket](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorCore/RawPacketEvidence.swift#L62); [bounded hex UI](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorApp/RawPacketView.swift#L23).
- **C11:** [packet budgets](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorCore/PacketBudget.swift#L3); [decoder batching/bounds](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorCore/Import.swift#L96); [formatting](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorApp/UIComponents.swift#L81).
- **C12:** [two-source investigation guard](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorApp/ContentViewActions.swift#L127); [two-source live finalization](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorApp/LiveCaptureService.swift#L190); [two-source live rebuild](https://github.com/hideouts-io/RVI-Correlator/blob/12c62bba8bbe6aeb99493d93e748fb24ac640f15/Sources/CorrelatorApp/LiveCaptureView.swift#L257).

External primary references, checked alongside the installed field catalog:

- **W1:** [Wireshark frame field reference](https://www.wireshark.org/docs/dfref/f/frame.html), including Darwin process/effective-process and direction fields. Darwin process fields are listed from Wireshark 4.6.0; negotiate capabilities rather than assume older decoders expose them.
- **W2:** [Wireshark PKTAP field reference](https://www.wireshark.org/docs/dfref/p/pktap.html).
- **W3:** [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html), output formats and name-resolution options. The installed Apple `man tcpdump` documents `-P`/`--apple-pcapng` as aliases.
