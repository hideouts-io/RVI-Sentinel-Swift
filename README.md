# Native macOS RVI-Sentinel remake specification

RVI-Sentinel-Swift is a separate, macOS-only native remake of [RVI-Sentinel](https://github.com/hideouts-io/RVI-Sentinel). The original cross-platform Python application remains intact and will not be removed, replaced, or retired. The parity matrix uses it as the functional reference while this edition develops its own verified Swift implementation.

## Current Python feature inventory

The repository audit found these user-visible and safety-critical behaviors:

- Apple CoreDevice and `xctrace` physical-device discovery with simulator exclusion, USB/pairing/boot readiness, and hidden device identifiers.
- A guided capture dialog for device, duration, PCAP/PCAPNG format, destination, and optional analysis.
- macOS `rvictl` creation, deterministic RVI identification, narrow native administrator authorization for `tcpdump`, five-second packet-arrival preflight, bounded capture, SIGINT flush, output validation, cancellation, and RVI cleanup.
- Linux and Windows capture through the separately installed and ignored `gh2o/rvi_capture` backend.
- Setup checks for trust, USB, capture backend, `tshark`, destination permissions, and disk space.
- A persistent completion card with packet count, size, actual duration, location, analysis, reveal, and repeat actions.
- PCAP/PCAPNG analysis through `tshark` for endpoints, IPv4/IPv6, TCP/UDP ports, DNS, TLS SNI, protocol frequency, QUIC-style traffic, and DNS entropy.
- Endpoint PTR enrichment, address-scope classification, optional local MaxMind-compatible GeoIP, and service/port explanations.
- Read-only analysis by default, suggested per-device or per-investigation baselines, explicit baseline updates, and new-versus-known findings.
- JSON reports and CSV exports, plain-language interpretation, drag/drop, advanced command/log details, redacted diagnostics, single-instance locking, and private artifact ignore rules.
- Deterministic analyzer, capture-contract, enrichment, model, and headless GUI tests.

## Proposed Swift architecture

| Component | Responsibility | Boundary |
|---|---|---|
| SwiftUI presentation | Guided workflow, accessibility, completion and interpretation views | No shell construction or packet inference |
| Core models | Typed devices, interfaces, evidence provenance, capture phases, findings, coverage | No I/O |
| Device discovery | Decode Apple `devicectl` JSON and exclude simulators | Apple CoreDevice evidence only |
| Setup checker | Exact readiness checks and corrective actions | Read-only except an explicit destination write test in a later stage |
| Interface inventory | Enumerate host-visible interfaces and classify ownership | Never infers an internal iOS route from RVI |
| Capture coordinator | Authorization, RVI lifecycle, packet preflight, timing, flush, validation, cleanup | One selected source; no silent interface expansion |
| Decoder adapters | Typed `tshark` field extraction and extensible protocol decoders | Decoder coverage is recorded per report |
| Enrichment | Optional local GeoIP/ASN and opt-in active resolution | Kept distinct from captured evidence |
| Baseline store | Read-only comparison, preview, explicit update, recoverable reset | Separate per device or investigation |
| Export service | JSON, CSV, HTML, optional PDF, hashes, provenance, coverage | Never rewrites the source capture |

Structured concurrency is used for external processes and long-running work. Pure parsing and classification functions are isolated from system connectors so synthetic fixtures can exercise behavior without a phone.

## Capture and privilege model

The native capture coordinator implements this sequence:

1. Re-check that the selected physical device is booted, paired, visible, and attached over USB.
2. Resolve `/Library/Apple/usr/bin/rvictl` and `/usr/sbin/tcpdump` explicitly.
3. Ask macOS for administrator authorization for only the bounded `tcpdump` operation; never request, read, or store a password.
4. Create an RVI only after readiness is reconfirmed, and identify the newly created interface from before/after inventories.
5. Capture one packet during a five-second preflight. A quiet phone yields a retryable no-traffic state; a disconnected phone yields a separate failure.
6. Start the visible countdown only after a packet is observed.
7. End `tcpdump` with SIGINT so buffered data is flushed, validate the requested file header and readable packets, and compute SHA-256.
8. Remove the RVI on success, cancellation, failure, termination, or disconnect and verify removal.
9. Preserve and report a valid saved capture as partial success if later cleanup fails.

The Swift capture path is enabled, but physical-device verification remains a release gate. Automated tests cover command construction, cancellation markers, SIGINT finalization, headers, and `capinfos` parsing; a real authorized iPhone/iPad matrix is still required before release qualification.

## Packet decoding and attribution

The native decoder uses current `tshark` as an explicit external dependency because it supplies maintained protocol dissectors. The Swift adapter reads the installed field catalog, requests only supported fields, validates streamed rows, retains unknown traffic as endpoint/port/timing/volume metadata, and records unsupported fields as coverage—not as negative evidence. Protocol-specific reducers remain pure functions over typed decoded packets.

Hostname observations are separate records keyed by hostname, related address, and provenance. Captured DNS, mDNS, DNS-SD, TLS SNI, HTTP Host, HTTP/2 authority, QUIC/HTTP/3 handshake evidence, certificate identities, and captured PTR records remain distinguishable. Active reverse lookup is disabled by default and will require explicit authorization because it generates traffic and discloses investigated addresses to the configured resolver.

Ordinary PCAP and RVI traffic does not inherently contain an iOS process name. The native app displays **Process not observable from this capture** unless a supported flow-ownership API, Network Extension record, PKTAP metadata, or authorized device diagnostic provides direct ownership evidence. Port, hostname, and vendor guesses are prohibited.

## Interface visibility limitations

`getifaddrs` proves which interfaces are visible to the Mac at inventory time. Names such as `en0`, `lo0`, `awdl0`, `llw0`, `bridge`, `utun`, `gif`, `stf`, `pdp_ip`, and `rvi` can be described, but name-based classification is labeled as such. An RVI packet does not prove that the iPhone used internal `en0`, `pdp_ip0`, or `utun`. That claim requires packet or device metadata that explicitly identifies the internal source interface.

## Feature parity matrix

Status meanings: **Implemented** is buildable native behavior with automated tests; **Scaffolded** is explicit UI/model structure without a production implementation; **Python reference** means that capability currently exists only in the separate Python edition.

| Capability | Python | Native status | Verification required |
|---|---:|---:|---|
| Single application instance | Yes | Implemented | Two-launch UI check |
| Plain-language opening workflow | Yes | Implemented | Accessibility/UI review |
| Physical device discovery | Yes | Implemented | Synthetic parser + physical device |
| Simulator exclusion | Yes | Implemented | Synthetic parser |
| USB, pairing, boot readiness | Yes | Implemented | Synthetic parser + physical device |
| Hidden UDID / advanced details | Yes | Implemented | UI review |
| Setup checks and exact fixes | Partial | Implemented for current native checks | Physical device and broken-state matrix |
| rpmuxd and orphaned-RVI checks | No/partial | Implemented | Host validation |
| Host interface inventory | No | Implemented | Live host inventory |
| Host/RVI/VPN ownership boundary | No | Implemented | Classification tests + UI review |
| MTU and network-service mapping | No | Scaffolded | SystemConfiguration implementation |
| Guided RVI capture | Yes | Implemented; hardware verification pending | Real-device lifecycle tests |
| Host/specific/multi-interface capture | No | Scaffolded | Privilege and evidence-boundary design |
| Live packet/byte progress | Partial | Implemented byte/time phases; live packet count pending | Real capture |
| Retryable packet preflight | Yes | Implemented; targeted recovery UI pending | Idle-device and disconnect tests |
| SIGINT flush and file validation | Yes | Implemented | PCAP and PCAPNG hardware tests |
| Partial-success cleanup semantics | Yes | Implemented | Forced cleanup failure |
| Completion card | Yes | Implemented | UI and real capture |
| Core endpoint/DNS/TLS/port analysis | Yes | Implemented native streaming core | Synthetic capture parity and large capture |
| Comprehensive protocol decoders | No | Field registry and protocol inventory implemented; detail decoders partial | Per-protocol synthetic captures |
| Unknown traffic representation | No | Implemented at flow/endpoint/port/size level | Synthetic unknown-IP-protocol fixture |
| Hostname provenance | Partial | Implemented for captured DNS, PTR, TLS SNI, HTTP Host, and HTTP/2 authority | Decoder fixtures and UI |
| Active resolution disabled by default | No | Implemented for native analysis; opt-in enrichment pending | Consent UI and network test |
| Process attribution evidence boundary | No | Implemented typed unavailable state in endpoint results | PKTAP and ordinary RVI fixtures |
| Local GeoIP | Yes | Python reference | Licensed local database fixture |
| Read-only baseline default | Yes | Implemented with separate local JSON baselines | Store and UI tests |
| Explicit baseline preview/update | Yes | Implemented with preview, backup, reset, and export copy | Physical workflow review |
| JSON and CSV export | Yes | Implemented with typed JSON and CSV hash manifest | Larger golden-schema corpus |
| HTML, PDF, hashes, coverage export | No/partial | HTML, hashes, provenance, and coverage implemented; PDF pending | Rendered HTML and PDF implementation |
| Redacted diagnostics | Yes | Scaffolded | Privacy corpus tests |
| Dark/light/accessibility | Partial | Native system behavior | UI automation and VoiceOver review |

## Dependencies and licensing

| Dependency | Purpose | Distribution | License/terms action |
|---|---|---|---|
| Swift, SwiftUI, AppKit, CoreDevice command-line tools | Native app and Apple device discovery | macOS/Xcode | Apple platform terms; do not redistribute private frameworks |
| `rvictl` | Apple RVI lifecycle | Apple device-support installation | Resolve at runtime; do not bundle |
| `tcpdump` | Packet capture | macOS | Resolve at runtime; show version in provenance |
| Wireshark `tshark` | Packet decoding | User-installed Wireshark | GPL-2.0-or-later external executable; do not copy into the app without a distribution review |
| Optional MaxMind-compatible `.mmdb` | Offline location/ASN enrichment | User-supplied local database | Record database name/version/license; never commit it |
| XcodeGen | Reproducible project generation during development | Development only | MIT; generated `.xcodeproj` is checked in |

The native app target has no third-party linked runtime package in the first milestone.

## Threat and privacy model

Protected assets include capture contents, endpoint and hostname inventories, device identifiers, private paths, baselines, reports, authorization state, and capture provenance. Relevant threats include accidental Git publication, unintended capture of unrelated interfaces, privilege expansion, command injection through paths or identifiers, active lookup disclosure, stale RVI interfaces, corrupted/truncated output, and conclusions that overstate evidence.

Controls are local-only storage, ignored evidence extensions/directories, structured arguments, fixed executable paths, one selected source, bounded capture, native authorization, preflight and postflight validation, RVI cleanup verification, SHA-256 provenance, hidden identifiers, redacted diagnostics, opt-in active enrichment, read-only baseline comparison, and explicit coverage/limitation labels. Packet data, IPs, hostnames, UDIDs, diagnostics, baselines, and reports must never leave the Mac without a separate user-authorized export or upload action.

## Milestones

1. **Foundation:** native Xcode project, workflow UI, CoreDevice discovery, setup checks, interface inventory, evidence contracts, and tests.
2. **Capture lifecycle:** authorization, RVI creation, packet preflight/retry, exact timing, progress, SIGINT flush, validation, hash, cleanup, completion card, cancellation, disconnect handling, and app-termination recovery.
3. **Analysis parity:** typed TShark adapter, Python report parity, endpoint/port explanations, hostname provenance, local enrichment, and coverage reporting.
4. **Baseline and exports:** New/Known/Changed/Removed comparison, review-before-update, recoverable reset, JSON/CSV/HTML, hashes, provenance, and limitations are implemented; optional PDF remains pending.
5. **Extended protocols and capture modes:** protocol fixture matrix, host/specific/multi-interface evidence files, and time alignment without silent capture expansion.
6. **Release qualification:** accessibility, dark/light mode, large/corrupt capture behavior, memory profiling, signed/notarized build, screenshots, and a real-device test matrix. The Python edition continues as a separate application.

## Risks

- Apple command output and RVI behavior can change between macOS/Xcode/device OS releases.
- Authorization and process lifecycle bugs can leave a capture running or an RVI orphaned.
- TShark fields vary by version and protocol visibility; absent fields must not be treated as absent behavior.
- Large captures can exhaust memory if decoding is not streamed.
- Active enrichment can create new evidence and disclose investigated addresses.
- iOS process and internal-interface attribution are normally unavailable from RVI alone.
- A valid capture can coexist with a cleanup failure; collapsing both into one status can destroy useful evidence or mislead the user.

## Acceptance criteria

The native macOS remake is release-ready only when all required parity rows are implemented; automated tests cover discovery, readiness, authorization, RVI lifecycle, preflight, timing, cancellation, disconnect, flush, validation, baselines, provenance, redaction, accessibility, corrupt inputs, and large captures; signed builds pass on every supported macOS release; real authorized iPhone and iPad captures validate PCAP and PCAPNG outputs; privacy review confirms no implicit uploads or active lookups; and the UI never overstates process, hostname, protocol, or interface evidence. Reaching these criteria does not remove or replace the Python edition.

## Build and test

Generate the checked-in Xcode project after changing `project.yml`:

```bash
xcodegen generate
```

Build and test without signing:

```bash
xcodebuild -project RVISentinel.xcodeproj -scheme RVISentinel -configuration Debug -derivedDataPath DerivedData CODE_SIGNING_ALLOWED=NO build test
```

The generated app is under `DerivedData/Build/Products/Debug/RVI-Sentinel.app`. Do not add real captures, reports, baselines, device identifiers, or local GeoIP databases to this directory or to Git.
