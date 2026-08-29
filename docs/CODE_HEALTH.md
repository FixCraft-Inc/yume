# YUME code health and remediation register

Status: the audited remediation set is implemented in the current source;
this remains the active public engineering register for the
`0.2.0-dev6` development line. It records code-health findings that affect the
supported native YUME tree. It is intentionally tracked with the source; it is
not an agent note, private qualification artifact, or substitute for release
gates.

The audit baseline was signed commit
`7f1bf8a30fb6fb579b83103cd0dd044344cfe3f6`. At that point the overall grade
was **B (7.5/10)**: strong pre-release protocol engineering, but not
release-ready. A resolved row below means the current source contains a fix
and a focused regression path. It does not transfer old build evidence to a
new commit or waive the matrix in `YUME_2_0_STABILIZATION.md`.

## Remediation register

| ID | Severity | Area | State | Required outcome |
| --- | --- | --- | --- | --- |
| YH-001 | High | Debian daemon startability | Resolved | The installed configuration, service preconditions, and operator instructions name both protected 32-byte secret files and a live loopback cover backend. |
| YH-002 | Medium | Operator signing keys | Resolved | Anonym CA and delegated private keys use the bounded, descriptor-bound, no-follow, owner-only loader and are wiped after parsing. |
| YH-003 | Medium | History authentication failure | Resolved | The default relay-history path delegates explicit-nonce ChaCha20-Poly1305 to BaseFWX, whose owned decrypt stages plaintext in wiping storage until tag verification. The `YUME_USE_BASEFWX=OFF` fallback retains an armed wipe, finalization slack, bounded output accounting, and exact authenticated-length enforcement. A fixed pre-migration record proves byte identity and old-record decode. |
| YH-004 | Medium | C ABI stream-open cleanup | Resolved with a coverage gap | Reservation, callback registration, remotely visible OPEN, acceptance, and C-handle publication are covered by one no-throw rollback transaction, and registration failure is checked. Injected state-machine failures prove the phase-to-action mapping and exactly-once guard behavior; execution against a live tunnel and reservation reuse after rollback remain untested. |
| YH-005 | Medium | Anonym refresh lifetime | Resolved | One operator-proof runtime owns the mutex, condition variable, and `std::jthread`; it is constructed after `Manager`, requests stop, wakes its wait, and joins before manager destruction on every stack-unwind path. |
| YH-006 | Medium, static-Linux only | Curl proof transport | Resolved | The optional fallback opens an absolute, verified curl executable without following symlinks and executes that descriptor directly: no shell or `PATH` lookup. Credentials and request policy live in a mode-0600 config under mode 0700; only its path enters `argv`. The child receives null stdin, a minimal environment, and no unrelated daemon descriptors. Output is bounded to 1 MiB. |
| YH-007 | Medium | Crypto ownership documentation | Resolved | Architecture prose distinguishes BaseFWX-owned default primitives from the BaseFWX-disabled compatibility fallback and remaining YUME-local helpers. |
| YH-008 | Medium | Installed documentation | Resolved | The installed tree contains the documentation map, control API, protocol documents, stabilization gates, and their relative-link targets. |
| YH-009 | Medium | CLI help/manual consistency | Resolved for audited options | Client cluster, packet-TUN, benchmark/evidence, and TLS-name options plus server admin-store/key-enrolment options appear in both help and man pages. |
| YH-010 | Low/medium | Status and website chronology | Partial | Current versus historical native-TLS text is labelled explicitly, and recursive installed publication preserves the protocol/document hierarchy. Broader website and historical chronology consolidation remains open. |
| YH-011 | Low/medium | Coordinator seams and dead crypto surface | Resolved for the audited set | Five uncalled crypto helpers are removed after exact reference checks. Argument parsing, local attach, AUTH commit, TCP/UDP open classification, write settlement, control-request bounds, and server worker/proof lifetime now have explicit seams. Shared dial/tunnel/AUTH ownership is neutral under `src/outbound/`, with no server-to-CLI production dependency. Further decomposition requires a demonstrated invariant or test seam rather than a line-count threshold. |
| YH-012 | High | Operator-proof HTTPS | Resolved | Both proof transports share a strict HTTPS endpoint grammar. The in-process path binds certificate verification to the DNS name or IP literal, enforces one 30-second resolve/connect/handshake/write/read deadline, constructs HTTP with Beast, and limits response headers to 64 KiB and bodies to 1 MiB. Bearer-token controls, URI credentials/fragments, ambiguous IPv6, and invalid ports fail before network use. Remote proof JSON must be an object with a bounded string signature; API-supplied error text is never reflected into daemon errors. |

## Current strengths to preserve

- AUTH v2 parsing is bounded, canonical, and fail-closed.
- Ratchet derivations use versioned HKDF domains, and AES-GCM AAD binds the
  transport profile, direction, epoch, sequence, frame type, stream ID, and
  flags.
- Replay, nonce, epoch, queue, history, and record limits are explicit.
- Live KEM/X25519 secret ownership is generally move-only and wiping; missing
  PQ support and unrequested embedded-master use fail closed.
- The C ABI contains exceptions and keeps its 43-symbol header, map, Debian,
  test, and documentation surfaces synchronized.
- Federation remains direct and single-hop. No remediation item here relaxes
  its identity, hop, trust, or egress fences.

## Grade boundary

The baseline component grades were security architecture **B+**, C++
correctness/resource safety **B**, test/build discipline **B+**, documentation
and contracts **B**, packaging/operational readiness **C+**, and
maintainability **B-**. YH-001 must be validated through an installed binary
package before packaging can move out of the C range. An A-range overall grade
still requires closing YH-004's live-tunnel rollback coverage gap, a
sanitizer matrix, the remaining
platform/consumer gates, and independent cryptographic/deployment review.

## Candidate validation evidence

The reviewed candidate was configured as portable `RelWithDebInfo` with pinned
patched OpenSSL 3.5.7, first-party warnings as errors, tests, and the shared C
ABI. The focused security/ABI set passed 10/10: protected relay persistence,
protected private files, curl child isolation, the stream-open transaction,
ABI runtime, real service-stream integration, exports, header/map agreement,
Debian symbols, and an installed C consumer.

The curl regression proves the shared endpoint parser rejects credentials,
fragments, controls, invalid ports, and ambiguous IPv6, while valid DNS and
bracketed-IPv6 authorities remain stable. It also proves bearer and proxy
secrets are absent from `argv`,
ambient proxy variables and unrelated parent descriptors do not reach the
child, request files are mode 0600 under mode 0700, CR/LF injection is
rejected, unsafe executable permissions are rejected, and success plus forced
child failure remove all request paths. The full build exercises the
in-process Beast transport with warnings as errors; external certificate and
deadline behavior remain integration gates. The transaction test proves
exactly-once phase-to-action selection; it still does not invoke real tunnel
rollback or prove reservation reuse.

This evidence is not a release-candidate claim. Sanitizers, a binary Debian
startup, external proof-service behavior, WAN, soak, GUI behavior, Android,
cross-platform, release, and independent-review gates remain separate.

## Validation rule

Run the smallest focused regression first, then the candidate matrix
proportionate to the touched boundary. A stale build is diagnostic only. Every
result must identify its exact source commit/tree and end with
`git diff --check`; external browser, WAN, soak, Android, GUI-behavior, and
independent-review gaps remain explicit until separately closed.
