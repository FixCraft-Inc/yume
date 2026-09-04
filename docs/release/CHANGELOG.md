# Changelog

## [Unreleased 0.3.0-dev1]

The product version moved to `0.3.0-dev1`. The runnable `yume` and `yumed`
binaries keep speaking the transport-v2 wire `0.2.0-dev6` recorded in the next
section; the wire, AUTH, relay, YTP/1, schema, ABI, and evidence-profile
versions are independent axes. `docs/IMPLEMENTATION_STATUS.md` is the current
boundary for what the 0.3 foundation implements, tests, and still gates.

### Added

- **YTP/1 replacement foundation.** Dependency-pure engine and protocol
  kernel, numeric config schema 1, the role-neutral C ABI v1 candidate with a
  transport-v2 backend that carries authenticated named byte streams, and the
  opt-in TLS 1.3, HTTP/2 duplex carrier, hybrid session-security, and Asio
  byte-channel provider candidates. None of it is a live YTP/1 endpoint.
- **Own liboqs dependency edge.** YUME's ML-KEM key generation in
  `core/security/inner_crypto.cpp` links liboqs through YUME's own CMake
  discovery (`yume_liboqs`, `YUME_HAS_OQS`) instead of inheriting it from the
  BaseFWX build. `YUME_REQUIRE_OQS` fails configuration when liboqs is
  missing.
- **libFuzzer harnesses for the untrusted parsers.** `YUME_BUILD_FUZZERS`
  (Clang-only, never installed) builds `yume_fuzz_h2_probe_decoder`,
  `yume_fuzz_client_config`, and `yume_fuzz_server_config`. Each asserts that
  its parser rejects malformed input rather than throwing, because the H2
  probe decoder runs on an Asio worker where an escaping exception does not
  reach the session. `tests/fuzz/run_fuzzers.sh` seeds the corpora, enforces a
  per-target budget, and fails on any artifact, so CI, a build host and a local
  run are the same invocation. `docs/DIAGNOSTICS.md` records it.
- **ThreadSanitizer and fuzzing are CI gates.** A `thread-sanitize` job builds
  with `YUME_SANITIZE=thread` and runs the full suite, and a `fuzz` job builds
  the Clang harnesses and runs each briefly against the seeded corpus. Neither
  had ever run automatically, so a data race or a parser crash could reach
  `main` with nothing objecting.

### Changed

- **Client configuration keys are a closed set.** The `yume` CLI parser and
  the facade parser used by the GUI and the C ABI share one key table in
  `src/config/client_document_keys.hpp`. An unknown key is an error, a
  retired key names its replacement, and integral fields reject values they
  cannot represent instead of wrapping. Both parsers previously ignored
  unknown keys, so a misspelled `tls_pin` silently disabled pinning.
- **Obfuscation jitter and worker threads are bounded.** `obfs_jitter_ms`
  and `threads` were only checked for representability, so a config could
  ask for roughly 49 days of delay on every outbound frame or a thread
  count that exhausts the process limit at start. Both parsers now
  enforce `policy::kMaxObfsJitterMs` and `policy::kMaxIoThreads`.
- **Inline `obfs_secret` is refused at parse time.** The client and server
  configuration fields that carried an inline admission secret were rejected
  at start since transport v2; the field and its plumbing are gone and every
  parser now rejects the key with the file-based replacement named.
- **Server teardown always joins its workers.** `RuntimeController::stop()`
  contains a throwing runtime or manager stop, joins every worker, and
  reports the contained failure in the status message. Previously a throw
  between the move and the join would destroy a joinable thread and
  terminate the process, including from the destructor.
- **A cancelled endpoint start reaches `STOPPED`.** The C ABI no longer
  strands a handle in `STARTING` when a runtime stop races a start; the
  endpoint moves to `STOPPED` and emits a `CANCELLED` event.
- **Registration shape and H2 regression test renamed.** The only control
  registration format the client sends was called "legacy"; it is now
  `ControlRegistration`, and the retained transport-v2 H2 regression test is
  `yume_transport_v2_h2_regression_test`.
- **Share-file KDF label is pinned.** New `.yss` share files always request
  Argon2id explicitly, so the `BASEFWX_USER_KDF` environment variable can no
  longer downgrade them to PBKDF2 or fail encoding with an unsupported label.
  Existing files are read from their serialized label as before.
- **Manual pages and front-door documents name the product version.** The
  `.TH` headers and the README, documentation map, and status page state
  `0.3.0-dev1` and describe `0.2.0-dev6` only as the transport-v2 wire.
  `tests/test_project_metadata.py` now fails when they drift.
- **Third-party attribution corrected.** The GUI credits page names OpenSSL
  as the ML-DSA-87 provider and the downstream OpenSSL patch overlay, and no
  longer calls BaseFWX the core crypto engine or claims ML-DSA comes from
  liboqs.

- **No built-in cover page, and a cover source is required.** `yumed` shipped a
  redirect stub compiled into the binary. It was byte-identical on every
  deployment, and the HTTP/2 decoy served it whenever only `real_backend` was
  configured, so a single HTTP/2 request identified the server as YUME
  regardless of what the HTTP/1.1 cover backend served. Startup now refuses
  unless one of `upstream_response_dir`, `upstream_response`, `real_root`, or
  `real_index_path` is set alongside `real_backend`, which answers HTTP/1.1
  only. A configured source that disappears at run time yields the profile's
  ordinary 404 rather than a substitute page.
- **Packet-mode DNS has no default.** The resolver was silently `1.1.1.1` when
  none was configured, making a third party the observer of every hostname a
  tunnelled client resolved. `--packet-egress tun` now refuses to start until
  an IPv4 resolver is named.
- **Server configuration keys are a closed set.** The `yumed` CLI loader and
  the facade parser used by the GUI share one key table in
  `src/config/server_document_keys.hpp`, over the same predicate as the client
  set. An unknown key is an error instead of "leave the default", and several
  of those defaults are security decisions.
- **Server `obfs_jitter_ms` and `threads` are bounded.** The server loader
  accepted any representable value, so a config could delay every outbound
  batch by up to roughly 49 days or request an unbounded worker count. Both
  now use `policy::kMaxObfsJitterMs` and `policy::kMaxIoThreads`, matching the
  client.
- **Configuration and start failures are typed.** A failure attributable to
  one member now carries an RFC 6901 JSON pointer in both dialects, malformed
  input is `YUME_STATUS_PARSE_ERROR` and a document that parses but does not
  validate is `YUME_STATUS_INVALID_ARGUMENT`, and `yume_endpoint_start`
  reports the runtime's typed outcome instead of collapsing every failure to
  `YUME_STATUS_IO_ERROR`. A refused bind is now distinguishable from a
  transient failure without parsing the diagnostic text.
- **The release lane is `linux-desktop-0.3.0`.** It accepted only `v0.2.0`
  tags while the product was `0.3.0-dev1`, so it could not ship the tree.
- **The plain `attach` control command is named truthfully.** Its refusal
  called it "legacy" while `admin.attach` is a different operation, not a
  newer generation of the same one.
- **HPACK integers no longer wrap on the unauthenticated carrier probe.**
  `decode_hpack_varint` accumulated shifts and additions without an overflow
  check, so a peer could declare a string length near `2^64` that made
  `decode_hpack_string`'s bounds check wrap and pass, reaching
  `std::string::assign` with that length. The resulting exception escaped
  `Session::on_h2_probe_read` into the Asio worker, which aborts the process
  (see the worker-containment entry below). A wrapped value could also
  resolve to a static-table index the wire never carried. The decoder now
  rejects both operands before evaluating them, compares remaining length by
  subtraction, and bounds the header count and aggregate bytes one block may
  retain. The probe read contains a decoder throw and serves the masquerade
  response. Reachable before authentication.
- **A throwing completion handler no longer aborts the process.** The server
  and client worker threads ran `io_context::run()` as the thread body. An
  exception that escapes a completion handler propagates out of `run()`, and
  an exception that escapes a thread entry point calls `std::terminate`, so
  any peer able to reach a throwing handler could abort the daemon. Both
  workers now go through `runtime::run_worker`, which contains the exception,
  drops only the connection whose handler threw, re-enters `run()` for every
  other session, and records the occurrence in a rate-limited warning.
  Containment is a backstop: a handler at a trust boundary must still reject
  bad input rather than throw.
- **One frame-payload bound, not three.** `server::detail::kMaxFrameSize` was
  a third independent spelling of the same 16 MiB limit on the same header
  field, alongside the outbound constant and a bare literal in the prefetch
  classifier. All three now resolve to `protocol::kMaxFramePayloadBytes`.
- **Control frames are bounded before allocation.** `protocol::read_frame`
  resized the payload to a peer-supplied 32-bit length, so a hostile server
  could ask a client for 4 GiB before anything parsed. The cap now belongs to
  `core/protocol`, which defines the header, and is shared by the synchronous
  reader, the asynchronous transport path, and the prefetch classifier that
  previously repeated the number by hand.
- **The optional TLS fingerprint diagnostic is bounded.** Its HTTP/1.1 fetch
  appended to EOF and its HTTP/2 fetch allocated each peer-declared frame,
  accumulated DATA, and waited for END_STREAM, all without a limit or a
  deadline, so a redirected endpoint could hang or exhaust the client. The
  fetch moved to `core/stealth/tls_verify_fetch.hpp` with total, per-frame,
  and frame-count caps plus a wall-clock deadline, and the socket carries a
  receive timeout. It runs only under `openssl-diagnostic` with
  `tls_fingerprint_verify`.
- **MaxMind record parsing is valid C++.** `MmdbValue` held
  `std::vector<std::pair<std::string, MmdbValue>>`, and `std::pair` does not
  admit an incomplete member type the way `std::vector` admits an incomplete
  element type. GCC accepted it; Clang rejected it, which blocked every
  Clang-based analysis of the server tree. The key now lives on the value and
  the vector holds the element type directly.
- **The vendored nlohmann tree is complete, so CI builds again.**
  `third_party/nlohmann_json/nlohmann/` shipped `json.hpp` but not
  `json_fwd.hpp`. That directory is first on the include path, so
  `config/v1/config.hpp`'s `#include <nlohmann/json_fwd.hpp>` fell through to
  whatever the build host had installed while `json.hpp` came from the bundle.
  A host whose distribution nlohmann matched the bundled 3.11.3 built fine,
  which is why every developer and build-host lane was green while every CI
  lane failed inside the vendored header: Ubuntu 22.04 ships 3.10.5, which
  declares `basic_json` and `json_pointer` differently. An amalgamated
  `json_fwd.hpp`, extracted verbatim from the vendored `json.hpp` so the two
  cannot disagree about the inline namespace they open, now sits beside it.
  Upstream's multi-header `json_fwd.hpp` cannot be used here because it pulls
  `nlohmann/detail/abi_macros.hpp`, which the single-header amalgamation does
  not ship. A metadata test enforces both halves: every `<nlohmann/...>`
  include in the sources is satisfied by the vendored tree, and no vendored
  header includes one that is not. The dependency and its version are
  unchanged, so the notices and SBOM are too.
- **The CI OpenSSL guard counts lanes instead of assuming three.**
  `release_preflight.py` required exactly three occurrences of the
  dependency-setup block and of `-DYUME_STATIC_OPENSSL=ON`. The invariant is
  that *every* lane which configures CMake carries both, so the literal count
  went stale as soon as a lane was added and would also have passed if one
  lane were deleted and another added in its place. It now derives the lane
  count and names the mismatch.
- **A Clang build of the whole tree links again.**
  `yume_anonym_curl_transport_test` used `yume_apply_warnings` where every
  other non-ABI target uses `yume_apply_perf_opts`, so it linked the
  LTO-built `yume_core` without `-flto`. GCC hides that by using the linker
  plugin automatically. Clang does not, and GNU `ld` reported "file format
  not recognized" on a bitcode archive. The ABI targets remain the deliberate
  exception, because their inputs are built without LTO.
- **`yume-packet-quick` examples are valid input.** `--listen` requires a
  numeric IPv4 address, which the helper renders into nftables and UFW rules,
  but the documentation, the parser's own error message, and the test fixtures
  all used a hostname. The test was also never registered, so two failing
  cases passed CI; it now runs in CTest.

### Removed

- **Inline `real_secret` and the `--real-secret` flag.** The cover-backend
  secret could be passed in argv, where the process table exposes it, or
  written into the configuration file. Both server loaders now refuse the key
  and name `real_secret_file`, which is read at start or created with fresh
  random contents.
- **Five unused server configuration aliases.** `allow_monero_rpc`,
  `codec_allow`, `deny_default`, `exposure_check`, and the combined
  `monero_rpc_backend` spelling had no writer and named no consumer. The
  equivalent CLI flags remain, because a flag name and a config key are
  separate surfaces.
- **`docs/release/RELEASE-NOTES-1.1.md`.** It described a stable 1.1 release
  that never happened and was installed into every package. Git history keeps
  it.
- **Unused dependency-manifest parsing in CMake.** The BaseFWX repository and
  revision fields were parsed and never used; `ezbuild.sh` remains the
  enforcement point for the pin.

## [Unreleased 0.2.0-dev6]

Product and transport versions were rebaselined to reflect YUME's experimental
maturity. This transport is a hard break from `0.2.0-dev5`, and dev6 has
one evidence-backed `chrome151-node24-v1` identity. No dev5 compatibility or
downgrade mode exists.

### Added

- **Generated transport-profile registry.** Capture manifests and H2 evidence
  now generate immutable C++ and Go registries consumed through browser-neutral
  API. Bounded schema/path/uniqueness checks and negative metadata tests reject
  stale output or unsafe fixture references. The authenticated dev6 ID and all
  wire/crypto domains remain unchanged.

- **Single-source dependency manifest.** BaseFWX repository, exact revision,
  and minimum compatible version now live in `config/dependencies.json` and are
  consumed by CMake, local build scripts, CI, CodeQL, and release preflight.
  The dependency remains reproducibly pinned; duplicated workflow literals and
  the unsafe CI fallback to a floating branch are removed.

- **Five-run Chrome 151 / Node 24 evidence.** Five fresh normal-Chrome profiles
  cover TLS outcome, ordered H2 settings and headers, page/assets, RFC 8441,
  bidirectional bulk flow control, 42-second idle behavior, and graceful close.
  A committed validator separates stable identity fields from measured timing
  and flow-control distributions.

- **Authenticated transport profile.** Admission HMAC input, schema-3 AUTH
  challenge/response/confirmation records, the signed TLS-exporter transcript,
  initial root, and per-frame AES-GCM AAD now all bind the exact
  `chrome151-node24-v1` identifier. Stale identifiers, schema-2/dev5 records,
  missing fields, and configured profile mismatches fail closed without a
  fallback.

- **Fail-closed Linux 0.2.0 release lane.** The `linux-desktop-0.2.0` profile
  builds only glibc Linux x86-64, statically embeds the checksum-pinned patched
  OpenSSL 3.5.7, and retains the exact-Go-1.26.5 Chrome helper as an optional
  comparison backend. It emits `yume-amd64-linux.tar.xz` with the client/helper,
  licensing, quick-start, and machine manifest, plus a separate
  `yumed-amd64-linux`. The preflight rejects other platforms and variants,
  incomplete bundles, version/tag drift, unequal clean helper rebuilds, or
  relaxed PQ, Argon2, and LZMA requirements. Publishing is disabled by default
  and requires explicit independent-review and RC-gate acknowledgements.

### Changed

- **Experimental version rebaseline.** Product, package, release-profile, and
  authenticated transport identity now use `0.2.0-dev6`; AUTH v2, relay-v2,
  ABI v1, helper IPC v1, and crypto domain schemas remain independently
  versioned. The obsolete `v1.0` tag was withdrawn because it named an
  unstable, incorrect project state.

- **Go helper dependency floor.** The opt-in uTLS helper now requires Go 1.25
  module semantics while retaining the exact Go 1.26.5 build toolchain. Its
  indirect `golang.org/x/crypto` dependency moves from 0.36.0 to 0.52.0 and
  `golang.org/x/sys` from 0.31.0 to 0.45.0, leaving GitHub's reported vulnerable
  module ranges while preserving the pinned uTLS and wire protocol versions.

- **Native OpenSSL ClientHello emitter and helper retention.** The default
  `openssl-chrome151` backend opts into an additive, default-off patch on the
  exact OpenSSL 3.5.7 source. Its emitted-byte gate closes all six pinned
  ClientHello structure rows across 12 SSL objects sharing one context,
  including per-connection GREASE, edge placement, extension shuffling,
  `[0]` point formats, both real key shares, and Brotli-only certificate
  compression. The pinned Go/uTLS helper remains an explicit optional
  comparison backend until the native path passes full handshake, exporter,
  validation, HRR/resumption, lifecycle, soak, same-session, classifier, and
  reproducibility gates. There is no fallback between backends.

- **One coherent identity.** Chrome is rebased to exact Google Chrome
  `151.0.7922.71` and official Node `24.18.0`. The incomplete Firefox/Safari
  presets and dead rotation state were removed instead of being carried as
  unsupported claims. The native ClientHello structure is now closed, but
  complete-session qualification and a capture of the `0x001b` algorithm value
  remain explicit gaps. The helper has passed local wire/performance, lifecycle, process-scale,
  reconnect, and segmented-soak gates but remains opt-in pending matched WAN,
  same-session stealth, independent review, and the remaining RC gates.

- **Bounded TCP producer backpressure.** SOCKS and TCP forwarders now advance
  local reads on transport-write completion, preventing fast producers from
  overflowing the bounded application queue. The benchmark failure path is
  SIGPIPE-safe and always joins its receive workers, so failures are reported
  instead of ending in `std::terminate`.

- **Qualified helper boundary.** The production Go entry point still applies
  Linux-only `no_new_privs` and adopts connected TCP/IPC descriptors 3 and 4,
  while its connection core is injectable for real TLS qualification. Wrong
  CA, hostname, leaf pin, ALPN, and exporter behavior now fail through fixed,
  bounded IPC errors; detailed verification causes stay local. Native launcher
  tests cover unsafe file modes and symlinks, partial control and plaintext I/O,
  post-ready half-close/cancellation, child teardown, and repeated fd/zombie
  balance. Connection IDs use the BaseFWX RNG abstraction; the explicit
  no-BaseFWX build retains the YUME CSPRNG fallback.

- **Bounded Linux process and soak qualification.** At the exact clean signed
  lifecycle checkpoint, the 1/10/50/100/256-client Chrome-helper ramps
  completed with exact bytes and zero unexpected failures. The 256-client run
  held 256 clients plus 256 helpers concurrently and transferred 65,536 MiB.
  A 1,000/1,000 sequential reconnect storm transferred 2,000 MiB with no
  helper, zombie, fd, or thread growth. A 2,333-second full-speed batch moved
  112,640 MiB per direction at 816.607 Mbit/s aggregate with zero byte mismatch,
  timeout, interruption, or unexpected server error. The soak used seven
  consecutive segments to preserve the signed endpoint's 16,384 MiB
  per-invocation bound; it does not claim one uninterrupted >16 GiB connection
  or WAN behavior.

### Fixed

- **Core receive backpressure and bounded queues.** Both H2 roles transfer
  move-only receive-credit ownership through ordinary TCP, UDP, service,
  codec, packet, forwarding, and federation sinks. Slow consumers plateau and
  resume without automatic credit. Cover requests, pre-auth serialized wire,
  service writes, packet batches, and client UDP paths have independent bounded
  admission, cancellation, shutdown wakeup, and recovery behavior.

- **Strict peer-controlled schemas and stream ownership.** Generic OPEN,
  client SOPEN/ROPEN, CONTROL registration/lifecycle, relay, codec, and auth
  metadata reject unknown fields, wrong scalar types, over-length strings, and
  invalid ranges without escaping the session boundary. Client and server
  stream IDs reserve atomically through map publication; collisions never
  replace local, pending, control, federated, or retired owners.

- **Durable configuration and authorization snapshots.** Client/server config
  saves use owner-only temporary files and durable atomic replacement on the
  qualified POSIX path. Authorization-key and metadata operations share
  canonical persistent sidecar locks; daemon startup/reload parses one locked
  five-resource visitor/operator/admin snapshot before publishing it. ABI
  config/lifecycle/stream/packet outcomes now derive from typed internal
  statuses rather than diagnostic strings.

- **Relay and listener lifecycle hardening.** Relay v2 binds composite peer
  identity, hybrid ML-KEM-1024/X25519 establishment, ratchet state, record
  counters, invite lifetimes, target policy, and trust persistence. Outbound
  files are hashed and streamed from one pinned regular-file descriptor, and
  POSIX receive publication is confined, no-clobber, bounded, and atomic.
  Federation duplicate peer IDs and reverse-listener accept ownership now fail
  without orphaning links, retaining sessions, or spinning cancellation paths.

- **EXEC fail-closed cleanup.** Direct and relayed command execution remain
  unavailable regardless of reserved policy fields or build option. Clients do
  not advertise or enable inbound EXEC, and the former detached worker is
  removed pending a cancellable, joinable, sandboxed design.

- **Exceptional-path key lifetime.** Superseded inner keys, AUTH transcripts,
  relay pending/KDF/channel state, ratchet roots/message keys, PSKs, exporters,
  and raw shared secrets are scoped or explicitly wiped across failure, throw,
  close, and teardown paths covered by the stabilization tests.

- **Sanitized ABI integration.** Linux address-sanitizer builds resolve the
  selected compiler's ASan and C++ runtimes and preload them in loader order
  for the Python/ctypes strict-C integration orchestrator. Instrumented
  `libyume` is therefore never loaded late into an unsanitized Python process,
  and the sanitizer suite does not depend on an undocumented caller
  environment.

- **Parallel federation fixture isolation.** The real two-node federation
  integration gives each daemon the fixture's private HOME and XDG runtime,
  matching its client. Independent build matrices no longer contend for one
  user-level daemon instance lock when their federation tests overlap.

- **GUI facade synchronization boundary.** Client status now exposes the
  configured security mode, composite/hybrid-ratchet posture, TLS backend,
  rekey window, peer fingerprint, and capabilities rather than obsolete
  light/heavy/off state. Chat open/send/close/history honor real channel and
  peer identities, and the unused callback promises are removed. Log
  subscribers run outside the sink lock with exception containment; the GUI
  resolver is owned through shutdown; and macOS bundle versions derive from
  the project version.

- **Hardened BaseFWX dependency pin.** The pinned BaseFWX revision is now
  `e6ffbb79daa02bf62c31c3ae6513d5c603ec8dcd`. It retains repeat-safe Argon2
  discovery, fail-closed crypto/format limits, safer caller-buffer primitives,
  peer KDF policy coverage, and corrected Java streaming-test nonce discipline.
  It also supplies the owned explicit-nonce ChaCha20-Poly1305 operation used by
  YUME's existing relay-history format, propagates Java benchmark worker
  failures, bounds whole-file benchmark concurrency, and defaults retired
  compatibility performance rows off. YUME's consumed wire contracts are
  unchanged.

- **Bounded operator-proof HTTPS.** External proof URLs now use one strict
  HTTPS authority/target grammar across the in-process and static-Linux curl
  transports. The native path verifies the configured DNS name or IP literal,
  applies a 30-second end-to-end request deadline, constructs and parses HTTP
  with bounded Beast messages, and rejects bearer-token controls before any
  connection is attempted. Remote responses require an object containing a
  bounded canonical signature; untrusted API error text is not reflected into
  daemon errors.

- **Helper crash and truncation lifecycle.** After `posix_spawn`, the parent
  retained duplicate copies of the child-side IPC and connected TCP
  descriptors. Those copies masked EOF/HUP when a helper crashed or returned a
  truncated response, delaying failure until the handshake timeout and keeping
  the TCP peer open. The parent now closes both duplicates immediately after a
  successful spawn while preserving RAII cleanup on every failure path.

### Remaining dev6 limitations

- `openssl-chrome151` is the development default and runs without the helper;
  this is not a release-qualification claim. Matched WAN evidence, one
  uninterrupted >16 GiB connection, exact Chrome
  `151.0.7922.71` same-session recapture, external classifier/active-probe
  evidence, and independent security review remain release gates. Installed
  Chrome `151.0.7922.108` is functional-only evidence and does not replace or
  rewrite the dev6 fixture. Android, GUI, Windows, macOS, ARM, OpenWRT, static
  builds, and Debian archive publication are outside the first official 0.2.0
  scope.

## [Unreleased 0.2.0-dev5]

Hard break from `0.2.0-dev4`: AUTH now carries each endpoint's accepted ratchet
policy. Exact version equality rejects mixed dev4/dev5 peers; no compatibility
mode exists.

### Added

- **Authenticated security modes.** Extreme preserves the dev4 default
  (256 KiB, 512 application frames, 500 ms sender-active). Normal uses 8 GiB,
  262,144 frames, and 60 seconds. Soft uses 256 GiB, 8,388,608 frames, and
  30 minutes. Ultimate accepts exact bounded JSON values, including arbitrary
  millisecond values such as 4281. Each direction uses the component-wise
  stricter local/peer policy. ML-KEM-1024, X25519, the random PSK, HKDF labels,
  AES-GCM/AAD, and one-use per-frame keys are unchanged.
  Challenge critical field 8 carries the server policy; response critical
  field 5 carries the client policy and moves the Ed25519 signature to field 6.
- **Current BaseFWX 3.8 development pin.** YUME now pins remotely reachable
  BaseFWX commit `4692d4ce4edec2aa9835d04ad9ff6c3ad3ab9374`; the consumed crypto APIs and
  wire contracts are unchanged from the prior pin.

## [Unreleased 0.2.0-dev4]

Hard break from `0.2.0-dev2` and `0.2.0-dev3`: the exact transport version changed,
so dev2, dev3, and dev4 binaries do not interoperate at admission or AUTH. No
compatibility mode exists or is planned.

### Added

- **TLS-exporter channel binding for AUTH.** The Ed25519 signature input and
  the establishment root now cover a 32-byte RFC 8446 section 7.5 exporter
  (`EXPORTER-yume/2.0/auth-channel-binding/v1`) that each endpoint derives from
  its own live TLS object and never transmits. A malicious endpoint that
  terminates TLS with a client and holds compatible admission and inner PSK
  material can no longer forward that live AUTH exchange to a second server:
  the two connections have independent exporters, so the relayed signature does
  not verify at the far end. Both peers require TLS 1.3 and a finished
  handshake; a peer that cannot produce a 32-byte binding fails AUTH. There is
  no unbound mode to negotiate. The signature domain moves to
  `yume/2.0/auth-signature/v2` and the root label to `yume/2.0/root/v2`, so a
  dev3 peer fails loudly instead of downgrading.

- **Bounded multi-epoch ratchet window.** A direction may keep several
  authenticated, strictly contiguous future epochs in flight or prepared
  instead of one, negotiated per connection through the AUTH transcript and
  configured with `--rekey-window` / `rekey_window` (1..64, default 8). A
  byte-saturated direction rises from 256 KiB to `window * 256 KiB` per rekey
  round trip: roughly 35 Mbit/s to 280 Mbit/s at 60 ms RTT by the protocol
  model. Every per-epoch limit is unchanged — 256 KiB, 512 application frames,
  500 ms of activity — and the receiver still enforces the byte and frame
  limits on authenticated plaintext. Gaps, duplicates, reordered ACKs, and
  offers past the advertised depth stay fatal. Offers are paced by application
  progress so a filling window does not emit a burst of rekey records. The
  public implementation status records what remains unmeasured.

### Changed

- **Stealth and cryptographic claims now match the implementation.** One
  immutable Chrome 151/Debian 13 + Node 24 profile supplies the production TLS
  selection, User-Agent/client hints, capture-backed H2 opening, assets, and
  cover identity. Profile rotation remains rejected. Chrome/BoringSSL TLS
  parity and traffic padding remain evidence-driven work, and the 500 ms
  ratchet limit is sender-active rather than a twice-per-second wall-clock
  promise.
- **The untrusted-server boundary is explicit.** Client AUTH sends a public
  Ed25519 identity plus transcript signature, not the private key; ephemeral
  hybrid exchanges provide conditional forward secrecy against later
  persistent-file compromise. `yumed` remains the terminating single-hop proxy
  with access to decrypted YUME stream bytes. AUTH is now TLS-exporter-bound,
  so live forwarding by a malicious compatible endpoint is closed, but that
  does not make the terminating node blind to traffic it exits.
- **Client identity files are owner-only by contract.** `--keys-gen`
  serializes to memory and creates both halves through the exclusive
  owner-only writer at mode `0600`, wipes the private PEM, and refuses to
  replace an existing path instead of silently overwriting an identity.
  Loading reads the private key through an already-validated descriptor and
  rejects symlinks, foreign ownership, group/world permission bits, and
  out-of-range sizes, so a poorly protected key can no longer sign an AUTH
  transcript. Enforcement is Linux/POSIX; Windows identity loading fails
  closed.
- **AUTH v2 records carry the negotiated window.** The challenge gains critical
  field 7 and the response gains critical field 4, moving the Ed25519 signature
  to field 5. The client's advertised depth is inside the signed record, so the
  negotiation is covered by the existing transcript signature.
- **An acknowledged epoch is prepared, not entered.** A direction advances when
  the current epoch can no longer carry the next application frame, so each
  prepared epoch delivers its whole byte budget.

### Fixed

- **Rekey ACKs are sealed in wire order.** `SessionRatchet::Open` used to seal
  the REKEY_ACK on the read path. A directional chain assigns sequence numbers
  at seal time, so a data frame sealed afterwards on the write path could reach
  the wire first and the peer would close the session with "replay or
  unexpected epoch/sequence". `OpenResult::control_response` is now plaintext
  and is sealed by the caller's ordered write path like any other frame. The
  defect predates the window but was only reachable in practice with several
  exchanges outstanding.
- **Federation link stream ownership.** The dialing loop's TLS stream is now
  heap-owned and shared with the write path by a counted reference instead of a
  pointer into the loop's stack frame. The lifetime was already guarded, but a
  counted reference removes the class of defect entirely.

## [Unreleased 0.2.0-dev2]

Dev2 was the first hard-break 2.0 desktop transport line. It was superseded by
dev3 before release; neither development version is a stable release.

### Added

- **Bounded server capacity controls.** Administrators can set worker threads,
  aggregate tracked sessions, default bulk-key sessions, aggregate accepts per
  second, and an optional weighted-fair egress cap. Default tracked and bulk
  limits are 256 and 64 respectively; unlimited behavior must be explicit.
- **Regular individual/bulk keys and a physical operator trust store.** Shared
  bulk credentials are separately counted per connection and cannot receive
  controller, exec, LAN/full-control, privileged codec/service, or federation
  policy. Only individual keys in the separate operator store may receive
  outbound admin policy.
- **External benchmark resource telemetry.** Localhost, LAN, and WAN harnesses
  can sample server/client CPU time, fair per-core CPU, RSS/peak RSS, threads,
  and host CPU/RAM context. Multi-client runs are bounded by default and require
  explicit acknowledgement above the safe local ceiling.

### Changed

- **Directional rekeys are pipelined without widening their blast radius.**
  Each sender prepares the next authenticated ML-KEM-1024 + X25519 + PSK epoch
  while bounded current-epoch traffic remains. The existing 256 KiB, 512-frame,
  and 500 ms limits remain independently enforced; writes block only if the
  ACK has not arrived at the hard boundary. Exact version equality rejects
  dev1 peers rather than silently mixing the two scheduling contracts.

- **AUTH policy lookup uses immutable snapshots.** Regular and operator
  key/policy files are parsed and validated before atomic startup/reload
  publication. Failed reloads preserve the complete previous snapshot, and the
  same public key cannot appear in both stores.
- **Capacity logic is modular.** Thread-safe identity admission and weighted
  egress controllers are independent server runtime units with focused tests.
  The optional limiter is not constructed when egress shaping is disabled.
- **Developer timing is centralized and absent from production binaries.**
  Debug/RelWithDebInfo builds share stopwatches, batched samples, asynchronous
  intervals, and event macros across connection, AUTH, ratchet, scheduler,
  TLS, H2, and WebSocket boundaries. Runtime collection remains opt-in.
  Release/MinSizeRel preprocess the hooks and detail construction away, while
  `/proc` resource sampling remains external to the measured processes.

### Security

- Authentication remains Ed25519 over the canonical transcript, and admission
  still occurs before ML-KEM decapsulation. Rekey pipelining does not change
  AEAD AAD, HKDF labels, hybrid secret composition, or directional usage
  limits. The dev2 version bump deliberately changes when the existing rekey
  records are scheduled and accepted.

## [Unreleased 1.1 historical work]

Target: `v1.1`. Do not tag until the remaining release work and remote
validation are complete.

### Added
- **Static-site masquerade cover (`--real-root <dir>`).** yumed serves GET/HEAD
  for real files under one root with correct MIME, `Content-Length`,
  `Last-Modified`, nginx-style `ETag`, and `Accept-Ranges`, so the decoy is a
  coherent multi-asset site instead of "`/` => 200, everything else => 404".
  Path resolution rejects traversal, encoded-slash/backslash, control bytes,
  over-length targets, and symlink escape (canonicalized against the root); a
  per-response size cap bounds one cover reply. The same root/index backs both
  the HTTP/1.1 probe and the H2 decoy, with HTTP/1.1 keep-alive across a page's
  assets (bodyless GET/HEAD only, bounded by a per-connection request cap and an
  idle timeout), conditional GET (`If-None-Match`/`If-Modified-Since` -> 304),
  and byte `Range` requests (-> 206 Partial Content, or 416 when unsatisfiable).
  Implies `--real`; pair with `--hide-in-the-crowd nginx` for the closest header
  fit.

### Changed
- **License**: YUME source, apps, daemon, proxy, GUI, and libyume are
  AGPL-3.0-or-later. Build scripts and CMake entry points now carry
  matching source headers.
- **Masquerade is now the active-probe boundary.** `--public-node` requires
  obfs plus a nonempty shared secret. Missing, malformed, wrong-key, bad-order,
  or SNI/authority/listener-port-mismatched H2 admission stays outside AUTH.
  Empty-secret structural admission remains development-only.
- **The H2 opening is standards-oriented, not exact-browser branding.** HPACK
  indexes, SETTINGS/ACK ordering, END_STREAM behavior, authority validation,
  mandatory client ACK of server settings, serialized fallback writes, and
  client decoy classification were corrected. Synthetic web profiles are not
  native nginx/Apache/etc. implementations.
- **TLS profile rotation now advances after successful connections.** The
  carrier User-Agent follows the active profile unless explicitly overridden.

### Fixed
- **Preauth privilege promotion.** Self-signed peers admitted for configured
  named services now persist as `PreauthServiceOnly`; a central gate confines
  them to service.v1 OPEN/DATA/CLOSE and PING/PONG.
- **Caller-blind admin attach.** Modern and legacy paths now share the trusted
  relay + caller outbound + target inbound authorization predicate.
- **Bounded shutdown and queues.** Added a five-second session-close deadline,
  64-per-service/256-total pending service limits, four-worker client EXEC cap,
  and best-effort sensitive-buffer erasure. Sanitizer and soak validation remain
  outstanding; detached EXEC workers are bounded but not cancellable/joined.

## [v1.1] - TBD

### Added
- **`--cluster-join <spec>`** + **`--cluster-bootstrap`** on `yumed`. Friendly shorthand over the existing `--peer '<json>'` federation surface: `--cluster-join [id@]host[:port][?pin=<sha256>]` parses into the same FederationPeer JSON the daemon already consumes. `--cluster-bootstrap` marks a node as a cluster entry point so federation works without an outbound peer list. Bracketed IPv6 is supported with an explicit valid `id@` prefix. Implies `--federation-enable`.
- **`--cluster <host[:port]>`** on `yume` (client) as a friendly alias for `--server` + `--port`.
- **`--public-node`** on `yumed`: hardening preset for internet-facing daemons. Rejects `--allow-exec` / `--allow-local-ip` / `--control-full` / `--no-inner` / `--no-obfs`, requires `--auth-keys` and a nonempty `--obfs-secret`, defaults `--hide-in-the-crowd` to `nginx`, and applies bounded session/Argon2 defaults.
- **`--hide-in-the-crowd <profile>`** on both binaries: HTTP-layer disguise. Server profiles (`nginx`, `nginx-stable`, `apache`, `caddy`, `cloudflare`, `express`, `gunicorn`, `none`, `yumed`) are synthetic templates with profile-specific header order, charset, extras, and body shapes; they are not native server implementations. Client profiles (`chrome`, `firefox`, `safari`, `edge`, `curl`, `wget`, `yume`) set the User-Agent in stealth probes; when unspecified, the UA follows the active TLS preset.
- **Profile-driven disguise on every non-YUME probe.** Pre-1.0 yumed closed the connection on HTTP probes when `--real` wasn't set — TLS-handshake-then-immediate-close is a textbook DPI signal. Now serves a profile-matching 404 even without `--real`, by routing through `Session::send_disguise_404`.
- **`yume-net-map`** new read-only CLI tool: connects to a yumed admin socket and renders the current node + its federation peers as an ASCII fan/spoke diagram (Unicode box-drawing or `--ascii` fallback). `--json` mode for downstream tooling. Auto-discovers local sockets under `$XDG_RUNTIME_DIR/yume`, `/run/yume`, `/tmp/yume`.
- **`scripts/yume_disguise_check.py`** automated profile-fidelity test: spins up yumed once per profile, probes with curl, validates Server header regex / extra headers / body length range / canonical body substrings. `--dpi` mode adds nDPI flow classification (needs `tcpdump` capability and `libndpi-bin`). CI-runnable in <60 s.
- **`scripts/yume_bench_wan.py`** virtual-WAN benchmark with DPI comparison: two `ip netns` connected by a veth + tc-netem WAN profile, runs the same workload over yume and as a curl/chromium baseline, runs `ndpiReader` on captured pcaps, emits a side-by-side report (markdown or JSON).
- **Native embed C ABI in `libyume.so.1`.** `include/yume/yume.h` now exposes opaque `yume_client`, `yume_server`, and `yume_stream` handles, JSON lifecycle/status helpers, fixed-buffer last-error reporting, and direct named service stream read/write calls for C/C++ embedders.
- **Authenticated named service streams.** Clients can open project-neutral `proto: "service.v1"` streams such as `example-service-v1`; servers must explicitly enable the application-defined service in config, authorize it per key with `allow_services`, and register it through the C ABI before accepts are queued.
- **Stream peer metadata in the native ABI.** `yume_stream_peer_json` exposes the accepted stream's service, authenticated Ed25519 SPKI SHA-256 fingerprint, peer/session ids, and remote address so embedders can bind sessions to their own device registry.
- **Embed JSON bind address support.** `yume_server_start_json` accepts `listen_address` with `listen_port`, allowing loopback-only native tests and embedded local services without a wildcard bind.

### Changed

> **Browser profiles:** The withdrawn v1.0 test-release block below documents the TLS profiles shipped at 1.0. Current builds use the bumped versions listed in this section.

- **Historical release line moved to 1.1.** At the time, the now-withdrawn
  `v1.0` tag named the first test release and the tree targeted `1.1` as its
  first stable line.
- **BaseFWX pin currently names legacy-history 3.7.0 commit** `ddf31617aab6bb9ac87129295564d6736e48c601`, carrying Java Argon2id support, fixed Argon2 lane defaults across runtimes, secret-hygiene hardening, and the blackbox plugin ABI surface. The SHA remains fetchable but is not on the rewritten current `main`/`v3.7.0` lineage; choose and validate the intended canonical release commit before shipping 1.1.
- **Inner crypto secret hygiene.** Introduced `basefwx::crypto::SecureBytes` — move-only RAII owner that wraps `Bytes` and SecureClears on destruction. Replaces the `SecretGuard` raw-pointer pattern at every KEM-touching call site in yume (`server_derive_key`, `validate_pq_keypair`) and basefwx (`filecodec.cpp` 4 sites, `keywrap.cpp` 2 sites). Eliminates a use-after-free class fixed in 66153f6 by structural change rather than placement discipline. Existing string-secret SecretGuard sites are unchanged.
- **TLS browser-profile labels corrected** to match the captured shapes: Chrome 131, Firefox 126, Safari 18, and Edge 123.
- **JA4 diagnostics made canonical.** Fingerprints now use FoxIO's `a_b_c` format, GREASE filtering, sorted lower-case cipher/extension hex lists, SNI/ALPN exclusions, and original-order signature algorithms. Focused official-vector and match-threshold tests cover the implementation.
- **`X-Yume-Blob` HTTP response header removed.** It had zero consumers in the tree; the substring "Yume" was a passive fingerprint for any layer-7 inspector. The anonym blob still ships in the body (zero-width `<span>` + HTML comment) where the actual readers look.

### Fixed
- **Use-after-free on KEM secret wipe.** SecretGuard stores raw `Bytes*` pointers and SecureClears them from its destructor. Reverse-construction-order destruction meant a SecretGuard declared BEFORE the locals it tracked accessed already-freed vector storage on scope exit. Manifested as `malloc(): unaligned tcache chunk detected` immediately after PQ keypair validation on `--pq-auto-generate` startup. Closed first by reordering (commit 66153f6), then by structural replacement with SecureBytes (commit 58c39a7).
- **Pre-existing yume_server link break** from the `f6db161` session.cpp split: `epoch_now_ms` was anonymous-namespace-local in session.cpp but referenced from session_control.cpp. Exposed at file scope in session.hpp; duplicate copy in federation_link.cpp removed.
- **Argon2 admission was not aggregate.** `argon2_env_limits()` previously returned `{0,0,0}` by default, making the parameter guard a no-op. It now seeds per-derivation ceilings (`time=12, memory=512 MiB, parallelism=8`), and positive environment values may deliberately lower or raise them. The server additionally reserves each Argon2 derivation against manager-owned aggregate memory/job limits before allocation; move-only RAII leases release accounting on all exits. Defaults are 512 MiB aggregate and four jobs, configurable through CLI or JSON. The `has_argon2_limits` gate this enabled was dead code and is removed; the client local-cap check stays for old-server backwards compatibility.

## [withdrawn v1.0] - 2026-05-16

Former tag commit: <https://github.com/FixCraft-Inc/yume/commit/82735dc12b17e7bc72592e32e74f52afd4b46247>

### Added
- **First public test release** of YUME (Yume Universal Multiprotocol Engine) — an open-source post-quantum stealth transport that tunnels TCP and UDP through real TLS 1.3 sessions using the project's browser-oriented presets. The client (`yume`), daemon (`yumed`), proxy, GUI, and libyume surface are AGPL-3.0-or-later and build from this tree.
- **Three-layer stealth stack** stacked on top of TLS 1.3, all on by default and toggleable independently:
  - Browser-oriented JA3 shaping plus the original project-local, pre-canonical JA4-like diagnostic via genuine OpenSSL 3.5 `ClientHello` configuration. `--profile chrome` (Chrome 131) is the default; `--profile firefox` (Firefox 126) and `--profile safari` (Safari 18) are selectable, plus per-N-connection rotation via `--tls-stealth-rotate` / `--tls-stealth-rotation-interval`.
  - HTTP/2 carrier handshake (`--obfs`) with the then-current project SETTINGS, `WINDOW_UPDATE`, and a `HEADERS` frame opening a `POST` to `/<token>/<nonce>`. The token is `HMAC-SHA256(K, sni || hour_epoch || "yume-obfs-v2")` truncated to 16 bytes hex; 1.0 allowed optional peer-pinning via `--obfs-secret` and accepted ±1 hour of clock skew.
  - Real HTML facade (`--real`) so a browser hitting the same `:443` with `GET / HTTP/1.1` is served a real HTML page (or a Wikipedia redirect by default). YUME and a normal website coexist on a single port.
- **Post-quantum KEM/DEM inner crypto** via BaseFWX 3.6.4 (separate library;
  current dependency metadata is centralized in `config/dependencies.json`):
  - **ML-KEM-768** (NIST FIPS 203 / Kyber-768) encapsulation for session keys when a master public key is configured.
  - **AES-256-GCM** AEAD with a 12-byte nonce and 16-byte tag.
  - **Argon2id** or **PBKDF2-HMAC-SHA256** as an optional work factor over the high-entropy ML-KEM shared secret. The YUME transport handshake does not mix in a user password / PSK.
  - **HKDF-SHA256** for all subkey derivation.
  - **Ed25519** for client authentication via `--auth` / `--auth-keys`.
- **Live key hopping** at 1–4 Hz (`--hop-interval`, default ~500 ms). Each window encrypts with an `HKDF(master, hop_index)` derivative. This separates derived hop keys but is not forward secrecy: compromise of the retained master reveals every window. Disable for latency-sensitive paths with `--no-hop`.
- **Five routing modes**, combinable:
  - `--socks [addr:]port` — SOCKS5 listener on the client side.
  - Local TCP/UDP forward (`--proxy host:port -> local:port`).
  - `--run <cmd …>` — spawn a command and pipe its stdio through the tunnel.
  - Android VPN capture (separate [yume4a](https://github.com/FixCraft-Inc/yume4a) APK that captures all OS-level traffic).
  - Server-side reverse port tunneling via `yumed --reverse-port-min` / `--reverse-port-max`.
- **Server-side egress options**: direct, Tor outbound (`yumed --proxy tor://…`, optional obfs4 bridge), and yumed-to-yumed federation links over mutual TLS 1.3 (`--federation-enable`, `--federation-auth-key`, `--federation-anonym-ca`, `--peer`).
- **Anonym / no-log mode** (`yumed --anonym`) for run-by-third-party endpoints: drops connection-level logs before disk, decoupled CA / sub-key flow (`--anonym-ca-key`, `--anonym-sub-key`), optional `--anonym-token` rate-limiting that doesn't tie tokens back to user identities, operator key management via `--operator-keys`.
- **Optional Dear ImGui-based desktop GUI** (`yume-gui`) for Linux, macOS, and Windows. Ships as a portable single-file `.exe` on Windows (static MinGW runtime + `x64-mingw-static` vcpkg triplet).
- **9-target release matrix**: linux-amd64 (dynamic + static), linux-armv7, linux-armv8, busybox-amd64-static, busybox-armv7-static, busybox-armv8-static, openwrt-mips (maintainer-attached), macos-arm64, windows-amd64 (CLI tarball + portable GUI .exe). Android via [yume4a](https://github.com/FixCraft-Inc/yume4a) (~28 MiB arm64-v8a APK).
- **Minimal footprint**: the static BusyBox build runs on routers with as little as **128 MiB of RAM** and no glibc.
- **Release pipeline** with full pre-publish self-test:
  - `light-tests` host-build + `yume --version` / `yumed --version` smoke pre-gate.
  - GUI cross-builds for the three desktop OSes (continue-on-error so a GUI dep regression doesn't block CLI release).
  - Static-link assertion on every `*-static` artifact (`file` must not say "dynamically linked"; `readelf -d` must show no `NEEDED` entries).
  - `--version` self-test on every published binary (native amd64 directly, ARM via `qemu-aarch64-static`/`qemu-arm-static`, MIPS via `qemu-mips-static`, PE via wine if available else PE32 header check, tar.xz CLI bundles extracted and tested).
  - GPG-signed `*.sig` per artifact plus aggregate `SHA256SUMS.txt`, `MD5SUMS.txt`, `release-manifest.json`.
- Project documentation included the main README, setup, security, routing,
  operations, packaging, permissions, release notes, and project website.

### Changed
- Wire format, authentication key file format, anonym CA / sub-key file format, and the `yume-obfs-v2` HTTP/2 token format were test-published in 1.0 and are treated as the compatibility base for the 1.1 stable line.
- Server-to-server federation links are pinned to **TLS 1.3 only** (no fallback to earlier TLS versions) — see commit `f13fbdb`.
- Build pipeline rewritten end-to-end vs the BETA cycle: smoke-gate before heavy builds, GUI added for desktop OSes, dynamic "busybox" artifacts dropped (they were misleadingly named — a glibc-dynamic binary can't run on a real busybox/musl target), only verified-static `*-busybox-static` ships, macOS job is matrix-ized so Intel can be added in a follow-up by uncommenting one matrix entry.
- Website's `assetMap` aligned with the new release-artifact set: GUI download cards for Linux / macOS / Windows added; dynamic-busybox cards dropped.

### Fixed
- Federation TLS regression: an earlier commit used the wrong TLS-method constant (`tls_client` instead of `tlsv13_client`); pinned in `f13fbdb`.
- 240-commit history through the ALPHA → BETA cycle accumulated and addressed: TLS-fingerprint correctness, HTTP/2 obfs token rotation, key-hop window seam handling, federation handshake edge cases, anonym-mode metadata leaks, Android VPN capture restart bugs, Windows MinGW cross-build deps, BusyBox static-link reliability across glibc/musl toolchains, GUI font rendering on Wayland vs X11 (URW Gothic Demi double-bold fix), CodeQL high-severity findings, OpenWRT SDK feed wiring, and assorted CI/website hash-rendering bugs.

### Notes
- **Threat model recap** (full version in `docs/STEALTH.md` and `docs/EXPLAINED.md`): YUME defends the **transport**. The route you choose decides who can see the client, who can see the target, and how much trust is placed in the YUME server. YUME does **not** by itself provide anonymity — combine with Tor egress, Tor-over-YUME, or YUME-Tor-YUME for that.
- **OpenWRT MIPS** is intentionally **not** built in CI because cross-builds against the OpenWRT SDK are slow and brittle on hosted runners; maintainers attach the MIPS artifacts manually when a release is cut. The static BusyBox builds cover most embedded use.
- **Intel macOS** is not built in 1.0. The `build-macos` workflow is matrix-ized so an Intel entry is a one-line uncomment in `.github/workflows/release.yml`. Rosetta 2 covers Intel Macs running the arm64 binary.
- **Windows GUI cross-build is best-effort** in 1.0: marked `continue-on-error: true` because the GUI-specific vcpkg packages (Freetype, GLFW3) on a fresh runner can take significantly longer than the CLI path and may time out. If the cross-build fails the CLI tarball still ships and the GUI lands in a follow-up.
- **Performance**: one April 2026 WAN run measured about 234 Mbps download and
  36 Mbps upload on the 1.x SOCKS path. CPU cost was not isolated, so the prior
  "<1 % typical, <5 % always" wording was not supported by that dataset. This
  historical result does not describe the current transport.
- **Compatibility policy for the 1.x line**: authorised-key files (`--auth-keys`), anonym CA / sub-key files, and the `yume-obfs-v2` token format carry forward unchanged. The BaseFWX inner format is byte-compatible across the 3.6.x and 3.7.x lines for non-plugin-tagged blobs per BaseFWX's own compatibility policy.
- **License**: AGPL-3.0-or-later across YUME binaries, source, and libyume. Bundled BaseFWX code follows its own split policy: LGPL library/API/runtime, GPL standalone tools, MIT OR Apache-2.0 example plugin templates. See `LICENSE`.
