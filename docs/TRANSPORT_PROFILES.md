# Transport profile architecture

YUME separates an authenticated transport identity from whatever browser is
currently installed on the host. Browser auto-updates must not silently change
wire behavior: the profile ID participates in admission, AUTH, establishment,
and protected-frame AAD, so changing its meaning in place would be a protocol
and security regression.

## Sources of truth

| Surface | Role |
| --- | --- |
| `config/transport_profiles.json` | Registered profiles and the active profile |
| Registry-selected fixture manifest | Exact browser, OS, cover runtime, binaries, hashes, and evidence provenance |
| Registry-selected HTTP/2 profile | Capture-derived HTTP/2, HTTP, WebSocket, and shaping values |
| Registry-selected TLS profile and candidates | Normalized ordered TLS first-flight acceptance profile and samples |
| `src/core/stealth/transport_profiles.inc` | Generated immutable C++ registry; never edit manually |
| `helper/chrome_tls/transport_profiles_generated.go` | Generated helper build-ID to provider registry; never edit manually |
| `helper/chrome_tls/profile.go` | Audited TLS-emitter provider implementations |

Each entry names its own artifact files; shared generator, CMake, test, install,
and release logic does not depend on Chrome-specific filenames.
`scripts/generate_transport_profiles.py` validates bounded schemas, fixture and
artifact path containment, unique profile/alias/helper identities, required
evidence fields, and header geometry. It requires the registry's active ID to
equal the authenticated `kTransportProfile`, then generates both the C++
registry consumed through `cover_profile::active()` and the Go helper registry.
TLS/HTTP/H2 consumers contain no browser-version branches.

Dev6's carrier implementation currently requires exactly two assets and the
captured stream sequence 1/3/5/7 (priming, CSS, JavaScript, extended CONNECT).
The generator rejects any other geometry instead of admitting metadata that
`H2Carrier` cannot execute. Generalizing that carrier is a separate reviewed
change.

The generated files are committed so production builds do not acquire a Python
code-generation dependency. CI and release preflight run the generator in
`--check` mode and reject stale output.

The matched Gate B browser workload is separately frozen in
`tools/cover-node/workload-v1.json`. The direct HTTP/2 capture target and
classifier-input validator consume that file. It defines reference page assets
and the transfer/control/idle contract, not a second transport identity and not
the installed production HTTP/1 cover backend. Changing it requires new
matched captures and must not silently rewrite the existing
`chrome151-node24-v1` evidence claim.

The opt-in YUME `--outer-carrier-evidence` path is admitted only when this
active profile, its declared `chrome151` helper backend, and the frozen
one-tunnel workload all match. The capture-only application transaction is 64
ordered 16-KiB messages echoed byte-for-byte; ordinary endpoint benchmarks do
not use that protocol. Its stable behavior summary is reconstructed from
bounded live carrier events; the registry is used to validate and redact
expected metadata, never to fabricate observed events. The application match
does not hide YUME framing/ratchet overhead: the observer reports the actual
outer WebSocket geometry and the classifier may correctly return `DRIFT`. The
stable classifier projection also retains ordered request and WebSocket
lifecycle. In particular, normal Chrome's stream-9 favicon request and
PING-before-first-fragment relationship are compared even though the current
production YUME carrier does not reproduce them.

The transport and dependency registries are source/build metadata and are not
installed as runtime examples. The transport registry contains
repository-relative evidence paths; install rules copy only the active,
flattened evidence files that installed diagnostics consume.

## Adding or refreshing a browser profile

1. Capture several normal-browser sessions in an isolated profile using exact
   browser, OS, server runtime, certificate/SNI/ALPN, and workload conditions.
   Keep raw NetLogs and PCAPs private.
2. Sanitize and review the fixture. Record exact binary hashes and preserve
   measured distributions instead of inventing stable timing constants.
3. Add a new fixture directory and a new registry entry. Never rewrite the
   evidence behind an existing authenticated profile ID.
4. Add or select a TLS-emitter provider in `helper/chrome_tls/profile.go` and
   name that reviewed provider in the registry. A
   browser name or uTLS preset is not proof of parity; the provider must pass
   the ordered wire comparator, certificate/pin/ALPN/exporter failures, and
   lifecycle tests.
5. Fill in `openssl_selection` for the native backend. This is what lets the
   in-process OpenSSL path track the same browser without a helper, and it is
   deliberately data rather than code so a new browser needs no C++ change:

   | Key | Meaning |
   | --- | --- |
   | `cipher_suites` | Offered suites, in order. Split across `SSL_CTX_set_ciphersuites` (TLS 1.3) and `SSL_CTX_set_cipher_list` (TLS 1.2); both preserve order. |
   | `signature_algorithms` | Offered schemes, in order. JA4 hashes these in order, so the sequence is load-bearing, not just the set. |
   | `supported_groups` | Offered groups, in order. |
   | `extensions` | The target extension set. Not an emission order: see below. |
   | `injected_extensions` | Extensions OpenSSL will not emit itself, each with a body shape. `"GREASE"` as the type allocates an RFC 8701 value per connection. |
   | `alps_protocols` | Body for the injected `0x44cd` extension. |
   | `ech_grease_lengths` | Permitted total lengths for the injected `0xfe0d` GREASE ECH body, taken from the capture. |
   | `no_encrypt_then_mac` | Suppresses `0x0016`, which OpenSSL offers by default and browsers generally do not. |
   | `status_request` | `"ocsp"` emits `0x0005`, which `add_custom_ext` cannot because OpenSSL owns that number internally. |
   | `min_version` / `max_version` | The offered range. Browser-shaped, so usually TLS 1.2 through 1.3 — offering only 1.3 silently drops the TLS 1.2 half of the cipher list and extension `0xff01`. |
   | `require_negotiated_version` | The version the handshake must actually end on. Keeps a browser-shaped offer from becoming a carrier downgrade; enforced in `handshake_with_timeout` and fails closed. |

   Extension *emission order* is not configurable and is not claimed. OpenSSL
   fixes the order of its built-in extensions and prepends injected ones, and
   Chrome has permuted its own order per connection since v110 — which is what
   broke JA3 as a browser discriminator and motivated JA4's sorted,
   GREASE-excluding construction. The gate targets JA4.

6. Record the residual gap in `known_tls_divergence` and let the tests pin it.
   `scripts/generate_transport_profiles.py` compares the declared selection
   against the capture, and `tests/test_yume_native_tls_wire.py` re-derives the
   same gap from the bytes the production backend actually emits. Both fail if
   the gap widens, so a divergence cannot be introduced silently.
7. Regenerate and validate:

   ```sh
   python3 scripts/generate_transport_profiles.py
   python3 scripts/generate_transport_profiles.py --check
   python3 tests/test_project_metadata.py
   ```

8. Bind the new ID only in a deliberate development protocol revision, update
   KATs and wire documentation, then run same-session capture, matched
   performance, sanitizer, classifier/active-probe, soak, packaging, and
   independent-review gates.

The registry can hold several immutable profiles, but dev6 intentionally
activates exactly `chrome151-node24-v1`. Runtime negotiation or accepting a
second ID is not a cosmetic configuration change and is not introduced by this
registry refactor.

## Installed-browser updates

An operating-system Chrome update does not require rewriting YUME or
downgrading the daily browser. It only means that installed Chrome cannot be
used as evidence for the older frozen profile. Reproduction should use an
isolated, checksum-verified browser artifact or container/VM; a newly captured
version becomes a new profile ID after its evidence passes.

Do not download a browser during a normal YUME connection or build. Do not
silently map an unknown/current browser to the closest registered profile.
Unsupported profiles fail closed.

## BaseFWX dependency metadata

BaseFWX remains pinned for reproducible cryptographic builds, but its repository,
exact revision, and minimum compatible version now live once in
`config/dependencies.json`. CMake, local build scripts, CI, CodeQL, and release
preflight read that manifest through `scripts/yume_dependencies.py`; they must
not copy those values into another workflow.

Pinned build modes and `fullau.sh` overrides accept only an exact lowercase
40-hex commit. Developer worktree mode remains explicit and never rewrites an
existing BaseFWX checkout.

This removes update choreography without weakening reproducibility: updating
BaseFWX is one reviewed manifest change followed by its own compatibility,
security, ABI, and build validation—not an unbounded floating dependency.
