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
5. Regenerate and validate:

   ```sh
   python3 scripts/generate_transport_profiles.py
   python3 scripts/generate_transport_profiles.py --check
   python3 tests/test_project_metadata.py
   ```

6. Bind the new ID only in a deliberate development protocol revision, update
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
