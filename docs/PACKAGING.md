<!-- Generated from docs/src/en_US/pages/packaging.doc by scripts/yume_docs.py. Edit that file, not this one. -->
# YUME packaging

## Current install contract

The default CMake graph builds and installs the native application candidate:

- `yume` and `yumed`;
- the schema-1 `yume-setup` provisioner and `yume-doctor` validator;
- native executable manuals, configuration examples and documentation.

These programs compose YTP/1 directly. The native application and schema-1
tools remain experimental. Setup and doctor require Python 3 and an OpenSSL
3.5 or newer command-line executable, including when the native binaries
embed their own patched OpenSSL.

The GUI, Chrome comparison helper and other transport-v2 tools remain
available in explicit development builds with `YUME_BUILD_TRANSPORT_V2=ON`.
They are not part of the installed native payload. The GUI still consumes the
reference facade; its build and lifecycle tests use the reference daemon.
GUI, helper and CodeQL build lanes select that graph explicitly. Native
packaging and metadata tests also run with the reference graph disabled.

After activating the pinned patched OpenSSL described in
[CONTRIBUTING.md](../CONTRIBUTING.md), a native development install is:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DYUME_BUILD_TESTING=ON \
  -DYUME_WARNINGS_AS_ERRORS=ON
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/install"
```

`YUME_BUILD_SHARED_ABI=ON` builds the unversioned ABI candidate. Adding
`YUME_INSTALL_EXPERIMENTAL_SDK=ON` installs its library, C header, CMake
package and pkg-config metadata for development. The SDK remains
experimental and is not a frozen runtime package.

The ABI tests compile the public header as strict C, exercise the C++
contract, validate exported symbols, parse configuration and run native
schema-1 named streams against provisioned peers. The native ABI also
supports named packet channels and routed TCP/UDP OPEN. Explicit reference
builds retain transport-v2 named-stream tests; reference packets and routed
OPEN remain typed unsupported boundaries. Clean-prefix CMake and pkg-config
fixtures run when SDK installation and tests are enabled.

## Debian packages and service

The Debian source metadata selects the native application and disables
transport v2, BaseFWX, GUI and the experimental SDK. It declares two packages:

- `yume`: the native client, schema-1 setup and doctor, manuals and examples;
- `yume-daemon`: the native server, schema-1 bootstrap configuration, locked
  service account and hardened systemd unit.

The service is neither enabled nor started on installation. The bootstrap
ships no credentials. Operators must install a provisioned server kit,
review endpoint and destination policy, and validate it as the service
account before starting it. The unit checks required paths and runs native
configuration validation before startup. `systemctl reload yumed` validates
again and then sends SIGHUP, which reloads the credential stores without
dropping other clients. The server serves its cover site
in-process; the package no longer expects a transport-v2 loopback backend.
See the package's `README.Debian` for paths and permissions.

Debian builds use system dependencies and dynamically linked OpenSSL; they
must not download dependencies. The build still requires OpenSSL 3.5 or newer
with YUME's reviewed ClientHello patch. A separately packaged patched
OpenSSL and its exact binary-package dependency remain publication
prerequisites. Metadata, configure probes and archive tests do not qualify
Debian build/install/upgrade behavior or a running packaged service. Those
checks remain release gates.

No `libyume1` or `libyume-dev` release package is emitted before ABI freeze
and release qualification. Their eventual split will separate the frozen
runtime library from the C header, discovery metadata and contract
documentation. The planned replacement GUI will consume the public C ABI.

## Linux release archive

The Linux archive contains the native client, schema-1 setup and doctor,
licensing documents, quick start and manifest. The native daemon is a
separate artifact. The package writer and validator require YTP/1/schema-1
identity, check ELF/linkage and file hashes, and reject unexpected or
duplicate archive entries. The reference helper remains a separate build
and reproducibility check; it is not shipped as a native runtime capability.
See the [Linux quick start](release/LINUX-QUICKSTART.md).

Package descriptions and dependencies must match the exact payload.
Production, platform, package/service and release-signature qualification
remain separate from these checks.

## ABI rules

The experimental library is unversioned `libyume.so`, not
`libyume.so.1`. It exports only the symbols in `src/abi/yume.map` and must not
be distributed as a frozen runtime package until its functional gates pass.
Every ABI change still synchronizes the public header, map, candidate Debian
symbols, strict C/C++ consumers, and [ABI.md](ABI.md). The CMake package,
pkg-config metadata and clean-prefix fixtures change with the same candidate. C++ engine and provider headers remain private.

YTP, config, ABI, provider, cryptographic backend, and evidence profile have
independent versions. Package version changes must not silently change any
wire or ABI axis.

## Source and provenance

The deterministic source dependency record is
`docs/release/SBOM.spdx.json`. Run:

```bash
python3 scripts/check_dependency_sbom.py --check
python3 scripts/yume_dependencies.py verify
```

The manifest distinguishes a minimum compatible version from the exact bundled
source version. It also records downstream patch-series licensing separately
from the upstream source license; the generated SPDX conclusion combines both
for a modified source. These checks validate declared source metadata and
reproduce the checked-in inventory. They do not establish source ancestry and
do not constitute a binary SBOM, vulnerability assessment, license opinion, or
release signature. Candidate packages still require exact dependency, linkage,
reproducibility, signature, and installed-file evidence.
