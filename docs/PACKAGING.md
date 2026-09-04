# YUME transition packaging

## Current install contract

The default CMake graph builds and installs the runnable transport-v2 product:

- `yume` and `yumed`;
- the transport-v2 `yume-setup` provisioner;
- current executable manuals and transition documentation;
- optional current GUI and supporting tools when their build options are
  enabled.

The YTP/1 engine and codec foundations also compile in this graph, but their
operator and ABI surfaces are explicit experiments. The schema-1 tools may be
installed with `YUME_INSTALL_EXPERIMENTAL_YTP1_TOOLS=ON`; they are named
`yume-setup-ytp1` and `yume-doctor-ytp1` so a schema-1 kit cannot be mistaken
for input to the runnable binaries. `YUME_BUILD_SHARED_ABI=ON` builds the
unversioned ABI candidate and its tests only in the build tree. It adds no ABI
header, library, CMake-package, or pkg-config install rule.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DYUME_BUILD_TESTING=ON \
  -DYUME_BUILD_SHARED_ABI=ON \
  -DYUME_INSTALL_EXPERIMENTAL_YTP1_TOOLS=ON
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/install"
```

The current experimental tests link the build-tree target directly. They
compile the public header as strict C, exercise the C++ contract, validate the
exported symbol set, parse both configuration dialects, and run an authenticated
transport-v2 named stream against a provisioned server. Schema-1 start, packet
channels, and destination-routed OPEN remain typed unsupported boundaries. The
clean-prefix CMake and pkg-config fixtures are retained as future freeze gates;
the build does not currently invoke them.

## Replacement package target after freeze

- future `libyume1`: the frozen ABI runtime and no public C++ implementation
  surface.
- future `libyume-dev`: the C header, CMake package, pkg-config file, and
  contract documentation.
- future `yume`: the config-only client CLI plus setup, doctor, SOCKS5,
  named-service, and packet adapters once implemented.
- future `yume-daemon`: the config-only server runtime and direct TCP/UDP
  service adapters once implemented.

The current `yume`, `yume-daemon`, and optional `yume-gui` Debian packages
continue to carry the transport-v2 product during the transition. No
`libyume1` or `libyume-dev` binary package should be emitted from the unwired
replacement scaffold. A future replacement GUI should consume the installed C
ABI like any external application after that ABI becomes functional.

Package descriptions and dependencies must match the exact candidate payload;
metadata is never proof that a runtime or ABI data path works.

## ABI rules

The experimental build-tree artifact is unversioned `libyume.so`, not
`libyume.so.1`. It exports only the symbols in `src/abi/yume.map` and must not
be distributed as a frozen runtime package until its functional gates pass.
Every ABI change still synchronizes the public header, map, candidate Debian
symbols, strict C/C++ consumers, and [ABI.md](ABI.md). The dormant CMake,
pkg-config, and clean-prefix fixtures must be synchronized when installation is
implemented. C++ engine and provider headers remain private.

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
