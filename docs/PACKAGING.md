# YUME transition packaging

## Current install contract

The default CMake graph builds and installs the runnable transport-v2 product:

- `yume` and `yumed`;
- the transport-v2 `yume-setup` provisioner;
- current executable manuals and transition documentation;
- optional current GUI and supporting tools when their build options are
  enabled.

The YTP/1 engine and codec foundations also compile in this graph, but their
operator and ABI surfaces are explicit experiments. Enable those surfaces
with `YUME_BUILD_SHARED_ABI=ON` and
`YUME_INSTALL_EXPERIMENTAL_YTP1_TOOLS=ON`; the commands install as
`yume-setup-ytp1` and `yume-doctor-ytp1` so a schema-1 kit cannot be mistaken
for input to the runnable binaries.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DYUME_BUILD_TESTING=ON \
  -DYUME_BUILD_SHARED_ABI=ON \
  -DYUME_INSTALL_EXPERIMENTAL_YTP1_TOOLS=ON
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/install"
```

The current experimental consumer test uses the build-tree CMake and pkg-config
metadata, validates exported symbols, parses a schema-1 config, and confirms
the unwired endpoint fails closed. The clean-prefix install consumer remains a
freeze gate; neither test qualifies a tunnel data path.

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

The experimental `libyume.so.1` scaffold exports only the symbols in
`src/abi/yume.map`. It must not be distributed as a frozen runtime package
until its functional gates pass. Every ABI change still synchronizes the public
header, map, candidate Debian symbols, CMake/pkg-config exports, installed
consumers, and [ABI.md](ABI.md). C++ engine and provider headers remain private.

YTP, config, ABI, provider, cryptographic backend, and evidence profile have
independent versions. Package version changes must not silently change any
wire or ABI axis.

## Source and provenance

The deterministic source dependency record is
`docs/release/SBOM.spdx.json`. Run:

```bash
python3 scripts/check_dependency_sbom.py --check
python3 scripts/yume_dependencies.py validate
```

The checks validate declared source dependency metadata and reproduce the
checked-in inventory. They do not establish source ancestry and do not
constitute a binary SBOM, vulnerability assessment, license opinion, or release
signature. Candidate packages still require exact dependency, linkage,
reproducibility, signature, and installed-file evidence.
