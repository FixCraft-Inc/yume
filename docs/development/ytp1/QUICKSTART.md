# YTP/1 foundation quick start

YUME 0.3 is being rebuilt around an experimental C ABI and YTP/1. The
provisioning and validation path below is implemented. The tree also contains
opt-in TLS, HTTP/2 carrier, hybrid-security, and direct-route provider
candidates, but they are not composed into a YTP/1 endpoint. The final `yume`
and `yumed` replacement runtimes and authenticated setup-to-SOCKS path are not
implemented yet. See
[IMPLEMENTATION_STATUS.md](../../IMPLEMENTATION_STATUS.md) before using a development
checkout. The default build still produces the runnable transport-v2
`yume`/`yumed` product; use the current
[quick start](../../QUICKSTART.md) for that path.

## Build the ABI candidate and install the schema-1 tools

The replacement ABI and schema-1 operator tools are explicit experimental
surfaces. Enable them without disabling the current transport:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DYUME_BUILD_TESTING=ON \
  -DYUME_BUILD_SHARED_ABI=ON \
  -DYUME_INSTALL_EXPERIMENTAL_YTP1_TOOLS=ON \
  -DYUME_WARNINGS_AS_ERRORS=ON
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/install"
```

The build tree contains unversioned `src/libyume.so` and its contract tests.
The install contains `yume-setup-ytp1` and `yume-doctor-ytp1`, but it does not
install the experimental ABI library, header, CMake package, or pkg-config
metadata. Transport-v2 configurations can start and move authenticated named
stream bytes through the build-tree ABI. Schema-1 endpoint start still fails
closed with `YUME_STATUS_UNSUPPORTED`; packet and destination-routed ABI paths
are also unsupported.

## Generate a server kit and first client

Use a new output directory. Setup never replaces an existing kit.

```bash
install/bin/yume-setup-ytp1 init \
  --host tunnel.example.com \
  --output "$PWD/yume-kit" \
  --client-name laptop
```

The generated tree contains:

- owner-only server and per-identity composite Ed25519 + ML-DSA-87 keys;
- ML-KEM-1024 server material;
- a unique 32-byte access PSK for the client identity;
- an `authorized_keys` traffic store plus a separate, initially empty
  `admin_keys` second-factor store, so a fresh deployment has no administrator
  and admin can never be turned on by editing the traffic list;
- separate client references for the server composite public identity, TLS
  trust, and server ML-KEM public material;
- a separate admission key and TLS CA/leaf material;
- strict schema-1 server and client configurations;
- a static default cover site and service/adapter manifests.

Private values are written atomically with restrictive permissions and are not
printed. Move the client bundle to its host over an authenticated channel.
Do not put a generated kit in Git.

## Validate both configurations

```bash
install/bin/yume-doctor-ytp1 --config yume-kit/server/yumed.json
install/bin/yume-doctor-ytp1 --config yume-kit/client/yume.json
```

Doctor validates schema, exact suite and profile values, restrictive secret
file modes, no-symlink and file-race checks, credential algorithms and
relationships, cover content, and resource bounds. It does not inspect file
ownership, consume a separate compatibility manifest, or print private
material.

## Expected development boundary

The following commands are the intended 0.3 operator path but are not available
until the runtime gate closes:

```bash
yumed --config yume-kit/server/yumed.json
yume --config yume-kit/client/yume.json
curl --proxy socks5h://127.0.0.1:1080 https://example.com/
```

Release documentation must not present that final block as working until the
provider candidates are composed behind a real front door and admission path,
the schema-1 ABI and adapters carry traffic, and the browser-cover,
clean-machine, sanitizer, and qualification gates pass.

The unqualified commands `yume-setup`, `yume`, and `yumed` belong to the
runnable transport-v2 lane during this transition. A schema-1 kit is not valid
input for those binaries.
