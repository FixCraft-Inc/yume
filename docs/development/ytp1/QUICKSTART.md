# YTP/1 foundation quick start

YUME 0.3 is being rebuilt around the installed C ABI and YTP/1. The
provisioning and validation path below is implemented. The final `yume` and
`yumed` runtimes, native TLS/HTTP/2 providers, direct adapters, and an
authenticated setup-to-SOCKS path are not implemented yet. See
[IMPLEMENTATION_STATUS.md](../../IMPLEMENTATION_STATUS.md) before using a development
checkout. The default build still produces the runnable transport-v2
`yume`/`yumed` product; its signed-baseline instructions are preserved in the
[0.2 quick start](https://github.com/FixCraft-Inc/yume/tree/f0cc9e7/docs/QUICKSTART.md).

## Build and install the current SDK

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

The install contains `libyume.so.1`, `<yume/yume.h>`, CMake and pkg-config
metadata, `yume-setup-ytp1`, and `yume-doctor-ytp1`. The install contract
builds external C and C++ consumers against that prefix without private
headers or libraries.
`yume_endpoint_start()` currently fails closed with
`YUME_STATUS_UNSUPPORTED`.

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
printed. Move the client bundle to the device over an authenticated channel.
Do not put a generated kit in Git.

## Validate both configurations

```bash
install/bin/yume-doctor-ytp1 --config yume-kit/server/yumed.json
install/bin/yume-doctor-ytp1 --config yume-kit/client/yume.json
```

Doctor validates schema, exact provider composition, file ownership and mode,
credential algorithms and relationships, cover content, resource bounds, and
the compatibility manifest. It does not print private material.

## Expected development boundary

The following commands are the intended 0.3 operator path but are not available
until the runtime gate closes:

```bash
yumed --config yume-kit/server/yumed.json
yume --config yume-kit/client/yume.json
curl --proxy socks5h://127.0.0.1:1080 https://example.com/
```

Release documentation must not present that final block as working until the
native providers, adapters, public-ABI data path, browser cover smoke, and
clean-machine setup test all pass.

The unqualified commands `yume-setup`, `yume`, and `yumed` belong to the
runnable transport-v2 lane during this transition. A schema-1 kit is not valid
input for those binaries.
