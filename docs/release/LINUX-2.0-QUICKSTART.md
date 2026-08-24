# YUME 0.2.0 Linux x86-64 quick start

The first YUME 0.2.0 release lane supports only glibc Linux on x86-64. The client
archive and server executable are separate artifacts:

- `yume-amd64-linux.tar.xz` contains `yume`, the adjacent
  `yume-chrome-tls-helper`, licensing documents, and `manifest.json`.
- `yumed-amd64-linux` is the server.

Android, GUI, Windows, macOS, ARM, OpenWRT, static binaries, and a Debian
archive are not supported by this release lane.

The native binaries are dynamically linked and require OpenSSL 3.5 or newer at
runtime. This is a functional requirement, not only a build-host preference:
composite client identities require the OpenSSL ML-DSA-87 provider.
The release lane links its pinned liboqs 0.16.0 archive statically; neither `yume` nor
`yumed` may have a `liboqs.so` runtime dependency or an embedded build/cache
library search path. Release packaging and preflight reject both conditions.

## Verify and unpack

Verify the release SHA-256 files and signatures before installation. Then:

```sh
tar -xJf yume-amd64-linux.tar.xz
cd yume-amd64-linux
./yume --version
./yume-chrome-tls-helper --version
```

Keep the helper next to `yume`, owned by root or the account running YUME, and
not writable by group or other users. The client rejects symlinked,
non-executable, or unsafe helper files.

Install the server separately if this machine hosts a YUME endpoint:

```sh
sudo install -m 0755 yumed-amd64-linux /usr/local/bin/yumed
```

The current preparation-only server download is not self-contained: YUME 2.0
also requires the Node 24 loopback cover backend, but this bare-binary artifact
does not include `backend.mjs` or a service unit. Do not treat it as a deployable
stable server package. Development installs should use the matching exact
source/CMake install layout until release packaging carries and pins the cover
service contract.

## Configure and connect

Provision certificates, independent admission and inner PSKs, and a composite
Ed25519 + ML-DSA-87 client identity by following the full `docs/QUICKSTART.md`
from the matching source release. The opt-in Chrome 151 backend is selected explicitly:

```sh
./yume \
  --server server.example \
  --port 443 \
  --tls-name server.example \
  --tls-ca /path/to/server-ca.pem \
  --auth /path/to/client.key \
  --obfs-secret-file /path/to/admission.hex \
  --inner-psk-file /path/to/inner.hex \
  --transport-profile chrome151-node24-v1 \
  --tls-backend chrome151 \
  --socks 127.0.0.1:1080
```

There is no silent fallback. `openssl-diagnostic` remains the default until
matched WAN, an uninterrupted deployed-network soak, exact-Chrome same-session
cover, classifier/active-probe, and independent-review gates are complete. The
bounded lifecycle, process-scale, reconnect, and segmented loopback-soak gates
pass. Do not describe the opt-in backend as invisible to DPI or independently
audited.
