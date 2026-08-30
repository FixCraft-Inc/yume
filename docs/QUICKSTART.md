# YUME quick start

This starts the focused Linux desktop client/server slice on one machine. It
uses the real HTTP/2 carrier, mandatory hybrid ratchet, and a separate Node.js
cover bound to loopback.

## Build

```bash
git clone https://github.com/FixCraft-Inc/yume.git
cd yume
./ezbuild.sh
```

On a fresh clone, `ezbuild.sh` creates `basefwx/` at the pinned dependency
commit. An existing attached BaseFWX branch is treated as a developer worktree
and is never fetched or detached automatically. Set
`BASEFWX_SYNC_MODE=pinned` for an explicitly pinned build, or
`BASEFWX_SYNC_MODE=worktree` to require the current checkout.

`ezbuild.sh` always selects the pinned, checksum-verified and patched OpenSSL
source because the default native ClientHello emitter requires that capability.
It also prepares the supported nghttp2 revision when the system copy is too
old.
Direct CMake builds must first source `scripts/ensure-openssl.sh` and call
`yume_openssl_ensure`; stock OpenSSL is rejected. The normal build embeds the
patched library. The default is a portable Release build with `-O3`, LTO,
fast-math disabled, and developer timing code compiled out. `./ezbuild.sh --native`
produces the fastest executables for the current CPU but they are not portable;
`./ezbuild.sh --dev` produces optimized RelWithDebInfo binaries with opt-in
`--timing` hooks. The build produces `build/bin/yume` and
`build/bin/yumed`. See [DIAGNOSTICS.md](DIAGNOSTICS.md).

## One-command server and device kit

After building, install the binaries/helpers or run the helper directly from
the clone:

```bash
sudo cmake --install build
yume-setup init \
  --output ~/yume-kit \
  --host build-host.example \
  --port 8443 \
  --tls-name remote-builder-test \
  --client-name phone
```

The helper uses the operating system CSPRNG for both 256-bit secret files,
generates browser-compatible ECDSA TLS certificates, the delegated operator
certificate key, and composite Ed25519 + ML-DSA-87 client identities, writes
owner-only configs, and
prints the exact server and device paths. It never prints secret values. For a
real deployment, supply an existing operator CA with `--ca-key` and
`--ca-cert`; otherwise the generated CA is a test/bootstrap CA whose private
key lives under `offline-ca/` and should be moved off-server.

Start packet routing and the two server processes as printed by the helper.
`start-yumed` waits for the cover backend, avoiding the startup race that can
otherwise look like a TLS failure. A browser URL is only a cover-health check;
YUME clients use the same listener for the authenticated H2 tunnel.

Issue more credentials without editing PEM or metadata files by hand:

```bash
yume-setup issue-key --kit ~/yume-kit --name laptop --type individual
yume-setup issue-key --kit ~/yume-kit --name shared-lab --type bulk --max-sessions 50
yume-setup issue-key --kit ~/yume-kit --name controller --type admin
```

Bulk credentials are denied relay/admin privileges by default and remain
independently session-counted and fair-shared. An admin profile gets one visitor
identity in the operator store and a different second identity in `admin_keys`.
Each client directory includes a desktop config,
`DEVICE_SETUP.txt`, and launchers. Run `./start-socks` to use the default
`~/yume/build/bin/yume`, or `./export-yss [output.yss]` to create an encrypted `.yss`
containing both required YUME transport-v2 secrets. The separate Android client
has earlier import evidence but must be re-synchronized to the
current native candidate; its connected VPN/routing and release path is also
not qualified. Share passwords must be at least 12 characters, matching
BaseFWX itself.

## Create local test material

Generate a client identity:

```bash
install -d -m 0700 ~/.config/yume
./build/bin/yumed --keys-gen ~/.config/yume/client
sudo install -d -m 0755 /etc/yume
sudo install -m 0644 ~/.config/yume/client.pub /etc/yume/authorized_keys
```

Create the two independent 32-byte random secrets:

```bash
umask 077
openssl rand -hex 32 | tr -d '\n' > ~/.config/yume/admission.hex
openssl rand -hex 32 | tr -d '\n' > ~/.config/yume/inner.hex
chmod 0600 ~/.config/yume/admission.hex ~/.config/yume/inner.hex
```

Each file must contain exactly 64 lowercase hex characters and must not be
group/world-readable. Production clients receive both files through a secure
out-of-band channel; there is no public-key-only 2.0 mode.

Create a local TLS certificate if you do not already have one:

```bash
install -d -m 0700 certs
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout certs/server.key -out certs/server.crt \
  -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost,IP:127.0.0.1
chmod 0600 certs/server.key
```

## Start the cover and daemon

Run the pinned development cover in one terminal:

```bash
node tools/cover-node/backend.mjs
```

Use the Node version named by the active transport profile. It listens on
`127.0.0.1:3000`. In production, supervise the Node process separately and
never expose its port publicly.

Start `yumed` in another terminal:

```bash
sudo ./build/bin/yumed \
  --listen 443 \
  --cert certs/server.crt \
  --key certs/server.key \
  --auth-keys /etc/yume/authorized_keys \
  --max-sessions 256 \
  --bulk-key-max-sessions 64 \
  --accept-rate-limit 100 \
  --obfs-secret-file "$HOME/.config/yume/admission.hex" \
  --inner-psk-file "$HOME/.config/yume/inner.hex" \
  --real-backend loopback://127.0.0.1:3000
```

`yumed` terminates public TLS/H2 and proxies ordinary GET/HEAD cover requests
to Node. Node never receives tunnel payloads, identities, or secret material.

## Connect the client

```bash
./build/bin/yume \
  --server 127.0.0.1 \
  --port 443 \
  --tls-name localhost \
  --tls-ca certs/server.crt \
  --auth ~/.config/yume/client.key \
  --obfs-secret-file ~/.config/yume/admission.hex \
  --inner-psk-file ~/.config/yume/inner.hex \
  --profile chrome \
  --socks 127.0.0.1:1080
```

Point an application at the local SOCKS5 listener on `127.0.0.1:1080`.

## Verify the tools

Version output is offline by default:

```bash
./build/bin/yume --version
YUME_UPDATE_CHECK=1 ./build/bin/yume --version
```

Build and run the optional benchmark path:

```bash
./ezbuild.sh --selftest --tests
./build/bin/yume --quick-bench
./build/bin/yume --full-bench
ctest --test-dir build --output-on-failure
```

The full benchmark is intentionally heavy. Use an approved benchmark host, not
a daily-driver laptop. See [SELFTEST.md](SELFTEST.md) for the local transport,
real endpoint, and crypto-only benchmark boundaries.

One-stream LAN results do not establish high-latency performance. The
[implementation status](IMPLEMENTATION_STATUS.md#performance-and-network-qualification)
lists the remaining network qualification work.

## Production notes

- Keep Node on a loopback IP literal and supervise it separately from `yumed`.
- Keep TLS private keys and both shared secret files owner-readable only.
- Distribute the admission and inner PSK files out of band to every client.
- Treat regular keys as individual by default. If many clients must share one
  private key, explicitly configure a bounded `bulk` policy; privileged
  permissions are rejected for bulk keys. Keep operator/controller keys in the
  separate operator trust store. See [PERMISSIONS.md](PERMISSIONS.md).
- Set `--egress-mbps` at or below the server's measured upstream limit when
  clients should share a bounded link fairly. Size session and accept-rate
  limits for the host, and enforce hard process CPU/RAM ceilings through the
  service manager. See [OPERATIONS.md](OPERATIONS.md).
- Do not place an HTTP-mode reverse proxy in front of `yumed`; it must receive
  the original TLS connection. Use TCP passthrough when a fronting layer is
  required.
- The development tree is not release-complete. Check the
  [implementation status](IMPLEMENTATION_STATUS.md) before treating a test
  result as a production support claim.
