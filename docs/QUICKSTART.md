# YUME 2.0 desktop quick start

This starts the focused Linux desktop client/server slice on one machine. It
uses the real HTTP/2 carrier, mandatory hybrid ratchet, and a separate Node.js
cover bound to loopback.

## Build

```bash
git clone https://github.com/FixCraft-Inc/yume.git
cd yume
git clone https://github.com/F1xGOD/basefwx.git basefwx
git -C basefwx checkout "$(cat config/refs/basefwx.ref)"
./ezbuild.sh
```

`ezbuild.sh` requires nghttp2 1.64 or newer. When the system package is too
old, it builds the pinned, checksum-verified nghttp2 1.69.0 library under the
user cache. The build produces `build/bin/yume` and `build/bin/yumed`.

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
npx --yes node@24.18.0 tools/cover-node/backend.mjs
```

It listens on `127.0.0.1:3000`. In production, supervise the Node process
separately and never expose its port publicly.

Start `yumed` in another terminal:

```bash
sudo ./build/bin/yumed \
  --listen 443 \
  --cert certs/server.crt \
  --key certs/server.key \
  --auth-keys /etc/yume/authorized_keys \
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

## Production notes

- Keep Node on a loopback IP literal and supervise it separately from `yumed`.
- Keep TLS private keys and both shared secret files owner-readable only.
- Distribute the admission and inner PSK files out of band to every client.
- Do not place an HTTP-mode reverse proxy in front of `yumed`; it must receive
  the original TLS connection. Use TCP passthrough when a fronting layer is
  required.
- `2.0-dev1` is not release-complete. Check
  [YUME_2_0_IMPLEMENTATION_STATUS.md](YUME_2_0_IMPLEMENTATION_STATUS.md) before
  treating a test result as a production support claim.
