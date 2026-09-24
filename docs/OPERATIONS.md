<!-- Generated from docs/src/en_US/pages/operations.doc by scripts/yume_docs.py. Edit that file, not this one. -->
# YUME operations

This page covers running `yume` and `yumed` after a first local connection
from the [quick start](QUICKSTART.md). Neither is qualified for production
yet. Read [implementation status](IMPLEMENTATION_STATUS.md) before exposing a
server.
The explicitly enabled transport-v2 reference programs have their own
[reference operations](TRANSPORT_V2_OPERATIONS.md). Their flags, key files and
configuration do not apply here.

## Provision a kit

`yume-setup init` creates one server tree and one client bundle in a new
directory. It never overwrites an existing path.

```bash
yume-setup init --host vpn.example.net --port 443 \
  --output "$PWD/yume-kit" --client-name laptop
yume-doctor --config yume-kit/server/yumed.json
yume-doctor --config yume-kit/client/yume.json
```

The [native guide](development/ytp1/README.md#identity-and-authorization)
lists every generated file and its purpose. Move the client bundle to its
machine over an authenticated channel. Remove offline CA material from the
server host, and never commit a kit, capture or diagnostic artifact.

Each device gets its own composite identity and access PSK. Issue another
client bundle from the server tree, then reload the daemon so it reads the
extended store:

```bash
yume-setup add-client --server yume-kit/server --host vpn.example.net \
  --output "$PWD/tablet" --client-name tablet --max-sessions 2
```

`add-client` writes a new bundle, the client's public key and PSK under the
store's `authorized/` directory, and a replacement `authorized-keys.json` that
grants the kit's standard `tcp` and `udp` services. It changes nothing unless
every step succeeds, and files it adds to the server tree keep the store's
owner. `--host` must be the name the server certificate was issued for.
`--max-sessions` is optional, and `init` accepts it too.

To revoke a device, remove it and reload. Its sessions end at once:

```bash
yume-setup remove-client --server /etc/yume --client-name tablet
systemctl reload yumed
```

`remove-client` replaces the store atomically, then deletes the client's
public key and PSK. It refuses to remove the last client, because the daemon
requires at least one.

## Run the daemon as a service

The Debian `yume-daemon` package installs `/usr/bin/yumed`, a credential-free
bootstrap `/etc/yume/yumed.json` and a hardened, disabled `yumed.service` that
runs as the locked `yume` account. Install only the kit's `server/` contents
under `/etc/yume`, keeping its `credentials/` and `cover-site/` layout. Private
files must be owned by `yume` with mode `0600`, and `credentials/` should be
mode `0700`. Then validate as the service account and start the service:

```bash
runuser -u yume -- yume-doctor --config /etc/yume/yumed.json
runuser -u yume -- yumed --config /etc/yume/yumed.json --validate
systemctl start yumed.service
```

The unit repeats validation before every start, grants only
`CAP_NET_BIND_SERVICE` for port 443, and reads `/etc/yume` without being able to
modify it. Enable it at boot only once the deployment is ready. The static
cover site is served in-process; no separate HTTP backend runs. If a proxy sits
in front of `yumed`, use TCP passthrough; terminating TLS breaks admission,
which is bound to the TLS connection. The package's `README.Debian` holds the
complete checklist.

## Client identities and limits

`credentials/authorized-keys.json` lists the client identities the daemon
accepts. Each entry names a composite identity with its SHA-256 fingerprint,
its access PSK file, and the configured services it may open. An entry may add
`max_sessions`, an integer from 1 to 1024. When a new session of that identity
would exceed it, the daemon ends the identity's oldest session. A client that
reconnects after a network change therefore replaces its own half-open session
instead of being refused. Without the field an identity is bounded only by the
daemon's 128-session capacity. `admin-keys.json` is a separate store of
second-factor identities and grants no traffic.

SIGHUP, or `systemctl reload yumed` with the packaged unit, makes the daemon
read both stores and its composite and ML-KEM keys again without dropping other
clients. Later sessions authenticate against the new stores. Established
sessions use the new grants for their next stream. Sessions of a removed
identity, or beyond a lowered `max_sessions`, end at once. An invalid store is
refused and the previous credentials stay in force. The daemon logs the outcome
either way. TLS certificate and admission key changes still need a restart,
and a changed admission key is refused. The schema-1 `limits` object bounds each session's frames,
streams, queued bytes, pending opens, rekey work, control messages and packets;
the [native guide](development/ytp1/README.md#configuration-authority) owns
those fields.

For hard process ceilings, use systemd rather than in-process settings:

```ini
# systemctl edit yumed.service
[Service]
CPUQuota=800%
MemoryHigh=768M
MemoryMax=1G
TasksMax=1024
```

Keep `MemoryMax` above expected session, socket, TLS and library memory.
Too tight a ceiling lets the kernel terminate the daemon instead of the daemon
refusing work.

## Name resolution

The client resolves a server host that is a name, and the daemon resolves the
destination names that clients request through direct TCP/UDP adapters and
SOCKS5. Both use the system resolver configuration, including `/etc/hosts` and
NSS modules, in a separate helper process. It appears as a `yume-resolver`
child after the first lookup. The helper holds no connections, keeps no
capabilities, and runs each lookup on its own thread. Stopping `yume` or
`yumed` kills it, so a stalled DNS server or NSS module never delays shutdown.
A numeric host or `endpoint.connect_address` needs no lookup. A client with a
managed TUN adapter requires one, so that its own server route can be excluded
before the tunnel changes routing. Every address a destination name resolves
to must be permitted before the daemon connects.

## Release verification

A Linux x86-64 release publishes `yume-amd64-linux.tar.xz`, holding `yume`,
`yume-setup`, `yume-doctor`, the license, third-party notices, quick start and
a `manifest.json`, and the standalone daemon `yumed-amd64-linux`. Each artifact
has a `.sha256` file, and the release adds `SHA256SUMS.txt` and
`release-manifest.json`. Detached `.sig` files exist only when the release
signing key is configured.

```bash
sha256sum -c SHA256SUMS.txt
gpg --verify yumed-amd64-linux.sig yumed-amd64-linux
```

Treat a missing SHA-256 as a release defect. Before a stable release, the
signatures, and signed commit and tag verification, must become mandatory
rather than skipped when no key is configured.

## Public endpoints

Do not advertise a public endpoint until its users can detect replacement or
downgrade. Publish at least the hostname and port, the daemon release, the TLS
certificate identity, the server's composite identity fingerprint, and the
services and fair-use limits it offers. Whether an operator keeps logs is a
policy claim that clients cannot verify remotely.

## Troubleshooting

`--validate` checks configuration, credentials and destination policy without
opening a network connection. `yume-doctor` also checks the cover site and TLS
material. Both programs exit with `0` after a requested stop, `1` for a runtime
failure, and `2` for a usage or configuration error.

If a client cannot connect:

- confirm TCP reachability to the daemon's port from the client network;
- confirm no HTTP proxy terminates TLS in front of `yumed`;
- check that the client's `endpoint.host` matches the server certificate and
  that client and server come from the same kit, since the admission key and
  TLS trust are per deployment;
- check that the client's identity is listed in `authorized-keys.json` with the
  services it opens;
- check that the cover site still contains the browser profile's assets, which
  `yume-doctor` verifies.

If a session connects but a destination fails, the SOCKS5 reply reports a
refusal or route failure without its detail. Check that the destination, and
every address its name resolves to on the daemon host, lies inside the direct
adapter's configured networks, and that the client's identity is granted that
service. The daemon does not log individual opens.
