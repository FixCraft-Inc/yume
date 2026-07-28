# YUME operations

This page covers the release, deployment, and service workflows that operators need after the first successful connection.

## Release verification

Each release is expected to publish:

- client and daemon artifacts for supported targets
- per-artifact `.sha256` files
- per-artifact `.md5` files
- aggregate `SHA256SUMS.txt` and `MD5SUMS.txt`
- `release-manifest.json`
- optional `.sig` detached signatures when GPG secrets are configured

Recommended verification:

```bash
sha256sum -c SHA256SUMS.txt
md5sum -c MD5SUMS.txt
gpg --verify yumed-amd64-linux.sig yumed-amd64-linux
```

The manifest records file size, OS, architecture, component, linkage, hashes, and signature sidecars. Treat missing mandatory hashes as a release problem.

## BaseFWX pinning

YUME depends on BaseFWX for post-quantum and AEAD primitives. The release and CI workflows read `config/refs/basefwx.ref`, fetch that exact ref, and fail preflight if it is not reachable. Keep this file pinned to a commit or immutable release ref for production releases.

For normal local development, `ezbuild.sh` preserves an existing attached
BaseFWX branch and builds its current files in place. It does not shallow the
repository or detach the branch. Use `BASEFWX_SYNC_MODE=pinned ./ezbuild.sh`
for release evidence; pinned mode refuses a dirty BaseFWX worktree instead of
overwriting it. `BASEFWX_SYNC_MODE=worktree` makes the no-fetch behavior
explicit.

Fetchability alone does not prove that a SHA belongs to the intended release
lineage after a history rewrite. Before a stable release, also verify that the
pin is the chosen canonical tag/commit and build YUME against a clean checkout
of that exact object; a build against the local sibling's `main` is not proof
of the pinned dependency.

## Service deployment

A minimal systemd service can run the daemon with a dedicated user:

```ini
[Unit]
Description=YUME daemon
After=network-online.target
Wants=network-online.target

[Service]
User=yume
Group=yume
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/yumed --listen 443 --cert /etc/yume/server.crt --key /etc/yume/server.key --auth-keys /etc/yume/authorized_keys --obfs-secret-file /etc/yume/secrets/admission.hex --inner-psk-file /etc/yume/secrets/inner.hex --real-backend loopback://127.0.0.1:3000
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

The Node.js 24 LTS cover site is a separate service bound only to the configured
loopback address. Start and health-check it before `yumed`; do not expose its
port publicly. Keep `auth_keys.meta`, TLS private keys, and both 32-byte secret
files readable only by the daemon user. Each secret file is exactly 64 lowercase
hex characters with no group/world permission bits.

## Capacity, fairness, and process limits

Set `egress_mbps` at or below the server's measured upload/link capacity. Leave
headroom for TLS overhead, the cover service, SSH, and normal host traffic. For
example, start around `900` on a stable 1-Gbit/s link or `2200` on a 2.5-Gbit/s
link, then verify from a remote client. `0` disables shaping and is not
recommended for a shared public server.

```jsonc
{
  "threads": 8,
  "max_sessions": 256,
  "bulk_key_max_sessions": 64,
  "accept_rate_limit": 100,
  "egress_mbps": 900,
  "filter_memory_mib": 64
}
```

The matching CLI flags are `--threads`, `--max-sessions`,
`--bulk-key-max-sessions`, `--accept-rate-limit`, `--egress-mbps`,
and `--filter-memory-mib`. The daemon defaults to 256 live sessions and 64
authenticated sessions per bulk key. An administrator can explicitly use
`--max-sessions 0` to remove the global cap, but should normally raise a finite
limit instead.

`threads` bounds YUME worker concurrency; it is not a hard machine-wide CPU
percentage. Per-session queue bounds, the filter memory limit, and session
limits constrain known allocations, but no portable
in-process setting can guarantee a final RSS ceiling for OpenSSL, the C++
runtime, socket buffers, and plugins. Use systemd/cgroup controls for hard
process limits:

```ini
# systemctl edit yume-daemon.service (unit name may be yumed.service)
[Service]
# At most eight logical CPUs.
CPUQuota=800%
# Reclaim/throttle pressure before the hard limit.
MemoryHigh=768M
# Hard cgroup memory ceiling.
MemoryMax=1G
TasksMax=1024
LimitNOFILE=65536
```

Run `systemctl daemon-reload && systemctl restart yume-daemon`, then confirm
with `systemctl show yume-daemon -p CPUQuotaPerSecUSec -p MemoryHigh -p
MemoryMax -p TasksMax`. Keep `MemoryMax` comfortably above expected
session/socket, TLS, and runtime-library memory; setting it too tightly can
cause the kernel to terminate the daemon rather than gently reject work.

With `egress_mbps` enabled, active identities receive weighted shares. Put a
top-level decimal `weight` in the fingerprint's metadata; `1.5` receives 1.5
times the share of a simultaneously active `1.0` identity. Individual and
operator keys form one identity each. Every authenticated bulk-key session is
counted separately and receives its own fair-share slot. See
`docs/PERMISSIONS.md` for safe bulk/operator examples and restrictions. The
packet-native TUN uplink must additionally be capped on its TUN/physical
interface with Linux `tc`; it does not traverse every socket-shaper hook.

For an optional, reversible TUN/NAT/UFW setup, review and apply the separate
host helper instead of granting firewall privileges to the daemon:

```bash
yume-packet-quick up --listen build-host.example:8443 \
  --allow-from 192.168.1.0/24 --dry-run
sudo yume-packet-quick up --listen build-host.example:8443 \
  --allow-from 192.168.1.0/24
sudo yume-packet-quick down
```

The helper refuses existing TUN/nft objects, does not flush firewall state or
change default policies, and stores the exact resources it owns under `/run`.
`yumed` itself never invokes it.

## Key and permission operations

For new deployments, `yume-setup init` creates the protected admission/inner
secret files, TLS and operator-identity chain, safe key stores, configs, and a
first device profile in one owner-only directory. `yume-setup issue-key`
handles individual, bounded bulk, and separate admin/operator credentials
without manual PEM concatenation or JSON editing. See `docs/QUICKSTART.md`.

List keys and aliases:

```bash
yumed --auth-keys /etc/yume/authorized_keys --keys-list
```

Add a generated key:

```bash
yumed --auth-keys /etc/yume/authorized_keys --keys-gen ./keys/user1 --keys-gen-add
```

Remove a key or alias:

```bash
yumed --auth-keys /etc/yume/authorized_keys --keys-remove alice
```

`authorized_keys` and `auth_keys.meta` control regular admission and policy.
Controller keys live separately in `operator_keys` and `operator_keys.meta`.
Restart after editing, or use the authenticated reload operation; reload swaps
all four files as one validated snapshot and preserves the previous snapshot if
any new file is malformed.

## Public endpoint policy

Public endpoints should publish:

- hostname and port
- daemon release tag
- TLS certificate identity
- YUME public key or expected key fingerprint
- allowed modes and fair-use limits
- operator CA and delegated-server-certificate SHA-256 fingerprints/serial
- whether the operator advertises privacy-minimizing mode (a policy claim, not remotely provable)
- whether the endpoint accepts only SOCKS/forwarding or also admin/file/chat channels

Do not advertise a public endpoint until users can pin enough metadata to detect replacement or downgrade.

## Website documentation mirror

The GitHub Pages site at `website/` publishes a subset of `docs/` for
browser reading. The canonical copies live in the repository root
`docs/` tree; `website/docs/` is a curated mirror, not a second source
of truth.

Current mirrored pages (under `website/docs/`):

- `QUICKSTART.md`
- `STEALTH.md`
- `PERFORMANCE.md`
- `OPERATIONS.md`
- `PERMISSIONS.md`

When you change an operator-facing doc that appears on the site, update
the matching file under `website/docs/` in the same commit, or remove
the page from the site index until it is synced. Release and packaging
docs (`PACKAGING.md`, man pages, `ARCHITECTURE.md`) stay repo-only
unless explicitly added to the mirror list.

## Troubleshooting

If the client cannot connect:

- confirm direct TCP reachability to the daemon port
- confirm no HTTP proxy is terminating TLS in front of `yumed`
- ensure client and server use the same `--obfs-secret-file` and
  `--inner-psk-file` contents; there is no accepted 2.0 no-inner/no-obfs mode
- verify the separately supervised Node cover is listening on the configured
  loopback IP and passes `yumed`'s startup health check
- check that the client's public key is present in `authorized_keys`
- verify that the server certificate chain matches what the client expects

If forwarding connects but cannot reach a target:

- check `auth_keys.meta` for LAN/private-IP permission if the target is RFC1918 or loopback
- confirm the release was built with the required feature switch
- confirm the daemon was started with the matching runtime flag
- inspect daemon logs for an auth-policy denial
