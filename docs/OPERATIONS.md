# YUME operations

> **Runnable transport-v2 path:** this is the current operator reference. The
> [YTP/1 foundation page](development/ytp1/README.md#configuration-authority) covers an
> experimental schema-1 surface that does not drive these binaries.

This page covers the release, deployment, and service workflows that operators need after the first successful connection.

## Release verification

The first stable release surface is Linux x86-64 only. A release publishes:

- `yume-amd64-linux.tar.xz`, the client bundle (`yume`, the optional temporarily
  retained Chrome TLS helper, license, third-party notices, quick start, and a
  per-bundle `manifest.json`)
- `yumed-amd64-linux`, the daemon executable
- a `.sha256` file for each of those two artifacts
- aggregate `SHA256SUMS.txt`
- `release-manifest.json`
- detached signatures once the stable publication gate is enabled

Recommended verification:

```bash
sha256sum -c SHA256SUMS.txt
gpg --verify yumed-amd64-linux.sig yumed-amd64-linux
```

The manifest currently records file size, OS, architecture, component, linkage,
SHA-256 and an informational MD5 digest. The workflow does not emit MD5 sidecar
files, and it generates the manifest before signing, so its current signature
fields remain null even when `.sig` files are subsequently produced. Treat a
missing mandatory SHA-256 as a release problem. Before stable publication,
generate/finalize the manifest after signing and make commit/tag verification
and artifact signatures mandatory rather than silently continuing when the
signing secret is absent.

## BaseFWX pinning

YUME depends on BaseFWX for post-quantum and AEAD primitives. The release and
CI workflows read its repository, exact commit, and minimum compatible version
from `config/dependencies.json`, then fail preflight if the commit is not
reachable. Keep production revisions immutable; use
`scripts/yume_dependencies.py get basefwx revision` instead of copying the
commit into another script or workflow.

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
ExecStart=/usr/local/bin/yumed --listen 443 --cert /etc/yume/server.crt --key /etc/yume/server.key --auth-keys /etc/yume/authorized_keys --obfs-secret-file /etc/yume/secrets/admission.hex --inner-psk-file /etc/yume/secrets/inner.hex --real-backend loopback://127.0.0.1:3000 --real-index /etc/yume/cover-index.html
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

H2 cover proxying admits four retained GET/HEAD streams per connection and 32
per process. A slot spans backend work and flow-controlled H2 response lifetime;
reset or disconnect cancels it. The resulting maximum cover-body state is 32
MiB per connection and 256 MiB process-wide before protocol/header overhead,
with a separate 32-MiB carrier output cap. Serialized cover wire also remains
charged at 32 MiB per connection and 256 MiB process-wide until the TLS write
finishes. The conservative combined maxima, when new backend bodies coexist
with wire from earlier requests, are therefore 64 MiB per connection and 512
MiB process-wide before protocol/TLS overhead. Request-count saturation returns
retryable `REFUSED_STREAM`; exhausting the downstream wire budget closes that
connection fail-closed. Alert on either: it can be an undersized/slow cover
backend, a slow reader, or an unauthenticated fan-out/window-update attempt.
Raising the fixed limits without a measured memory and active-probe review is
not an operational fix.

The current preparation-only release output copies `yumed` as a bare binary and
does not bundle `tools/cover-node/backend.mjs` or a Node service unit. It is
therefore not a standalone deployable server artifact despite the binary name;
use the exact-source/CMake install layout for development. Packaging the pinned
cover backend and supervision contract is a release blocker.

## Capacity, fairness, and process limits

Set `egress_mbps` at or below the server's measured upload/link capacity. Leave
headroom for TLS overhead, the cover service, SSH, and normal host traffic. For
example, start around `900` on a stable 1-Gbit/s link or `2200` on a 2.5-Gbit/s
link, then verify from a remote client. `0` disables shaping and is not
recommended for a shared public server.

```jsonc
{
  "threads": 8,
  "transport_profile": "chrome151-node24-v1",
  "max_sessions": 256,
  "bulk_key_max_sessions": 64,
  "security_mode": "extreme",
  "rekey_window": 8,
  "accept_rate_limit": 100,
  "egress_mbps": 900,
  "filter_memory_mib": 64
}
```

`transport_profile` is mandatory protocol identity, not presentation metadata.
Dev6 accepts only `chrome151-node24-v1`; a stale or missing supported identity
cannot be negotiated or silently downgraded.

The matching CLI flags are `--threads`, `--max-sessions`,
`--bulk-key-max-sessions`, `--rekey-window`, `--accept-rate-limit`,
`--egress-mbps`, and `--filter-memory-mib`. `rekey_window` is the number of
concurrent directional epoch offers accepted from one session and the ceiling
on the server's own sending window (1..64, default 8). It is what lifts
per-round-trip throughput on high-latency links. Under Extreme, each prepared
epoch adds 256 KiB per rekey round trip. It also bounds how much ML-KEM work
one peer can request. Under the default Extreme security mode, the 256 KiB,
512-frame, and 500 ms per-epoch limits are the same at every depth. See
`docs/IMPLEMENTATION_STATUS.md` for the public network qualification boundary.
The daemon defaults to 256
live sessions and 64 authenticated sessions per bulk key. An administrator can
explicitly use `--max-sessions 0` to remove the global cap, but should normally
raise a finite limit instead.

Security mode selection is currently a JSON configuration contract. Use
`extreme`, `normal`, `soft`, or the complete `ultimate` object documented in
`docs/SECURITY_MODES.md`; there is no partial Ultimate fallback.

`threads` bounds YUME worker concurrency; it is not a hard machine-wide CPU
percentage. Per-session queue bounds, the filter memory limit, and session
limits constrain known allocations, but no portable
in-process setting can guarantee a final RSS ceiling for OpenSSL, the C++
runtime, socket buffers, and plugins. Use systemd/cgroup controls for hard
process limits:

```ini
# systemctl edit yumed.service   (package yume-daemon installs yumed.service)
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

Run `systemctl daemon-reload && systemctl restart yumed`, then confirm
with `systemctl show yumed -p CPUQuotaPerSecUSec -p MemoryHigh -p
MemoryMax -p TasksMax`. Keep `MemoryMax` comfortably above expected
session/socket, TLS, and runtime-library memory; setting it too tightly can
cause the kernel to terminate the daemon rather than gently reject work.

With `egress_mbps` enabled, active identities receive weighted shares. Put a
top-level decimal `weight` in the fingerprint's metadata; `1.5` receives 1.5
times the share of a simultaneously active `1.0` identity. Individual and
operator keys form one identity each. Every authenticated bulk-key session is
counted separately and receives its own fair-share slot. See
`docs/PERMISSIONS.md` for safe bulk/operator examples and restrictions. The
packet-native TUN uplink must also be capped on its TUN/physical
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

## Weak-host and portable-server status

The current 2.0 qualification target is glibc Linux x86_64 for the CLI and
daemon, using the in-process patched-OpenSSL backend. The retained helper is a
separate comparison arm. This document does **not** claim that YUME is ready
for every server, architecture, libc, container image, or init system. Add a
support-matrix cell only after its exact dependency build, package, startup,
service, native TLS capability, certificate/exporter, multi-epoch transfer and
shutdown checks pass; name QEMU/emulation evidence when real hardware was not
used.

Two useful future qualification targets are a constrained 1-vCPU/1-GiB host
and a small 2-vCPU/2-GiB host. They are test targets, not current minimum-system
claims.

`scripts/yume_constrained_host.py` applies those tiers. It runs the workload in
a transient systemd user scope with `CPUQuota`, `MemoryMax`, `MemorySwapMax=0`
and `TasksMax` set, and reads the accounting back from the scope's own cgroup:
`memory.peak` and `pids.peak` are exact high-water marks, where sampling from
outside only sees whatever a poll happened to catch. Swap is pinned off because
a tier that silently swaps is not the tier it claims. No privilege is needed
where the `cpu`, `memory` and `pids` controllers are delegated to the user
slice, and the tool refuses to report a tier at all when they are not -- an
unbounded run must not be recorded as a bounded one.

    scripts/yume_constrained_host.py --tier 1v1g -- <workload command>

`--repeat N` runs the workload N times in one scope, which is what percentiles
and leak detection need: peak descriptors, tasks and RSS that do not scale with
N are evidence nothing is retained between sessions. `--collect
NAME=GLOB:PATH` reads a numeric value out of each iteration's JSON and reports
p50/p95/p99 by nearest rank, so a reported p99 is a value that actually
occurred. `--evidence GLOB` points at the logs proving the cryptographic stack
stayed on, restricted to files written during the run so a stale tree cannot
satisfy the check.

The verdict is deliberately hard to earn. A workload that was OOM-killed fails
even if it exited zero, missing accounting fails as unproven rather than
passing, and output showing the cryptographic stack was reduced to fit the tier
fails regardless of resource use. That last rule is the point of the exercise:
fitting a small host by weakening post-quantum establishment, ratcheting or
verification is not a pass.

Freeze a workload and explicit cgroup CPU, memory, task and fd limits, then
retain artifacts for:

- cold and warm handshake plus rekey p50/p95/p99;
- steady and peak RSS, CPU, client/Node tasks, open fds and queue depth;
- upload, download, interactive latency and high-RTT prepared-depth behavior;
- admission floods, backend slowdown, memory pressure, session-cap rejection,
  cleanup and recovery; and
- a sustained run with no root/window leak, unbounded queue growth, child
  residue or cryptographic downgrade.

Derive `threads`, `max_sessions`, `bulk_key_max_sessions`, `rekey_window`,
`filter_memory_mib`, socket credit and cgroup values from those measurements;
do not publish an untested “low-memory preset.” A smaller `rekey_window` reduces
per-session ML-KEM work and retained future roots, but can reduce throughput on
a high-RTT path. Solve that trade-off with a bounded authenticated-ACK
preparation policy and admission/resource caps, never by enlarging the
per-epoch byte/frame/time limits or disabling hybrid-PQ establishment, TLS
verification, ratcheting, replay protection, or fail-closed behavior.

On overload, the desired behavior is bounded rejection and recovery. An OOM
kill, swap storm, process storm, silent fallback to the diagnostic TLS
backend, or a cover identity that changes with machine size fails the tier.
See `docs/IMPLEMENTATION_STATUS.md` for the current high-latency validation
boundary.

## Key and permission operations

For new deployments, `yume-setup init` creates the protected admission/inner
secret files, TLS and operator-identity chain, safe key stores, configs, and a
first client profile in one owner-only directory. `yume-setup issue-key`
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

Prefer `yume-setup issue-key`. The `--keys-gen` command creates both files
exclusively at mode `0600`, refuses to overwrite either path, and removes the
private half if it cannot complete the pair. A private `0700` output directory
still protects file names and other provisioning artifacts.

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

## Website documentation

The GitHub Pages site at `website/` publishes the tracked top-level documents
under `docs/`, the protocol documents, and `CONTRIBUTING.md`. The canonical
Markdown stays in the repository root. Generated files under
`website/docs/` are ignored and must not be edited by hand.

Run `bash scripts/sync_website_docs.sh`, then
`python3 scripts/check_website_catalog.py`. CI and Pages follow that order and
build only from the freshly generated mirror. Because `website/docs/**/*.md`
is ignored, running `--check` on a clean checkout would compare canonical
sources with an absent mirror; after local generation it can confirm that no
later local edit changed the mirror. The catalog check validates source routes,
source markers, and fenced-code language tags.
`website/docs/index.html` remains hand-written, and `docs/agents/` stays outside
the website reader path.

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
