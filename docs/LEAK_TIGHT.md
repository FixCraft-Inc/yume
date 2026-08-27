# Leak-tight SOCKS5 setup

If you connect to yume via `--socks [addr:]port` and point a browser at
`socks5://127.0.0.1:<port>`, **the SOCKS proxy only covers what the
browser actually routes through it**. Several common things bypass the
proxy by design and leak your real IP. None of these are yume bugs —
they're browser/OS behavior — but yume can't fix them from inside the
SOCKS server. This page lists each leak vector and the exact knob to
close it.

For the current Linux desktop development slice, full-system enforcement requires
an independently reviewed OS-level routing/kill-switch setup such as the
iptables design at the bottom of this page. The separate Android client has
earlier `0.2.0-dev6` non-connected evidence but has not been synchronized to
the current native candidate. It also has not passed connected VPN, DNS, IPv6,
bypass, kill-switch, or release qualification and is not a supported leak-tight
option.

## What leaks, and why

| Leak | What happens | Why SOCKS5 can't catch it |
| --- | --- | --- |
| **WebRTC** | Browser collects ICE candidates from local NICs and STUN/TURN servers over UDP. Sites that probe via WebRTC (`whoer.net`, `browserleaks.com`, most "what's my IP" pages) see your real LAN + public IP. | WebRTC bypasses HTTP proxy settings entirely. SOCKS5 doesn't see it. |
| **QUIC over UDP** | Chromium prefers QUIC for Cloudflare / Google / many CDN-hosted sites. Chrome's SOCKS5 implementation does **not** proxy UDP. Outcome: either falls back to TCP+TLS (slow, possibly partial-page leaks during fallback) or fails to load. | SOCKS5 v5 supports UDP only via UDP ASSOCIATE which most browsers don't implement. |
| **DNS prefetcher / DoH** | Browsers may resolve domains via the system resolver or a configured DNS-over-HTTPS endpoint **before** the request goes to the proxy. The lookup itself leaks the domain (to your ISP / your DoH provider). | The lookup never enters the SOCKS connection. |
| **Captive-portal probe, Safe Browsing pings, telemetry** | Chromium periodically hits `gstatic.com` / `clients4.google.com` / similar for connectivity check, malware lookup, etc. These can use a separate code path that bypasses the proxy under some flag combinations. | Same as above — they don't go through the user-facing SOCKS path. |
| **OS-level traffic** | Anything *outside* the browser — system updaters, dropbox, telemetry agents, NTP, mDNS — continues using the default route. | SOCKS5 is application-level only. |

## Chromium / Edge / Brave — leak-tight launch flags

Replace `1088` with whatever port you passed to `--socks`.

```bash
chromium \
  --proxy-server="socks5://127.0.0.1:1088" \
  --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1" \
  --disable-quic \
  --webrtc-ip-handling-policy=disable_non_proxied_udp \
  --disable-features=AsyncDns,WebRtcAllowInputVolumeAdjustment \
  --enable-features=WebRtcHideLocalIpsWithMdns \
  --no-pings
```

Flag by flag:

- `--proxy-server` — route HTTP/HTTPS through SOCKS5.
- `--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"` —
  refuse to resolve anything locally. Forces every name lookup through
  the proxy. `EXCLUDE 127.0.0.1` keeps Chrome's internal pages
  (`chrome://`) working.
- `--disable-quic` — kills the UDP fast-path that bypasses SOCKS5.
  Slightly slower on QUIC-supporting sites but consistently routed.
- `--webrtc-ip-handling-policy=disable_non_proxied_udp` — the most
  important WebRTC flag. Tells WebRTC to skip any candidate that
  would leak a non-proxy interface. Sites that need WebRTC (Meet,
  Discord, Whereby) may not work without a TURN-over-TCP server.
- `--enable-features=WebRtcHideLocalIpsWithMdns` — extra mitigation
  that masks local IPs with mDNS hostnames in any WebRTC offer that
  still happens.
- `--no-pings` — drops the hyperlink-`ping` attribute beacon path
  that some sites use for click tracking via a separate connection.
- `--disable-features=AsyncDns` — disables Chrome's built-in async
  DNS resolver, forcing it onto the SOCKS DNS path.

A profile-isolated launch:

```bash
chromium \
  --user-data-dir=$HOME/.cache/chromium-yume \
  --proxy-server="socks5://127.0.0.1:1088" \
  --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1" \
  --disable-quic \
  --webrtc-ip-handling-policy=disable_non_proxied_udp \
  --enable-features=WebRtcHideLocalIpsWithMdns \
  --no-pings
```

## Firefox — leak-tight `about:config`

| Pref | Set to |
| --- | --- |
| `network.proxy.type` | `1` |
| `network.proxy.socks` | `127.0.0.1` |
| `network.proxy.socks_port` | `1088` (or your port) |
| `network.proxy.socks_version` | `5` |
| `network.proxy.socks_remote_dns` | **`true`** ← critical, else DNS leaks |
| `network.http.http3.enabled` | `false` (kills QUIC) |
| `network.http.http3.enable_qlog` | `false` |
| `media.peerconnection.enabled` | `false` (kills WebRTC entirely) |
| `media.peerconnection.ice.no_host` | `true` (if you keep WebRTC) |
| `media.peerconnection.ice.default_address_only` | `true` |
| `network.dns.disablePrefetch` | `true` |
| `network.dns.disablePrefetchFromHTTPS` | `true` |
| `network.predictor.enabled` | `false` |
| `network.prefetch-next` | `false` |
| `browser.safebrowsing.downloads.remote.enabled` | `false` |

## Verifying you're tight

```bash
# 1. tcpdump: only the yume client should be talking to your yume server.
sudo tcpdump -n -i any 'not host 127.0.0.1 and not host <your-yume-server-ip>'
# If anything shows up while you browse, that's a leak. Identify by
# port (53=DNS, 443/UDP=QUIC, 19302=STUN, etc) and close per the
# table above.

# 2. ipinfo.io check via curl — must show the server's exit IP.
curl --socks5-hostname 127.0.0.1:1088 https://ipinfo.io/ip
# --socks5-hostname forces curl to send the domain via the proxy
# instead of resolving locally; matches what a leak-tight browser
# should do.

# 3. WebRTC leak check (requires browser):
#    https://browserleaks.com/webrtc
#    Pre-fix expected: shows your real public + LAN IP.
#    With the flags above expected: no candidates, or mDNS-only.

# 4. QUIC check (Chromium):
#    chrome://net-internals/#quic
#    Pre-fix: lists active QUIC sessions.
#    With --disable-quic: empty.
```

## Full-system tight: iptables / nftables

The browser-flag approach only covers one browser. To force **all
outbound** to go through yume's SOCKS port (including system services,
other apps, anything else on the box), use a redirector like
[`redsocks`](https://github.com/darkk/redsocks) + iptables.

```bash
# Install redsocks (Debian/Ubuntu)
sudo apt install redsocks

# /etc/redsocks.conf — point at yume's SOCKS port
base { log_debug = off; log_info = on; daemon = on;
       redirector = iptables; }
redsocks { local_ip = 127.0.0.1; local_port = 12345;
           ip = 127.0.0.1; port = 1088; type = socks5; }

sudo systemctl restart redsocks

# Redirect every outbound TCP from non-root processes to redsocks.
# Replace YUME_UID with the UID that runs the yume client itself
# (we never want yume's own traffic to recurse into the redirect).
sudo iptables -t nat -N YUMETIGHT
sudo iptables -t nat -A YUMETIGHT -m owner --uid-owner $YUME_UID -j RETURN
sudo iptables -t nat -A YUMETIGHT -d 127.0.0.0/8         -j RETURN
sudo iptables -t nat -A YUMETIGHT -d <your-yume-server>  -j RETURN
sudo iptables -t nat -A YUMETIGHT -p tcp -j REDIRECT --to-ports 12345
sudo iptables -t nat -A OUTPUT -p tcp -j YUMETIGHT

# Block all outbound UDP except DNS-to-the-proxy. UDP can't be NAT'd
# to a SOCKS5 v5 ASSOCIATE in practice, so the safe option is to
# drop. Browsers fall back to TCP for everything.
sudo iptables -A OUTPUT -p udp ! --dport 53 -m owner ! --uid-owner $YUME_UID -j REJECT

# Block IPv6 outbound entirely (it bypasses the IPv4 NAT redirect).
sudo ip6tables -A OUTPUT -m owner ! --uid-owner $YUME_UID -j REJECT
```

With this in place, the browser-side flags become belt-and-suspenders
rather than mandatory — anything that escapes the SOCKS path hits the
iptables wall and fails closed.

**Test the kill-switch:** stop the yume client. With the rules above,
nothing on the box should be able to reach the internet. If anything
still loads, your rule set has a hole.

## Android: native re-synchronization and connected leak gates remain open

The Android architecture uses `android.net.VpnService` and a TUN device to
capture app traffic. The separate checkout has earlier `0.2.0-dev6`
client-only ABI and non-connected ARM64/device lifecycle evidence, but it has
not been synchronized against the current native stabilization candidate.
That also does not establish routed behavior: matching-server packet transfer,
DNS/IPv6 policy, bypass, leak, revoke/reconnect, and recovery qualification
remain open.

Do not rely on the present Android build as a YUME kill switch. Its TUN
capture, route/DNS policy, bypass behavior, and fail-closed recovery need direct
connected-device evidence before this claim can be made.

## Quick decision tree

```
Are you on Android?
├─ Yes → Connected Android leak-tight support is not qualified; do not rely on it yet.
└─ No → Are you OK with browser-only coverage?
        ├─ Yes → Use the Chromium / Firefox flags above.
        └─ No  → Set up redsocks + iptables for full-system tight.
```
