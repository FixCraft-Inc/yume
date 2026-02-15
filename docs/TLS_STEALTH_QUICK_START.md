# YUME TLS Stealth Mode - Quick Start

## What is TLS Stealth Mode?

TLS Stealth Mode makes YUME connections look like legitimate browser traffic by mimicking browser TLS fingerprints. This helps evade Deep Packet Inspection (DPI) and censorship systems.

## Quick Start

### Basic Usage (Stealth Mode ON by Default)
```bash
yume --server your.server.com -i ~/.ssh/id_ed25519 --socks 1080
```

### Use Firefox Profile
```bash
yume --server your.server.com -i ~/.ssh/id_ed25519 --socks 1080 --profile firefox
```

### Disable Stealth Mode
```bash
yume --server your.server.com -i ~/.ssh/id_ed25519 --socks 1080 --no-stealth
```

### Enable Logging
```bash
yume --server your.server.com -i ~/.ssh/id_ed25519 --socks 1080 --tls-fingerprint-log
```

## Available Browser Profiles

- `chrome` - Chrome 135 (default, latest)
- `firefox` - Firefox 126
- `safari` - Safari 17

## All Options

| Option | Description |
|--------|-------------|
| `--profile <name>` | Choose browser profile (chrome, firefox, safari) |
| `--no-stealth` | Disable stealth mode (enabled by default) |
| `--tls-stealth-rotate` | Rotate between profiles |
| `--tls-stealth-rotation-interval <n>` | Rotate every N connections |
| `--tls-fingerprint-log` | Log TLS fingerprints |
| `--tls-fingerprint-log-path <path>` | Set log directory |
| `--tls-fingerprint-verify` | Verify fingerprint online |
| `--tls-fingerprint-test-endpoint <host>` | Test endpoint |

## Common Use Cases

### Maximum Stealth
```bash
yume --server your.server.com -i ~/.ssh/id_ed25519 --socks 1080 \
  --tls-stealth-rotate \
  --tls-stealth-rotation-interval 50 \
  --tls-fingerprint-log
```

### Debug Mode
```bash
yume --server your.server.com -i ~/.ssh/id_ed25519 --socks 1080 \
  --tls-fingerprint-log \
  --tls-fingerprint-verify
```

## View Logs

```bash
# Latest fingerprint (JSON)
cat ./logs/fingerprints/fingerprints-latest.json | tail -1 | jq '.'

# All logs
cat ./logs/fingerprints/fingerprints-latest.json | jq '.'

# CSV format
column -t -s, < ./logs/fingerprints/fingerprints-latest.csv
```

## Test Your Fingerprint

```bash
# Connect to test endpoint
yume --server tls.peet.ws -i ~/.ssh/id_ed25519 --tls-fingerprint-verify

# Check online
curl https://tls.peet.ws/api/all
```

## When to Use Stealth Mode

✅ **Use when:**
- Connecting through censored networks
- Evading DPI-based blocking
- Need traffic to look like browser traffic
- Maximum privacy desired

❌ **Not needed when:**
- Direct connection to trusted server
- Performance is critical (minimal overhead though)
- Simple VPN usage on free network

## Performance

- **CPU**: <1% additional overhead
- **Memory**: ~100KB per connection
- **Latency**: ~5ms additional handshake time

## Learn More

- Full documentation: [docs/TLS_STEALTH_MODE.md](TLS_STEALTH_MODE.md)
- Examples: [docs/TLS_STEALTH_EXAMPLES.sh](TLS_STEALTH_EXAMPLES.sh)
- Implementation: [docs/TLS_STEALTH_IMPLEMENTATION.md](TLS_STEALTH_IMPLEMENTATION.md)

## Troubleshooting

**Connection fails:**
```bash
# Try different profile
--tls-stealth-profile firefox126
```

**Fingerprint doesn't match:**
```bash
# Enable verification
--tls-fingerprint-verify --tls-fingerprint-log
```

**Need help:**
```bash
yume --help
```

---

**Tip**: Stealth mode is ON by default. Combine with `--inner` and `--hop` for maximum security:
```bash
yume --server your.server.com -i ~/.ssh/id_ed25519 --socks 1080 \
  --inner --inner-heavy --hop
```
