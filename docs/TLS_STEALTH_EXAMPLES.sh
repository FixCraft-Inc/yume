#!/bin/bash
# YUME TLS Stealth Mode Examples
# Demonstrates various stealth mode configurations

echo "=== YUME TLS Stealth Mode Examples ==="
echo ""

# Example 1: Basic usage (Stealth mode ON by default)
echo "Example 1: Basic usage with default Chrome profile"
echo "---------------------------------------------------"
cat << 'EOF'
yume --server vpn.example.com \
  -i ~/.ssh/id_ed25519 \
  --socks 1080
EOF
echo ""

# Example 2: Firefox profile with logging
echo "Example 2: Firefox profile with fingerprint logging"
echo "----------------------------------------------------"
cat << 'EOF'
yume --server vpn.example.com \
  -i ~/.ssh/id_ed25519 \
  --socks 1080 \
  --profile firefox \
  --tls-fingerprint-log
EOF
echo ""

# Example 3: Profile rotation for maximum stealth
echo "Example 3: Profile rotation (rotate every 50 connections)"
echo "----------------------------------------------------------"
cat << 'EOF'
yume --server vpn.example.com \
  -i ~/.ssh/id_ed25519 \
  --socks 1080 \
  --tls-stealth-rotate \
  --tls-stealth-rotation-interval 50 \
  --tls-fingerprint-log \
  --tls-fingerprint-log-path ./logs/tls
EOF
echo ""

# Example 4: Safari profile with verification
echo "Example 4: Safari profile with external verification"
echo "-----------------------------------------------------"
cat << 'EOF'
yume --server vpn.example.com \
  -i ~/.ssh/id_ed25519 \
  --socks 1080 \
  --tls-stealth \
  --tls-stealth-profile safari17 \
  --tls-fingerprint-verify \
  --tls-fingerprint-test-endpoint tls.peet.ws
EOF
echo ""

# Example 5: Complete stealth setup with all features
echo "Example 5: Complete stealth configuration"
echo "------------------------------------------"
cat << 'EOF'
yume --server vpn.example.com \
  -i ~/.ssh/id_ed25519 \
  --socks 1080 \
  --tls-stealth \
  --tls-stealth-profile chrome135 \
  --tls-stealth-rotate \
  --tls-stealth-rotation-interval 100 \
  --tls-fingerprint-log \
  --tls-fingerprint-log-path ./logs/fingerprints \
  --inner \
  --inner-heavy \
  --hop
EOF
echo ""

# Example 6: Test fingerprint without connecting
echo "Example 6: Test TLS fingerprint verification"
echo "---------------------------------------------"
cat << 'EOF'
# First, create a test connection to verify fingerprint
yume --server tls.peet.ws \
  -i ~/.ssh/id_ed25519 \
  --tls-stealth \
  --tls-stealth-profile chrome135 \
  --tls-fingerprint-verify \
  --tls-fingerprint-log

# Check the logs
cat ./logs/fingerprints/fingerprints-latest.json | tail -1 | jq '.'
EOF
echo ""

# Example 7: Port forwarding with stealth mode
echo "Example 7: Local port forward with stealth mode"
echo "------------------------------------------------"
cat << 'EOF'
yume --server vpn.example.com \
  -i ~/.ssh/id_ed25519 \
  -L 8080:internal.example.com:80 \
  --tls-stealth \
  --tls-stealth-profile firefox126
EOF
echo ""

# Example 8: Remote command execution with stealth
echo "Example 8: Run command through stealth tunnel"
echo "----------------------------------------------"
cat << 'EOF'
yume --server vpn.example.com \
  -i ~/.ssh/id_ed25519 \
  --run "ssh -p 22 user@remote-host" \
  --tls-stealth
EOF
echo ""

# Example 9: Configuration file with stealth settings
echo "Example 9: Using configuration file"
echo "------------------------------------"
cat << 'EOF'
# Create config/yume.json with stealth settings:
{
  "server": "vpn.example.com",
  "port": 443,
  "identity": "~/.ssh/id_ed25519",
  "socks_port": 1080,
  "tls_stealth_enabled": true,
  "tls_stealth_profile": "chrome135",
  "tls_stealth_rotate": true,
  "tls_stealth_rotation_interval": 100,
  "tls_fingerprint_log": true,
  "tls_fingerprint_log_path": "./logs/tls"
}

# Then run:
yume --config config/yume.json
EOF
echo ""

# Example 10: Monitoring and analysis
echo "Example 10: Analyze fingerprint logs"
echo "-------------------------------------"
cat << 'EOF'
# View latest fingerprint
cat ./logs/fingerprints/fingerprints-latest.json | tail -1 | jq '{
  ja3_hash,
  ja4_hash,
  profile,
  handshake_duration_ms,
  similarity_score
}'

# Count connections per profile
cat ./logs/fingerprints/fingerprints-latest.json | jq -r '.profile' | sort | uniq -c

# Calculate average handshake time
cat ./logs/fingerprints/fingerprints-latest.json | jq '.handshake_duration_ms' | \
  awk '{sum+=$1; count++} END {print "Average:", sum/count, "ms"}'

# Export to CSV for Excel analysis
cat ./logs/fingerprints/fingerprints-latest.csv | column -t -s,
EOF
echo ""

echo "=== Testing TLS Fingerprints ==="
echo ""
echo "You can test your TLS fingerprint at these endpoints:"
echo "  - https://tls.peet.ws/api/all"
echo "  - https://ja3er.com/"
echo "  - https://browserleaks.com/ssl"
echo ""
echo "Compare your fingerprint with real browsers to verify stealth mode."
echo ""
