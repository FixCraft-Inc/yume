#!/usr/bin/env bash
# Run the YUME fuzz harnesses for a bounded time and fail on any finding.
#
# Usage: run_fuzzers.sh BIN_DIR SECONDS [OUT_DIR]
#
#   BIN_DIR   directory holding the built yume_fuzz_* executables
#   SECONDS   wall-clock budget per harness
#   OUT_DIR   working directory for seeds, corpora, logs and artifacts
#
# A libFuzzer finding is written under OUT_DIR/artifacts and this script exits
# nonzero, so the same invocation works as a CI gate and as a local run. Longer
# campaigns use the same script with a larger budget and a corpus carried over
# from a previous run.
set -euo pipefail

BIN_DIR=${1:?usage: run_fuzzers.sh BIN_DIR SECONDS [OUT_DIR]}
SECONDS_PER_TARGET=${2:?usage: run_fuzzers.sh BIN_DIR SECONDS [OUT_DIR]}
OUT_DIR=${3:-fuzz-out}
if [[ ! "$SECONDS_PER_TARGET" =~ ^[1-9][0-9]*$ ]]; then
    echo "SECONDS must be a positive integer" >&2
    exit 2
fi
if [[ $# -gt 3 ]]; then
    echo "usage: run_fuzzers.sh BIN_DIR SECONDS [OUT_DIR]" >&2
    exit 2
fi

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

mkdir -p "$OUT_DIR/artifacts"
python3 "$HERE/make_seeds.py" "$OUT_DIR"

# harness binary : seed and corpus suffix : maximum input bytes
TARGETS=(
    "yume_fuzz_ytp1_protocol:ytp1_protocol:1048589"
    "yume_fuzz_ytp1_auth:ytp1_auth:65537"
    "yume_fuzz_config_v1:config_v1:1048577"
)

status=0
for entry in "${TARGETS[@]}"; do
    IFS=: read -r binary tag max_length <<< "$entry"
    path="$BIN_DIR/$binary"
    if [[ ! -x "$path" ]]; then
        echo "missing harness: $path" >&2
        status=1
        continue
    fi
    mkdir -p "$OUT_DIR/corpus_$tag"
    echo "=== $binary (${SECONDS_PER_TARGET}s) ==="
    # -rss_limit_mb bounds a harness that allocates from a peer-declared
    # length. -timeout turns a hang into a reported finding rather than a
    # silent budget overrun.
    if ! "$path" \
            "$OUT_DIR/corpus_$tag" "$OUT_DIR/seeds_$tag" \
            -max_total_time="$SECONDS_PER_TARGET" \
            -max_len="$max_length" \
            -rss_limit_mb=4096 \
            -timeout=25 \
            -artifact_prefix="$OUT_DIR/artifacts/${tag}_" \
            -print_final_stats=1 \
            > "$OUT_DIR/log_$tag.txt" 2>&1; then
        echo "FINDING in $binary; tail of $OUT_DIR/log_$tag.txt:" >&2
        tail -40 "$OUT_DIR/log_$tag.txt" >&2
        status=1
        continue
    fi
    grep -E '^Done .* runs in|^stat::' "$OUT_DIR/log_$tag.txt" || true
done

found=$(find "$OUT_DIR/artifacts" -type f | wc -l)
if [[ "$found" -ne 0 ]]; then
    echo "libFuzzer wrote $found artifact(s) under $OUT_DIR/artifacts" >&2
    status=1
fi

if [[ "$status" -eq 0 ]]; then
    echo "fuzz: all harnesses completed with no finding"
fi
exit "$status"
