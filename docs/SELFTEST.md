# Local Self-Test Benchmark

`yume-selftest` is an optional desktop developer tool. It starts temporary
local `yumed` and `yume` processes, routes SOCKS traffic to a loopback echo
server, and reports protocol-only latency and throughput against direct
loopback.

Build it explicitly:

```bash
cmake -B build-selftest \
  -DYUME_BUILD_SELFTEST=ON \
  -DYUME_FEATURE_LAN_BRIDGE=ON
cmake --build build-selftest --target yume-selftest yume yumed
```

Run a quick local benchmark:

```bash
build-selftest/bin/yume-selftest --configs base-direct,heavy-hop-2hz
```

Useful options:

```bash
build-selftest/bin/yume-selftest --list-configs
build-selftest/bin/yume-selftest --latency-iters 200 --bulk-mib 64
build-selftest/bin/yume-selftest --json selftest.json
build-selftest/bin/yume-selftest --keep-workdir
```

The routed benchmark requires `YUME_FEATURE_LAN_BRIDGE=ON` because the server
must connect to a loopback echo target. The tool creates a temporary
`authorized_keys.json` and grants `allow_local_ip` only to the generated test
key.

Inner-crypto configs let the temporary `yumed` generate a throwaway PQ keypair
and pass the generated public key to the temporary client. The harness also
passes `--accept-monitoring`, because this is an explicit local benchmark
rather than an anonym-mode trust test.

Heavy mode is still bounded by default: `YUME_ARGON2_MEM` and server caps are
set to 32768 KiB with parallelism 2 for the child processes. Use
`--argon-mem-kib` and `--argon-parallelism` when intentionally profiling
larger KDF settings on a suitable machine.
