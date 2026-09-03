# Experimental YTP/1 interface drafts

This directory preserves operator, interface, and verification drafts produced
for the modular YTP/1 replacement. They are design inputs, not installed
contracts and not evidence that a runtime exists.

- `QUICKSTART.md` and `OPERATIONS.md` describe the explicitly enabled schema-1
  setup and doctor preview.
- `PERMISSIONS.md` and `PACKET_NATIVE_BULK.md` describe intended identity,
  authorization, and packet contracts.
- `DIAGNOSTICS.md` and `SELFTEST.md` record replacement diagnostics and gates.
- `man/yume.1` sketches the intended narrow config-driven client.
- `man/yumed.8` sketches the intended YTP/1 front-door daemon.

The runnable transport-v2 binaries continue to use the active manuals in
[`../../man/`](../../man/). Replacement drafts move into installed paths only
after their commands exist and their end-to-end acceptance gates pass.
