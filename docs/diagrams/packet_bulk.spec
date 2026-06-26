# Packet-native bulk path (PACKET_NATIVE_BULK.md).
# Render with: scripts/draw_pipeline.py docs/diagrams/packet_bulk.spec
--
title: ANDROID TUN
sub:   VpnService capture
--
title: YUME CLIENT
sub:   YBP1 batch on packet stream
arrow: ==YUME==> encrypted DATA
--
title: YUMED SERVER
sub:   packet_bulk_v1 decode
arrow: write to operator TUN
--
title: SERVER TUN/NAT
sub:   yume-pkt0 + CIDR pool
arrow: routed egress
--
title: INTERNET
sub:   target sees NAT IP
