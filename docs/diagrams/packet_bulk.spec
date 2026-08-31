# Packet-native bulk path (PACKET_NATIVE_BULK.md).
# Render with: scripts/draw_pipeline.py docs/diagrams/packet_bulk.spec
--
title: ANDROID TUN
sub:   VpnService capture
--
title: YUME CLIENT
sub:   YBP1 batch on packet stream
--
title: YUMED SERVER
sub:   packet_bulk_v1 decode
arrow: ==YUME==> encrypted DATA
--
title: SERVER TUN/NAT
sub:   yume-pkt0 + CIDR pool
arrow: write to operator TUN
--
title: INTERNET
sub:   target sees NAT IP
arrow: routed egress
