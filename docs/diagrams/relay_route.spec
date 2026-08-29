# Current direct federated relay path. YRR2 payload protection is endpoint to
# endpoint; federation uses one direct server link and never selects an exit.
# Render with: scripts/draw_pipeline.py docs/diagrams/relay_route.spec
--
title: PEER APP A
sub:   chat / file / bytes
--
title: YUME CLIENT A
sub:   relay-v2 initiator
arrow: local request
--
title: YUMED A
sub:   direct federation peer
arrow: TLS / H2 / YRR2
--
title: YUMED B
sub:   one hop; no exit or transit
arrow: direct federation link
--
title: YUME CLIENT B
sub:   relay-v2 responder
arrow: TLS / H2 / YRR2
--
title: PEER APP B
sub:   chat / file / bytes
arrow: local delivery
