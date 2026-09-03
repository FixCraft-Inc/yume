# YUME transport-v2 federation transit design

> **Design-only transport-v2 record:** direct single-hop federation exists in
> the runnable 0.2 product. Multi-hop transit described here is not implemented
> and is not a YTP/1 capability claim.

Status: **design only. Transit is not implemented.** Nothing in this document
is a supported command, wire contract, compatibility promise, or privacy claim.
Current federation is direct and single-hop:

- `federation.directory` advertises a node's local endpoints only;
- a client-visible federated endpoint has exactly one peer prefix;
- `federation.topology` schema v1 reports `transit.supported = false` and
  `transit.max_hops = 1`; and
- every active federated relay channel reports `route_hops = 1`.

The `route` arrays in the current topology response are display data for direct
links. They are not authenticated route offers and must not be reinterpreted as
the multi-hop protocol described here.

## Current evidence boundary

The executable fixtures describe only current one-hop behavior:

- [`tests/test_yume_federation_v2.py`](../../tests/test_yume_federation_v2.py)
  launches two directly peered daemons and two clients, then exercises one
  federated relay-v2 DATA/CLOSE transfer.
- [`tests/test_yume_federation_cluster.py`](../../tests/test_yume_federation_cluster.py)
  forms a three-node line and requires each end to neither learn nor address an
  endpoint two links away while transit is off.
- [`src/core/protocol/directory_policy_test.cpp`](../../src/core/protocol/directory_policy_test.cpp)
  pins the existing raw and one-prefix directory grammar.

Those artifacts are direct-federation regressions. They do not demonstrate a
transit forwarder, chained route authentication, intermediate-node payload
opacity, multi-hop resource bounds, or a safe protocol upgrade. No such evidence
exists yet.

## Scope fences

Transit may be designed only for ordinary end-to-end relay channels:

- chat;
- file transfer; and
- byte transfer.

The following are excluded even when an operator enables transit:

- **Admin channels and controller operations.** Administrative authority must
  remain direct. An invite or OPEN for `admin` with more than one route hop is
  rejected before forwarding or allocating channel state.
- **Exit and proxy traffic.** SOCKS, forward, reverse-forward, packet/TUN,
  service, codec, and host-controller traffic never traverse a federation
  transit node. `yumed` remains the terminating proxy and egress for those
  features.
- **Onion-routing or anonymity claims.** Transit is a reachability feature for
  relay endpoints. It exposes the path to every endpoint and every node on it.

No generic “forward unknown frames” path is acceptable. Channel kind and frame
family are validated at every authoritative boundary, and excluded traffic
fails closed.

## Stable authenticated route identities

Today's configured `peer_id` is a local operator label. Two nodes can assign the
same label to different peers, so a list of those labels is not a globally
meaningful or authenticated route.

Before transit, the protocol needs one canonical, stable federation-node
identity. Each route entry must be derived from, or cryptographically bound to,
the composite identity authenticated on the adjacent AUTH-v2 federation link.
The exact encoding belongs in the normative wire revision, but it must have all
of these properties:

1. the identity is independent of a dial address, display name, or local alias;
2. the adjacent link proves that the connected peer owns the named identity;
3. route advertisements carry a verifiable attestation chain for non-adjacent
   identities; and
4. identity rotation has an explicit overlap/revocation policy rather than
   silently creating a different route.

Endpoint identities remain separately composite-signed by relay protocol. A
server route identity never substitutes for either endpoint identity.

## Immutable signed route context

A selected path is a complete immutable value. A forwarding node must not strip,
prepend, truncate, reorder, or rewrite it. At minimum its canonical context binds:

- the transit-routing protocol version and selected relay protocol version;
- a route generation/expiry and a domain-separated route identifier;
- the complete ordered vector of stable federation-node identities;
- both endpoint identities and endpoint IDs;
- the exact channel kind; and
- every policy bit whose interpretation can change admission or forwarding.

The initiator signs the entire context in its relay request. The responder
verifies that exact context and signs the same context in its response. The
canonical route digest must also enter the versioned relay root/AAD context so a
valid record cannot be transplanted to another route. A retry or route change
therefore requires a new endpoint handshake; an established channel never
silently fails over to a different path.

Current relay v2 does not sign this route context. Its version-2 transcript must
not be changed in place to add transit. Transit requires a new, explicitly
negotiated relay protocol version and new domain labels.

### A cursor is not the path

Forwarding still needs to know which hop is next. That mutable progress value is
a separate hop envelope, never part of or a replacement for the signed path. A
forward envelope contains the immutable route identifier/digest, direction, and
a bounded cursor. Every node validates all of the following before forwarding:

1. the full route context and its attestation chain are valid and unexpired;
2. the cursor is an integer in range;
3. the stable identity at the cursor is the current node;
4. the next identity is the peer authenticated on the chosen adjacent link;
5. forward traffic advances by exactly one and reverse traffic retreats by
   exactly one; and
6. the envelope's route digest equals the route fixed to the channel.

The hop count is always derived from the authenticated vector. A peer-supplied
`route_hops`, TTL, or cursor can never override it. Cursor mutation, skipping,
regression, wrong-direction use, or an identity/link mismatch closes the
forwarded channel.

This structure can attest the route YUME selected and each compliant hop
accepted. It cannot prove that a malicious operator did not copy traffic through
an undisclosed out-of-band system. Preventing or detecting that stronger
deception is not claimed.

## Route advertisement and cycle control

A node may advertise a learned route only through a versioned, signed route
offer. An advertising node creates a new outer attestation that binds its own
stable identity to the exact digest of the received offer. The expanded vector
is the advertiser followed by the received vector; no node edits the received
vector or any existing signature. Admission requires:

- every identity in the vector is unique;
- the advertising peer is the identity authenticated on the receiving link;
- the receiver and next recipient do not already appear in the vector;
- the route generation is current and its expiry is bounded;
- the encoded vector and attestation chain fit fixed byte and hop limits; and
- withdrawal and expiry remove the route and prevent new channel admission.

These checks provide split-horizon behavior and reject loops by construction.
The old endpoint-ID byte budget is not a valid reason to choose a transit hop
limit because the authenticated route is separate from the endpoint's stable
visible name. The normative protocol must select an explicit maximum hop count,
route byte size, and attestation byte size before implementation.

### Deterministic route selection

Route discovery must not broadcast an invite over every available path. For one
destination and route generation, every implementation uses one documented
total ordering, for example:

1. fewest authenticated hops;
2. then the canonical stable-identity vector; and
3. then the route digest as a final tie-breaker.

The exact order is a protocol decision and must be test-vector backed. A node
retains only a bounded number of alternatives per destination, chooses once
before the relay handshake, and freezes that route for the channel lifetime.
Load-aware or randomized routing would change metadata and traffic shape and
requires a later version rather than an implementation-specific tie-breaker.

## Capability and protocol-version negotiation

Direct relay v2 remains the current protocol. A transit-capable directory offer
must separately advertise:

- the supported federation-transit protocol versions;
- the supported endpoint relay protocol versions for transit;
- the supported ordinary channel kinds; and
- the route and resource limits relevant to admission.

The initiator selects one exact common transit version and one exact common relay
version across every hop and both endpoints. The responder confirms both, and
both endpoint signatures bind them. Each hop verifies that it advertised and
supports the selected versions before retaining state.

Missing capability, an empty intersection, an unknown version, a version change,
an unsupported kind, or a request to use direct relay v2 as a transit protocol is
a hard rejection. A multi-hop request must never downgrade to direct routing,
TOFU, a shorter path, or a legacy transcript merely to connect. Existing peers
that do not advertise transit continue to behave exactly as they do today.

The directory and topology schemas also need explicit new versions. Existing
schema-v1 fields retain their current direct-only meaning.

## Trust policy

Multi-hop channels require all of the following:

- pinned composite endpoint identities at both ends;
- a validated stable identity and attestation for every server in the route;
- explicit endpoint acceptance of the complete route before the handshake; and
- explicit operator opt-in on every transit server, default off.

TOFU is insufficient for a multi-hop route because a forwarding node can present
a new name and key together. A multi-hop invite cannot create or update learned
TOFU state. Pin disagreement, route-attestation failure, identity rotation
outside an approved overlap, or route expiry fails before channel OPEN.

## Admission, flow control, and budgets

Transit makes a node retain third-party state. Every implementation must define
and enforce fixed limits at connection, authenticated peer, route, endpoint,
channel, and process scope. At minimum the budgets cover:

- advertisements, withdrawals, alternative routes, and total route bytes;
- update frequency and validation work;
- pending invites and OPENs;
- active transit channels by kind;
- buffered and in-flight records and bytes in each direction;
- per-link and process-wide queued bytes;
- channel idle time, establishment deadline, and maximum lifetime; and
- error/retry work after a peer or link disappears.

Admission is acquired before parsing expensive attestations, allocating channel
state, or forwarding data, and remains held until every queued write and callback
releases ownership. Backpressure propagates hop by hop; no hop may acknowledge
or release upstream credit merely because it copied a record into another
unbounded queue. Saturation rejects new work deterministically and existing work
either drains within its deadline or closes. Fan-out, retry storms, and
unbounded alternate-path retention are forbidden.

The numeric limits and overload responses are part of the versioned protocol and
need plateau, recovery, cancellation, and fairness tests before deployment.

## Payload boundary and metadata disclosure

For chat, file, or bytes transit, intermediate nodes must forward the endpoint's
serialized relay records byte-for-byte. They do not instantiate the endpoint
relay ratchet, derive endpoint channel keys, rewrite the signed context, or
publish plaintext. Authentication failure is endpoint-fatal; a transit node
cannot repair, retry under a new sequence, or replace a record.

If those invariants are implemented and verified, an honest transit node does
not learn application payload plaintext. It still learns or can infer all of the
following:

- the complete claimed server route, its own position, route version, lifetime,
  and stable server identities;
- source and destination routing identifiers and the adjacent network peers;
- channel kind (chat, file, or bytes), establishment outcome, close reason, and
  policy refusals;
- record sizes, counts, directions, timing, bursts, total volume, duration,
  retries, stalls, and link failures;
- directory reachability, route additions/withdrawals, and endpoint availability;
  and
- its adjacent peers' IP addresses, TLS certificates, authenticated federation
  identities, and operational schedule.

Endpoints learn the complete claimed route and therefore every named transit
operator. Adjacent network observers see separate TLS connections and their
timing/volume. Colluding nodes can correlate ingress and egress. Any node can
drop, delay, reorder, throttle, selectively refuse, or lie about availability.
Route signatures provide integrity for the claimed route; they provide no
anonymity, traffic-analysis resistance, availability, or proof against hidden
out-of-band forwarding.

These disclosures must appear in client confirmation, topology/control output,
the threat model, operator documentation, and release notes before transit can be
enabled.

## Required implementation and evidence gates

Transit remains unsupported until every gate below is complete on one exact
candidate:

1. **Normative protocol.** Specify canonical route/attestation/cursor encodings,
   new relay and transit versions, signature and KDF/AAD domains, limits, expiry,
   errors, and downgrade behavior. Publish positive and negative vectors.
2. **Stable identity and advertisements.** Bind stable server identities to
   federation AUTH, validate chained route offers, cap storage/update work, and
   implement deterministic selection, expiry, withdrawal, and cycle rejection.
3. **Immutable endpoint handshake.** Both endpoint signatures and the relay root
   bind the exact full route; altered route, version, kind, endpoint, attestation,
   or digest fails before trust is committed.
4. **Cursor and forwarding.** Link-to-link invite, OPEN, DATA, and CLOSE use the
   separately validated cursor and byte-identical opaque records. Wrong-hop,
   skip, regression, reverse-direction, stale-route, and link-identity negatives
   fail closed.
5. **Policy fences.** Transit-off remains byte-identical to current behavior.
   Admin, controller, SOCKS, forward/reverse-forward, packet/TUN, service, codec,
   and host-controller requests are rejected on every multi-hop path.
6. **Resource behavior.** Per-scope limits, sink-coupled credit, saturation,
   cancellation, link loss, timeout, plateau, fairness, cleanup, and recovery are
   proven under optimized and sanitizer builds.
7. **Integration.** Preserve the current two-node direct DATA/CLOSE test and the
   three-node transit-off absence/unroutability test. Add a transit-on
   hub-and-spoke fixture in which two spokes exchange exact ordinary relay data
   through one hub, plus mutations proving that the hub cannot terminate the
   endpoint ratchet or obtain plaintext.
8. **Version interop.** Cover every supported/unsupported version intersection,
   unknown and missing capabilities, mixed paths, downgrade attempts, and a
   legacy direct peer. Unsupported combinations reject without partial state.
9. **Operational evidence.** Run loss, reconnect, restart, route withdrawal,
   sustained soak, and metadata/capture review. Document measured resource and
   traffic-shape costs without turning a passed fixture into an anonymity claim.
10. **Documentation and review.** Update architecture, threat model, permissions,
    control API, CLI/man pages, topology schema, and operator consent UX, then
    obtain an independent security and protocol review.

Only after all gates pass may implementation status change
`transit.supported` or raise `transit.max_hops`. This design document alone is
not authorization to add a forwarding flag or relax the current one-hop grammar.

## Related tracked contracts

- [Architecture](../ARCHITECTURE.md)
- [Threat model](../THREAT_MODEL.md)
- [Permissions](../PERMISSIONS.md)
- [Current implementation status](../IMPLEMENTATION_STATUS.md)
- [JSON control API](../CONTROL_API.md)
- [YUME transport-v2 wire contract](YUME_2_0_WIRE.md)
