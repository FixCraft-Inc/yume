# YUME 0.3 identity and authorization

Authentication, advertised capabilities, and authorization are separate gates.

YUME uses two key classes, and the split is permanent. `authorized_keys`
holds ordinary traffic identities. `admin_keys` is a physically separate store
of distinct second-factor identities carrying no policy metadata. Admin is
proved by presenting one authorized traffic identity **plus a different
identity from `admin_keys`**, never by a boolean in the traffic store. The
stores must not overlap, and a schema-1 entry in `authorized_keys` has no
field that can grant admin. This is the same invariant the transport-v2 daemon
enforces; schema 1 keeps it structural so administrative capability cannot be
switched on for a traffic key by editing one list.

Each authorized key receives a composite Ed25519 + ML-DSA-87 identity and its
own 32-byte access PSK. The server maps that identity to its access PSK and
policy. Sharing one deployment-wide inner PSK across identities is forbidden.
Both signature components and all establishment contributions must verify;
there is no partial-authentication mode or provider fallback.

The second-factor AUTH exchange is **not implemented** in the YTP/1 candidate.
Until it is, schema 1 exposes no administrative capability at all: the
capability manifest carries only named services and kinds, so there is nothing
an operator could grant by accident. `admin_keys` is parsed, validated, and
checked for overlap so the store boundary exists before the capability does.

After AUTH, the peer advertises a bounded canonical capability manifest of
named services and kinds. A service is uniquely identified by `(name, kind)`,
so the same name may safely advertise one stream and one packet capability. A
capability is not an authorization grant. Every
OPEN is independently checked against:

1. the authenticated peer identity and role;
2. the exact authenticated capability bytes;
3. the registered service kind and per-service policy;
4. destination policy for built-in TCP/UDP encodings;
5. stream, pending-open, queue, packet, and route resource limits.

Failure at any layer closes or rejects that application stream. A
`RouteProvider` can receive only an `AuthorizedRouteRequest` constructed after
the dispatcher passes identity, service, destination, and resource policy; it
cannot be used as an authorization bypass.

Schema 1 keeps private material in referenced files. It rejects inline
secrets, aliases, unknown keys, unsupported providers, and unsafe combinations.
Setup generates the initial authorized-key manifest. The production runtime
and policy-management workflow are not implemented yet, so this document is a
contract, not evidence that key issuance or revocation is live.

Federation, directory, relay applications, reverse administration, server
command execution, host-controller modes, product-specific codecs, and dynamic
plugins are outside the first YTP/1 path. They do not have permissions or
compatibility aliases in schema 1; current transport-v2 implementations remain
a separate lane during the transition.
