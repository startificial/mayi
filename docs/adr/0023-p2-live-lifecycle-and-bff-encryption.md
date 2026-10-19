# ADR 0023: Live credential lifecycle, authoritative status and BFF encryption

Status: accepted for the P2 preview. This decision does not mark P2 complete.

## Ownership and consistency

`services/clients` owns registered authentication and secret rotation;
`services/tokens` owns code/refresh/machine issuance and credential status;
`services/grants` owns connected-app queries and user/administrator revocation.
Session controls remain in `services/authentication`. HTTP and Fosite callbacks
translate these operations without receiving a database handle. Fosite composes
only code, refresh and machine token handlers. Each response handler must decline
unrelated grant types before performing effects.

Registered authentication is `none`, `client_secret_basic` or `private_key_jwt`.
Machine clients use a separate `client:` identity namespace and confidential
authentication. Introspection permission is explicit and requires a confidential
client. Authentication versions are rechecked inside protected operations.
Private assertions use only registered inline/remote keys, exact token-endpoint
audience, bounded time and an atomic client-namespaced replay record. Fetching
remote keys uses constrained egress; assertion-controlled URLs are never used.

Codes, refresh tokens, opaque access tokens and generated client secrets use a
version-prefixed random value and HMAC-SHA-256 with tenant, issuer and purpose
separation. Startup supplies reviewed 256-bit key material; retained versions
verify older credentials and exactly one version creates new material. Removing
a key invalidates its outstanding opaque credentials. This is separate from
asymmetric signing-key rotation.

PAR and authorization snapshots persist OIDC nonce and offline-access intent in
immutable companion records. Consent explicitly displays identity and continued
access. An initial refresh family is created only for approved offline access;
its creation, code consumption, access issuance, successor and audit commit
together. Rotation preserves the approved revision and typed ceiling, and clamps
idle/absolute lifetimes by current policy. Signing version selection occurs in
the issuance transaction; the signer must use that version without acquiring a
second database connection. Returned Transit signatures are verified with the
configured public key before issuance can commit.

## Strict resource decisions

The public `pkg/resource` facade composes only `services/resource`, public-value
mapping, authenticated status transport and the bounded
`outbound/egress/httpclient` infrastructure helper. The helper has no server,
identity-service or database dependency. CI checks the transitive SDK graph.

Every resource decision authenticates introspection and consults primary issuance,
grant, revision, family, membership, client and current machine-policy state.
Tokens are looked up using their exact-byte digest: a JWT must match a committed,
signature-verified issuance; an opaque token uses its keyed digest. Introspection
does not trust unsigned JWT claims or accept ID tokens as access tokens. This
preview deliberately has no offline/local-JWT fallback or stale positive cache.

The SDK checks tenant/issuer, exact audience, expiry, permission scope and complete
typed object/action ceiling before invoking the application's permission guard.
The resource owner holds current ACL authority through the protected callback;
the SDK owns neither application ACL tables nor payload queries. Optional DPoP
resource proofs are verified through authenticated introspection with the exact
configured resource target, method, token hash and authoritative replay state.

User grant revocation authenticates browser/session scope before grant details,
and locks an ownership projection before mutation. Administrator incident
revocation requires `grants:write` and selects an exact grant, user or client in
the configured tenant. Both consult the same authoritative roots used by status.
Session listing/revocation and a same-origin touch operation enforce a 15-minute
idle deadline plus the existing one-hour absolute deadline. Ending a session and
revoking an application grant remain distinct operations.

## BFF encryption and Additional Authenticated Data

The application under `examples/bff` uses public OAuth/OIDC contracts and its own
ports/adapters; CI rejects imports of Mayi's privileged internal packages. It uses
the already admitted Go OAuth client and JOSE libraries, with no new dependency
version. Login is top-level, uses required PAR/S256/state/nonce and independently
verifies the ID token against the configured issuer's public keys. The reference
requests the resource's object `123`/read authority; the resource defines the type.

The application's crypto adapter uses standard-library AES-256-GCM with
`NewGCMWithRandomNonce`. Both stored OAuth tokens and login proof material are
encrypted. AAD is a fixed-order, unambiguous JSON array containing a domain
separator, algorithm, envelope version, key ID, tenant, issuer, client, resource,
session record ID, payload purpose and store generation. These are authenticated
identifiers, not secrets. Expected tenant/client/resource values come from trusted
application configuration. Session identity is checked against the authenticated
opaque cookie before opening an envelope; expected context is never accepted from
the envelope itself.

Tests substitute every context field, key ID, version, ciphertext and nonce, and
exercise retained decryption keys, new-key encryption and removed-key failure.
Separate `login-state` and `oauth-tokens` purposes prevent cross-use. AAD does not
prevent rollback of an entire valid ciphertext and its independently trusted
generation: durable deployments must enforce monotonic revision/CAS and lease
state in their application store. Rotate keys before the Go AEAD limit of 2^32
messages under one key; coordinate that budget across replicas.

The reference memory store is bounded and single-process. Restart invalidates its
cookies; it makes no durability or multi-replica claim. Its per-session lease
serializes refresh. It marks the old refresh credential unavailable before one
network attempt and persists the encrypted successor before forwarding an API
request. An uncertain refresh outcome invalidates the session without retrying
the one-use credential. API forwarding accepts only a configured destination and
never forwards browser-supplied authorization or arbitrary URL parameters.

## Evidence and remaining gates

`tests/integration/live_protocol_test.go` exercises real PostgreSQL/OpenBao and
the public wire codecs, authenticated HTTP introspection and SDK decisions. It
also connects the reference BFF through PAR, upstream login, consent, code/ID-token
validation and object access. HTTP application routing in the BFF integration
fixture is in-process; this is not a retained real-browser or deployment test.
The BFF unit suite separately proves encrypted storage, concurrent refresh
serialization and no retry after an uncertain refresh outcome.

Remaining P2 work includes complete fresh-schema mandatory RAR/PAR cutover of the
older internal proof scaffolding, configured distributed abuse limits, complete
endpoint recovery/conformance coverage, incremental-grant presentation and the
remaining resource-binding/operator examples. No completion or production claim
follows from this ADR. UserInfo/complete OIDC identity features retain their
documented phase and are not advertised as implemented.
