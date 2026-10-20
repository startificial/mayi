# ADR 0026: DPoP proof admission, nonces and binding policy

Status: Accepted. Completes the bounded P3 ES256 sender-binding slice; P3 remains
in progress for unknown-client registration/policy and the browser-token example.

## Ownership and profile

Token lifecycle owns proof admission, nonce/replay contracts and credential key
binding. Its existing proof service is shared by token/PAR adapters and resource
introspection; there is no second SDK proof validator. Resource enforcement owns
current resource policy and the SDK error/metadata projection. Client registration
owns the per-client `dpop_bound_access_tokens` policy, stored as require_binding.
Administration reuses its existing authorized creation path. Tenant, client and
resource binding requirements combine restrictively, including machine issuance,
refresh and fresh online status. The API can additionally require DPoP locally.

The published proof algorithm is ES256 with a public P-256 JWK. The existing
reviewed JOSE library validates signatures/thumbprints. Strict bounded decoding
rejects duplicate/case-variant/unknown header and claim names, private key fields,
remote key URLs, null/wrong-type claims, wrong algorithms/purposes and nonmatching
HTTP targets, methods, token hashes or keys. The profile accepts header alg/typ/jwk
and bounded public JWK kty/crv/x/y plus optional alg/use/kid; no arbitrary JOSE
extension or token-directed fetching is enabled. iat spans the previous 60 seconds
through five seconds ahead. Proof IDs are printable bounded 16–256 byte values.

Public HTTPS targets come from configured endpoint/resource routing, never Host
or untrusted forwarding headers. Query is excluded from the target comparison;
proof htu must omit it. Scheme/host case and default HTTPS port normalize, while
escaped path bytes stay exact. Dot segments, fragments, credentials and malformed
queries fail. This deliberately conservative path profile does not claim all
optional RFC 3986 normalization equivalents. DPoP does not authenticate query or
body content; ordinary boundary validation and RAR/object policy remain mandatory.

Interactive DPoP credentials bind their key during required PAR, through dpop_jkt
or a validated DPoP header. If both are supplied they must match. Proof-header PAR
uses the exact configured ordinary/resource-bound PAR endpoint and shared proof
admission. The resulting thumbprint is immutable in the request/code/family;
redemption cannot introduce or replace a key. Bearer credentials cannot upgrade
or rebind through refresh. Key loss requires fresh authorization. Confidential
machine clients can present their key at token issuance, without interactive PAR.

## Shared nonce and replay state

All live DPoP proofs require a server-issued nonce. A valid signature and any
expected token key are checked before reading/generating nonce state. A challenge
therefore cannot make a mismatching key usable. The existing credential-material
adapter generates 256 random bits and a versioned tenant/purpose-separated HMAC
hash with the new dpop_nonce purpose. It does not introduce a new crypto algorithm
or export signing keys. PostgreSQL stores only the digest, issuer-scoped tenant,
proof purpose, canonical public target, key thumbprint and a one-minute expiry.
Token/PAR and resource nonce contexts are distinct, as are endpoint paths and keys.

Migration 16 adds this nonce table and per-client binding flag, with forced RLS
and narrow runtime privileges. The proof replay port rechecks nonce validity and
atomically inserts the unique tenant/key/jti under one database statement. A nonce
can accompany several fresh proofs until expiry; one proof ID has one winner
across replicas. Bounded cleanup removes expired nonce/replay rows. Application
clocks must be synchronized; database expiry predicates fail closed rather than
accepting stale state. Missing/unavailable state returns unavailable, never a
positive decision or an offline fallback.

Nonce challenges commit their bookkeeping before returning the nonce. They occur
before PAR persistence, code/refresh consumption, issuance or protected callbacks.
The explicit challenge can be retried with a newly signed proof. This is distinct
from an ambiguous network/5xx result, which remains unsafe to retry for one-use
credentials. Replay reservation precedes issuance, so after any uncertain outcome
a caller must never retry the same proof JWT. Denied requests may only perform
existing narrow audit/admission/replay bookkeeping, never disclose protected data.

## Transport and resource integration

Token/PAR nonce challenges use 400 use_dpop_nonce and one DPoP-Nonce header.
Resource proof challenges traverse authenticated introspection without disclosing
active claims, then the SDK returns 401 use_dpop_nonce with a DPoP challenge and
the nonce. Invalid proofs receive invalid_dpop_proof; inactive/revoked authority
receives generic invalid_token. Shared-state failure is 503 without a misleading
authentication challenge. No raw proof, token or dependency error is returned.

Resource metadata advertises ES256 and explicit required-binding policy. A
required-binding resource advertises no Bearer transport and defaults to DPoP
challenges. Optional-binding resources select WriteDPoPChallenge for DPoP
requests. SDK RequireDPoP and MetadataConfig.RequireDPoP must describe the same
enforced deployment policy. Metadata cannot substitute for enforcement. Cross-origin
browser deployment still needs an explicit origin policy and exposure of
DPoP-Nonce/WWW-Authenticate; no wildcard credentialed CORS or browser guarantee is
introduced by this slice.

## Evidence and limits

The P3 evidence manifest links strict parsing, target handling, service call-order
and failure classification, ordinary/resource-bound PAR header/JKT correlation,
JWT/opaque token and refresh binding, nonce retry/expiry, copied/wrong-key denial,
concurrent replay, two-service shared state, tenant/purpose/target/key isolation,
nonce-expiry races and nonce/replay dependency failures. Real PostgreSQL/OpenBao
and the reference BFF remain required CI gates. No dependency, tool, license
exception, AWS access or external certification is added. The WebCrypto/browser
sample, CIMD, DCR and unknown-client policy remain explicit later P3 work.
