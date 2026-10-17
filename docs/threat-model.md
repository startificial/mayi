# Mayi threat model

Status: Initial P0 design model · 2026-10-17 · External review pending

Scope: standalone authorization server, browser login/consent, upstream identity providers, gateways, workloads, PostgreSQL, signer, workers, administrator APIs and companion resource enforcement. The public internet, client metadata, user input, upstream assertions and tenant-controlled configuration are untrusted. A valid signature establishes provenance, not sufficient authorization. Tenant administrators control only their tenant's explicit policy surface.

## Assets and boundaries

| Asset / boundary | Trust and required protection |
| --- | --- |
| Tenant issuer and authority namespace | Provisioned immutable mapping; no request-host or email-domain inference; every ownership lookup scoped to tenant. |
| Grants, revisions and policy | Root revocation dominates all descendants; immutable ceilings; authorization before protected reads; atomic version checks at mutation. |
| Codes, refresh families and replay entries | Unpredictable plaintext delivered only to intended holder; hashed storage; bounded lifetime; serialized consume and durable replay response. |
| Access/ID/assertion/logout tokens | Distinct purpose validators, exact issuer/audience, algorithm allowlist and trusted key source; never interchangeable. |
| Signing keys | Non-exportable production KMS/HSM handles, explicit algorithm and usage; no logs, crash dumps or development-key fallback. |
| Browser sessions and consent | Secure HttpOnly cookies, CSRF, CSP, top-level consent, reauthentication; browser storage/access cannot broaden grant authority. |
| Resource decisions and gateway hops | Current permission/status check; proof binding at receiving resource; explicit recipient exchange edge; no ambient forwarded bearer authority. |
| Audit and outbox | Atomic security-event intent, bounded retention and redaction, authenticated destination; delivery retries cannot repeat authorization or credential issuance. |

## Abuse cases and verification

| Threat | Control / failure rule | Evidence now; remaining work |
| --- | --- | --- |
| Tenant/issuer confusion or guessed object IDs | Trusted scope plus scoped port lookup, exact stored ownership checks, composite SQL keys | P0 denial/call-order tests; SQL/routing/key isolation in P1. |
| Consent expansion inflates old credentials | Exact revision and predecessor ceiling, current policy intersection | P0 immutable-revision and refresh-successor attenuation tests. |
| Code/refresh races mint duplicates | One serialized transaction, unique consumed state and issuance IDs; authenticated replay commits invalidation | P0 transaction-double concurrency/replay tests; multi-connection PostgreSQL/crash proof in P1/P2. |
| Attacker triggers victim revocation | Verify authenticated client, resource, sender key and S256 before replay mutation | P0 wrong-client/key/verifier/tenant tests. Real client authentication and DPoP signature/replay validators remain P2/P3. |
| Signer/storage/audit fails after state write | No response before commit; atomic rollback, no credential leaks or best-effort cleanup | P0 injected signer/audit/commit/cancellation failures and response-order fixture; real KMS/DB failure proof pending. |
| Stale authorization during policy/revoke change | Policy/grant/family locks or equivalent compare-and-swap through commit; online status after revocation acknowledgement | P0 version mismatch/revoked-root tests; live resource and distributed consistency tests pending. |
| Captured bearer token is replayed | Short lives, exact audience, holder-key proof and atomic proof replay state | P0 exact audience/key-context checks only; cryptographic DPoP and online status are pending. |
| Malicious gateway expands authority | Declared resource-recipient edge, narrow scope map, preserved actors/ancestry and expiry; no generic rebinding | ADR 0004; P4 implementation and topology fixtures pending. |
| CIMD/JWKS/IdP metadata fetch reaches internal service | Restricted egress: HTTPS, DNS/IP validation on actual connection, bounded redirects/time/size; reject token-supplied key URLs | Design only; constrained egress adapter and DNS-rebinding tests in P3. |
| Login/consent injection or confused redirect | Validated redirect snapshots, strict parsing, nonce/state/S256, CSP/frame protections, no unsafe error redirects | P0 S256 and original-redirect contract; browser/HTTP tests pending. |
| Upstream identity becomes unrestricted access | Per-tenant trust and purpose/audience/client rules; explicit local grant and policy; no email account linking | Design only; federation and identity lifecycle tests in P2/P5. |
| Dependency/license/toolchain drift | Immutable pins, complete graph/evidence admission, MPL source-access notices, strict architecture CI | Existing checker plus P0 spec/MPL rejection tests; actual release packaging and binary/source availability verification pending. |
| Credential/resource exhaustion | Body/header/parameter bounds, endpoint budgets and rate limits, bounded ancestry, predictable failure behavior | P0 service scope-count/string bounds; HTTP/network limits and abuse-load tests pending. |

## Accepted assumptions and unresolved risks

The initial threat model trusts the database and KMS administration boundary. Host/root compromise, malicious database operators, upstream IdP compromise and an authorized gateway acting maliciously can defeat some controls; minimize privileges, audit administration and bound each component's authority. Holder-key binding cannot prevent malicious code already executing in the holder's process/page from using its key.

The strict profile trades availability for current authorization: status/replay-authority outages deny access. Long operations, stream termination, region failover and upstream deprovisioning require explicit consistency contracts; the initial contract does not promise to undo requests already authorized.

Before the P0 exit gate, choose and exercise the protocol integration, prove a real KMS signing path, and inspect the exact admitted dependency graph. Before production, complete tenant/transaction/adversarial/conformance tests and an external security review with tracked remediation (SEC-12). This initial model is published review input, not security certification.
