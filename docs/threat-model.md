# Mayi threat model

Status: P0/P1 foundation model · 2026-10-17 · External review pending

Scope: standalone authorization server, browser login/consent, upstream identity providers, gateways, workloads, PostgreSQL, signer, workers, administrator APIs and companion resource enforcement. The public internet, client metadata, user input, upstream assertions and tenant-controlled configuration are untrusted. A valid signature establishes provenance, not sufficient authorization. Tenant administrators control only their tenant's explicit policy surface.

## Assets and boundaries

| Asset / boundary | Trust and required protection |
| --- | --- |
| Tenant issuer and authority namespace | Provisioned immutable mapping; no request-host or email-domain inference; every ownership lookup scoped to tenant. |
| Grants, revisions and policy | Root revocation dominates descendants; immutable scope and typed RAR object/action ceilings; authorization before protected reads; atomic version checks at mutation. |
| Codes, refresh families and replay entries | Unpredictable plaintext delivered only to intended holder; hashed storage; bounded lifetime; serialized consume and durable replay response. |
| Access/ID/assertion/logout tokens | Distinct purpose validators, exact issuer/audience, algorithm allowlist and trusted key source; never interchangeable. |
| Signing keys | Non-exportable production KMS/HSM handles, explicit algorithm and usage; no logs, crash dumps or development-key fallback. |
| Browser sessions and consent | Secure HttpOnly cookies, CSRF, CSP, top-level consent, reauthentication; browser storage/access cannot broaden grant authority. |
| Embedded application and parent | Explicit tenant/client frame policy; parent messaging cannot confer identity or permission. Partitioned BFF session is distinct from the top-level login session; proof-bound handoff has a one-use, audience/session/origin-bound lifetime. |
| Resource decisions and gateway hops | Current permission/status check; proof binding at receiving resource; explicit recipient exchange edge; no ambient forwarded bearer authority. |
| Audit and outbox | Atomic security-event intent, bounded retention and redaction, authenticated destination; delivery retries cannot repeat authorization or credential issuance. |

## Abuse cases and verification

| Threat | Control / failure rule | Evidence now; remaining work |
| --- | --- | --- |
| Tenant/issuer confusion or guessed object IDs | Trusted scope plus scoped port lookup, exact stored ownership checks, composite SQL keys | P0 denial/call-order tests; real SQL/RLS isolation now tested; routing and published key isolation remain P1. |
| Consent expansion inflates old credentials | Exact revision and predecessor scope/RAR object/action ceiling, current policy intersection; new approval cannot widen older credentials | P0 scope tests exist; [P2 RAR gate](adr/0010-rar-object-grants-prerequisite.md) adds immutable object-grant and refresh tuple tests; these remain Planned. |
| Broad scopes or current user ACL bypass a document-specific grant | Require registered RFC 9396 details for protected object profiles; enforce complete tenant/audience/type/identifier/action tuples plus current ACL before document payload load; deny missing/unknown semantics | Mandatory P2 proof: document 123/read succeeds, 124/write fails even when the user has both; revocation and ACL-removal tests remain Planned. |
| RAR request is altered, swapped or interpreted differently across layers | Required PAR profile, immutable request/consent snapshots, registered type semantics, exact comparison, no client-controlled schema fetching; resource shares the approved interpretation | RFC 9126/RFC 9396 boundary, response/introspection parity and adversarial P2 tests remain Planned. |
| Code/refresh races mint duplicates | One serialized transaction, unique consumed state and issuance IDs; authenticated replay commits invalidation | P0 memory and real multi-connection PostgreSQL concurrency/replay tests, plus backend termination/rollback/retry; whole-cluster recovery remains P6. |
| Attacker triggers victim revocation | Verify authenticated client, resource, sender key and S256 before replay mutation | P0 wrong-client/key/verifier/tenant tests. Fosite client assertion/replay and real DPoP signature/SQL replay prototypes now run; production endpoint composition remains P2/P3. |
| Signer/storage/audit fails after state write | No response before commit; atomic rollback, no credential leaks or best-effort cleanup | P0 injected signer/audit/commit/cancellation failures and response-order fixture; actual Transit credential revocation, audit-trigger and deferred commit failures now tested. |
| Stale authorization during policy/revoke change | Policy/grant/family locks or equivalent compare-and-swap through commit; online status after revocation acknowledgement | P0 version mismatch/revoked-root tests; live resource and distributed consistency tests pending. |
| Captured bearer token is replayed | Short lives, exact audience, holder-key proof and atomic proof replay state | P0 cryptographic DPoP/nonce/ath and SQL replay checks now run; full resource middleware/online status remains P2/P3. |
| Malicious gateway expands authority | Declared resource-recipient edge, narrow scope map, preserved actors/ancestry and expiry; no generic rebinding | ADR 0004; P4 implementation and topology fixtures pending. |
| CIMD/JWKS/IdP metadata fetch reaches internal service | Restricted egress: HTTPS, DNS/IP validation on actual connection, bounded redirects/time/size; reject token-supplied key URLs | P2 upstream-only constrained transport and destination/mixed-answer tests exist; full P3 fetching profiles and network-abuse evidence remain pending. |
| Login/consent injection or confused redirect | Validated redirect snapshots, strict parsing, nonce/state/S256, CSP/frame protections, no unsafe error redirects | P2 OIDC/browser HTTP fixtures cover state/nonce/S256, escaping, CSRF/origin and immutable consent; real-browser and broader protocol evidence remain pending. |
| Malicious parent/frame steals or replays embedded authentication | Exact message origin/source/correlation and ancestor policy, recipient proof, distinct short-lived handoff with atomic consume/session/audit; no tokens in messages/URLs; login/consent/step-up remain unframeable | [Embedded integration plan](implementation-plan.md#embedded-authentication-and-sessions); P2 contract and P5 browser/foreign-tenant/client/replay tests remain Planned. |
| Browser blocks storage/popups or retains a stale embedded session | Capability-test cookie round trips and permitted Storage Access; explicit top-level recovery, session expiry/termination checks and authoritative resource revocation; no silent credential downgrade | P5 browser matrix and lifecycle/failure evidence remain Planned; no universal iframe SSO claim. |
| Upstream identity becomes unrestricted access | Per-tenant trust and purpose/audience/client rules; explicit local grant and policy; no email account linking | P2 requires explicit issuer/subject mapping and active membership; assertion federation, assurance and upstream lifecycle integrations remain P5. |
| Dependency/license/toolchain drift | Immutable pins, complete graph/evidence admission, MPL source-access notices, strict architecture CI | Existing checker plus P0 spec/MPL rejection tests; actual release packaging and binary/source availability verification pending. |
| Credential/resource exhaustion | Body/header/parameter bounds, endpoint budgets and rate limits, bounded ancestry, predictable failure behavior | P0 service scope-count/string bounds; HTTP/network limits and abuse-load tests pending. |

## Accepted assumptions and unresolved risks

The initial threat model trusts the database and KMS administration boundary. Host/root compromise, malicious database operators, upstream IdP compromise and an authorized gateway acting maliciously can defeat some controls; minimize privileges, audit administration and bound each component's authority. Holder-key binding cannot prevent malicious code already executing in the holder's process/page from using its key.

The strict profile trades availability for current authorization: status/replay-authority outages deny access. Long operations, stream termination, region failover and upstream deprovisioning require explicit consistency contracts; the initial contract does not promise to undo requests already authorized.

Before the P0 exit gate, choose and exercise the protocol integration, prove a real KMS signing path, and inspect the exact admitted dependency graph. Before production, complete tenant/transaction/adversarial/conformance tests and an external security review with tracked remediation (SEC-12). This initial model is published review input, not security certification.

## P0 infrastructure limits

The [P1 foundation](p1-foundation.md) adds startup-validated non-owner connections, checksummed explicit migrations, scoped management credentials, immutable issuer SQL enforcement, public-key rotation, request/body/header/concurrency limits and secret-free logging. Management service tests fail if denied/foreign actors access protected ports; real-service tests cover API/RLS/key isolation and atomic audit/outbox failure. Attempt-fenced outbox leases prevent stale acknowledgements, with at-least-once JSON output and downstream deduplication. These controls supplement the future protocol tests above.

Configuration and provisioning are trusted local operator capabilities. Static bootstrap admin tokens are not OAuth user/admin tokens and do not provide step-up; rotate via configuration/restart and restrict the administration network. The loopback listener assumes a trusted local HTTPS proxy; spoofed Host/Forwarded headers cannot change issuers. PostgreSQL primary state is authoritative. Provider/pooler compatibility, upstream identities, distributed rate limiting, browser defenses, durable remote event receipt, full observability, upgrade/restore/zone drills and independent review remain outstanding before production.

The local source-built OpenBao dev server demonstrates the remote signing API and non-exportable key configuration. It is not a hardware boundary and does not resist a privileged host operator reading memory. Production TLS, credentials, seal/storage, HA and key administration remain P1/P6. The PostgreSQL proof terminates a backend and tests transactional retry, not a whole-cluster/zone-loss recovery. The exchange service only plans a disabled one-hop profile; no subject-token validator or exchange token issuance is enabled. See ADR 0005 and the P0 evidence report.
