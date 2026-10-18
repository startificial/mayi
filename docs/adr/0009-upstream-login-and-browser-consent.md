# ADR 0009: Upstream login and browser consent

Status: accepted for the P2 preview; no production or OP-conformance claim.

## Ownership and trust

Pure `domain/identity` values define bounded login correlation and fresh identity evidence. `services/authentication` orchestrates login, local identity resolution and session creation/rotation/termination. The upstream adapter validates OIDC wire evidence; `services/authorization` remains the single consent/grant/code owner. Browser handlers decode bounded input, manage cookies and render explicit escaped view models.

This milestone supports one configured upstream OIDC provider per tenant. Discovery must match the configured issuer and exact authorization/token/JWKS endpoints. The profile requires code/S256, query callbacks, nonce, `client_secret_basic`, and fresh `auth_time` after `max_age=0`. ID tokens must have exactly the Mayi RP client audience; `azp`, if present, must match. Pin one of ES256, RS256 or PS256 for upstream verification; this does not enable RS256 for Mayi-issued tokens. Reject token-controlled key URLs, embedded keys, ambiguous JSON, missing claims and unknown critical headers. Discard upstream access tokens.

Map `(tenant, provider ID, upstream issuer, upstream subject)` to an existing active local member. Membership and mappings stay operator-owned: no email linking or automatic enrollment. A signature establishes upstream evidence, not tenant membership or permission. Fingerprint provider issuer/client/endpoints/algorithm into each attempt, invalidating outstanding attempts on a trust-configuration change. Use a new provider ID when changing the identity relationship. Assurance mapping and MFA step-up remain P5.

## Correlation and atomicity

Persist the existing authorization workflow before redirecting upstream. Each login references its exact workflow/browser and expires within that workflow's five-minute deadline. Store hashes of state, nonce and PKCE verifier; retain raw correlation in a bounded Secure/HttpOnly SameSite=Lax `__Host-` cookie. Cookie contents confer no identity: all hashes/timestamps must match the stored attempt, and callback state must also match the cookie. A dedicated tenant callback and fixed provider/token endpoint prevent caller-selected provider switching; check response `iss` when present.

Atomically claim each login once **before** exchanging the upstream code. External token/JWKS requests run outside database locks. Replay/concurrent callbacks cannot repeat the exchange. Failure, crash or final commit failure requires a new workflow; do not replay an upstream code after uncertain external effects.

Session insertion, revoking the previous matching browser-bound handle, authentication evidence and audit/outbox commit together. Recheck pending workflow/client/policy, identity mapping and active membership at that final transaction. Return the handle only after commit. Identity/session writers acquire the tenant row FOR UPDATE before workflow/session rows, conflicting with consent's FOR SHARE coordination. Migration 4 permits runtime session insertion and only `revoked` updates; mappings/membership stay read-only, and login updates are restricted to claim/completion columns.

A session is a random hashed handle with a one-hour absolute deadline. Consent checks its authentication evidence/browser binding in the authorization projection before loading protected request content. Legacy operator-created sessions without that evidence require a new login. Ending a local session does not revoke durable grants. Idle timeout, listing and downstream logout propagation remain later P2/P5 work.

## Browser and egress profile

When configured, expose `I/authorize`, `I/upstream/callback`, `I/consent` (GET/POST) and `I/session/end` (POST), where `I` is the configured tenant issuer. The limited authorization boundary accepts one business resource, registered HTTPS redirects, code/S256 and explicit resource permissions. Invalid/duplicate/unsupported input fails locally. Fixed redirect queries cannot collide with `code`, `state`, `iss` or error response fields. Append response fields without re-encoding original query bytes, preserving ordering, repeated values and escape spelling; include issuer correlation.

Consent names the registered client ID, API audience, redirect and permissions. Script-free escaped pages send no-store/no-referrer, CSP, Trusted Types and frame denial. Approval requires stored CSRF proof, exact Origin and permitted Fetch Metadata; ending a session requires exact Origin plus browser/session proof. Tenant-specific cookies use Secure, HttpOnly, Path=/, no Domain and the `__Host-` prefix. TLS at the trusted proxy is required; no insecure-cookie fallback. These top-level pages do not implement the BFF's embedding/handoff contract.

Every upstream fetch uses constrained egress: exact configured URLs, HTTPS/443, no proxy or redirects, bounded time/headers/JSON, no compression, and DNS/IP validation on each connection. Dial the validated literal while retaining normal TLS hostname verification; mixed private/public answers and special-use addresses fail closed. The explicit development flag permits HTTP to literal loopback addresses only. Private-network production upstreams need a reviewed destination policy; never disable SSRF checks as a workaround. This is P3 groundwork, not complete network-abuse certification.

## Evidence and remaining gates

Domain/service tests cover freshness, correlation, call order and no session before commit. Adapter tests reject invalid signature/issuer/audience/nonce/type, unsafe metadata/keys and egress responses. Real PostgreSQL tests cover single-winner callbacks, rotation, foreign references, membership/mapping loss, audit rollback and the browser login/consent/session flow against a local OIDC fixture. The full CI harness also tests server routing with OpenBao. HTTP fixtures do not certify real-browser cookie behavior or enterprise-provider compatibility.

Fosite remains selected. Live token composition, downstream OIDC tokens/UserInfo, keyed credential hashing, refresh issuance, resource enforcement and the BFF/resource exit remain milestones 3/4. Discovery retains its foundation preview. No dependency, tool, copied source or license exception is added.

Sources: pinned [OIDC Core errata 2](https://openid.net/specs/openid-connect-core-1_0-errata2.html) sections 3.1.2/3.1.3.7, [Discovery errata 2](https://openid.net/specs/openid-connect-discovery-1_0-errata2.html) section 4, [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700#section-4.4), and ADRs 0005/0008.
