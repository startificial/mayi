# Mayi requirement delivery matrix

October 18, 2026 · Delivery coverage and bounded implementation evidence

This matrix covers all 156 requirements in [the README](../README.md): 111 MUSTs, 34 SHOULDs and 11 MAYs. It accompanies [the implementation plan](implementation-plan.md). Owners are component responsibilities, not named staff. Phase P6 is the first production gate; earlier phases are limited previews. All full requirements remain **Planned**; P0 architecture/protocol work is complete as documented below, without marking protocol or production behavior Verified.

The phase is the intended delivery or final acceptance phase. Cross-cutting work starts earlier; later flows must inherit existing controls. MUST acceptance conditions incorporate the interpretation decisions in the plan, which P0 must resolve. P7 schedules recommended extensions; P8 contains optional profiles. A MAY promoted earlier remains optional in the requirements baseline.

During implementation, append evidence links to exact tests, CI artifacts, conformance runs and review results before changing a row to Verified. A test title or a dependency feature claim is not evidence.

## P0 evidence

The [P0 report](p0/protocol-spike.md) links the pinned specification manifest, accepted interpretation profiles, issuer/revocation/grant/exchange ADRs, initial threat model and executable issuance contract fixtures. This provides partial groundwork for OPS-9, ADM-1/2, CORE-1/2/5/6/8, CLI client assertion authentication, GRANT-2/6, LIFE-2/3, BIND and OIDC. The report now includes actual PostgreSQL/RLS/race/failure tests, a real OpenBao Transit signer, a service-owned Fosite callback and DPoP/OIDC/exchange hook evidence. These prototypes do not complete full production requirements: the server listener, resource SDK, login/consent, production operations and external security/conformance review remain planned.

## P1 foundation evidence

 [the runbook](p1-foundation.md), [ADR 0006](adr/0006-external-postgres-and-foundation-operations.md) and [real-service tests](../tests/integration/foundation_test.go) cover supplied PostgreSQL, explicit migrations/checksums, owner/runtime separation, immutable issuers, two-tenant API/RLS/key isolation, actual rotated Transit signatures, atomic audit/outbox failure and lease retry fencing. [Management service tests](../internal/services/administration/service_test.go) assert denial before every protected management access. Delivery and HTTP boundary tests cover failed acknowledgement and credential parsing.

[P1 review regression tests](../tests/integration/foundation_regression_test.go) cover authenticated runtime login and inherited migration-column grants, disabled active signing versions, liveness under public saturation and canceled worker output without acknowledgement. The issuance test checks exported grant/`jti` correlation; domain and HTTP tests preserve fixed redirect queries. Sink and CLI tests bound output waits and preserve secret-free diagnostics. [ADR 0007](adr/0007-p1-review-boundary-corrections.md) records the corrected contracts and operational limitations. These tests require the real-service harness for persistence/Transit evidence; ordinary `go test` skips those integration cases without its environment.

This supplies partial evidence for ADM-1/2/3/4/5, CLI-7, RES-2, GRANT-1, LIFE-10/11 and OPS-1/4/6. It does not implement users, consent/grant endpoints, full admin UI/step-up, enforced token policy at live endpoints, production alerts, HA/restore or conformance. DISC-1 has a marked foundation preview only; DISC-2 remains disabled until P2. Full requirement rows remain Planned until their entire acceptance conditions have evidence.

## P2 milestone 1 evidence

The [P2 progress document](p2-core-authorization.md), [ADR 0008](adr/0008-authorization-transactions-and-consent.md), [domain tests](../internal/domain/authorization/transaction_test.go), [service denial/order tests](../internal/services/authorization/service_test.go), and [real PostgreSQL tests](../tests/integration/authorization_test.go) cover the in-process consent boundary. Evidence includes exact request snapshots, S256 challenge validation, scoped reference authentication before protected payload loads, one-session binding, expiry/replay/concurrent decisions, immutable grant/revision/code correlation, identity coordination and audit/outbox rollback.

This is partial groundwork for CORE-1/2/3/5, GRANT-3/4, ADM-1/5 and OPS-4. No public login/authorization route or token response is enabled by this milestone. Upstream authentication, browser protections, refresh issuance, resource enforcement and the P2 BFF/resource exit demonstration remain Planned. Full requirement rows remain Planned.

## P2 milestone 2 evidence

[ADR 0009](adr/0009-upstream-login-and-browser-consent.md), [login service tests](../internal/services/authentication/service_test.go), [OIDC adapter tests](../internal/adapters/outbound/identity/oidc_test.go), [egress tests](../internal/adapters/outbound/egress/client_test.go), [real session transaction tests](../tests/integration/authentication_test.go) and [browser HTTP fixtures](../tests/integration/browser_test.go) add partial evidence for FED-1/3, WEB-4/7/8/10, CORE-1/2/3/5 and ADM-5. They cover provider trust, state/nonce/S256, explicit identity mapping, active membership, one-use callbacks, browser-bound sessions, rotation/termination, escaped consent, CSRF/origin denial and session/audit rollback.

Token endpoints, downstream OIDC, idle/session-list APIs, BFF/resource enforcement, external-provider and real-browser compatibility, and the complete P2 exit remain pending. Full requirement rows stay Planned; these fixtures complete no production or conformance gate.

## CORE

| ID | Level | Phase | Owner | Acceptance condition |
| --- | --- | --- | --- | --- |
| CORE-1 | MUST | P2 | Protocol and authorization | Public and confidential code clients require S256; missing PKCE, plain and incorrect verifiers fail. |
| CORE-2 | MUST | P2 | Protocol and authorization | Implicit and password requests fail and are absent from discovery. |
| CORE-3 | MUST | P2 | Protocol and authorization | Wildcard, prefix, altered path and unregistered redirects fail without an unsafe redirect. |
| CORE-4 | MUST | P3 | Protocol and authorization | Native loopback port exception works; host/path changes fail; private schemes and claimed HTTPS have separate fixtures. |
| CORE-5 | MUST | P2 | Protocol and authorization | A code expires within 60 seconds; concurrent redemption has one winner; authenticated reuse invalidates its issued lineage. |
| CORE-6 | MUST | P2 | Protocol and authorization | Public refresh follows rotation and any configured sender binding; stale credentials cannot mint new tokens. |
| CORE-7 | MUST | P2 | Protocol and authorization | Confidential clients obtain only approved machine-resource scopes. |
| CORE-8 | MUST | P4 | Protocol and authorization | RFC 8693 request/response fixtures and rejected exchange cases pass. |
| CORE-9 | MUST | P5 | Protocol and authorization | JWT bearer grant is distinct from client assertion authentication and rejects purpose confusion. |
| CORE-10 | SHOULD | P7 | Protocol and authorization | Device flow enforces expiry, polling interval, slow_down, rate limits and explicit user verification. |
| CORE-11 | MAY | P8 | Protocol and authorization | CIBA has client authentication, user binding, approval timeout and tested delivery/polling semantics. |
| CORE-12 | MUST | P2 | Protocol and authorization | Resources reject access tokens in query/body credentials and accept only the configured authorization scheme. |
| CORE-13 | MUST | P3 | Protocol and authorization | Token errors and resource challenges have endpoint-correct fields and a discoverable resource metadata URL. |

## DISC

| ID | Level | Phase | Owner | Acceptance condition |
| --- | --- | --- | --- | --- |
| DISC-1 | MUST | P1 | Protocol and resource integration | RFC 8414 issuer-path discovery resolves correctly for two tenants and rejects spoofed hosts. |
| DISC-2 | MUST | P2 | Protocol and resource integration | OIDC discovery returns the same issuer and consistent endpoint and algorithm metadata. |
| DISC-3 | MUST | P3 | Protocol and resource integration | Each sample resource serves correct protected-resource metadata and advertises its URL in challenges. |
| DISC-4 | MUST | P2 | Protocol and resource integration | Successful and applicable error authorization responses carry the correct iss; metadata advertises it. |
| DISC-5 | MUST | P5 | Protocol and resource integration | Metadata is generated from implemented capabilities, including CIMD and enabled binding/authentication methods. |
| DISC-6 | MAY | P8 | Protocol and resource integration | Signed metadata validates under configured trust and cannot override authoritative issuer identity inconsistently. |
| DISC-7 | SHOULD | P5 | Protocol and resource integration | Pinned MCP enterprise grant-profile discovery interoperates with the enterprise client fixture. |
| DISC-8 | MUST | P1 | Protocol and resource integration | Automated tests reject metadata for disabled or unenforced capabilities. |

## CLI

| ID | Level | Phase | Owner | Acceptance condition |
| --- | --- | --- | --- | --- |
| CLI-1 | MUST | P3 | Client registry and egress | A previously unknown permitted HTTPS client resolves from a validated CIMD document and cache policy is honored. |
| CLI-2 | MUST | P3 | Client registry and egress | DNS rebinding, private/mapped/link-local addresses, forbidden redirects and oversized/slow responses fail. |
| CLI-3 | MUST | P3 | Client registry and egress | Consent shows metadata host and redirect destination; policy rejects unapproved cross-origin or native redirect exceptions. |
| CLI-4 | MUST | P3 | Client registry and egress | DCR validates metadata, quotas and optional initial access tokens; public registration never creates trusted status. |
| CLI-5 | SHOULD | P7 | Client registry and egress | Registration read/update/delete is limited to the owning registration token and invalidates affected metadata safely. |
| CLI-6 | MAY | P8 | Client registry and egress | Trusted software statements validate issuer, signature, audience and expiry; statements cannot bypass tenant policy. |
| CLI-7 | MUST | P1 | Client registry and egress | Tenant admins register clients; foreign-tenant reads and mutations fail. |
| CLI-8 | MUST | P2 | Client registry and egress | private_key_jwt works with registered inline/remote keys; wrong client, audience, time or replay fails. |
| CLI-9 | SHOULD | P7 | Client registry and egress | PKI and self-signed mTLS client authentication have certificate and reverse-proxy negative tests. |
| CLI-10 | MUST | P2 | Client registry and egress | Basic authentication validates hashed generated secrets and tested bounded rotation overlap. |
| CLI-11 | MUST | P3 | Client registry and egress | Public code clients cannot bypass PKCE, refresh rotation or required sender binding. |
| CLI-12 | SHOULD | P3 | Client registry and egress | Web and native client metadata select distinct tested redirect-validation policies. |
| CLI-13 | MAY | P8 | Client registry and egress | Attestation validates pinned trust, freshness and build policy without turning untrusted attestation into identity. |
| CLI-14 | MUST | P3 | Client registry and egress | Any-client, CIMD-host allowlist and admin-approved-only tenant policies have positive and negative cases. |

## RES

| ID | Level | Phase | Owner | Acceptance condition |
| --- | --- | --- | --- | --- |
| RES-1 | MUST | P2 | Authorization and resource SDK | Authorize/token resource selection yields exactly that registered audience and rejects unauthorized changes. |
| RES-2 | MUST | P1 | Authorization and resource SDK | Resource catalog owns scopes, lifetime and clients; unknown targets fail with invalid_target. |
| RES-3 | MUST | P2 | Authorization and resource SDK | Missing resource succeeds only through an explicit server-owned binding; ambiguous requests fail. |
| RES-4 | SHOULD | P7 | Authorization and resource SDK | Multi-resource authorization records separate ceilings and returns one selected resource token per response. |
| RES-5 | MUST | P2 | Authorization and resource SDK | JWT profile claims, at+jwt purpose, audience, expiry and client identity validate in an independent verifier. |
| RES-6 | SHOULD | P2 | Authorization and resource SDK | Opaque tokens use the same grant/lineage decisions through authenticated introspection. |
| RES-7 | MUST | P2 | Authorization and resource SDK | Machine sub equals client_id; disjoint subject namespaces and principal_type prevent user/machine ambiguity. |
| RES-8 | MUST | P2 | Authorization and resource SDK | Dedicated tenant claim is issued from trusted transaction context and matched by resources. |
| RES-9 | MUST | P2 | Authorization and resource SDK | Resource A tokens fail at B even when both APIs share a deployment and signing infrastructure. |
| RES-10 | MUST | P2 prerequisite | Authorization, grants, tokens and resource SDK | [ADR 0010](adr/0010-rar-object-grants-prerequisite.md): standard RFC 9396 request/response, metadata and JWT/introspection details; registered document profile; protected consent; immutable object/action ceilings through code/refresh; resource enforcement and fail-closed unknown-type handling. Grant read on document 123, deny 124/write even when the user has both, and prove ACL removal, revocation, replay and narrowing. P2 cannot exit without this evidence. |

## GRANT

| ID | Level | Phase | Owner | Acceptance condition |
| --- | --- | --- | --- | --- |
| GRANT-1 | MUST | P2 | Grant services and resource SDK | Consent uses resource-owned descriptions and unknown scopes fail with invalid_scope. |
| GRANT-2 | MUST | P2 | Grant services and resource SDK | Enforce the approved RAR object/action ceiling and current resource-owned permissions before payload load; document 124 fails under a document-123 grant even if the user can access both. An unexpired token loses access immediately after ACL removal or grant revocation. |
| GRANT-3 | MUST | P2 | Grant services and resource SDK | Consent binds exact client/resource/scope request and resists CSRF, framing and malicious metadata. |
| GRANT-4 | MUST | P2 | Grant services and resource SDK | Immutable approved revisions retain principal/client/tenant/resource/validity and the typed RAR profile/version/object/action ceiling; codes, refresh families and issuances bind to that exact approval. |
| GRANT-5 | SHOULD | P2 | Grant services and resource SDK | New consent extends visible authorization while old refresh families retain their original scope ceilings. |
| GRANT-6 | MUST | P2 | Grant services and resource SDK | Refresh preserves or narrows scopes and complete RAR object/action tuples, never adds objects/actions or drops required details; P4 repeats this invariant for exchange and mapped resources. |
| GRANT-7 | MUST | P2 | Grant services and resource SDK | Users revoke only their own grants; tenant admins can revoke only grants in their tenant. |
| GRANT-8 | MAY | P8 | Grant services and resource SDK | Client grant management exposes only the caller's authorized grant operations and cannot silently expand consent. |
| GRANT-9 | MUST | P4 | Grant services and resource SDK | Root revocation blocks refresh and all multi-hop descendants on the next fresh authoritative decision. |
| GRANT-10 | MUST | P2 | Grant services and resource SDK | Grant lifetime, prohibited clients and admin-required scopes are enforced before approval and issuance. |
| GRANT-11 | SHOULD | P7 | Grant services and resource SDK | Admin approval produces per-user bounded grants; revoking its root invalidates all derived credentials. |
| GRANT-12 | MUST | P5 | Grant services and resource SDK | No-prompt issuance has audited first-party trust or explicit enterprise/admin authority; generic clients still prompt. |

## LIFE

| ID | Level | Phase | Owner | Acceptance condition |
| --- | --- | --- | --- | --- |
| LIFE-1 | MUST | P2 | Token lifecycle and keys | Effective access lifetime is capped by resource, client, tenant and grant deadlines; default is five minutes. |
| LIFE-2 | MUST | P2 | Token lifecycle and keys | Refresh tokens are hashed and one-use; authenticated reuse revokes family and authorization roots. |
| LIFE-3 | MUST | P2 | Token lifecycle and keys | Refresh idle and absolute expiries survive rotation and cannot exceed tenant or grant limits. |
| LIFE-4 | MUST | P2 | Token lifecycle and keys | Revocation authenticates confidential clients, enforces credential ownership and avoids unknown-token disclosure. |
| LIFE-5 | MUST | P2 | Token lifecycle and keys | Introspection authenticates the resource and reveals active claims only for its permitted tenant/audience. |
| LIFE-6 | MAY | P8 | Token lifecycle and keys | JWT introspection responses validate purpose, intended receiver, time and signature independently. |
| LIFE-7 | SHOULD | P7 | Token lifecycle and keys | Revoked-token event/denylist consumers converge, handle duplicates and retain entries through token expiry. |
| LIFE-8 | SHOULD | P7 | Token lifecycle and keys | Pinned SSF/CAEP events are authenticated, replay-safe and mapped to local revocation commands. |
| LIFE-9 | MUST | P2 | Token lifecycle and keys | User/client incident revocation invalidates all affected credentials, including later-added exchange actor dependencies. |
| LIFE-10 | MUST | P1 | Token lifecycle and keys | Keys publish before use and remain through maximum signed-artifact expiry plus allowed overlap. |
| LIFE-11 | MUST | P2 | Token lifecycle and keys | Configured asymmetric algorithms work; none, HMAC and algorithm/key confusion fail for access and ID tokens. |
| LIFE-12 | MUST | P4 | Token lifecycle and keys | Every issuance is traceable to root, family, code and parent as applicable; JWT jti and opaque internal IDs are unique. |

## BIND

| ID | Level | Phase | Owner | Acceptance condition |
| --- | --- | --- | --- | --- |
| BIND-1 | MUST | P3 | Binding validator and resource SDK | DPoP access and public refresh tokens are key-bound; copied tokens without the key fail. |
| BIND-2 | MUST | P3 | Binding validator and resource SDK | Endpoint-specific htm/htu/iat/jti checks and resource ath checks fail independently when tampered. |
| BIND-3 | SHOULD | P3 | Binding validator and resource SDK | Server nonce challenge, retry, expiry and replay fixtures pass at token and resource endpoints. |
| BIND-4 | SHOULD | P3 | Binding validator and resource SDK | A code issued with dpop_jkt cannot be redeemed using another key. |
| BIND-5 | SHOULD | P7 | Binding validator and resource SDK | Certificate-bound access tokens require the matching certificate and cannot downgrade to bearer use. |
| BIND-6 | MUST | P3 | Binding validator and resource SDK | Both client/resource binding policy and actual proof enforcement agree; missing proofs fail. |
| BIND-7 | MUST | P4 | Binding validator and resource SDK | Approved recipient-driven exchange binds output to the authenticated intermediary's key and rejects other topologies. |

## DEL

| ID | Level | Phase | Owner | Acceptance condition |
| --- | --- | --- | --- | --- |
| DEL-1 | MUST | P4 | Delegation services and gateway integration | Confidential intermediary authentication is mandatory; supplied actor tokens must match the authenticated actor. |
| DEL-2 | MUST | P4 | Delegation services and gateway integration | User subject stays stable and nested act history orders current and prior actors correctly. |
| DEL-3 | MUST | P4 | Delegation services and gateway integration | Reuse P2 typed RAR comparison: subset objects/actions succeed only on an approved edge; additional identifiers, action expansion, tuple recombination, tenant/user changes, unauthorized audiences and unknown mappings fail. |
| DEL-4 | MUST | P4 | Delegation services and gateway integration | Exchange requires applicable may_act or a configured recipient/intermediary/target delegation edge. |
| DEL-5 | MUST | P4 | Delegation services and gateway integration | Depth overflow, cycles and child lifetime beyond parent fail. |
| DEL-6 | MUST | P4 | Delegation services and gateway integration | Revoked or expired root, family, parent or applicable actor dependency prevents exchange. |
| DEL-7 | MUST | P4 | Delegation services and gateway integration | No-user operations follow the machine authorization path and cannot fabricate user claims. |
| DEL-8 | SHOULD | P7 | Delegation services and gateway integration | Pinned transaction-token profile constrains purpose, trust domain and expiry with its own validation tests. |
| DEL-9 | MUST | P4 | Delegation services and gateway integration | Audit and lineage can reconstruct every actor and parent of a multi-hop request. |
| DEL-10 | MUST | P2 | Delegation services and gateway integration | Autonomous agents receive separate machine client identities and auditable resource-limited credentials. |

## OIDC

| ID | Level | Phase | Owner | Acceptance condition |
| --- | --- | --- | --- | --- |
| OIDC-1 | MUST | P2 | OIDC provider and sessions | Code flow produces a client-audience ID token with bound nonce; sample RP validates it. |
| OIDC-2 | MUST | P2 | OIDC provider and sessions | Resources reject ID tokens and the provider rejects access tokens used as identity assertions without explicit trust. |
| OIDC-3 | MUST | P5 | OIDC provider and sessions | UserInfo uses its own audience and returns only verified, authorized scopes/claims; offline_access is not a claims bundle. |
| OIDC-4 | MUST | P5 | OIDC provider and sessions | All listed prompt modes, max_age, hints and assurance parameters have successful and rejected request fixtures. |
| OIDC-5 | SHOULD | P7 | OIDC provider and sessions | Pairwise identifiers are stable per approved sector and do not change internal identity or cross-sector privacy. |
| OIDC-6 | MUST | P5 | OIDC provider and sessions | Logout accepts only validated RP/session requests and registered return destinations. |
| OIDC-7 | MUST | P5 | OIDC provider and sessions | Back-channel logout queues every affected RP, signs purpose-specific tokens and retries safely. |
| OIDC-8 | MAY | P8 | OIDC provider and sessions | Optional browser logout/session mechanisms have capability tests and do not replace back-channel guarantees. |
| OIDC-9 | MUST | P2 | OIDC provider and sessions | Multi-tenant account selection cannot change an existing transaction's tenant authority. |
| OIDC-10 | MUST | P5 | OIDC provider and sessions | Email and phone verification flags reflect trusted verification evidence, never unchecked user input. |
| OIDC-11 | SHOULD | P7 | OIDC provider and sessions | Applicable basic/config/dynamic OP certification artifacts are obtained for the deployed configuration. |

## FED

| ID | Level | Phase | Owner | Acceptance condition |
| --- | --- | --- | --- | --- |
| FED-1 | MUST | P2 | Federation and enterprise integration | Tenant-configured upstream OIDC works with validated discovery, issuer, audience, nonce and keys. |
| FED-2 | SHOULD | P7 | Federation and enterprise integration | SAML signature, recipient, audience, correlation, replay and XML security cases pass. |
| FED-3 | MUST | P2 | Federation and enterprise integration | External issuer/subject links resolve stable local users; matching email cannot silently link accounts. |
| FED-4 | SHOULD | P7 | Federation and enterprise integration | Tenant/domain hints route login without creating membership or bypassing provider trust. |
| FED-5 | MUST | P5 | Federation and enterprise integration | Trusted ID-JAG issues a locally bounded enterprise-derived grant without interactive consent. |
| FED-6 | MUST | P5 | Federation and enterprise integration | Wrong type/issuer/audience/client/resource/scope/time/replay or local tenant mapping is rejected. |
| FED-7 | SHOULD | P7 | Federation and enterprise integration | Outbound ID-JAG exchange is explicitly admin-authorized and constrained to the trusted target AS/resource. |
| FED-8 | MUST | P5 | Federation and enterprise integration | XAA capability is limited to the implemented pinned ID-JAG profile, with end-to-end fixtures. |
| FED-9 | MUST | P5 | Federation and enterprise integration | Pinned MCP enterprise flow, discovery and lifecycle cutoff run end to end with an integration fixture. |
| FED-10 | MUST | P5 | Federation and enterprise integration | Generic assertion issuers have separate trust configuration, allowed subjects and resource ceilings. |
| FED-11 | SHOULD | P7 | Federation and enterprise integration | Upstream subject exchange only accepts approved issuers, recipients, token purposes and local mappings. |
| FED-12 | SHOULD | P7 | Federation and enterprise integration | SCIM creation/update/deactivation is tenant-scoped; deactivation revokes sessions and all user authority. |
| FED-13 | MAY | P8 | Federation and enterprise integration | OpenID Federation trust-chain validation includes anchors, policy combination, expiry and key rollover. |

## M2M

| ID | Level | Phase | Owner | Acceptance condition |
| --- | --- | --- | --- | --- |
| M2M-1 | MUST | P2 | Machine identity and client registry | Machine client credentials enforce registered target and scope allowlists. |
| M2M-2 | SHOULD | P7 | Machine identity and client registry | Each supported workload provider has explicit format/audience/subject mapping and replay tests; unsupported credentials fail. |
| M2M-3 | MAY | P7 | Machine identity and client registry | SPIFFE certificate identity maps only to configured clients and combines with tested mTLS binding. |
| M2M-4 | MUST | P2 | Machine identity and client registry | Machine tokens are recognizable by explicit principal type and contain no user authentication/profile claims. |
| M2M-5 | MUST | P2 | Machine identity and client registry | Generated secrets are displayed once, hashed, expiring and safely rotated with limited overlap. |
| M2M-6 | SHOULD | P7 | Machine identity and client registry | Issuance limits and unusual-volume alerts work per machine client without leaking secrets in telemetry. |

## SEC

| ID | Level | Phase | Owner | Acceptance condition |
| --- | --- | --- | --- | --- |
| SEC-1 | MUST | P6 | Security across all components | RFC 9700 control checklist is complete with reviewed and justified applicability/deviation entries. |
| SEC-2 | SHOULD | P2 (required for object-RAR profile) | Security across all components | RFC 9126 PAR is a dependency of the mandatory P2 object-RAR profile. Apply the registered client authentication policy, bounded lifetime, S256/client binding and immutable request handling; front-channel replacement, request_uri swapping and required-PAR bypass fail. Wider FAPI requirements remain P7. |
| SEC-3 | MAY | P8 | Security across all components | JAR validates client signatures, audience, time and request-parameter consistency without remote key-header trust. |
| SEC-4 | MAY | P8 | Security across all components | JARM responses validate audience, signing policy, expiry and client processing in conformance fixtures. |
| SEC-5 | MUST | P5 | Security across all components | Resource step-up challenge leads to verified fresh required assurance; failure or unsupported assurance blocks issuance. |
| SEC-6 | MUST | P2 | Security across all components | Issuer identification and upstream callback correlation prevent AS mix-up in multi-issuer tests. |
| SEC-7 | MUST | P2 | Security across all components | Unregistered clients and redirects never cause attacker-controlled redirects, including error cases. |
| SEC-8 | MUST | P2 | Security across all components | Login/consent CSRF, framing and referrer tests pass; callback correlation cannot be bypassed. |
| SEC-9 | MUST | P2 | Security across all components | Purpose-specific JWT validators enforce type, algorithm, issuer and audience without following jku/x5u. |
| SEC-10 | SHOULD | P7 | Security across all components | Full FAPI profile conformance passes for supported confidential-client configurations before it is advertised. |
| SEC-11 | MUST | P2 | Security across all components | Login, token and introspection limits apply across replicas by configured IP/client/user dimensions. |
| SEC-12 | MUST | P6 | Security across all components | Published threat model and external review are complete, findings remediated and critical cases retested. |

## WEB

| ID | Level | Phase | Owner | Acceptance condition |
| --- | --- | --- | --- | --- |
| WEB-1 | MUST | P2 | Browser integration and sessions | Runnable [Go reference BFF](implementation-plan.md#go-reference-backend-for-frontend) keeps tokens server-side, serializes refresh, permits only configured API forwarding and gives the browser hardened opaque session cookies. Document standalone/existing-Go-backend deployment and a language-independent integration contract. |
| WEB-2 | MUST | P3 | Browser integration and sessions | Browser-token sample uses short-lived DPoP credentials and a non-exportable key with no token URL leakage. |
| WEB-3 | SHOULD | P7 | Browser integration and sessions | Supported-browser DBSC registration/refresh works and registered sessions cannot silently downgrade. |
| WEB-4 | MUST | P2 | Browser integration and sessions | Sensitive pages enforce nonce CSP, supported Trusted Types and escaped untrusted content. |
| WEB-5 | MUST | P5 (contract in P2) | Browser integration and sessions | [Embedded-session integration](implementation-plan.md#embedded-authentication-and-sessions) extends the same Go reference BFF with a runnable cross-origin parent/iframe example, iframe-context cookie establishment, partitioned-cookie and permitted Storage Access paths, proof/origin/session-bound one-use handoff, atomic replay/concurrency checks, lifecycle/revocation evidence and a versioned browser matrix with blocked-storage/popup fallbacks. Tokens remain server-side; unsupported cases fail explicitly. |
| WEB-6 | MUST | P5 (contract in P2) | Browser integration and sessions | Exact tenant/client parent-origin and full ancestor policy permits only approved application frames; login, account selection, consent and step-up remain unframeable and use popup/top-level continuation. Sandbox, opaque-origin, nested-frame and forged message origin/source cases fail safely. |
| WEB-7 | MUST | P2 | Browser integration and sessions | CORS is explicit per origin; wildcard credentialed responses and reflected arbitrary origins fail. |
| WEB-8 | MUST | P2 | Browser integration and sessions | Idle/absolute timeout, list/end sessions and sensitive-action reauthentication work; P5 completes assurance integration. |
| WEB-9 | SHOULD | P7 | Browser integration and sessions | Documented device/network changes produce bounded step-up/revocation decisions with false-positive monitoring. |
| WEB-10 | MUST | P2 | Browser integration and sessions | URL, fragment, email and WebSocket fixtures contain no access/refresh tokens; tickets are single-use and audience-bound. |

## ADM

| ID | Level | Phase | Owner | Acceptance condition |
| --- | --- | --- | --- | --- |
| ADM-1 | MUST | P1 | Administration and audit | Cross-tenant API, SQL relationship, token, key and job access fails under adversarial fixtures. |
| ADM-2 | MUST | P1 | Administration and audit | Immutable tenant issuer and key/discovery boundaries are documented and exercised with two tenants. |
| ADM-3 | MUST | P5 | Administration and audit | Every listed client/IdP/MFA/lifetime/binding/admin-scope policy affects authorization and subsequent status decisions. |
| ADM-4 | MUST | P5 | Administration and audit | Admin API and UI cover specified resources; foreign-tenant operations and insufficient scope/step-up fail. |
| ADM-5 | MUST | P2 | Administration and audit | Security decisions record required correlation fields without raw credentials; P4/P5 add exchange/federation coverage. |
| ADM-6 | SHOULD | P7 | Administration and audit | SIEM exporters and Shared Signals deliver tenant-correct events with retries, redaction and delivery telemetry. |
| ADM-7 | SHOULD | P7 | Administration and audit | Retention is tenant-specific and external anchors/immutable storage detect audit alteration. |
| ADM-8 | MUST | P2 | Administration and audit | Connected apps shows grant scopes and usage and proves immediate revoke on the next resource check. |
| ADM-9 | SHOULD | P7 | Administration and audit | New-grant/client and suspicious-activity notifications deduplicate events and respect configured recipients. |

## OPS

| ID | Level | Phase | Owner | Acceptance condition |
| --- | --- | --- | --- | --- |
| OPS-1 | MUST | P1 | Platform and release engineering | Production signer uses non-exportable KMS/HSM keys; scheduled/emergency rotation runbooks are validated by P6. |
| OPS-2 | MUST | P6 | Platform and release engineering | Zone-loss drill preserves issuance and JWKS with acknowledged-state consistency. |
| OPS-3 | SHOULD | P7 | Platform and release engineering | Representative regional load meets p99 below 10 ms or the miss is recorded; no stale-allow shortcut is accepted. |
| OPS-4 | MUST | P1 | Platform and release engineering | Durable PostgreSQL and expand/contract migrations work; P6 validates mixed-version upgrade and restore. |
| OPS-5 | SHOULD | P7 | Platform and release engineering | Self-hosted/air-gapped installation works with local signer/IdP or approved metadata mirrors and enforced egress. |
| OPS-6 | MUST | P1 | Platform and release engineering | Structured telemetry and security alerts are wired; P6 validates end-to-end failure detection without credential leakage. |
| OPS-7 | SHOULD | P7 | Platform and release engineering | Tenant routing, databases, backups and audit exports satisfy configured residency boundaries. |
| OPS-8 | MUST | P6 | Platform and release engineering | Applicable OP tests and pinned MCP/adversarial suites run in CI; FAPI plans run when P7 enables the profile. |
| OPS-9 | MUST | P0 | Platform and release engineering | Each implemented draft has an exact revision/hash and fixtures; upgrades require reviewed behavior changes. |
