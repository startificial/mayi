# Mayi requirement delivery matrix

October 18, 2026 · Implementation and bounded local verification

This matrix retains all 156 requirements in the [README](../README.md), their levels, owners and delivery phases. P2 locally verified means the configured experimental preview has executable evidence for its assigned acceptance condition; it is not a production, external certification or universal interoperability claim. P6 remains the production MUST gate. Later extensions must inherit these controls.

[P0 evidence](p0/protocol-spike.md) established the pinned standards, Fosite/transaction/signing selection and license admission. [P1 evidence](p1-foundation.md) established supplied PostgreSQL, explicit migrations, owner/runtime isolation, stable issuers, key publication and atomic audit/outbox. Current behavior is documented in [the P2 runbook](p2-core-authorization.md) and [ADR 0024](adr/0024-p2-required-authority-and-completion.md).

The [P2 evidence manifest](../tests/conformance/p2-evidence.json) maps requirement groups to executable tests and exact standard revisions. Its CI test rejects missing source/test references and pin drift. The manifest is traceability, not a substitute for executing those tests: `go run ./tools/p0` supplies real PostgreSQL/OpenBao and the complete public protocol/BFF/SDK fixtures; ordinary `go test` skips those integration cases without the harness environment. CI also runs race, vet, formatting, architecture, license and error-contract checks.

The connected reference BFF and resource API prove read 123, deny 124/write before payload, current ACL removal, refresh rotation/replay and fresh revocation cutoff. Completion tests additionally cover finite budgets shared across replica instances, required PAR/options commits, explicit resource bindings, incremental revisions with frozen old-family ceilings, administered machine authority, connected usage and trusted audit correlation. Operator-owned resource authority requires one physical PostgreSQL database; browser certification, production operations, full OIDC/UserInfo/logout and iframe support retain later gates.

## CORE

| ID | Level | Phase | Owner | Acceptance condition  Status / evidence |
| --- | --- | --- | --- | ---  --- |
| CORE-1 | MUST | P2 | Protocol and authorization | Public and confidential code clients require S256; missing PKCE, plain and incorrect verifiers fail. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| CORE-2 | MUST | P2 | Protocol and authorization | Implicit and password requests fail and are absent from discovery. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| CORE-3 | MUST | P2 | Protocol and authorization | Wildcard, prefix, altered path and unregistered redirects fail without an unsafe redirect. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| CORE-4 | MUST | P3 | Protocol and authorization | Native loopback port exception works; host/path changes fail; private schemes and claimed HTTPS have separate fixtures. | [P3 native/discovery slice verified](../tests/conformance/p3-evidence.json) |
| CORE-5 | MUST | P2 | Protocol and authorization | A code expires within 60 seconds; concurrent redemption has one winner; authenticated reuse invalidates its issued lineage. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| CORE-6 | MUST | P2 | Protocol and authorization | Public refresh follows rotation and any configured sender binding; stale credentials cannot mint new tokens. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| CORE-7 | MUST | P2 | Protocol and authorization | Confidential clients obtain only approved machine-resource scopes. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| CORE-8 | MUST | P4 | Protocol and authorization | RFC 8693 request/response fixtures and rejected exchange cases pass. | Planned (foundation evidence above where applicable) |
| CORE-9 | MUST | P5 | Protocol and authorization | JWT bearer grant is distinct from client assertion authentication and rejects purpose confusion. | Planned (foundation evidence above where applicable) |
| CORE-10 | SHOULD | P7 | Protocol and authorization | Device flow enforces expiry, polling interval, slow_down, rate limits and explicit user verification. | Planned (foundation evidence above where applicable) |
| CORE-11 | MAY | P8 | Protocol and authorization | CIBA has client authentication, user binding, approval timeout and tested delivery/polling semantics. | Planned (foundation evidence above where applicable) |
| CORE-12 | MUST | P2 | Protocol and authorization | Resources reject access tokens in query/body credentials and accept only the configured authorization scheme. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| CORE-13 | MUST | P2 foundation / P3 completion | Protocol and authorization | P2 has endpoint-specific errors/recovery, typed mappings, trusted request correlation, redaction and denial/non-enumeration evidence. P3 completes resource challenges and discoverable resource metadata URLs. | [P2 locally verified](../tests/conformance/p2-evidence.json); [P3 Bearer metadata/challenges verified](../tests/conformance/p3-evidence.json); DPoP challenges verified in the same P3 profile; step-up retains later gates |

## DISC

| ID | Level | Phase | Owner | Acceptance condition  Status / evidence |
| --- | --- | --- | --- | ---  --- |
| DISC-1 | MUST | P1 | Protocol and resource integration | RFC 8414 issuer-path discovery resolves correctly for two tenants and rejects spoofed hosts. | Planned (foundation evidence above where applicable) |
| DISC-2 | MUST | P2 | Protocol and resource integration | OIDC discovery returns the same issuer and consistent endpoint and algorithm metadata. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| DISC-3 | MUST | P3 | Protocol and resource integration | Each sample resource serves correct protected-resource metadata and advertises its URL in challenges. | [P3 native/discovery slice verified](../tests/conformance/p3-evidence.json) |
| DISC-4 | MUST | P2 | Protocol and resource integration | Successful and applicable error authorization responses carry the correct iss; metadata advertises it. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| DISC-5 | MUST | P5 | Protocol and resource integration | Metadata is generated from implemented capabilities, including CIMD and enabled binding/authentication methods. | Planned (foundation evidence above where applicable) |
| DISC-6 | MAY | P8 | Protocol and resource integration | Signed metadata validates under configured trust and cannot override authoritative issuer identity inconsistently. | Planned (foundation evidence above where applicable) |
| DISC-7 | SHOULD | P5 | Protocol and resource integration | Pinned MCP enterprise grant-profile discovery interoperates with the enterprise client fixture. | Planned (foundation evidence above where applicable) |
| DISC-8 | MUST | P1 | Protocol and resource integration | Automated tests reject metadata for disabled or unenforced capabilities. | Planned (foundation evidence above where applicable) |

## CLI

| ID | Level | Phase | Owner | Acceptance condition  Status / evidence |
| --- | --- | --- | --- | ---  --- |
| CLI-1 | MUST | P3 | Client registry and egress | A previously unknown permitted HTTPS client resolves from a validated CIMD document and cache policy is honored. | Planned (foundation evidence above where applicable) |
| CLI-2 | MUST | P3 | Client registry and egress | DNS rebinding, private/mapped/link-local addresses, forbidden redirects and oversized/slow responses fail. | Planned (foundation evidence above where applicable) |
| CLI-3 | MUST | P3 | Client registry and egress | Consent shows metadata host and redirect destination; policy rejects unapproved cross-origin or native redirect exceptions. | Planned (foundation evidence above where applicable) |
| CLI-4 | MUST | P3 | Client registry and egress | DCR validates metadata, quotas and optional initial access tokens; public registration never creates trusted status. | [P3 public DCR profile verified](../tests/conformance/p3-evidence.json); explicit public code/refresh profile, broader interoperability remains |
| CLI-5 | SHOULD | P7 | Client registry and egress | Registration read/update/delete is limited to the owning registration token and invalidates affected metadata safely. | Planned (foundation evidence above where applicable) |
| CLI-6 | MAY | P8 | Client registry and egress | Trusted software statements validate issuer, signature, audience and expiry; statements cannot bypass tenant policy. | Planned (foundation evidence above where applicable) |
| CLI-7 | MUST | P1 | Client registry and egress | Tenant admins register clients; foreign-tenant reads and mutations fail. | Planned (foundation evidence above where applicable) |
| CLI-8 | MUST | P2 | Client registry and egress | private_key_jwt works with registered inline/remote keys; wrong client, audience, time or replay fails. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| CLI-9 | SHOULD | P7 | Client registry and egress | PKI and self-signed mTLS client authentication have certificate and reverse-proxy negative tests. | Planned (foundation evidence above where applicable) |
| CLI-10 | MUST | P2 | Client registry and egress | Basic authentication validates hashed generated secrets and tested bounded rotation overlap. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| CLI-11 | MUST | P3 | Client registry and egress | Public code clients cannot bypass PKCE, refresh rotation or required sender binding. | [P3 ES256 profile verified](../tests/conformance/p3-evidence.json); browser sample remains WEB-2 |
| CLI-12 | SHOULD | P3 | Client registry and egress | Web and native client metadata select distinct tested redirect-validation policies. | [P3 native/discovery slice verified](../tests/conformance/p3-evidence.json) |
| CLI-13 | MAY | P8 | Client registry and egress | Attestation validates pinned trust, freshness and build policy without turning untrusted attestation into identity. | Planned (foundation evidence above where applicable) |
| CLI-14 | MUST | P3 | Client registry and egress | Any-client, CIMD-host allowlist and admin-approved-only tenant policies have positive and negative cases. | DCR open/admin-only admission verified in [P3 evidence](../tests/conformance/p3-evidence.json); CIMD host policy remains planned |

## RES

| ID | Level | Phase | Owner | Acceptance condition  Status / evidence |
| --- | --- | --- | --- | ---  --- |
| RES-1 | MUST | P2 | Authorization and resource SDK | Authorize/token resource selection yields exactly that registered audience and rejects unauthorized changes. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| RES-2 | MUST | P1 | Authorization and resource SDK | Resource catalog owns scopes, lifetime and clients; unknown targets fail with invalid_target. | Planned (foundation evidence above where applicable) |
| RES-3 | MUST | P2 | Authorization and resource SDK | Missing resource succeeds only through an explicit server-owned binding; ambiguous requests fail. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| RES-4 | SHOULD | P7 | Authorization and resource SDK | Multi-resource authorization records separate ceilings and returns one selected resource token per response. | Planned (foundation evidence above where applicable) |
| RES-5 | MUST | P2 | Authorization and resource SDK | JWT profile claims, at+jwt purpose, audience, expiry and client identity validate in an independent verifier. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| RES-6 | SHOULD | P2 | Authorization and resource SDK | Opaque tokens use the same grant/lineage decisions through authenticated introspection. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| RES-7 | MUST | P2 | Authorization and resource SDK | Machine sub equals client_id; disjoint subject namespaces and principal_type prevent user/machine ambiguity. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| RES-8 | MUST | P2 | Authorization and resource SDK | Dedicated tenant claim is issued from trusted transaction context and matched by resources. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| RES-9 | MUST | P2 | Authorization and resource SDK | Resource A tokens fail at B even when both APIs share a deployment and signing infrastructure. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| RES-10 | MUST | P2 prerequisite | Authorization, grants, tokens and resource SDK | Required RFC 9396 request/response/metadata/JWT/introspection details; registered object semantics; PAR-bound guarded consent; immutable code/family/issuance ceilings; SDK tuple/current-ACL enforcement; denial, narrowing, replay and immediate cutoff. | [P2 locally verified](../tests/conformance/p2-evidence.json) |

## GRANT

| ID | Level | Phase | Owner | Acceptance condition  Status / evidence |
| --- | --- | --- | --- | ---  --- |
| GRANT-1 | MUST | P2 | Grant services and resource SDK | Consent uses resource-owned descriptions and unknown scopes fail with invalid_scope. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| GRANT-2 | MUST | P2 | Grant services and resource SDK | Enforce the approved RAR object/action ceiling and current resource-owned permissions before payload load; document 124 fails under a document-123 grant even if the user can access both. An unexpired token loses access immediately after ACL removal or grant revocation. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| GRANT-3 | MUST | P2 | Grant services and resource SDK | Consent binds exact client/resource/scope request and resists CSRF, framing and malicious metadata. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| GRANT-4 | MUST | P2 | Grant services and resource SDK | Immutable approved revisions retain principal/client/tenant/resource/validity and exact typed object/action ceilings. Codes, refresh families and issuances bind to the exact approved transaction and revision. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| GRANT-5 | SHOULD | P2 | Grant services and resource SDK | New consent extends visible authorization while old refresh families retain their original scope ceilings. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| GRANT-6 | MUST | P2 | Grant services and resource SDK | Refresh preserves or narrows scopes and complete resource/type/object/action tuples, never adds authority or drops required details. Omission preserves only the original bounded credential; P4 repeats this for exchange. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| GRANT-7 | MUST | P2 | Grant services and resource SDK | Users revoke only their own grants; tenant admins can revoke only grants in their tenant. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| GRANT-8 | MAY | P8 | Grant services and resource SDK | Client grant management exposes only the caller's authorized grant operations and cannot silently expand consent. | Planned (foundation evidence above where applicable) |
| GRANT-9 | MUST | P4 | Grant services and resource SDK | Root revocation blocks refresh and all multi-hop descendants on the next fresh authoritative decision. | Planned (foundation evidence above where applicable) |
| GRANT-10 | MUST | P2 | Grant services and resource SDK | Grant lifetime, prohibited clients and admin-required scopes are enforced before approval and issuance. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| GRANT-11 | SHOULD | P7 | Grant services and resource SDK | Admin approval produces per-user bounded grants; revoking its root invalidates all derived credentials. | Planned (foundation evidence above where applicable) |
| GRANT-12 | MUST | P5 | Grant services and resource SDK | No-prompt issuance has audited first-party trust or explicit enterprise/admin authority; generic clients still prompt. | Planned (foundation evidence above where applicable) |

## LIFE

| ID | Level | Phase | Owner | Acceptance condition  Status / evidence |
| --- | --- | --- | --- | ---  --- |
| LIFE-1 | MUST | P2 | Token lifecycle and keys | Effective access lifetime is capped by resource, client, tenant and grant deadlines; default is five minutes. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| LIFE-2 | MUST | P2 | Token lifecycle and keys | Refresh tokens are hashed and one-use; authenticated reuse revokes family and authorization roots. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| LIFE-3 | MUST | P2 | Token lifecycle and keys | Refresh idle and absolute expiries survive rotation and cannot exceed tenant or grant limits. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| LIFE-4 | MUST | P2 | Token lifecycle and keys | Revocation authenticates confidential clients, enforces credential ownership and avoids unknown-token disclosure. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| LIFE-5 | MUST | P2 | Token lifecycle and keys | Introspection authenticates the resource and reveals active claims only for its permitted tenant/audience. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| LIFE-6 | MAY | P8 | Token lifecycle and keys | JWT introspection responses validate purpose, intended receiver, time and signature independently. | Planned (foundation evidence above where applicable) |
| LIFE-7 | SHOULD | P7 | Token lifecycle and keys | Revoked-token event/denylist consumers converge, handle duplicates and retain entries through token expiry. | Planned (foundation evidence above where applicable) |
| LIFE-8 | SHOULD | P7 | Token lifecycle and keys | Pinned SSF/CAEP events are authenticated, replay-safe and mapped to local revocation commands. | Planned (foundation evidence above where applicable) |
| LIFE-9 | MUST | P2 | Token lifecycle and keys | User/client incident revocation invalidates all affected credentials, including later-added exchange actor dependencies. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| LIFE-10 | MUST | P1 | Token lifecycle and keys | Keys publish before use and remain through maximum signed-artifact expiry plus allowed overlap. | Planned (foundation evidence above where applicable) |
| LIFE-11 | MUST | P2 | Token lifecycle and keys | Configured asymmetric algorithms work; none, HMAC and algorithm/key confusion fail for access and ID tokens. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| LIFE-12 | MUST | P4 | Token lifecycle and keys | Every issuance is traceable to root, family, code and parent as applicable; JWT jti and opaque internal IDs are unique. | Planned (foundation evidence above where applicable) |

## BIND

| ID | Level | Phase | Owner | Acceptance condition  Status / evidence |
| --- | --- | --- | --- | ---  --- |
| BIND-1 | MUST | P3 | Binding validator and resource SDK | DPoP access and public refresh tokens are key-bound; copied tokens without the key fail. | [P3 ES256 profile verified](../tests/conformance/p3-evidence.json); browser sample remains WEB-2 |
| BIND-2 | MUST | P3 | Binding validator and resource SDK | Endpoint-specific htm/htu/iat/jti checks and resource ath checks fail independently when tampered. | [P3 ES256 profile verified](../tests/conformance/p3-evidence.json); browser sample remains WEB-2 |
| BIND-3 | SHOULD | P3 | Binding validator and resource SDK | Server nonce challenge, retry, expiry and replay fixtures pass at token and resource endpoints. | [P3 ES256 profile verified](../tests/conformance/p3-evidence.json); browser sample remains WEB-2 |
| BIND-4 | SHOULD | P3 | Binding validator and resource SDK | A code issued with dpop_jkt cannot be redeemed using another key. | [P3 ES256 profile verified](../tests/conformance/p3-evidence.json); browser sample remains WEB-2 |
| BIND-5 | SHOULD | P7 | Binding validator and resource SDK | Certificate-bound access tokens require the matching certificate and cannot downgrade to bearer use. | Planned (foundation evidence above where applicable) |
| BIND-6 | MUST | P3 | Binding validator and resource SDK | Both client/resource binding policy and actual proof enforcement agree; missing proofs fail. | [P3 ES256 profile verified](../tests/conformance/p3-evidence.json); browser sample remains WEB-2 |
| BIND-7 | MUST | P4 | Binding validator and resource SDK | Approved recipient-driven exchange binds output to the authenticated intermediary's key and rejects other topologies. | Planned (foundation evidence above where applicable) |

## DEL

| ID | Level | Phase | Owner | Acceptance condition  Status / evidence |
| --- | --- | --- | --- | ---  --- |
| DEL-1 | MUST | P4 | Delegation services and gateway integration | Confidential intermediary authentication is mandatory; supplied actor tokens must match the authenticated actor. | Planned (foundation evidence above where applicable) |
| DEL-2 | MUST | P4 | Delegation services and gateway integration | User subject stays stable and nested act history orders current and prior actors correctly. | Planned (foundation evidence above where applicable) |
| DEL-3 | MUST | P4 | Delegation services and gateway integration | Reuse P2 typed RAR comparison: subset objects/actions succeed only on an approved edge; additional identifiers, action expansion, tuple recombination, tenant/user changes, unauthorized audiences and unknown mappings fail. | Planned (foundation evidence above where applicable) |
| DEL-4 | MUST | P4 | Delegation services and gateway integration | Exchange requires applicable may_act or a configured recipient/intermediary/target delegation edge. | Planned (foundation evidence above where applicable) |
| DEL-5 | MUST | P4 | Delegation services and gateway integration | Depth overflow, cycles and child lifetime beyond parent fail. | Planned (foundation evidence above where applicable) |
| DEL-6 | MUST | P4 | Delegation services and gateway integration | Revoked or expired root, family, parent or applicable actor dependency prevents exchange. | Planned (foundation evidence above where applicable) |
| DEL-7 | MUST | P4 | Delegation services and gateway integration | No-user operations follow the machine authorization path and cannot fabricate user claims. | Planned (foundation evidence above where applicable) |
| DEL-8 | SHOULD | P7 | Delegation services and gateway integration | Pinned transaction-token profile constrains purpose, trust domain and expiry with its own validation tests. | Planned (foundation evidence above where applicable) |
| DEL-9 | MUST | P4 | Delegation services and gateway integration | Audit and lineage can reconstruct every actor and parent of a multi-hop request. | Planned (foundation evidence above where applicable) |
| DEL-10 | MUST | P2 | Delegation services and gateway integration | Autonomous agents receive separate machine client identities and auditable resource-limited credentials. | [P2 locally verified](../tests/conformance/p2-evidence.json) |

## OIDC

| ID | Level | Phase | Owner | Acceptance condition  Status / evidence |
| --- | --- | --- | --- | ---  --- |
| OIDC-1 | MUST | P2 | OIDC provider and sessions | Code flow produces a client-audience ID token with bound nonce; sample RP validates it. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| OIDC-2 | MUST | P2 | OIDC provider and sessions | Resources reject ID tokens and the provider rejects access tokens used as identity assertions without explicit trust. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| OIDC-3 | MUST | P5 | OIDC provider and sessions | UserInfo uses its own audience and returns only verified, authorized scopes/claims; offline_access is not a claims bundle. | Planned (foundation evidence above where applicable) |
| OIDC-4 | MUST | P5 | OIDC provider and sessions | All listed prompt modes, max_age, hints and assurance parameters have successful and rejected request fixtures. | Planned (foundation evidence above where applicable) |
| OIDC-5 | SHOULD | P7 | OIDC provider and sessions | Pairwise identifiers are stable per approved sector and do not change internal identity or cross-sector privacy. | Planned (foundation evidence above where applicable) |
| OIDC-6 | MUST | P5 | OIDC provider and sessions | Logout accepts only validated RP/session requests and registered return destinations. | Planned (foundation evidence above where applicable) |
| OIDC-7 | MUST | P5 | OIDC provider and sessions | Back-channel logout queues every affected RP, signs purpose-specific tokens and retries safely. | Planned (foundation evidence above where applicable) |
| OIDC-8 | MAY | P8 | OIDC provider and sessions | Optional browser logout/session mechanisms have capability tests and do not replace back-channel guarantees. | Planned (foundation evidence above where applicable) |
| OIDC-9 | MUST | P2 | OIDC provider and sessions | Multi-tenant account selection cannot change an existing transaction's tenant authority. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| OIDC-10 | MUST | P5 | OIDC provider and sessions | Email and phone verification flags reflect trusted verification evidence, never unchecked user input. | Planned (foundation evidence above where applicable) |
| OIDC-11 | SHOULD | P7 | OIDC provider and sessions | Applicable basic/config/dynamic OP certification artifacts are obtained for the deployed configuration. | Planned (foundation evidence above where applicable) |

## FED

| ID | Level | Phase | Owner | Acceptance condition  Status / evidence |
| --- | --- | --- | --- | ---  --- |
| FED-1 | MUST | P2 | Federation and enterprise integration | Tenant-configured upstream OIDC works with validated discovery, issuer, audience, nonce and keys. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| FED-2 | SHOULD | P7 | Federation and enterprise integration | SAML signature, recipient, audience, correlation, replay and XML security cases pass. | Planned (foundation evidence above where applicable) |
| FED-3 | MUST | P2 | Federation and enterprise integration | External issuer/subject links resolve stable local users; matching email cannot silently link accounts. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| FED-4 | SHOULD | P7 | Federation and enterprise integration | Tenant/domain hints route login without creating membership or bypassing provider trust. | Planned (foundation evidence above where applicable) |
| FED-5 | MUST | P5 | Federation and enterprise integration | Trusted ID-JAG issues a locally bounded enterprise-derived grant without interactive consent. | Planned (foundation evidence above where applicable) |
| FED-6 | MUST | P5 | Federation and enterprise integration | Wrong type/issuer/audience/client/resource/scope/time/replay or local tenant mapping is rejected. | Planned (foundation evidence above where applicable) |
| FED-7 | SHOULD | P7 | Federation and enterprise integration | Outbound ID-JAG exchange is explicitly admin-authorized and constrained to the trusted target AS/resource. | Planned (foundation evidence above where applicable) |
| FED-8 | MUST | P5 | Federation and enterprise integration | XAA capability is limited to the implemented pinned ID-JAG profile, with end-to-end fixtures. | Planned (foundation evidence above where applicable) |
| FED-9 | MUST | P5 | Federation and enterprise integration | Pinned MCP enterprise flow, discovery and lifecycle cutoff run end to end with an integration fixture. | Planned (foundation evidence above where applicable) |
| FED-10 | MUST | P5 | Federation and enterprise integration | Generic assertion issuers have separate trust configuration, allowed subjects and resource ceilings. | Planned (foundation evidence above where applicable) |
| FED-11 | SHOULD | P7 | Federation and enterprise integration | Upstream subject exchange only accepts approved issuers, recipients, token purposes and local mappings. | Planned (foundation evidence above where applicable) |
| FED-12 | SHOULD | P7 | Federation and enterprise integration | SCIM creation/update/deactivation is tenant-scoped; deactivation revokes sessions and all user authority. | Planned (foundation evidence above where applicable) |
| FED-13 | MAY | P8 | Federation and enterprise integration | OpenID Federation trust-chain validation includes anchors, policy combination, expiry and key rollover. | Planned (foundation evidence above where applicable) |

## M2M

| ID | Level | Phase | Owner | Acceptance condition  Status / evidence |
| --- | --- | --- | --- | ---  --- |
| M2M-1 | MUST | P2 | Machine identity and client registry | Machine client credentials enforce registered target and scope allowlists.  [P2 locally verified](../tests/conformance/p2-evidence.json) |
| M2M-2 | SHOULD | P7 | Machine identity and client registry | Each supported workload provider has explicit format/audience/subject mapping and replay tests; unsupported credentials fail.  Planned |
| M2M-3 | MAY | P7 | Machine identity and client registry | SPIFFE certificate identity maps only to configured clients and combines with tested mTLS binding.  Planned |
| M2M-4 | MUST | P2 | Machine identity and client registry | Machine tokens are recognizable by explicit principal type and contain no user authentication/profile claims.  [P2 locally verified](../tests/conformance/p2-evidence.json) |
| M2M-5 | MUST | P2 | Machine identity and client registry | Generated secrets are displayed once, hashed, expiring and safely rotated with limited overlap.  [P2 locally verified](../tests/conformance/p2-evidence.json) |
| M2M-6 | SHOULD | P7 | Machine identity and client registry | Issuance limits and unusual-volume alerts work per machine client without leaking secrets in telemetry.  Planned |

## SEC

| ID | Level | Phase | Owner | Acceptance condition  Status / evidence |
| --- | --- | --- | --- | ---  --- |
| SEC-1 | MUST | P6 | Security across all components | RFC 9700 control checklist is complete with reviewed and justified applicability/deviation entries. | Planned (foundation evidence above where applicable) |
| SEC-2 | MUST | P2 | Security across all components | RFC 9126 PAR is required for every interactive authorization request; no per-client or scope-only bypass. Apply the registered client authentication policy, bounded lifetime, S256/client binding and immutable request handling; front-channel replacement, request_uri swapping and required-PAR bypass fail. Wider FAPI requirements remain P7. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| SEC-3 | MAY | P8 | Security across all components | JAR validates client signatures, audience, time and request-parameter consistency without remote key-header trust. | Planned (foundation evidence above where applicable) |
| SEC-4 | MAY | P8 | Security across all components | JARM responses validate audience, signing policy, expiry and client processing in conformance fixtures. | Planned (foundation evidence above where applicable) |
| SEC-5 | MUST | P5 | Security across all components | Resource step-up challenge leads to verified fresh required assurance; failure or unsupported assurance blocks issuance. | Planned (foundation evidence above where applicable) |
| SEC-6 | MUST | P2 | Security across all components | Issuer identification and upstream callback correlation prevent AS mix-up in multi-issuer tests. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| SEC-7 | MUST | P2 | Security across all components | Unregistered clients and redirects never cause attacker-controlled redirects, including error cases. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| SEC-8 | MUST | P2 | Security across all components | Login/consent CSRF, framing and referrer tests pass; callback correlation cannot be bypassed. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| SEC-9 | MUST | P2 | Security across all components | Purpose-specific JWT validators enforce type, algorithm, issuer and audience without following jku/x5u. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| SEC-10 | SHOULD | P7 | Security across all components | Full FAPI profile conformance passes for supported confidential-client configurations before it is advertised. | Planned (foundation evidence above where applicable) |
| SEC-11 | MUST | P2 | Security across all components | Login, token and introspection limits apply across replicas by configured IP/client/user dimensions. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| SEC-12 | MUST | P6 | Security across all components | Published threat model and external review are complete, findings remediated and critical cases retested. | Planned (foundation evidence above where applicable) |

## WEB

| ID | Level | Phase | Owner | Acceptance condition  Status / evidence |
| --- | --- | --- | --- | ---  --- |
| WEB-1 | MUST | P2 | Browser integration and sessions | Runnable [Go reference BFF](implementation-plan.md#go-reference-backend-for-frontend) keeps tokens server-side, serializes refresh, permits only configured API forwarding and gives the browser hardened opaque session cookies. Document standalone/existing-Go-backend deployment and a language-independent integration contract. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| WEB-2 | MUST | P3 | Browser integration and sessions | Browser-token sample uses short-lived DPoP credentials and a non-exportable key with no token URL leakage. | Planned (foundation evidence above where applicable) |
| WEB-3 | SHOULD | P7 | Browser integration and sessions | Supported-browser DBSC registration/refresh works and registered sessions cannot silently downgrade. | Planned (foundation evidence above where applicable) |
| WEB-4 | MUST | P2 | Browser integration and sessions | Sensitive pages enforce nonce CSP, supported Trusted Types and escaped untrusted content. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| WEB-5 | MUST | P5 (contract in P2) | Browser integration and sessions | [Embedded-session integration](implementation-plan.md#embedded-authentication-and-sessions) extends the same Go reference BFF with a runnable cross-origin parent/iframe example, iframe-context cookie establishment, partitioned-cookie and permitted Storage Access paths, proof/origin/session-bound one-use handoff, atomic replay/concurrency checks, lifecycle/revocation evidence and a versioned browser matrix with blocked-storage/popup fallbacks. Tokens remain server-side; unsupported cases fail explicitly. | P2 contract defined; P5 implementation planned |
| WEB-6 | MUST | P5 (contract in P2) | Browser integration and sessions | Exact tenant/client parent-origin and full ancestor policy permits only approved application frames; login, account selection, consent and step-up remain unframeable and use popup/top-level continuation. Sandbox, opaque-origin, nested-frame and forged message origin/source cases fail safely. | P2 contract defined; P5 implementation planned |
| WEB-7 | MUST | P2 | Browser integration and sessions | CORS is explicit per origin; wildcard credentialed responses and reflected arbitrary origins fail. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| WEB-8 | MUST | P2 | Browser integration and sessions | Idle/absolute timeout, list/end sessions and sensitive-action reauthentication work; P5 completes assurance integration. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| WEB-9 | SHOULD | P7 | Browser integration and sessions | Documented device/network changes produce bounded step-up/revocation decisions with false-positive monitoring. | Planned (foundation evidence above where applicable) |
| WEB-10 | MUST | P2 | Browser integration and sessions | URL, fragment, email and WebSocket fixtures contain no access/refresh tokens; tickets are single-use and audience-bound. | [P2 locally verified](../tests/conformance/p2-evidence.json) |

## ADM

| ID | Level | Phase | Owner | Acceptance condition  Status / evidence |
| --- | --- | --- | --- | ---  --- |
| ADM-1 | MUST | P1 | Administration and audit | Cross-tenant API, SQL relationship, token, key and job access fails under adversarial fixtures. | Planned (foundation evidence above where applicable) |
| ADM-2 | MUST | P1 | Administration and audit | Immutable tenant issuer and key/discovery boundaries are documented and exercised with two tenants. | Planned (foundation evidence above where applicable) |
| ADM-3 | MUST | P5 | Administration and audit | Every listed client/IdP/MFA/lifetime/binding/admin-scope policy affects authorization and subsequent status decisions. | Planned (foundation evidence above where applicable) |
| ADM-4 | MUST | P5 | Administration and audit | Admin API and UI cover specified resources; foreign-tenant operations and insufficient scope/step-up fail. | Planned (foundation evidence above where applicable) |
| ADM-5 | MUST | P2 | Administration and audit | Security decisions record required correlation fields without raw credentials; P4/P5 add exchange/federation coverage. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| ADM-6 | SHOULD | P7 | Administration and audit | SIEM exporters and Shared Signals deliver tenant-correct events with retries, redaction and delivery telemetry. | Planned (foundation evidence above where applicable) |
| ADM-7 | SHOULD | P7 | Administration and audit | Retention is tenant-specific and external anchors/immutable storage detect audit alteration. | Planned (foundation evidence above where applicable) |
| ADM-8 | MUST | P2 | Administration and audit | Connected apps shows grant scopes and usage and proves immediate revoke on the next resource check. | [P2 locally verified](../tests/conformance/p2-evidence.json) |
| ADM-9 | SHOULD | P7 | Administration and audit | New-grant/client and suspicious-activity notifications deduplicate events and respect configured recipients. | Planned (foundation evidence above where applicable) |

## OPS

| ID | Level | Phase | Owner | Acceptance condition  Status / evidence |
| --- | --- | --- | --- | ---  --- |
| OPS-1 | MUST | P1 | Platform and release engineering | Production signer uses non-exportable KMS/HSM keys; scheduled/emergency rotation runbooks are validated by P6. | Planned (foundation evidence above where applicable) |
| OPS-2 | MUST | P6 | Platform and release engineering | Zone-loss drill preserves issuance and JWKS with acknowledged-state consistency. | Planned (foundation evidence above where applicable) |
| OPS-3 | SHOULD | P7 | Platform and release engineering | Representative regional load meets p99 below 10 ms or the miss is recorded; no stale-allow shortcut is accepted. | Planned (foundation evidence above where applicable) |
| OPS-4 | MUST | P1 | Platform and release engineering | Durable PostgreSQL and expand/contract migrations work; P6 validates mixed-version upgrade and restore. | Planned (foundation evidence above where applicable) |
| OPS-5 | SHOULD | P7 | Platform and release engineering | Self-hosted/air-gapped installation works with local signer/IdP or approved metadata mirrors and enforced egress. | Planned (foundation evidence above where applicable) |
| OPS-6 | MUST | P1 | Platform and release engineering | Structured telemetry and security alerts are wired; P6 validates end-to-end failure detection without credential leakage. | Planned (foundation evidence above where applicable) |
| OPS-7 | SHOULD | P7 | Platform and release engineering | Tenant routing, databases, backups and audit exports satisfy configured residency boundaries. | Planned (foundation evidence above where applicable) |
| OPS-8 | MUST | P6 | Platform and release engineering | Applicable OP tests and pinned MCP/adversarial suites run in CI; FAPI plans run when P7 enables the profile. | Planned (foundation evidence above where applicable) |
| OPS-9 | MUST | P0 | Platform and release engineering | Each implemented draft has an exact revision/hash and fixtures; upgrades require reviewed behavior changes. | Planned (foundation evidence above where applicable) |
