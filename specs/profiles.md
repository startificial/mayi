# Mayi capability contracts

Status: P0 baseline accepted; the bounded P2 preview is implemented with local automated evidence.

The [P2 runbook](../docs/p2-core-authorization.md) describes the live listener, configured discovery, required PAR/RAR, token endpoints and resource/BFF integration. [Local profile evidence](../tests/conformance/p2-evidence.json) is checked against exact test symbols and pinned specification revisions. P6 remains the production MUST gate; test doubles and a dependency certification do not certify Mayi.

## Interpretation decisions

These resolve the implementation plan's clarification table while preserving the README as the original requirements record.

| Requirements | Accepted interpretation and delivery condition |
| --- | --- |
| CORE-3/4 | Exact redirect matching, with only RFC 8252's native loopback port exception. Compare host/path/scheme; exceptions do not create wildcard redirects. The [first P3 slice](../docs/p3-agent-clients.md) proves registered public native callbacks, loopback port-only matching and exact redemption correlation. OS associations/browser interoperability remain unclaimed. |
| CORE-5 | Code stores original authorization transaction, redirect, exact revision and S256 challenge; lifetime ≤60s. OAuth 2.1 -16 permits omission of redirect_uri at redemption. When present it must match the original exactly. Authenticated reuse commits lineage revocation before returning invalid_grant. |
| GRANT-2 | Claims and approved typed RAR object/action tuples are immutable ceilings. Enforce the exact requested object/action and current resource-owned permissions before payload access; historical JWT claims cannot be edited after issuance. |
| RES-10/GRANT-4/6/SEC-2 | [ADR 0010](../docs/adr/0010-rar-object-grants-prerequisite.md) makes RFC 9396 object grants a P2 prerequisite, with required RFC 9126 PAR for that profile. Use registered `authorization_details` types with exact audience/identifier/action semantics, safe consent, immutable revision/credential ceilings, standard token/JWT/introspection details and resource enforcement. Scope-only fallback, extra objects/actions and unknown semantics fail closed; P4 exchange must preserve/narrow these tuples. Additional type profiles may follow later. |
| GRANT-9/LIFE-7/OPS-3 | Fresh authoritative decisions after revocation acknowledgement; no stale-positive cache/offline fallback in the strict profile. Push is supplementary. See ADR 0002. |
| GRANT-12/11/FED-5 | First-party interactive consent exemptions use an explicit audited tenant trust list. Administrative grants and trusted enterprise assertions are separately authorized sources and never confer missing user permissions. |
| CLI-3 | CIMD establishes metadata-host control. Use same-origin redirect policy by default; native and approved third-party exceptions require explicit policy/fixtures. Self-declared branding is not verified reputation. |
| BIND-2 | Check ath on resource requests carrying an access token. Ordinary token-endpoint DPoP proofs do not carry ath. Apply endpoint-specific validators. |
| BIND-7/DEL-1 | Recipient exchange/rebinding follows ADR 0004, requires authenticated gateway identity and an administrative edge, and stays disabled until P4 proves it. |
| RES-3/4 | Missing resource requires an explicit provisioned endpoint binding; otherwise invalid_target. Select one resource per token response. Multiple approved resources need separate selected-resource redemptions. |
| RES-7/M2M-4 | Separate user:/client: namespaces plus explicit principal_type. Machine sub equals client_id and has no user claims. |
| OIDC-1/3 | Mayi requires nonce for code flow. Bind and echo it; relying parties validate it. offline_access authorizes refresh capability. |
| OIDC-3/RES-4 | UserInfo is a separate registered audience. A business-resource token is never accepted as a UserInfo credential. Identity claims may be returned in an appropriately authorized ID token. |
| LIFE-12 | JWTs have jti; opaque tokens/codes have internal issuance/lineage IDs and hashed handles. Plaintext handles need not encode JWT claims. |
| SEC-10 | FAPI is a complete separately enabled profile with conformance evidence. Base public/native clients are not labeled FAPI. |
| WEB-1 | Deliver the [Go reference BFF](../docs/implementation-plan.md#go-reference-backend-for-frontend) in P2 with server-side credentials, opaque browser sessions, serialized refresh and allowlisted API forwarding. It may run standalone or in an existing Go backend. Its public integration contract remains language-independent. |
| WEB-3 | Capability-test DBSC; unsupported browsers do not imply the device-bound session guarantee. |
| WEB-5/6/8/10 | Authenticated embedded applications use the [BFF/session integration contract](../docs/implementation-plan.md#embedded-authentication-and-sessions). Interactive login/consent/step-up remain popup/top-level and unframeable. Use tested partitioned cookies or a permitted Storage Access path, exact frame/message origin and source checks, and a distinct proof-bound one-use handoff code. Preserve session and grant lifecycle semantics; blocked storage/popups require explicit recovery, never credentials in URLs/messages. Contract in P2; implementation and browser evidence in P5. |
| FED-9 | Signature verification of an enterprise assertion does not deliver upstream removal events. Immediate upstream cutoff requires authenticated lifecycle signals or a current upstream decision contract. |

## Intended profiles

| Profile | Intended behavior | Enabling evidence |
| --- | --- | --- |
| Base interactive and machine | S256, single-resource access tokens, explicit grants and tenant isolation; approved authentication methods only; P2 includes the mandatory RFC 9396 document-grant/PAR profile with resource enforcement | P2/P3 adapter tests and interoperability, real persistence/signer, mandatory document-123/read end-to-end and denial/refresh/revocation evidence |
| Strict resource enforcement | Signature/purpose/audience/binding plus current grant, subject, client, actor and permission decisions; fail closed | P3/P6 resource integration and partition/revocation tests |
| Gateway recipient exchange | Explicit edge, same tenant/user, bounded actor ancestry and attenuation; fresh gateway key proof | P4 topology and descendant-revocation tests |
| Enterprise assertion authorization | Distinct assertion purpose, per-tenant issuer/client trust, replay checks and current enterprise policy | P5 assertion and lifecycle tests |
| FAPI / recommended profiles | Entire selected security profile, including required PAR and sender constraints | P7 profile-specific conformance and operational evidence |

Only the documented P2 base/online resource preview is enabled by matching configuration and local evidence. Other profiles stay disabled until their evidence exists. Discovery must be derived from enforced configured capabilities, not from a library's available handlers. Implicit/password flows are never enabled. Do not compose an upstream all-enabled example.

The first P3 slice adds resource-owned RFC 9728 metadata and RFC 6750 Bearer
challenges through the existing resource SDK, plus native callback registration.
[P3 evidence](../tests/conformance/p3-evidence.json) is partial phase evidence:
CIMD, DCR, client policy, the WebCrypto sample remain outstanding. The shared ES256 DPoP profile with
nonce/replay state, PAR prebinding and resource enforcement is now implemented
with bounded protocol evidence. No unknown-client or full MCP profile is enabled.
