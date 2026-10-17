# Mayi P0 capability contracts

Status: Baseline decisions accepted; no externally enabled protocol capabilities.

The server has no HTTP listener, metadata document or token endpoint yet. The P0 service prototype can only be called in-process with trusted caller context and supplied policy, storage, entropy, clock and signer ports. Test doubles are not deployable adapters. P2 is the first planned useful preview; P6 remains the complete MUST gate.

## Interpretation decisions

These resolve the implementation plan's clarification table while preserving the README as the original requirements record.

| Requirements | Accepted interpretation and delivery condition |
| --- | --- |
| CORE-3/4 | Exact redirect matching, with only RFC 8252's native loopback port exception. Compare host/path/scheme; exceptions do not create wildcard redirects. Native fixtures arrive in P3. |
| CORE-5 | Code stores original authorization transaction, redirect, exact revision and S256 challenge; lifetime ≤60s. OAuth 2.1 -16 permits omission of redirect_uri at redemption. When present it must match the original exactly. Authenticated reuse commits lineage revocation before returning invalid_grant. |
| GRANT-2 | Claims are an immutable ceiling. Enforce current permissions at every resource request; historical JWT claims cannot be edited after issuance. |
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
| WEB-3/5 | Capability-test DBSC and embedding. Login/consent stay top-level. Fail unsupported embedding explicitly; never put tokens in URLs/postMessage. |
| FED-9 | Signature verification of an enterprise assertion does not deliver upstream removal events. Immediate upstream cutoff requires authenticated lifecycle signals or a current upstream decision contract. |

## Intended profiles

| Profile | Intended behavior | Enabling evidence |
| --- | --- | --- |
| Base interactive and machine | S256, single-resource access tokens, explicit grants and tenant isolation; approved authentication methods only | P2/P3 adapter tests and interoperability, real persistence and signer |
| Strict resource enforcement | Signature/purpose/audience/binding plus current grant, subject, client, actor and permission decisions; fail closed | P3/P6 resource integration and partition/revocation tests |
| Gateway recipient exchange | Explicit edge, same tenant/user, bounded actor ancestry and attenuation; fresh gateway key proof | P4 topology and descendant-revocation tests |
| Enterprise assertion authorization | Distinct assertion purpose, per-tenant issuer/client trust, replay checks and current enterprise policy | P5 assertion and lifecycle tests |
| FAPI / recommended profiles | Entire selected security profile, including required PAR and sender constraints | P7 profile-specific conformance and operational evidence |

All are **disabled** until their evidence exists. Discovery must be derived from enforced configured capabilities, not from a library's available handlers. Implicit/password flows are never enabled. Do not compose an upstream all-enabled example.
