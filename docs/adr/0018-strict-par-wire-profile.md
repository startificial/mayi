# ADR 0018: Strict PAR wire mapping and mixed-type vocabulary

Status: Implemented domain/codec foundation · 2026-10-18 · Public endpoint and object consent remain pending

## Ownership and decision

Extend the existing OAuth inbound adapter with pure PAR form, success-body and browser-reference codecs. These translate RFC 9126/9396 wire values into the existing authorization application's request/proof/result values; they do not implement authentication, consent, lifecycle or persistence. No route invokes them yet. Fosite remains the selected protocol engine; future endpoint composition must preserve its endpoint-specific authentication/error contracts rather than adding a second OAuth engine.

`domain/resources.ValidateObjectRequest` owns selection of exact registered type/action vocabulary for a single tenant/issuer/resource. It validates every supplied immutable profile, rejects duplicate/foreign definitions even when unused, and validates complete type/object/action tuples with the existing profile invariant. The authorization request's registration check and the RAR codec reuse this rule. The codec now accepts a bounded set of profiles rather than only one; single-profile callers retain identical behavior. A vocabulary projection contains at most 32 types; a request still contains at most 32 object entries under the existing bounds. Equal identifiers in different types do not combine their actions. Vocabulary validity is never evidence of client or principal authority.

## Wire profile and limits

The initial public-client profile accepts exactly these nine nonempty form parameters. They are mandatory Mayi profile choices, not universal requirements of PAR or RAR:

| Parameter | Accepted value / decoded byte bound |
| --- | --- |
| `client_id` | Existing registered-client ID grammar, at most 64 bytes |
| `response_type` | `code` |
| `redirect_uri` | Existing HTTPS web-client redirect grammar, at most 2,048 bytes; the service checks exact registration |
| `resource` | One exact registered API audience, at most 2,048 bytes; no prefix/normalization matching |
| `scope` | Space-separated nonempty unique permission names, at most 8,192 bytes; independent of object authority |
| `state` | Existing printable ASCII grammar, 16–1,024 bytes; clients must generate unpredictable state |
| `code_challenge` | Canonical 32-byte base64url S256 digest, 43 bytes |
| `code_challenge_method` | `S256` |
| `authorization_details` | Existing strict standard envelope, at most 32 KiB before and after response encoding |

Raw form size is at most 128 KiB. Parsing decodes each name/value once, rejects empty segments, malformed percent encoding, invalid UTF-8, unknown/case-variant names and duplicate decoded names (including escaped duplicates). JSON formatting whitespace remains valid inside the details value. No body/query merge or partial parse is accepted. The decoded request preserves state, redirect, PKCE and opaque object bytes exactly. Profiles and tenant context must come from trusted current client/resource registration, never client-supplied schema metadata. `Push` independently rechecks current registration/policy inside its existing transaction; a stale codec projection cannot authorize storage.

Confidential authentication parameters, JAR, OIDC extensions, `request_uri` in a push and `dpop_jkt` are unsupported in this bounded codec. Sender binding must come from a later validated-proof integration, not an arbitrary wire thumbprint. Policies requiring binding continue to fail closed. Unknown extensions are rejected explicitly. The eventual endpoint must reject unsupported authentication headers/proofs rather than silently treating them as an unauthenticated public request; these pure body codecs cannot enforce HTTP headers.

The success-body codec accepts only a canonical 256-bit base64url reference from the committed `PushedResult`. It emits `request_uri` using the inert prefix `urn:ietf:params:oauth:request_uri:` and a positive integer `expires_in`. Remaining lifetime is rounded down; less than one second, expired results, invalid time and values beyond the 90-second application lifetime produce no body. The caller supplies time. A future HTTP handler must use status 201, JSON, no-store/cache headers and the existing safe OAuth error strategy. No HTTP success/error contract is enabled by this change.

The browser-reference codec accepts exactly `client_id` and `request_uri`, with a 2,048-byte raw query limit. It rejects arbitrary URLs, alternate URNs, noncanonical secrets and all replacement request fields. It hashes only the raw secret suffix, matching existing persisted reference hashes, and combines it with trusted issuer routing and browser-credential context. It never fetches or resolves the URI. The declared client ID remains correlation, not authentication; the service verifies its stored binding before loading protected request payloads.

## Evidence, recovery and remaining gates

Domain and adapter tests cover mixed types, duplicate/foreign vocabulary, borrowed actions, exact tuple preservation, all missing/empty/repeated parameters, malformed encodings, bounds, safe fixed errors, response expiry and forbidden front-channel replacement/fetching. A mixed-type fuzz target checks accepted request/response authority preservation. Real PostgreSQL tests carry two registered types through form decoding, service push, success-body/reference round trip and one-use workflow storage, with exact state/request snapshots, wrong-client/replay denial, and stale-registration rejection. Consent and code creation remain denied.

No dependency, tool, schema migration, public SDK, discovery capability or specification-conformance claim is added. There is no legacy/scope-only PAR fallback. Existing direct scope-only preview fixtures remain unfinished scaffolding under ADR 0017, not a deployment contract. Public endpoint composition, current resource-owned permission/display projections with commit-time authorization guarantees, universal mandatory PAR/RAR cutover, token propagation and resource enforcement remain pending. Only the complete authorized flow may replace the preview. Lost or uncertain one-use responses retain ADR 0017's restart/reconciliation rules; these codecs do not make replay safe.

Sources: [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html), sections 2 and 4; [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html), sections 2/2.1. This is a bounded Mayi profile, not full interoperability evidence. Follow the [error strategy](../error-handling.md) when enabling its HTTP surface.
