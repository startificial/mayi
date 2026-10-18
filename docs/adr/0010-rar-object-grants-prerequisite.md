# ADR 0010: Standard RAR object grants are a P2 prerequisite

Status: Accepted requirement and design direction · 2026-10-18 · Implementation and verification pending

## Decision and delivery gate

The maintainer requires grants such as “this client may read document 123” in the core preview. Promote RES-10 from SHOULD/P7 to **MUST/P2**. Use [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) `authorization_details`; do not introduce a proprietary object-grant parameter or encode document identifiers into scope names. The RFC specifies the protocol envelope and permits API-specific authorization types. The document type below is Mayi's initial supported application profile, not a universal type defined by the RFC.

The existing scope-only authorization, consent and login milestones remain implemented partial groundwork. They do not meet this new prerequisite. Complete the typed model, persistence and consent work before enabling the remaining live token/resource preview. P2 cannot exit without an end-to-end object-specific grant and its negative cases. P4 delegation must preserve or narrow the same authority; P7 may add further type profiles but cannot defer basic RAR support. Re-estimate the remaining P2 effort.

## Initial document profile

Each resource owner registers a versioned, collision-resistant authorization type identifier, its action vocabulary, validation, safe consent projection and comparison semantics. Bind that registration to a tenant and registered API resource. A semantic version change gets a distinct type identifier; never reinterpret existing approved revisions with a newly changed handler. This is trusted configuration, not executable plugins or client-supplied schemas.

For example, an illustrative RFC 9396 `authorization_details` value is:

```json
[
  {
    "type": "https://api.example.com/authorization-types/document/v1",
    "locations": ["https://api.example.com"],
    "identifier": "123",
    "actions": ["read"]
  }
]
```

The example type URL is a configured identifier, not an endpoint to fetch. It does not define Mayi's deployment domain. This initial profile requires one exact registered audience/location, one nonempty document identifier and an explicit nonempty set of registered actions per entry. Document identity is scoped by tenant and resource; a bare `123` is not a globally meaningful object reference. Use exact comparisons with no path-prefix matching, URI dereferencing or silent identifier normalization. Missing identifiers, wildcards and unsupported fields/actions/types fail. Bound input bytes, depth, entry count and action count before implementation is enabled.

Multiple documents use multiple entries. Permission comparison preserves each complete tuple of tenant, issuer, resource, type/profile version, identifier and action; flattening separate object/action sets must never create permissions that were not approved together. Scope values, when accepted alongside details, are an additional configured bound and cannot override object restrictions. Resources configured for object grants reject requests that omit required details; absence never means “all documents.” Basic scope-only access to other configured API profiles is not a RAR implementation or fallback for this one.

## Request and approval integrity

Bring the necessary [RFC 9126 PAR](https://www.rfc-editor.org/rfc/rfc9126.html) implementation into P2 and require it for this object-RAR profile. Follow the registered client authentication policy, S256 and exact redirect rules. Bind a short-lived request reference to its client and immutable request; check expiry, policy changes, swapping and replay. Front-channel parameters cannot replace pushed authorization details. Public clients do not become confidential or prove reputation merely by using PAR. General FAPI and signed request-object support remain separately gated.

SEC-2 remains a general SHOULD in the requirement baseline, with earlier P2 delivery; PAR is mandatory within the RES-10 object-grant profile. This is a Mayi security-profile choice, not a claim that every RFC 9396 deployment must use PAR.

The resource integration supplies only authorized decision/display metadata needed to validate and render the request. Do not load a full document and authorize afterward or treat a client-supplied identifier/title as authority. Consent shows exact objects and actions, escapes display data and binds approval to the authenticated principal, client, tenant, audience and immutable request. Recheck current policy and relevant versions inside the approval unit of work. State, code, grant revision and security audit/outbox commit together before a credential is returned.

## Authority lifecycle and enforcement

Persist typed approved details and profile semantics with immutable grant revisions. Bind authorization transactions, codes, refresh families and token issuances to the exact revision and permission ceiling. Adding a document or action requires new authorization and a new revision; older credentials retain their previous limits. Do not infer object restrictions for old scope-only records or silently migrate them into unrestricted object grants. Use additive migrations and explicit validation.

Advertise enabled type identifiers through `authorization_details_types_supported` and handle the applicable client-registration `authorization_details_types` metadata. Tokens expose assigned permissions through the standard token-response `authorization_details` and the corresponding JWT/introspection representation defined by the chosen profile. Do not return arbitrary unvalidated JSON or advertise types whose enforcement is absent. A public SDK maps bounded public values to the shared domain/service rules without exposing internal types. Resource servers combine the token/revision ceiling, current authoritative grant/lineage status, current policy and their own current object permissions before protected payload access. Mayi stores delegation authority; it does not become a universal document ACL database or query the application's database directly.

Refresh can preserve or request a typed subset of the original credential's approved permissions. Omitting details preserves that bounded ceiling; it cannot query the latest grant or drop restrictions. A requested object/action expansion fails. The P4 exchange integration reuses this comparison with its authenticated actor and configured delegation-edge mapping, and rejects unsupported mappings or lost restrictions. Machine/enterprise issuance, when it supports this profile, needs an explicit bounded policy-derived authority source and the same enforcement; it cannot bypass checks by avoiding interactive consent.

Membership loss, resource-owned ACL removal and grant revocation must deny subsequent fresh resource decisions under the existing authoritative-status contract. An application's ability to read document 124 does not follow from the user's ability to read it when the app's grant names only document 123. Deletion/recreation must not cause an old identifier to acquire authority over a different logical document; the resource owner must provide stable, non-reassigned references or an incarnation identifier within its profile.

## Ownership and evidence

Keep the canonical package layout. `domain/grants` owns pure typed ceilings, immutable snapshots and comparison; `domain/resources` owns audience/type/action registration rules; `domain/authorization` owns the pending workflow. Existing authorization, grant, token and resource services orchestrate these rules through consumer-owned ports. Fosite/HTTP adapters map RFC wire input, PostgreSQL implements atomic persistence and the resource SDK invokes shared enforcement. The Go BFF uses the public RAR/PAR contracts. Do not create a parallel permission engine in handlers, persistence, SDK middleware or the BFF.

The P2 gate requires retained positive and adversarial evidence:

- A user can read documents 123 and 124, but a read-123 grant permits only read-123; 124, write-123 and a foreign tenant/resource/client fail before payload loading.
- Authorization, consent, immutable revision, code, refresh, token response, JWT/introspection, connected-app views and SDK agree on the approved tuples. Malformed details, duplicate JSON members, ambiguous bindings, unknown types or missing required details fail without widening authority.
- PAR references cannot be tampered with, swapped across clients, replayed or bypassed. State/audit failure returns no new credential, and concurrent approval/redemption cannot mint parallel authority.
- Narrowing preserves object/action relationships. An approval for read-123 plus write-124 cannot become write-123. Older revisions do not gain newly approved objects; removed ACL access and revoked grants fail immediately on the next fresh resource check.
- Standard metadata and errors match enforced capabilities, and the Go BFF/resource example demonstrates the standard protocol without exposing credentials or protected document content in URLs/logs. Full RFC and profile evidence remains Planned until these tests exist.

RFC 9396 and RFC 9126 source-byte pins are recorded in the specification manifest with empty `implemented_sections`. This decision admits no new software dependency, tool or license exception and does not enable a server capability.
