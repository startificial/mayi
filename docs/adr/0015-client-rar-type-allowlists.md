# ADR 0015: Client RAR type allowlists and registration projections

Status: Implemented registration foundation · 2026-10-18 · PAR and object consent remain pending

## Decision and ownership

Extend the existing client registration model with `AuthorizationDetailsTypes`, mapped to the standard `authorization_details_types` metadata name at the HTTP boundary. New managed clients must explicitly name between 1 and 32 distinct registered type URIs. Missing, null, empty, duplicate, malformed, unknown, foreign-tenant and wrong-resource types are rejected. This is Mayi's mandatory profile choice, not a claim that every RFC 9396 deployment requires this metadata or these HTTPS-only identifiers.

`domain/clients` owns the bounded client allowlist and its comparison against a resource/profile binding. `domain/resources` remains the sole owner of type/action interpretation. The existing administration service authenticates/authorizes the tenant action before protected reads, checks every requested type against the client's allowed registered resources, then creates the client, resource relations, type bindings, audit and outbox in the existing management transaction. Registered vocabulary is not principal/object authority. A client's resource list cannot make an unlisted type eligible, and a listed type cannot be rebound to a different resource.

## Administrative contract

The existing `POST /admin/t/{tenant}/clients` now requires `authorization_details_types`; `GET /admin/t/{tenant}/clients/{id}` returns it. Both retain existing permissions and trusted configured tenant/issuer context. For example, after registering the resource and its workflow profile:

```json
{
  "id": "web",
  "name": "Web client",
  "redirect_uris": ["https://app.example/cb"],
  "resources": ["api"],
  "authorization_details_types": ["https://api.example/types/workflow/v1"],
  "access_token_seconds": 300,
  "enabled": true
}
```

The list is a set; persistence reads return stable lexical ordering. No type URI is fetched. No client allowlist update/deletion API or public dynamic client registration is introduced. Later registration changes need an explicit policy operation with the existing tenant coordination lock and immutable credential ceilings; adding a type must never enlarge previously approved authority.

## Persistence and authorization projection

Append migration 7 without altering prior migration sources. `client_object_types` has tenant/client/type uniqueness and composite foreign keys to both the client's allowed resource and that resource's immutable profile. Forced RLS and explicit tenant predicates isolate reads/writes. Binding rows cannot be updated or deleted through ordinary SQL, including owner writes; the runtime receives no UPDATE/DELETE privilege. Current application code inserts them only during atomic client creation. The runtime remains trusted to create registration state; these constraints do not replace service authorization or protect against a fully compromised runtime.

Managed-client reads rehydrate and validate nonempty bounded metadata, failing closed on missing or oversized lists. No default, inferred type list or legacy backfill is provided. Raw P0 proof rows are incomplete scaffolding rather than valid managed registrations; universally required database snapshot/PAR constraints still belong to the required-flow cutover in ADR 0012. Updated consent/browser fixtures explicitly seed registered profile/client bindings rather than bypassing the new client invariant.

The existing authorization registration port now returns only the client-allowed profiles for the requested resource. Other-resource definitions and unallowed types do not enter that projection. Client and resource configuration locks plus the tenant guard remain held through commit. Domain `Request.MatchesObjectRegistration` validates exact tenant/issuer/audience/type/action vocabulary, existing redirect/permission/binding rules and client allowlists. Duplicate/foreign projection values fail closed.

This predicate is explicitly insufficient to authorize consent: it verifies neither PAR provenance nor a principal's current object permissions. `Begin`, consent and issuance retain the closed object-request gate. The later PAR operation can reuse the registration predicate rather than introducing a parallel vocabulary/policy implementation.

## Evidence and remaining work

Domain/service tests cover nonempty/bounded exact metadata, duplicate/foreign/missing profiles, invalid actions, wrong audience, disabled clients, authorization-before-port ordering and no mutation on invalid registration. Real PostgreSQL/server tests cover complete rollback on outbox failure, concurrent creation with one winner, foreign actor/type/resource denial, composite constraints/RLS, immutable binding rows, metadata round trips and resource-specific projection selection. A valid object registration still fails the live consent entrypoint without emitting a handle. Existing replay/issuance tests run against the full additive schema.

Next: required RFC 9126 PAR storage/reference/client binding, strict multi-type wire selection through the shared registered profiles, authorized resource-owned consent projections and the universally required RAR/PAR cutover. Object-aware token/refresh/introspection/SDK propagation, current object ACL enforcement and the BFF/resource demonstration remain pending. Discovery still advertises no RAR type or PAR endpoint, and specification `implemented_sections` stay empty. No dependency, tool, license exception or public SDK type is added.

Source: [RFC 9396 section 10](https://www.rfc-editor.org/rfc/rfc9396.html#section-10). This slice uses its metadata name in Mayi's operator registration API; it does not implement RFC 7591 dynamic registration or claim full RAR interoperability.
