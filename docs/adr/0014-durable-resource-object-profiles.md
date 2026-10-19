# ADR 0014: Durable resource-owned object profiles

Status: Implemented registration foundation · 2026-10-18 · Public RAR/PAR remains pending

## Decision and ownership

Extend the existing resource context and administration service with immutable object-profile registration. Reuse `resources.ObjectProfile` and its fixed `object-actions-v1` semantics. Administration authorizes the configured tenant/action before loading protected registration state; it validates the supplied tenant/issuer context, resource ID and full definition, then checks the exact audience against the registered resource. The existing management unit of work holds the tenant guard and commits registration, audit and outbox together.

This registers vocabulary and descriptions. It does not establish permission to any object, validate the resource owner's control of a DNS domain, fetch a type URI, or approve a grant. A configured administrator must select stable, versioned type URIs under the resource owner's control. The resource integration must separately supply current decision/display projections before object consent can be enabled.

## Persistence contract

Append migration 6 without changing earlier migration sources. `resource_object_profiles` stores tenant, resource ID, exact audience, type URI, semantics and action descriptions. Its primary key is `(tenant_id, type_uri)`: within a tenant, a type cannot be assigned to a second audience or acquire a different interpretation. Separate tenants remain isolated even when they use the same identifiers.

A composite foreign key binds the resource ID and audience together, preventing either registration substitution or a later resource-URI change from rebinding an existing definition. Profiles cannot be updated or deleted, including ordinary owner SQL. Different semantics, vocabulary or descriptions require a new versioned type URI. No activation/deactivation or historical-profile deletion lifecycle is introduced in this slice; later retirement needs a reviewed policy operation that cannot reinterpret existing grants.

Actions are an internal JSONB map from action name to description, preserving each association without exposing arbitrary RAR JSON. The domain rejects duplicate/invalid names, invalid descriptions, unknown semantics and more than 16 actions before insertion. Reads reconstruct and validate the immutable domain value against the trusted transaction scope; corrupt owner-supplied records fail closed. A map's iteration order confers no authority; reads sort names for stable presentation. Database shape/size constraints, forced RLS, tenant predicates and immutable triggers reinforce the application rules.

The runtime has SELECT/INSERT access to the new table; UPDATE is revoked and no DELETE is granted. The migration/physical-connection checks for forced tenant RLS and exact migration history also cover this table. Apply explicit owner migrations and restart matching runtimes; no scope-only compatibility/backfill project is introduced.

## Administrative HTTP contract

Use the existing authenticated administration namespace:

- `POST /admin/t/{tenant}/resources/{id}/object-profiles` requires `resources:write` and creates a definition; duplicates/redefinitions return 409.
- `GET /admin/t/{tenant}/resources/{id}/object-profiles?type={encoded-type-URI}` requires `resources:read` and returns exactly that definition. Missing, duplicate or unknown query parameters fail. A foreign actor is denied before storage access.

The bounded JSON body/response is:

```json
{
  "resource": "https://api.example",
  "type": "https://api.example/types/workflow/v1",
  "semantics": "object-actions-v1",
  "actions": [
    {"name": "read", "description": "Read this workflow"},
    {"name": "execute", "description": "Execute this workflow"}
  ]
}
```

`resource` must match the route's registered resource audience. Tenant/issuer identity and administrator permissions come from configured credentials, never this body. Handlers only validate/map DTOs, call the administration service and encode typed results/errors. This is an operator management API, not RFC 7591 dynamic client registration or a public authorization endpoint.

## Evidence and remaining gates

Service tests enforce authorization before ports, foreign scope/audience denial, semantic validation and no result before commit. Real PostgreSQL tests cover tenant isolation/RLS, immutable type/audience binding, corrupt-record rejection, outbox rollback and one concurrent winner. The composed server tests authenticated routes, malformed input, query ambiguity, conflicts and absence of premature discovery metadata. The full reviewed PostgreSQL/OpenBao harness exercises these alongside existing issuance/replay and runtime-privilege checks.

This completes durable resource-profile registration only. Client `authorization_details_types` registration/allowlisting, profile selection in the authorization projection, required PAR binding, authorized object consent, object-aware token/refresh/introspection/SDK behavior and the BFF/resource demonstration remain pending. The current scope-only preview still rejects RAR and request references. Registering a profile neither enables that flow nor advertises a RAR type or PAR endpoint. [ADR 0012](0012-durable-object-authority-snapshots.md)'s universally required RAR/PAR contract remains the cutover gate. No dependency, tool, public SDK export or license exception is added.
