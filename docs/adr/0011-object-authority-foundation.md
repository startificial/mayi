# ADR 0011: Object authority values and strict RAR mapping

Status: Accepted and implemented domain/codec foundation · 2026-10-18 · Runtime RAR integration pending

## Decision

Implement the first dependency of [ADR 0010](0010-rar-object-grants-prerequisite.md) in the existing grant and resource domain packages. This change does not enable an OAuth capability or change persisted grant semantics. The authorization/consent workflow, grant revisions and token service still use their existing scope-only representation; they must carry the new values durably before they can accept object requests. No migration or conversion of historical records occurs here.

`grants.ObjectCeiling` owns a deep immutable snapshot of trusted tenant/issuer scope, one exact audience and typed object/action entries. Location is the enclosing audience rather than an independently combinable list. Each entry preserves its complete type/identifier/actions relationship. `Permits` tests membership in this ceiling only: it cannot authenticate a client or principal, establish grant status, evaluate a resource ACL or authorize a protected payload load. Client/principal/revision binding remains the surrounding grant's responsibility.

`resources.ObjectProfile` is an immutable trusted registration value with a resource-owner-selected type URI, tenant/issuer/audience binding, fixed `object-actions-v1` semantics and action descriptions. It validates requests against its exact type and action vocabulary. Type URIs are inert identifiers and are never fetched. The operator must choose a versioned identifier under their control. Future durable registration must preserve that type's semantics; a different interpretation needs a different type URI. This value alone does not implement configuration/registration endpoints or object lookup.

The maintainer clarified that “document” is a worked example, not a built-in business resource or a document-specific product boundary. The same exact object/action semantics apply to workflows, projects, files and other stable resource-owned objects. The API audience is the registered OAuth resource; `type` identifies its object schema and `identifier` names an instance. Each owner defines its action vocabulary and current permission/display integration. Tests round-trip workflow execution, project membership management and file download without document assumptions. More complex RAR types involving amounts, ranges or other attributes need their own validated comparison semantics; this profile does not silently accept arbitrary schemas.

## Bounds and comparison semantics

- At most 32 distinct type/identifier entries per audience, at most 16 unique actions per entry, at most 256 identifier bytes and 64 action bytes. Type and audience identifiers have a 2,048-byte bound and require canonical HTTPS registration under the existing resource URI rules. The grant value checks structural bounds; resource registration owns canonical URI validation.
- The initial object/action profile uses nonempty opaque printable ASCII identifiers with no whitespace, `*` or `?`. Exact comparisons preserve case, percent bytes and path separators. These references must be stable and non-reassigned or include an incarnation. This is a bounded initial profile, not a claim that RFC 9396 universally requires ASCII or forbids extensions.
- Actions use lowercase ASCII letters, digits and `-._:`. Requests cannot add unregistered actions. One entry contains all requested actions for one type/identifier; duplicate targets, even with different action lists, are rejected instead of silently merged. Different objects or type versions remain separate entries.
- A valid bound empty ceiling permits no object. A zero/missing ceiling is invalid. Neither case means unrestricted authority. Object requests must be nonempty even though intersections may produce a bound empty denial.
- Narrowing intersects historical, current and additional credential/policy ceilings as complete tuples. Every ceiling must have the same tenant, issuer and audience. A nil requested slice means preserve this bounded intersection; an explicitly present empty slice is invalid under this profile. An explicit expansion fails. This API cannot perform cross-resource delegation mapping, reinterpret versions or query the latest grant.
- Broader scopes cannot change an object ceiling. Later services must intersect the independent scope and object bounds, retain exact revision/credential ancestry, and separately check current resource permissions and authoritative revocation.

## Boundary ownership

The OAuth adapter's RFC 9396 codec accepts only the standard `type`, `locations`, `identifier` and `actions` fields for this profile. There must be exactly one location equal to the selected registered audience. It validates against the trusted profile and maps to domain values without JSON/vendor types or tags in the domain. It returns only a classified error, without echoing request values.

The wire grammar is bounded to array → object → string/string-array, with at most 32 KiB both on input and after response escaping. Unknown fields, wrong JSON types, duplicate decoded members (including escaped names), case-variant member names, unsupported actions/types, extra locations, malformed UTF-8, invalid surrogate-derived identifiers, excess nesting and trailing values fail. Response encoding revalidates the assigned ceiling against the supplied immutable profile snapshot and emits only the standard fields. This codec performs no I/O, client authentication, consent or issuance.

## Delivery gates and evidence

Domain tests exercise immutable snapshots, explicit denial/omission, foreign bindings, exact tuple matching, all 4,096 historical/current/credential combinations over two documents/two actions, and requested subset/expansion cases. Profile and codec tests cover registration rules, strict parsing, standard-envelope round trips and fuzz seeds.

No production route invokes this codec, no RAR/PAR capability is advertised, and specification `implemented_sections` remain empty. The next slice must add append-only registration/request/revision/credential storage, required RFC 9126 PAR with client binding, and authorized resource-owned decision/display projections through the existing consent unit of work. Token/introspection/SDK propagation and the complete document-123 negative-flow demonstration remain required before the P2 preview gate. Do not expose a temporary endpoint that could drop these restrictions.

This change adds no dependency, tool, license exception or public SDK API.
