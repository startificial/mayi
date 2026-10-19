# ADR 0012: Durable object-authority snapshots

Status: Implemented storage foundation · 2026-10-18 · Public RAR/PAR and object issuance remain pending

## Required fresh-deployment contract

The maintainer explicitly requires RAR and PAR out of the box and does not require compatibility with deployed scope-only records. Every resource grant must define typed RAR authority; every interactive authorization request must use PAR. There is no optional scope-only resource profile, per-client PAR exemption or legacy upgrade/backfill project. This supersedes ADR 0010's narrower optional-profile language. SEC-2 is now a MUST. Machine grants require explicit typed policy-derived authority; RFC 9126 applies to authorization requests and does not add a browser authorization step to client credentials.

The existing P0/P1/scope-only consent fixtures are unfinished proof scaffolding, not an intended supported deployment contract. This storage slice does not yet complete mandatory RAR/PAR enforcement. Before the first usable P2 flow, require nonempty typed snapshots and verified PAR provenance everywhere, remove intermediate nullable/prototype allowances, and replace the direct scope-only authorization path. Fresh state may be required; do not infer object authority from old scopes or implement a fallback to make old data work.

## Decision and ownership

Continue [ADR 0010](0010-rar-object-grants-prerequisite.md) and [ADR 0011](0011-object-authority-foundation.md) through the existing authorization, grants and token boundaries. `authorization.Request`, immutable `grants.Revision` and current-grant state carry the same generic `grants.ObjectCeiling` value; the code stores the exact snapshot while its authentication projection exposes only the object-bound classification. The domain validates tenant/issuer/audience binding and nonempty approved details. A workflow's domain approval transition copies its exact ceiling to revision 1; later revisions and caller snapshot mutation cannot enlarge historical authority. No document-specific persistence or parallel permission engine is introduced.

The existing authorization store persists the typed request and atomically copies it into the new grant, immutable revision and code alongside decision/audit/outbox state. Final approval predicates compare the stored request's object snapshot, client, audience, scopes, redirect, PKCE, sender binding and client state against the supplied transition. A substituted snapshot causes the entire transaction to roll back. Authentication/session checks and tenant coordination retain their existing lock order.

## Migration and record contract

Append migration 5; do not change migrations 1–4 or their ledger digests. Add nullable JSONB ceilings to authorization transactions, grant revisions, credentials, refresh families and issuances, plus `grants.current_object_ceiling`. The persistence record has exact fields `version: 1`, `semantics: "object-actions-v1"`, `resource` and `details`; entries contain `type`, `identifier` and `actions`. This is an internal versioned record, not a replacement OAuth wire format. The tenant row's immutable issuer and the transaction's trusted tenant context supply the identity binding. Type URIs remain inert identifiers.

The intermediate nullable columns represent absent authority in unfinished proof scaffolding. This is not a compatibility mode or a supported P2 grant: absence must be rejected throughout the required flow before that flow is enabled. It never means unrestricted object access or a default grant to every object. JSON `null`, unknown record versions/semantics, missing/extra/case-variant record fields, empty approved details and invalid domain values fail rehydration. No migration/backfill of deployed scope-only grants is provided or required. Storage records have a 1 MiB defensive ceiling; the public wire codec retains its tighter 32 KiB bound.

Database constraints reinforce envelope shape, audience and lineage presence. Object descendants cannot omit their snapshot; a root without object authority cannot acquire it through an implicit conversion. Revision references cannot be reassigned. Snapshots are immutable, including for the owner through ordinary SQL updates. The current object ceiling is temporarily frozen because no reviewed mutation use case exists yet; revocation remains available. Later current-authority narrowing/incremental approval requires an explicit domain decision, service-owned transaction and coordinated predicates, followed by an additive migration if needed. These guards do not implement a second tuple/subset comparator in SQL.

Apply migrations explicitly with the owner command and restart the matching runtime. The standard runtime validates the exact ledger on each physical connection and rejects unknown history. Mixed-version operation remains unverified and is not an upgrade guarantee. The P0 fixtures now apply the complete additive schema so the shared adapter's original signing/replay/rollback tests continue to run against current columns and constraints.

## Staged capability gate

This is storage support, not an authorization mechanism. The current scope-only registration projection cannot approve an object request. `Begin`, consent presentation and approval remain closed to object-bound requests until durable profile registration, required PAR and authorized resource-owned decision/display metadata are connected. No public route invokes the RAR codec and no RAR/PAR capability is advertised. Adapter tests seed explicitly trusted synthetic workflows; this is not a production object-grant provisioning API or an ACL demonstration.

Redemption rejects object-bound credentials, revisions or current-grant state before entropy/signing/consumption. Pure scope-only token derivation and the PostgreSQL issuance commit also reject object-bound input. This prevents storage support from silently emitting a token without the approved restrictions. A consumed credential with valid client and possession proof still commits the existing replay revocation; foreign/wrong-proof presentations cannot trigger it. Actual object-aware refresh, token responses, JWT/introspection and SDK enforcement must replace this temporary denial with the complete bounded flow before the P2 gate can pass.

The pre-proof credential lookup reads only the presence of an object ceiling, not its object identifiers or actions. That narrow classification is sufficient for closed-path denial and replay handling. Full revision/current-authority snapshots are rehydrated only through the subsequent grant operation; live object redemption will additionally need its exact credential snapshot after client/possession checks. A missing projection must never be interpreted as an unrestricted credential.

## Evidence and remaining work

Real PostgreSQL tests cover request/revision/code round trips, foreign-tenant isolation, immutable snapshots and revision references, missing descendant restrictions, approval substitution, outbox rollback, concurrent decisions, denied scope-only issuance and replay cutoff. Domain/service/contract tests cover historical snapshots, invalid bindings, denial before unsupported consent effects, no entropy/signing/credential consumption, and possession-checked replay.

Durable profile/client-type registration, RFC 9126 PAR, authorized consent projections, object-aware lifecycle/enforcement and the Go BFF/resource exit demonstration remain pending. These tests do not establish mandatory RAR/PAR enforcement, live interoperability, current resource ACL evaluation, complete refresh narrowing or full specification conformance. No dependency, tool, license exception or public SDK API is added.

Subsequent work: [ADR 0014](0014-durable-resource-object-profiles.md) implements durable resource-profile registration. Client-type registration and the remaining public RAR/PAR/consent/enforcement gates remain pending.
