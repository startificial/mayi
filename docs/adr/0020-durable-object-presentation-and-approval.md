# ADR 0020: Durable object presentation and guarded approval

Status: Implemented application/persistence foundation · 2026-10-18 · Production provider, public PAR and token/resource flow remain pending

## Ownership and decision

Complete the next application boundary from ADR 0019 through the existing authorization service and unit of work. `ObjectConsentProjection.Equal` compares the exact workflow/client/subject, ceiling, resource permission revision and resource-owned labels. Provider ordering is irrelevant because the immutable request determines display order. Permission revisions occupy the positive signed-64-bit range. `Transaction.ApproveObjects` requires matching immutable presented evidence and a fresh guarded projection before using the existing revision/code transition. Registration validity and projection construction alone never authorize approval.

Migration 9 appends `authorization_object_presentations` without changing earlier migration sources. The first row binds one workflow, consent session, subject, client, audience, exact typed ceiling, resource permission version, requested labels and presentation time. SQL enforces the bound pending PAR workflow, exact complete display targets and lifetime. Evidence cannot be updated or deleted, even through ordinary owner DML; forced RLS, tenant predicates, composite foreign keys and no runtime UPDATE privilege reinforce the boundary. Retention still requires a later reviewed maintenance design.

Presentation evidence is not an ACL cache or a resource permission grant. The resource remains authoritative through ADR 0019's guard. The existing default server supplies no provider and stays closed to object display/approval; only explicit `NewObjectAuthorization` composition with a reviewed authority may invoke this application path. Integration tests supply an authoritative resource-owner fixture, not a production provider or supported external transport.

## Presentation and decision boundaries

Preparation acquires the resource guard outside any Mayi transaction, then repeats workflow/session/browser/member/client/policy checks inside the final transaction. It binds the consent session, records the first exact presentation and its audit/outbox, and returns a decision-capable view only after commit and successful guard return. A repeated identical display is idempotent and does not add another presentation audit. A changed version, name or ceiling cannot replace the row, even if current permission still allows the request. Restart with a fresh PAR/workflow rather than silently presenting a different approval context.

Approval authenticates the mutation proof, including CSRF, and performs an initial authorized workflow read with no effects. Under a newly acquired current resource guard, it repeats Mayi authorization and exact request/policy/PAR checks, loads only this actor/session/workflow's stored presentation, and compares it to the fresh projection. Missing evidence, changed permission revision, label drift, added/removed objects/actions, foreign correlation or permission loss denies **before entropy**. The persistence adapter also pins a transaction-local object approval authorization; a stored presentation by itself cannot call `CompleteAuthorization` successfully.

The shared decision helper invokes `ApproveObjects` for typed approvals and reuses the existing atomic workflow/root/revision/code/audit/outbox operation. The resource guard spans its database commit. Codes retain the exact approved ceiling and a 60-second lifetime, along with the existing redirect, S256, client, session/workflow and lineage bindings. SQL additionally forbids approval of a PAR workflow without its exact durable presentation. The adapter's object approval authorization is cleared on every new consent recheck and never survives a transaction.

Cancellation is an authenticated workflow operation. With the explicit object-aware composition, a valid denial proof may terminate a request without consulting resource permission or requiring a presentation. It returns no code, creates no grant, and commits a denial audit through the same unit of work. Resource outage or permission loss must not prevent cancellation. Default composition retains the prior closed typed path; universally required public PAR/RAR cutover remains separate unfinished work, not a scope-only compatibility promise.

## Recovery, trust and limits

Never return a code until approval state and audit/outbox commit and the resource guard returns successfully. Concurrent decisions permit one terminal winner; replays cannot recover the raw code. An audit failure rolls back the new grant, revision, credential and decision, preserving previously committed presentation evidence. A presentation-audit failure rolls back both new evidence and session binding. Failures return no view/code/redirect authority.

A timeout, failed guard return after a successful callback, or lost response leaves an uncertain outcome. Do not infer rollback or automatically retry approval, code redemption or other one-use operations. Use the documented authorized reconciliation path where available, otherwise restart. No code-recovery API or idempotency header is added. A dishonest resource provider, runtime or schema owner bypassing its controls is outside these guarantees; current permission coordination and trusted adapter admission remain necessary.

No new HTTP endpoint is mounted and no capability is advertised. The default browser route still rejects RAR/PAR references. Public protocol composition, the production resource-authority integration and mandatory cutover remain pending. Object-aware token response/JWT/introspection/refresh/SDK enforcement and the Go BFF/resource exit demonstration also remain pending. This application can now approve an object-bound code under explicit test/integration composition; the scope-only token path still rejects that authority rather than dropping it. This is not full RFC interoperability or a usable OAuth deployment.

## Evidence

Domain tests reject missing/changed presentation, version, label, subject, workflow or expanded authority. Service tests deny before entropy/provider access as appropriate, preserve the resource guard through decision commit, reject callback failures, enforce immutable first presentation and allow denial without resource availability.

Real PostgreSQL tests cover idempotent preparation, exact presentation → workflow → grant/revision/code ceilings, S256/redirect/code lifetime, resource lock exclusion through approval commit, foreign tenant/issuer and wrong CSRF, missing evidence, version/name/permission changes, session revocation during guard acquisition, immutable storage/RLS/runtime privileges, adapter approval bypass denial, presentation and approval audit rollback, concurrent single-winner decisions, replay and cancellation during resource outage. Existing protocol/transaction tests run against additive migration 9. Full production/conformance requirement status is unchanged; this adds partial RES-10, GRANT-1 and GRANT-2 evidence.

Apply the explicit owner migration before restarting matching runtimes. No dependency, tool, license exception, public SDK or package layout is added. Error mapping and uncertain-outcome guidance follow the existing [error strategy](../error-handling.md).
