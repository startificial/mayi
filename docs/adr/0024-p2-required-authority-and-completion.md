# ADR 0024: Required authority, shared admission and incremental consent

Status: Accepted. Supersedes the unfinished scope-only and optional-provenance
staging paths described in ADRs 0008, 0012 and 0023. It does not expand the P2
preview into a production or externally certified release.

## Ownership and authority

Authorization owns pushed requests, their immutable OIDC/offline options,
resource-guarded presentation and consent. Grants owns immutable ceiling values
and their union when **new consent** is approved. Token lifecycle keeps each
code, family and issuance bound to its exact revision and original ceiling.
Authentication owns shared abuse admission; delivery owns request correlation
and audit delivery. Interfaces remain in the consuming service packages.

Migration 11 requires nonempty typed authority on workflows, roots, revisions,
credentials, families and issuances, plus PAR provenance on every interactive
workflow and code. Deferred guards require matching pushed/workflow options.
Missing option rows fail rehydration. `Begin` rejects direct authorization;
private clients cannot use the internal public-client PAR helper. Existing
proof fixtures now explicitly construct the required snapshots. No authority
is inferred or backfilled from missing preview records.

## Shared admission

Migration 12 adds tenant-scoped PostgreSQL fixed-window budgets for login,
token and introspection operations, independently by IP, client and user.
Database time and conditional upserts give replicas a single finite counter.
Counters store SHA-256 pseudonyms of bounded keys, expire opportunistically in
bounded batches and never admit on missing or unavailable state. Fixed windows
permit a boundary burst; this is not a sliding-window or global-HA claim.
Operators configure the same limits on every replica and can choose finite
limits/window sizes; omitting settings selects documented finite defaults.

HTTP adapters establish IP trust. Only explicitly configured proxy CIDRs can
supply X-Forwarded-For; walk the chain from the trusted peer toward the first
untrusted address. Forwarded is not an identity source. Services additionally
limit authenticated clients and known users. Issuance user admission enlists
the existing transaction through the admission port, avoiding nested pool
acquisition. A rejected or failed transaction emits no credential. An upstream
login attempt remains consumed if subsequent user admission fails.

## Incremental consent

Migration 13 appends revisions to an active user/client/resource root. A
transaction advisory lock serializes the tuple even before its first root
exists; root row locking and the tenant coordination lock pin existing state.
The domain unions **complete tuples**, then appends an immutable revision. The
new code's own ceiling is still exactly its pushed request. Requesting both
old and new objects produces a combined new credential; requesting only the
new object does not implicitly grant the old objects to that credential.

Runtime roles retain no direct UPDATE privilege on root ceilings or lifetimes.
A schema-qualified SECURITY DEFINER function with a fixed pg_catalog search
path performs the one reviewed extension operation. It requires tenant context,
an unrevoked active root, a matching pending/session-bound workflow and the
expected revision. A deferred guard requires the corresponding approved
workflow/revision to commit atomically. The service authorizes first and the
resource guard spans commit. Public function execution is revoked. Existing
revisions and family deadlines never change; renewal cannot revive old
credentials. Root revocation invalidates every revision.

## Bound resources, policy and audit

Resource-bound PAR/authorize routes are provisioned in tenant configuration.
They supply an omitted audience and reject conflicts before consuming a
reference. Token/refresh omission inherits only the possessed credential's
stored audience after client/binding/S256 validation. RAR narrowing at token
redemption still requires an explicit resource parameter.

Administration exposes JWT/opaque format, refresh idle/absolute limits and
admin-required scopes. Ordinary user approval/issuance/status excludes those
scopes; separate machine policy is explicitly administered. Admin consent for
users remains P7. Machine policies use service authorization, registered
vocabulary, the tenant coordination lock and atomic policy-version/audit updates.

Migration 14 attaches generated request IDs, trusted peer IP, bounded User-Agent
and known tenant/user/client/resource/issuance correlation to audit/outbox.
Unknown identities remain empty rather than inferred from rejected input. HTTP
rejections and inactive authenticated introspection are recorded separately;
denial-audit storage failures are logged without credentials and never turn a
denial into success. Successful state mutations retain atomic audit/outbox.
Connected apps exposes issuance counts and last online token use/check. A check
is not proof that an application returned protected content; the resource owns
that audit. P2 has no intermediary actor chain; the export explicitly carries an
empty chain, which P4 must replace with authenticated delegation history.

## Verification and limits

`tests/integration/p2_completion_test.go` covers shared replica budgets,
foreign scope, dependency failure, omitted/conflicting resource bindings,
machine policy removal, option half-commits, trusted audit metadata, incremental
revision/old-refresh isolation and immediate root revocation. Existing real
PostgreSQL/OpenBao, public protocol, SDK and reference-BFF tests remain required.
Unit/contract tests cover tuple union, direct-call admission denial, strict
assertion/JWKS parsing, credential locations, escaping and safe error envelopes.

No dependency, tool, license allowance, AWS access or separate database authority
integration is added. PostgreSQL resource authority still requires one physical
database and shared atomic transaction with separate owners/schemas. Full OIDC
UserInfo/logout, MCP/client compatibility, external conformance/certification,
production HA/restore and iframe capability evidence retain their scheduled
later-phase gates.

## Requirement wording clarification

The literal instruction that a denied request must never mutate any state
conflicts with mandatory audit records, finite attempt budgets and authenticated
replay revocation. Those narrowly scoped security bookkeeping transitions are
required; denial must never load protected payloads, mutate application data or
issue/expand authority. The service/transaction tests distinguish those effects.
This clarification does not permit compensating credential issuance or an
exception to authorization-before-payload ordering.
