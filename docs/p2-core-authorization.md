# P2: Core authorization preview

P2 is in progress. Milestones 1/2 implement durable consent, configured upstream OIDC login and browser sessions/consent. The service is not yet a usable OAuth authorization server: live token endpoints, resource enforcement and the end-to-end P2 exit condition remain outstanding. Discovery retains its foundation preview.

## Milestones and acceptance

| Milestone | Status | Required evidence |
| --- | --- | --- |
| 1. Authorization transaction and consent core | Implemented | Exact redirect/resource/permission snapshot; five-minute workflow and 60-second code; session/browser/CSRF authorization before protected loads; immutable session binding; one concurrent decision; atomic grant/revision/code/audit/outbox; no plaintext secrets persisted. Domain/service tests and real PostgreSQL regressions exercise these conditions. |
| 2. Upstream OIDC login and browser consent | Implemented, limited preview | Constrained egress; state/nonce/issuer/audience/PKCE; explicit active-member mapping; atomic session issuance/rotation/termination; secure cookies; escaped consent and CSRF/CSP/origin checks. Real PostgreSQL and local OIDC HTTP fixtures cover the flow; browser/provider interoperability remains unverified. [ADR 0009](adr/0009-upstream-login-and-browser-consent.md). |
| 2a. Standard RAR object-grant prerequisite | In progress: typed snapshots, registrations, mixed-type wire codecs and pushed-request storage/binding; blocks live token/resource preview | Migrations 5–9 and real PostgreSQL tests preserve typed authority, one-use pushed references and immutable display/version evidence. Explicit resource-guard composition supports exact object consent-to-code approval. Production resource-provider/public PAR composition, universal RAR/PAR cutover, token propagation and resource enforcement remain outstanding. Documents are the worked exit example; the model also covers workflows, projects and files through resource-owned types/actions. |
| 3. Live protocol and token lifecycle | Planned; depends on 2a | Explicit Fosite composition; code/PKCE and refresh HTTP endpoints; consent-authorized initial refresh issuance and idle/absolute deadlines; reviewed keyed credential-hash/version policy; JWT/opaque access tokens and OIDC ID tokens; client authentication and machine credentials; current policy/resource/client lifetime enforcement; transaction-owned key selection without nested issuance-pool acquisition. |
| 4. Enforcement and complete preview | Planned; depends on 2a/3 | Authenticated introspection/revocation with approved RAR details, immediate authoritative resource checks, typed object/action SDK enforcement, connected-app grant details, Go BFF/document-123 example, denial before protected payload loads, current-permission loss, refresh replay/concurrency and immediate-cutoff tests. Only enforced RAR types and capabilities enter discovery. |

**P2 now has a mandatory RFC 9396 RAR prerequisite**, recorded in [ADR 0010](adr/0010-rar-object-grants-prerequisite.md). Complete milestone 2a before enabling the remaining live token/resource preview or declaring P2 complete. The exit demonstration must grant read access to document `123`, reject `124` and write operations even when the user has both permissions, and prove narrowing, refresh rotation, current-permission loss and immediate revocation. Existing milestones 1/2 are implemented scope-only groundwork; their status does not establish RAR support or satisfy this new gate.

**Fresh-deployment contract:** every resource grant must define typed RAR authority, and every interactive authorization request must use PAR. There is no optional scope-only resource profile or per-client PAR bypass. Existing proof/preview scaffolding is not a deployed-record compatibility commitment. Complete required snapshot/registration constraints and replace the old direct authorization path before enabling the P2 flow; no legacy backfill or upgrade project is required. Machine grants need explicit typed policy-derived authority; PAR applies to interactive authorization requests rather than adding a browser step to client credentials.

## RAR prerequisite implementation backlog

The [developer error contract](error-handling.md) is also a P2 acceptance gate. Its local JSON envelope, catalog and CI tests are implemented foundations. Each enabled P2 protocol/SDK surface still needs endpoint-correct errors, safe recovery documentation, redaction and denial/non-enumeration evidence; no full CORE-13 or SDK claim follows from the local catalog. See [ADR 0016](adr/0016-developer-error-contracts.md).

1. **Domain foundation implemented; runtime integration pending.** `domain/grants` owns immutable `ObjectCeiling` values and exact tuple comparison. `domain/resources` owns immutable `ObjectProfile` registration values with fixed `object-actions-v1` semantics and registered actions. The pure OAuth codec maps the standard envelope and rejects ambiguous input; no handler invokes it yet. [ADR 0011](adr/0011-object-authority-foundation.md) records bounds, omission/denial semantics and integration gates.
2. **Snapshot persistence and resource/client type registration implemented; live RAR issuance remains closed.** Migration 5 adds immutable, versioned request/revision/code ceilings and protected lineage fields for families/issuances; migrations 6/7 add immutable resource-owned type definitions and client/resource/type bindings. Domain approval and PostgreSQL mappings retain the exact typed ceiling; scope-only consent/redemption cannot discard it. [ADR 0012](adr/0012-durable-object-authority-snapshots.md) records the staged gate and actual transaction evidence. Universally required snapshot/PAR provenance constraints must land before accepting public requests. Intermediate nullable fields support unfinished proof scaffolding, not a supported deployment mode; remove that staging allowance at the required-flow cutover.
3. **PAR application/storage binding implemented; public integration pending.** [ADR 0017](adr/0017-pushed-request-storage-and-binding.md) adds 90-second hashed references, current client/policy checks, proof-before-payload loading and one-use atomic browser workflow binding. [ADR 0018](adr/0018-strict-par-wire-profile.md) adds strict mixed-type PAR form, success-body and browser-reference codecs, with wire-to-storage evidence. No PAR route is enabled. [ADR 0019](adr/0019-guarded-object-consent-display.md) adds authorized object display through an explicitly injected resource-owner guard, with session/policy rechecks and binding commit under that guard. The default server has no production provider. [ADR 0020](adr/0020-durable-object-presentation-and-approval.md) adds immutable first-display evidence and guarded object consent-to-code approval through the existing atomic path. Production provider/endpoint composition and universally required public provenance remain pending before exposing the flow. Reject unknown types and bypasses at every caller boundary.
4. Carry assigned details into token responses and JWT/introspection results, refresh comparison, SDK enforcement and grant-management views. Check resource-owned current permissions separately from the grant ceiling.
5. Retain end-to-end and adversarial evidence for document 123 versus 124, read versus write, foreign scope, tuple recombination, missing details, PAR swapping, immutable older revisions, revoked grants, current ACL removal, concurrency and state/audit rollback. Re-estimate remaining P2 effort before committing dates.

The domain/codec and durable snapshot foundations in items 1/2 are implemented. The current browser authorize route does not accept RAR, and existing tokens do not carry object restrictions. No RAR type or PAR endpoint is advertised. The default server continues to reject object-bound consent. An explicitly injected resource guard can provide an authorized display; the explicit guarded composition can approve an object-bound code using durable first-display evidence. Default production composition and object token issuance remain closed until the remaining integration preserves and enforces the ceiling end to end.

Durable resource-owned profile registration and client type allowlists are implemented through the existing administration service and authenticated management routes. [ADR 0014](adr/0014-durable-resource-object-profiles.md) specifies immutable type/audience/action definitions; [ADR 0015](adr/0015-client-rar-type-allowlists.md) adds explicit client metadata and resource-specific vocabulary projections. [ADR 0017](adr/0017-pushed-request-storage-and-binding.md) adds application/storage PAR binding. These foundations do not enable consent or grant authority. Strict wire mapping is implemented under [ADR 0018](adr/0018-strict-par-wire-profile.md); resource-guarded display is implemented under [ADR 0019](adr/0019-guarded-object-consent-display.md) with an explicit integration boundary. Durable first-display evidence and guarded approval are implemented under [ADR 0020](adr/0020-durable-object-presentation-and-approval.md). Production resource-provider composition, public PAR and mandatory cutover are next; token lifecycle/enforcement gates remain outstanding.

### RAR foundation evidence

`grants/objects_test.go` exhausts all 4,096 historical/current/credential combinations for two documents and two actions, and all explicit requested subsets against historical/current authority. It covers document/action recombination, foreign tenant/issuer/audience, new type versions, permission loss, explicit empty denial, missing authority and deep snapshot isolation. `resources/object_profile_test.go` covers profile/type/action registration and semantic validation. The OAuth codec tests standard-envelope round trips, duplicate and escaped/case-variant members, unsupported fields, malformed values, exact locations, bounds and fuzz seeds. `TestScopeOnlyPreviewRejectsRARAndPushedRequestsBeforeServices` proves the existing browser route rejects RAR/request-reference fields before invoking services, rather than dropping restrictions. These are pure model/adapter tests, not proof of live refresh, immediate revocation, resource ACL evaluation or protocol conformance. Complete end-to-end RAR evidence remains required.

`tests/integration/object_ceilings_test.go` adds real PostgreSQL snapshot/lineage, isolation, substitution, concurrency, audit rollback and replay-cutoff evidence. These are trusted adapter fixtures, not a public RAR authorization flow. The contract tests prove that object state in a credential, revision or current grant cannot fall back to scope-only issuance or reach entropy/signing, while valid consumed credentials retain replay revocation. Full end-to-end RAR/ACL/token evidence remains required.

## Implemented application contract

The composition entrypoint `app.NewAuthorization` wires the service, the PostgreSQL adapter and the existing cryptographic material source. It has no memory fallback. Its operations are:

1. `Begin`: resolve the current registered client/resource/tenant policy; validate the exact request and permission ceiling; persist a short-lived workflow and audit/outbox; return independent raw handle/CSRF material only after commit.
2. `PrepareConsent`: authenticate the session/membership and browser reference, repeat authorization before payload load, validate policy and bind the workflow to the session. Explicit object-aware composition additionally guards current resource permission/display state, repeats Mayi checks and persists the immutable first display/version with audit before returning it.
3. `Decide`: validate CSRF and current decision state, then commit root/revision/code/audit/outbox or terminal denial. Explicit object approval requires exact durable presentation and a fresh matching resource projection, with that resource guard spanning approval commit. Denial needs no resource availability. Failure returns no credential or redirect result.

The browser adapter must establish its own unpredictable browser-binding credential and hash raw correlation/session/CSRF handles before invoking this boundary. These application APIs are not public wire contracts. No HTTP route accepts caller-provided identity, membership or a precomputed hash as authority.

Run additive migrations with the explicit `migrate` owner command, then restart onto the matching application version; mixed-version rollout remains unverified. Migration 4 permits session creation/revocation through the authentication use case; migration 5 preserves typed authority without enabling public object requests or converting historical grants. Membership and identity mapping writes remain operator-only. Fixture sessions include browser authentication evidence; this is not an enrollment mechanism for deployment.

[ADR 0008](adr/0008-authorization-transactions-and-consent.md) defines ownership, lock ordering, identity coordination, session binding and remaining limits. No dependency or tool version is added.

## Configure the login preview

After migration, add `identity_provider` to a tenant's existing configuration. Register `https://auth.example/t/a/upstream/callback` as Mayi's redirect at that provider. Use its exact discovery values and supply the secret only through the named environment variable:

```json
{
  "id": "enterprise-v1",
  "issuer": "https://login.example.com",
  "client_id": "mayi",
  "client_secret_env": "MAYI_A_IDP_SECRET",
  "authorization_endpoint": "https://login.example.com/authorize",
  "token_endpoint": "https://login.example.com/token",
  "jwks_uri": "https://login.example.com/jwks",
  "signing_algorithm": "RS256"
}
```

The upstream profile requires advertised S256, `client_secret_basic`, a single client audience and fresh `auth_time` after `max_age=0`. Metadata mismatch, unavailable discovery or missing secrets prevent startup. Public HTTPS/443 endpoints are supported; the explicit development flag permits literal loopback HTTP fixtures. Private-network production IdPs require a later reviewed egress profile.

Provision local membership and the exact upstream mapping through the owner connection. These example statements show the operator-owned records; use bound parameters in integrations and take the tenant lock first. Never derive membership from email:

```sql
BEGIN;
SELECT tenant_id FROM mayi.tenants WHERE tenant_id = 'a' FOR UPDATE;
INSERT INTO mayi.principal_memberships (tenant_id, subject, active)
VALUES ('a', 'user:alice', true);
INSERT INTO mayi.external_identities
  (tenant_id, provider_id, upstream_issuer, upstream_subject, subject)
VALUES ('a', 'enterprise-v1', 'https://login.example.com', 'upstream-subject', 'user:alice');
COMMIT;
```

Start at `I/authorize` with `response_type=code`, registered `client_id`/exact `redirect_uri`, one `resource`, space-separated resource `scope`, unpredictable `state` (at least 16 characters) and S256 `code_challenge`/`code_challenge_method`. The browser returns through the tenant callback to consent. Every new request authenticates upstream; broader local SSO/prompt behavior remains later work. Approval creates a durable 60-second code, but **there is no live redemption endpoint yet**. This is a login/consent preview. Cookies require HTTPS through the trusted proxy.

Sessions have a one-hour absolute lifetime, rotate at login and end through a same-origin POST to `I/session/end`. Session end does not revoke durable grants. Idle timeout, listing, BFF/status integration and downstream logout remain pending. Login/consent stay unframeable; the Go BFF and embedded-session plan has separate acceptance gates.

## Verification

[ADR 0013](adr/0013-p2-review-corrections.md) records the three-reviewer P2 audit and corrections: attempt-relative upstream authentication freshness, browser-bound logout after membership loss, and narrower runtime lifecycle update privileges. Domain/service tests and the real PostgreSQL suite cover the new denial, replay, foreign-reference and reactivation cases. This internal review does not complete the independent production or interoperability gates.

```sh
go run ./tools/checks
go test -race -count=1 ./...
go vet ./...
go run ./tools/p0
```

The existing real-service CI harness includes authorization, authentication and browser tests automatically. Ordinary `go test` skips database cases without that environment. Login/consent tests can also use the reviewed PostgreSQL instance independently of Transit; the full-server routing test additionally requires Transit. The local OIDC fixture exchanges code/S256 and signs test ID tokens without contacting enterprise accounts or cloud services.
