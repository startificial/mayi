# P2: Core authorization preview

P2 is in progress. Milestones 1/2 implement durable consent, configured upstream OIDC login and browser sessions/consent. The service is not yet a usable OAuth authorization server: live token endpoints, resource enforcement and the end-to-end P2 exit condition remain outstanding. Discovery retains its foundation preview.

## Milestones and acceptance

| Milestone | Status | Required evidence |
| --- | --- | --- |
| 1. Authorization transaction and consent core | Implemented | Exact redirect/resource/permission snapshot; five-minute workflow and 60-second code; session/browser/CSRF authorization before protected loads; immutable session binding; one concurrent decision; atomic grant/revision/code/audit/outbox; no plaintext secrets persisted. Domain/service tests and real PostgreSQL regressions exercise these conditions. |
| 2. Upstream OIDC login and browser consent | Implemented, limited preview | Constrained egress; state/nonce/issuer/audience/PKCE; explicit active-member mapping; atomic session issuance/rotation/termination; secure cookies; escaped consent and CSRF/CSP/origin checks. Real PostgreSQL and local OIDC HTTP fixtures cover the flow; browser/provider interoperability remains unverified. [ADR 0009](adr/0009-upstream-login-and-browser-consent.md). |
| 3. Live protocol and token lifecycle | Planned | Explicit Fosite composition; code/PKCE and refresh HTTP endpoints; consent-authorized initial refresh issuance and idle/absolute deadlines; reviewed keyed credential-hash/version policy; JWT/opaque access tokens and OIDC ID tokens; client authentication and machine credentials; current policy/resource/client lifetime enforcement; transaction-owned key selection without nested issuance-pool acquisition. |
| 4. Enforcement and complete preview | Planned | Authenticated introspection/revocation, immediate authoritative resource checks, resource SDK, connected apps, BFF/resource example, current-permission loss, refresh replay/concurrency and immediate-cutoff tests. Only enforced capabilities enter discovery. |

The P2 exit condition remains the plan's BFF/resource demonstration of consent, current permissions, refresh rotation and immediate cutoff. A milestone's tests do not mark a full README requirement verified.

## Implemented application contract

The composition entrypoint `app.NewAuthorization` wires the service, the PostgreSQL adapter and the existing cryptographic material source. It has no memory fallback. Its operations are:

1. `Begin`: resolve the current registered client/resource/tenant policy; validate the exact request and permission ceiling; persist a short-lived workflow and audit/outbox; return independent raw handle/CSRF material only after commit.
2. `PrepareConsent`: authenticate the session/membership and browser reference, repeat that authorization inside the transaction before payload load, validate current policy, bind the workflow immutably to the session, and return a display projection.
3. `Decide`: additionally validate the CSRF proof, recheck current decision state under the same guard, then commit approval plus root/revision/code/audit/outbox or a terminal denial. Failure returns no credential or redirect result.

The browser adapter must establish its own unpredictable browser-binding credential and hash raw correlation/session/CSRF handles before invoking this boundary. These application APIs are not public wire contracts. No HTTP route accepts caller-provided identity, membership or a precomputed hash as authority.

Run additive migrations with the explicit `migrate` owner command, then restart onto the matching application version; mixed-version rollout remains unverified. Migration 4 permits session creation/revocation through the authentication use case. Membership and identity mapping writes remain operator-only. Fixture sessions include browser authentication evidence; this is not an enrollment mechanism for deployment.

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

```sh
go run ./tools/checks
go test -race -count=1 ./...
go vet ./...
go run ./tools/p0
```

The existing real-service CI harness includes authorization, authentication and browser tests automatically. Ordinary `go test` skips database cases without that environment. Login/consent tests can also use the reviewed PostgreSQL instance independently of Transit; the full-server routing test additionally requires Transit. The local OIDC fixture exchanges code/S256 and signs test ID tokens without contacting enterprise accounts or cloud services.
