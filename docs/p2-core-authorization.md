# P2 core authorization preview

P2 implements the core authorization preview. It remains experimental and is
not a production-supported or externally certified authorization server. The
[requirement matrix](requirement-matrix.md) distinguishes this phase's evidence
from later production, MCP, delegation and full OIDC requirements.

## Enabled behavior

| Capability | Implementation and evidence |
| --- | --- |
| Required RAR/PAR | Every resource grant has a registered typed object/action ceiling. Every interactive request uses one-use PAR. Domain, service, SQL and immutable option guards enforce the same model; there is no scope-only compatibility mode. |
| Login/consent | Explicit upstream OIDC discovery/key trust, state/nonce/S256, fresh upstream authentication, operator-owned issuer/subject mapping, browser-bound sessions, escaped resource-owned labels and guarded consent commit. |
| Live protocol | Public/confidential authorization code and refresh; Basic/private_key_jwt; machine credentials; one audience; ES256 access/ID tokens or opaque access tokens; authenticated online introspection and owner-scoped revocation. |
| Durable authority | Exact approved transaction and revision, one-use code/refresh, replay cutoff, idle/absolute deadlines, atomic issue/consume/audit and no token response before commit. |
| Incremental approval | New consent appends an immutable revision to the active root and extends connected authorization. Old codes/families keep their original ceilings. Revocation cuts off all revisions. |
| Resource enforcement | The Go SDK intersects credential ceilings with a fresh authoritative status and resource-owned current permission guard before any payload callback. ID tokens never authorize API access. |
| Browser integration | Runnable Go BFF with server-side AES-GCM-encrypted credentials and context-bound AAD, hardened opaque cookies, nonce/state/S256, serialized refresh and fixed API destinations. |
| Controls | Connected-app page and JSON, usage/check timestamps, user/session revoke, tenant administrator listing/revoke, client secret/key administration, machine policy management and finite shared abuse budgets. |

Current decisions and their consistency boundaries are in
[ADR 0024](adr/0024-p2-required-authority-and-completion.md), building on
[ADR 0021](adr/0021-postgresql-resource-authority.md) and
[ADR 0023](adr/0023-p2-live-lifecycle-and-bff-encryption.md).

## Deploy with PostgreSQL

Follow [the foundation runbook](p1-foundation.md) for the reviewed Go toolchain,
external PostgreSQL owner/runtime roles, explicit migrations, tenant provisioning
and OpenBao Transit. The process never borrows an owner connection or migrates
on startup. No AWS service or credentials are required.

Install [the resource-owner contract](../deploy/resource-authority.sql) with a
separate resource migration owner. Its permission/display projection must be in
the **same physical PostgreSQL database** as Mayi, with separate ownership and
only the documented narrow runtime grants. Maintain that projection synchronously
with the application's actual ACL. A separately hosted authority or asynchronous
ACL copy does not satisfy P2's atomic guard contract.

For each interactive tenant, add these fields to its foundation configuration:

```json
{
  "credential_keys": [
    {"version": 1, "secret_env": "MAYI_A_CREDENTIAL_KEY", "active": true}
  ],
  "resource_authorities": ["https://api.example"],
  "resource_bindings": [{"id": "api", "resource": "https://api.example"}],
  "identity_provider": {
    "id": "enterprise-v1",
    "issuer": "https://login.example.com",
    "client_id": "mayi",
    "client_secret_env": "MAYI_A_IDP_SECRET",
    "authorization_endpoint": "https://login.example.com/authorize",
    "token_endpoint": "https://login.example.com/token",
    "jwks_uri": "https://login.example.com/jwks",
    "signing_algorithm": "RS256"
  }
}
```

`MAYI_A_CREDENTIAL_KEY` contains a cryptographically generated 32-byte key encoded
as unpadded base64url. The server fails startup on invalid/missing key material.
Keep one active key and retained versions needed by outstanding credentials;
removing a version invalidates its keyed handles. Do not print secret values.
The IdP secret comes only from its named environment variable. Register
`https://auth.example/t/a/upstream/callback` at the provider. The upstream must
support configured algorithms, Basic, S256 and fresh auth_time after max_age=0.

With the owner connection, provision active membership and the exact upstream
identity mapping under the tenant coordination lock. Never infer either from
email, domain or a caller-provided user identifier:

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

Use authenticated management routes to create the resource and scopes, register
its immutable object type/actions, then create a client with that resource and a
nonempty authorization_details_types allowlist. Scopes can require administrator
approval; ordinary user consent then rejects them. Resources select token_format
`jwt` (default) or `opaque`. Tenant policy exposes refresh_idle_seconds and
refresh_absolute_seconds, with finite defaults of 86,400 and 2,592,000 seconds.
Grant/policy deadlines can shorten either lifetime.

## Wire flow

Let `I = https://auth.example/t/a`. Authenticate the client according to its
registration and POST an application/x-www-form-urlencoded body to `I/par`:

```text
client_id=web
response_type=code
redirect_uri=https://app.example/callback
resource=https://api.example
scope=read openid offline_access
state=<unpredictable client state, at least 16 characters>
nonce=<unpredictable relying-party nonce, at least 16 characters>
code_challenge=<S256 challenge>
code_challenge_method=S256
authorization_details=[{"type":"https://api.example/types/document/v1","locations":["https://api.example"],"identifier":"123","actions":["read"]}]
```

Percent-encode these fields using a form encoder. The type must have been
registered with this exact resource and the client; type URIs are inert names,
not schema fetch destinations. A successful 201 response contains a bounded
`request_uri`. Navigate top-level to `I/authorize?client_id=web&request_uri=...`.
No request substitution or extra authorization parameters are accepted there.
The browser authenticates upstream, displays current resource-owned labels and
approves the exact pushed request. Success returns a <=60-second code, state
and issuer to the registered redirect; explicit denial returns access_denied,
state and issuer. Untrusted/expired requests fail locally without redirecting.

Redeem at `I/token` with grant_type=authorization_code, the code and original
S256 verifier. A supplied redirect_uri must match exactly. A supplied resource
must match the stored audience. Omission inherits only that credential's audience
after possession checks. Requesting openid requires a bound nonce and produces
an ES256 ID token for the client; it is never an API credential. Approved
offline_access produces a one-use refresh family. Explicit scope attenuation
can drop continued-access capability; omitted scope preserves the bounded
credential authority. RAR narrowing at redemption requires an explicit resource.

Rotate at `I/token` with grant_type=refresh_token. Serialize refresh in every
client. Omission preserves only that family's authority; added objects/actions
or scopes fail. Authenticated reuse revokes its family/root and dependent access
tokens. An ambiguous network response is not safe to retry automatically.

The optional provisioned `I/r/api/par` and `I/r/api/authorize` routes bind the
resource from configuration when the parameter is omitted and reject conflicts.
They still require PAR, RAR, registered-client policy and normal consent.

## Resource and browser integrations

Use [pkg/resource](../pkg/resource/README.md) for the application API and
[examples/bff](../examples/bff/README.md) for a standalone or existing-Go-backend
BFF. A fresh online status check and current resource permission guard precede
the payload callback. Credentials belong only in one Authorization header; query
and form-body access_token credentials are rejected. JSON/business bodies need
the application's own strict boundary decoder. Neither JWT validation nor a
stale positive cache satisfies immediate revocation.

BFF encryption authenticates version, algorithm, key ID, tenant, issuer, client,
audience, session ID, credential purpose and generation as AAD. It rejects record
swaps and purpose/context changes. Whole-record rollback needs durable-store
monotonic state; AAD alone cannot solve it. The reference memory store is bounded,
single-process and restart-invalidating. Production BFF persistence and the
cross-replica GCM key usage budget are explicit integration responsibilities.

The [embedded-session/handoff contract](implementation-plan.md#embedded-authentication-and-sessions)
is defined, with implementation/browser capability evidence scheduled for P5.
P2 does not advertise iframe login, token handoff in URLs/messages or unsupported
browser storage guarantees.

## Management and abuse controls

Same-origin session-cookie operations:

| Endpoint | Behavior |
| --- | --- |
| GET `I/connected-apps` | Escaped Go-rendered applications, approved permissions, token issuance counts and last online token use/check, with revoke forms. A token check is not proof of protected-content delivery. |
| GET `I/grants` | Corresponding JSON grant summaries and typed details. |
| POST `I/grants/{id}/revoke` | Revoke the caller's own root and all its revisions. |
| GET `I/sessions` | Active sessions and current-session marker. |
| POST `I/sessions/{reference}/revoke` | End an owned session. |
| POST `I/session/touch` | Renew activity without extending the one-hour absolute cap. |
| POST `I/session/end` | End the browser-bound session; grant revocation is separate. |

Cookie POSTs require the exact configured Origin. Sessions have 15-minute idle
and one-hour absolute limits. Every new authorization authenticates upstream;
full assurance/logout integrations remain later phases.

Administrator routes require explicit scoped permissions. GET
`/admin/t/a/grants?after=<last-id>` uses grants:read and bounded ID-cursor pages;
POST `/admin/t/a/grants/revoke` uses grants:write and a grant/user/client selector.
PUT/DELETE `/admin/t/a/clients/{id}/machine-authorization` uses clients:write,
with a resource and, for PUT, scopes and authorization_details. Removal/narrowing
immediately affects fresh machine-token decisions. Secret rotation returns the
secret once; only versioned keyed hashes and finite expiries persist. Inline or
registered remote public JWKS support private_key_jwt; token-controlled key URLs
are never fetched. The strict assertion profile accepts only iss/sub/aud/jti/
iat/exp/nbf and public sig JWK fields; duplicate/case-variant/unsupported members,
private material, wrong algorithm/purpose/audience and assertion reuse fail.

Shared budgets apply to login/token/introspection by IP/client/user. Default
60-second capacities are login IP 120, client/user 30; token IP 600, client/user
120; introspection 6,000 per dimension. Override using top-level rate_limits with
all nine {operation, dimension, limit, window_seconds} entries; each limit is
1–1,000,000 and each window 1–3,600 seconds. All replicas must use the same rules.
These are fixed windows, with bounded expiry cleanup and no positive cache.
HTTP 429 includes Retry-After; shared-state failures fail closed.

By default peer IP is the socket address. Set top-level trusted_proxies to exact
canonical CIDRs only for proxies that overwrite/append X-Forwarded-For correctly.
The server walks from the trusted peer to the first untrusted address. Arbitrary
Forwarded/X-Forwarded-For headers cannot establish identity or issuer.

## Verification and evidence

Run the full required gates:

```sh
go run ./tools/checks
go test -race -count=1 ./...
go vet ./...
test -z "$(gofmt -l .)"
go run ./tools/p0
```

The last command builds reviewed PostgreSQL/OpenBao sources and runs real
integration tests. Plain go test skips those cases without the harness environment.
CI executes all of these gates; a workflow does not establish branch protection.

The [P2 evidence manifest](../tests/conformance/p2-evidence.json) links bounded
protocol/profile evidence. `live_protocol_test.go` covers the connected Go
BFF/SDK demonstration (read 123, deny 124/write before payload), actual PAR/login,
OIDC relying-party validation, signing, rotation, replay and current ACL/removal.
`p2_completion_test.go` covers shared replica limits, required option commits,
resource bindings, incremental revisions, old-family isolation, machine policy
removal, usage/admin scope and audit correlation. Existing persistence failure,
authorization order, foreign-tenant, parser/fuzz-seed and crypto tests remain gates.

This is executable local preview evidence, not OpenID certification, a real
browser compatibility matrix, managed-PostgreSQL certification, production HA,
restore/upgrade verification or an independent security audit. Those retain the
plan's later delivery gates. ES256 is the published server signing profile;
UserInfo, RP logout, native/MCP registration and delegation are not advertised.
