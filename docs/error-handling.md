# Error contracts and troubleshooting

Mayi returns stable machine-readable codes and safe public descriptions. Match codes and status, never message text. Messages can improve without changing the code's meaning. New meanings require a new code and contract evidence; do not repurpose an existing code. Services own decisions and typed errors; inbound adapters own their wire representation. See [ADR 0016](adr/0016-developer-error-contracts.md).

## Current support and P2 gate

Implemented: the local JSON envelope below, the [machine-readable catalog](error-catalog.json), typed-error mappings for current management/local browser boundaries, request correlation on observed requests, and CI contract tests. These foundations do not establish complete OAuth error handling, field-level diagnostics or a public SDK.

P2 completion requires endpoint-specific error fixtures for every enabled protocol surface, authorized validation diagnostics, safe recovery examples and denial/non-enumeration tests. The future resource SDK must document typed Go errors, `errors.Is`/`errors.As`, cancellation and recovery behavior before it is advertised. P3 resource-discovery/challenge extensions retain their existing delivery phase; they must preserve this strategy. Full CORE-13 is not verified by this document.

## Select the endpoint's contract

| Surface | Contract and recovery |
| --- | --- |
| Management, discovery/readiness failures and local browser failures | The local JSON envelope and catalog below. Local browser failures stay on Mayi when redirect safety is not established. |
| OAuth token, PAR and other protocol endpoints | Use the applicable pinned specification and Fosite adapter's standard fields, status, authentication challenge and cache requirements. Do not wrap protocol responses in the local JSON envelope. Return only safe fixed descriptions; use a documented `error_uri` only when its destination actually exists. Each enabled endpoint needs its own tests. |
| Authorization redirects | Validate client and exact redirect first. Only then return the permitted OAuth response with the original bound state and applicable issuer identification. Never redirect to a destination obtained from an invalid request. |
| Protected resource / UserInfo | Correct authentication challenge and endpoint-specific error, including resource metadata or step-up details only when that capability is implemented. Never accept an ID token as an API access token. |
| Introspection and revocation | Preserve standard privacy behavior: inactive credentials and revocation of an unknown credential must not become an existence oracle. Do not replace valid protocol success responses with local `not_found` errors. |
| CLI and workers | Sanitized diagnostics and non-success outcomes, without printing raw dependency errors or credentials. Workers acknowledge delivery only after the required effect succeeds. |

Future surfaces in this table describe implementation requirements, not enabled routes. Protocol error codes belong to their specification and are not additional local catalog entries.

## Local JSON envelope

For example, a management request with malformed input receives HTTP 400:

```json
{
  "error": "invalid_request",
  "message": "The request is malformed or contains unsupported values.",
  "request_id": "0123456789abcdef0123456789abcdef"
}
```

`error` is the compatibility contract. `message` is a fixed, credential-free description, not an exception string. `request_id`, when available, matches Mayi's generated `X-Request-ID` response header; it grants no access. Direct handler use, failures before observation, admission rejection and infrastructure-generated errors may have no request ID. Request-supplied correlation headers are not trusted or echoed by this contract. Clients must tolerate additive fields and handle unknown codes with a safe generic failure.

Local errors use `Content-Type: application/json` and `Cache-Control: no-store`. This envelope does not assert that every router, reverse proxy or network failure returns JSON. Unknown code/status combinations in the transport helper become a fixed HTTP 500 `internal_error`, never a reflection of the caller's string. The contract tests reject undocumented helper definitions; endpoint tests must still detect incorrect call-site mappings.

## Local error catalog

Exact statuses, current messages and recovery instructions are maintained in [error-catalog.json](error-catalog.json). These short sections provide stable documentation anchors.

### invalid_content_type

HTTP 415. Send a JSON object with `Content-Type: application/json`.

### invalid_request

HTTP 400. Correct the request shape or begin a fresh expired browser workflow. Unknown fields, malformed/duplicate parameters and unsupported values fail closed. The current preview deliberately uses a generic message.

### invalid_token

HTTP 401. Supply the correct endpoint credential. Invalid authentication does not reveal whether a user, client or credential record exists.

### forbidden

HTTP 403. Review authorized permissions and trusted tenant context. Do not disclose ownership or object existence in the response.

### conflict

HTTP 409. Reconcile state using an authorized operation before deciding whether to submit a revised mutation.

### not_found

HTTP 404. The requested resource is unavailable to this authorized lookup. Authorization must precede protected lookup; this code must not introduce an enumeration oracle.

### not_ready

HTTP 503. Readiness has not succeeded. Follow the [foundation runbook](p1-foundation.md); readiness itself is not proof that every protocol operation works.

### temporarily_unavailable

HTTP 503. A transient dependency or capacity failure may have occurred. Retry safety depends on the operation, not just this status.

### internal_error

HTTP 500. A safe fallback for an unexpected transport mapping. Keep the request ID for operator investigation; no internal cause is returned.

## Validation and safe diagnostics

Boundary parsing and service invariants remain separate. P2 field diagnostics may identify an allowlisted public field and constraint, such as a missing `resource` parameter, only after the caller is permitted to learn that fact. Do not echo rejected values, SQL, stack traces, upstream bodies, identity claims, permission projections, codes, cookies, tokens or secrets. Bound diagnostic counts and lengths. Authentication, foreign-tenant and protected-object denials remain deliberately generic.

Within a service, use the owning capability's typed/sentinel errors and `errors.Is`/`errors.As`; do not introduce a global business-error package or attach HTTP status codes to domain/service types. Translate database, KMS and upstream failures into those service-owned categories at the adapter boundary. Mapping to public codes stays in inbound adapters. Local public messages never come from `err.Error()`.

## Retry and recovery

- Correct 4xx input/permission failures before retrying. A conflict requires state reconciliation, not an unchanged replay.
- Read-only calls may use bounded exponential backoff with jitter, a maximum attempt count and a total deadline. Honor `Retry-After` if a future endpoint supplies a valid value; current local errors do not promise that header or automatic retries.
- A 5xx response, timeout or lost connection does not prove a mutation failed before commit. Do not automatically retry code redemption, refresh rotation, assertions, handoff redemption or any other one-use credential operation. Reconcile only through a documented authorized mechanism; otherwise restart the appropriate authentication/approval flow. Never invent an idempotency header that the endpoint does not support.
- Treat OAuth `invalid_grant` as a credential/flow recovery problem. Do not disclose whether the code was expired, consumed, revoked or foreign. No general retry flag in an error response can make replay safe.
- Cancellation stops the caller waiting; it does not promise transaction rollback. A future SDK must preserve cancellation classification while documenting an uncertain operation outcome.

## Debugging without secrets

Record operation name, timestamp, HTTP status, public error code and response request ID. Give those to an authorized operator. Do not paste request URLs, authorization headers, raw bodies, cookies or credentials into tickets or logs. Request IDs are correlation values, not authentication or a public log-search capability.

The operator correlates the ID with restricted structured logs and, where available, committed audit records. Current HTTP logs record ID/status/duration, not detailed dependency causes. Richer sanitized internal reason categories and full ADM-5 audit correlation remain P2/operations work; this change does not claim they are implemented. Metrics use bounded categories, not user/object IDs, arbitrary error text or request IDs as labels.

## CI evidence and limits

The workflow explicitly runs `go test -race -count=1 ./internal/adapters/inbound/http/... -run '^TestErrorContract'`; the full race suite also includes these tests. The tests compare every local transport definition with the catalog, require recovery guidance/documentation anchors, check status/body/headers and unknown-mapping fallback, exercise wrapped service-error mappings and prevent raw exception disclosure in those responses. They also preserve generic browser denials and safe authorization redirects.

CI cannot prove that every new endpoint uses the right semantics or that every diagnostic is safe. Every enabled endpoint needs positive, denial, foreign-tenant/non-enumeration, dependency-failure and protocol-format tests where applicable. Keep implemented, planned and verified distinct; full SDK/protocol coverage is a P2 gate, not a claim made by the catalog test.

### rate_limited

Local browser admission returns HTTP 429 with `Retry-After` when a configured shared budget is exhausted. Honor the delay and restart expired workflows. OAuth token/introspection admission uses `temporarily_unavailable` with HTTP 429 and the same header. No credential is issued by a request rejected at admission. This does not resolve an earlier request whose outcome was lost; do not automatically retry one-use credentials after an ambiguous failure.

## Enabled P2 protocol surfaces

OAuth adapters use fixed standard error names and no rejected values or raw internal errors. Successful token/PAR/introspection responses and errors use no-store. Registered client authentication failure is 401 invalid_client with a Basic challenge. Unknown credentials remain generic.

| Surface | Success | Denial / recovery |
| --- | --- | --- |
| PAR | 201 request_uri + finite expires_in | 400 invalid_request for malformed form; invalid_scope for unavailable user scopes; invalid_authorization_details for invalid/unknown typed authority; invalid_target for a conflicting provisioned binding. Correct the request and submit a new PAR. |
| Authorize / consent | 303 registered redirect with code/state/iss; explicit denial access_denied/state/iss | Untrusted or expired references fail locally without redirecting. Restart PAR/login. Cookie POSTs require exact Origin/CSRF as applicable. |
| Token | 200 exact bounded access authority, optional ID/refresh | 400 invalid_grant, invalid_scope, invalid_authorization_details, invalid_dpop_proof or unsupported_grant_type; 401 invalid_client. Invalid proof/expansion never issues authority. Authenticated credential reuse may revoke the lineage. |
| Introspection | 200 active claims or exactly active:false | 401 invalid_client for an unauthorized caller/target; invalid/inactive credentials reveal no extra state; 503 if authoritative status or audit state is unavailable. |
| Revocation | 200 empty, including unknown/non-owned token | Client authentication remains required according to registration. Hints are advisory. Retry is not a way to discover credential state. |
| User controls / connected apps | 200 views, 204 mutation | Generic invalid_request for foreign/invalid browser proof; same-origin cookie mutation; 503 on authority failure. |
| Administrator controls | 200/201/204 | 403 forbidden before protected reads/mutations; 400 invalid_request for malformed values; 409 conflict for version/uniqueness races; 503 dependency failure. |

Shared budget rejection is 429 with Retry-After. Known rejection before issuance does not resolve an earlier ambiguous one-use request. Never infer retry safety from timeout/5xx. The SDK returns typed ErrDenied/ErrUnavailable and preserves context cancellation; application callback errors remain the application's responsibility. See its integration guide for bounded form handling and body validation.

Generated X-Request-ID values link responses, transport logs and durable audit/outbox. Trusted peer IP and bounded printable User-Agent are stored as metadata; rejected credentials, bodies and arbitrary key URLs never become diagnostic text. Missing denial-audit storage is itself logged as security_audit_unavailable and never permits a rejected action.
