# P2: Core authorization preview

P2 is in progress. The first milestone implements the durable consent application boundary. The service is not yet a usable OAuth authorization server: upstream login, browser routes and the end-to-end P2 exit condition remain outstanding. The existing P1 HTTP surface stays unchanged.

## Milestones and acceptance

| Milestone | Status | Required evidence |
| --- | --- | --- |
| 1. Authorization transaction and consent core | Implemented | Exact redirect/resource/permission snapshot; five-minute workflow and 60-second code; session/browser/CSRF authorization before protected loads; immutable session binding; one concurrent decision; atomic grant/revision/code/audit/outbox; no plaintext secrets persisted. Domain/service tests and real PostgreSQL regressions exercise these conditions. |
| 2. Upstream OIDC login and browser consent | Planned | Constrained upstream egress; state/nonce/issuer/audience/PKCE validation; explicit local subject and tenant membership mapping; session issuance/rotation/termination; secure cookies; escaped consent views and CSRF/CSP/origin controls. Login must use the existing consent service rather than implement approval in handlers. |
| 3. Live protocol and token lifecycle | Planned | Explicit Fosite composition; code/PKCE and refresh HTTP endpoints; consent-authorized initial refresh issuance and idle/absolute deadlines; reviewed keyed credential-hash/version policy; JWT/opaque access tokens and OIDC ID tokens; client authentication and machine credentials; current policy/resource/client lifetime enforcement; transaction-owned key selection without nested issuance-pool acquisition. |
| 4. Enforcement and complete preview | Planned | Authenticated introspection/revocation, immediate authoritative resource checks, resource SDK, connected apps, BFF/resource example, current-permission loss, refresh replay/concurrency and immediate-cutoff tests. Only enforced capabilities enter discovery. |

The P2 exit condition remains the plan's BFF/resource demonstration of consent, current permissions, refresh rotation and immediate cutoff. A milestone's tests do not mark a full README requirement verified.

## Implemented application contract

The composition entrypoint `app.NewAuthorization` wires the service, the PostgreSQL adapter and the existing cryptographic material source. It has no memory fallback. Its operations are:

1. `Begin`: resolve the current registered client/resource/tenant policy; validate the exact request and permission ceiling; persist a short-lived workflow and audit/outbox; return independent raw handle/CSRF material only after commit.
2. `PrepareConsent`: authenticate the session/membership and browser reference, repeat that authorization inside the transaction before payload load, validate current policy, bind the workflow immutably to the session, and return a display projection.
3. `Decide`: additionally validate the CSRF proof, recheck current decision state under the same guard, then commit approval plus root/revision/code/audit/outbox or a terminal denial. Failure returns no credential or redirect result.

The browser adapter must establish its own unpredictable browser-binding credential and hash raw correlation/session/CSRF handles before invoking this boundary. These application APIs are not public wire contracts. No HTTP route accepts caller-provided identity, membership or a precomputed hash as authority.

The new additive migration is run using the existing explicit `migrate` owner command. Restart onto the matching application version afterward; mixed-version rollout is not yet verified. Runtime session/membership creation and mutation remain prohibited. The first milestone's integration tests seed those records through the private test DBA; this is not a login or enrollment mechanism for deployment.

[ADR 0008](adr/0008-authorization-transactions-and-consent.md) defines ownership, lock ordering, identity coordination, session binding and remaining limits. No dependency or tool version is added.

## Verification

```sh
go run ./tools/checks
go test -race -count=1 ./...
go vet ./...
go run ./tools/p0
```

The existing real-service CI harness includes `tests/integration/authorization_test.go` automatically. Ordinary `go test` without the harness environment skips database cases. The P2 regressions also run against the reviewed PostgreSQL instance independently of Transit, since this milestone creates codes and does not sign tokens.
