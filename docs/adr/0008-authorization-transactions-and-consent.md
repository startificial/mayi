# ADR 0008: Authorization transactions and atomic consent

Status: Accepted for P2 milestone 1 · 2026-10-18

P2 begins with the application boundary that upstream login and thin protocol/browser adapters will invoke. This milestone adds no HTTP authorization or login route. It does not enable a protocol capability or complete the P2 exit condition.

## Ownership and language

`domain/authorization` owns the short-lived authorization workflow: the exact client redirect, one resource URI, permission ceiling, S256 challenge, browser/CSRF proof references and terminal consent decision. It is distinct from a database transaction and from the durable grant. `services/authorization` authenticates/authorizes references and orchestrates that workflow. It reuses client redirect, resource catalog, tenant policy and immutable grant-revision invariants; none of those lifecycles gets a second implementation.

Identity owns membership and session validity. This milestone consumes only narrow identity decision projections, persisted in `principal_memberships` and `browser_sessions`. There is no upstream-to-local identity mapping, account enrollment, session issuance, login endpoint or assumption that email establishes membership. Session and membership writes remain denied to the runtime role until the authentication use case exists. Integration fixtures provision them through the isolated database administrator.

## Reference authorization and session binding

A pending workflow lasts at most five minutes. Its handle and CSRF secret are independently generated with the existing reviewed entropy adapter and stored only as hashes. Browser binding is an independently established hashed correlation credential supplied by the future browser adapter. The service boundary accepts bounded application values, not HTTP or Fosite request/session types.

Before loading protected request content, the service checks the trusted tenant/issuer, session handle, active membership, enabled client, pending reference, browser binding and, for a decision, CSRF proof. After acquiring the unit-of-work lock it repeats this authorization projection before payload load. The domain validates rehydrated state, the exact redirect, resource registration, scope ceiling and current tenant policy. A changed policy version requires restarting authorization.

`PrepareConsent` explicitly binds the workflow to the current authenticated session and returns a display projection. Binding is audited and immutable. A replacement session, including another login for the same subject, cannot reuse it. Direct approval also establishes that binding in its decision transaction. The future UI must render the returned projection without I/O, protect consent POSTs with the corresponding CSRF secret and cookie/origin controls, and restart on account/session changes.

## Atomic decision and identity consistency

The service-owned unit of work holds the existing tenant coordination row `FOR SHARE`, then locks the authorization reference before loading it. Client/resource configuration is read under that lock. Policy and future identity mutation use the conflicting tenant `FOR UPDATE` lock from the beginning of their unit of work. Database triggers also acquire this guard for membership/session writes, including operator writes. Identity writers must acquire the tenant write lock first rather than attempting a shared-to-exclusive upgrade. Operations affect one tenant per unit of work. This is an explicit consistency guard, not a tenant-wide domain aggregate or object graph.

The restricted runtime cannot update session or membership metadata. It consequently cannot take PostgreSQL row locks that require update privileges on those tables. The tenant guard provides the required conflict without granting it authority to manufacture identities or adding security-definer functions. Tests verify that identity mutations conflict while consent owns the guard and that membership loss between the initial and transaction-local checks causes no protected payload load.

Approval creates one durable root, revision 1 and a code in the same transaction as the terminal workflow state and audit/outbox records. The code expires in 60 seconds and retains the exact approved transaction, redirect, resource, client, S256 challenge, optional sender-binding reference and permission ceiling. Only its hash is persisted. A raw code is returned only after durable commit. Denial consumes the workflow without creating authority. Concurrent decisions serialize; a terminal decision cannot reopen or mint another code. An audit/outbox failure rolls back all decision writes. Incremental approval on an existing root is not implemented by this create-root operation.

The migration permits runtime insertion of immutable grant revisions for this service; update remains prohibited and the existing immutability trigger remains in place. Authorization request columns are immutable, session binding is one-use, and runtime updates are limited to binding/decision columns. Issuer/tenant predicates, composite references and forced RLS apply throughout. P0/P1 migration source strings remain unchanged; migration 3 is additive. Mixed-version upgrade/restore guarantees remain a later operations gate.

## Protocol and delivery limits

This is application/domain code, not a replacement OAuth protocol engine. Fosite remains selected. The new code records feed the existing redemption model; public parsing, response construction and redirect error handling arrive with the P2 HTTP integration. No metadata advertises these in-process operations. Authentication, cookies, UI CSP/CSRF, refresh issuance from consent, client authentication, OIDC tokens, status/revocation, resource middleware, machine credentials and connected apps remain explicit P2 work. The known nested signing-state pool acquisition must be removed before enabling live issuance.

Evidence: [domain tests](../../internal/domain/authorization/transaction_test.go), [service authorization-order tests](../../internal/services/authorization/service_test.go), [real PostgreSQL tests](../../tests/integration/authorization_test.go). Protocol references: [PKCE](https://www.rfc-editor.org/rfc/rfc7636), [authorization code](https://www.rfc-editor.org/rfc/rfc6749#section-4.1), and the existing pinned [capability profiles](../../specs/profiles.md).
