# ADR 0013: P2 review corrections

Status: Implemented · 2026-10-18

## Review scope

Three independent reviewers examined the implemented P2 authorization/browser flow, PostgreSQL consistency, and protocol/egress/composition boundaries. The review also covered the typed object-ceiling/profile/codec foundation. This is an internal engineering review of an unfinished preview, not the independent production security or protocol-conformance gate.

## Authentication freshness

The upstream adapter requests `max_age=0`, but the application previously checked only that authentication occurred within five minutes of callback processing. A newly issued, correctly nonce-bound token could therefore reuse authentication from before this login attempt. The reviewer reproduced a new one-hour local session from authentication four minutes before the attempt.

`identity.Assertion.ValidFor` now owns the attempt-relative rule: the login must still be active, the assertion must satisfy its existing structural/time bounds, and `AuthenticatedAt` must be at least `Login.CreatedAt - 30 seconds`. The fixed allowance accommodates upstream clock skew and whole-second claim precision; it does not prove user interaction within that allowance. Both the authentication service and the persistence completion boundary reuse this rule. The stored correlation must still match exactly, so callback timestamps cannot move the freshness boundary.

Stale evidence consumes the already claimed login attempt and returns no session. It cannot be retried against the provider. Domain tests cover the skew boundary, timestamp precision, delayed callbacks, expiry and future evidence. Service and real PostgreSQL tests cover denial without session/audit effects and replay rejection.

This makes the existing upstream profile enforce its documented freshness requirement. It does not implement the later downstream OIDC `max_age`/assurance policy. Source: pinned [OIDC Core errata 2](https://openid.net/specs/openid-connect-core-1_0-errata2.html), sections 3.1.2.1 and 3.1.3.7.

## Session termination after membership loss

Session termination previously required active membership. A deactivated member possessing the correct browser/session proof could not sign out; reactivation before expiry could make that session usable again despite the attempted termination.

Ending an existing local session now requires its configured tenant/issuer, exact session hash, matching authenticated browser hash and an unrevoked, unexpired session. Active membership is required for consent and protected-resource authority, but not for this authority-reducing operation. Termination and its audit/outbox remain atomic. Tests reject foreign browser/tenant references, allow termination while inactive and prove reactivation does not revive the ended session. Ending a session still does not revoke durable grants.

## Runtime update privileges

The review also identified unnecessary database privileges rather than an exposed service bypass: the runtime's broad table UPDATE grants permitted changing grant identity and credential provenance columns that current services never update. Provisioning now grants only the existing lifecycle updates: grant/family/issuance `revoked` and credential `consumed`. Migration and each physical runtime connection reject effective UPDATE privileges on any other column in these four tables, including inherited table/column grants. Future current-authority narrowing or provenance changes require an explicit service operation and privilege review. Tenant RLS, immutable snapshot/revision triggers and the domain's authority comparison remain in force; column grants do not replace them.

Apply the explicit owner `migrate` operation to reconcile runtime grants even when the migration ledger is current, and remove separately granted unsafe column/inherited privileges if rejected. No historical migration source or digest changes. The runtime remains trusted to create authority records through its service-owned operations; this change is not protection against a fully compromised runtime or the database owner. `TestP2RuntimeCanOnlyConsumeAndRevokeStoredAuthority` covers privilege denial and successful lifecycle updates; `TestP2RejectsInheritedAuthorityUpdates` covers rejection and repair of effective inherited privileges.

## Remaining gates

The review found no additional confirmed tenant/consent/protocol bypass in the implemented paths. This is limited evidence, not proof of their absence. Mandatory public RAR/PAR, durable profile registration, object-aware token lifecycle/enforcement, the BFF/resource exit flow, real-browser/provider interoperability and production conformance remain pending as recorded in the [P2 status](../p2-core-authorization.md). The fixes preserve the stated architecture and mandatory RAR/PAR direction; none requires a requirement exception or new dependency.
