# ADR 0003: Immutable ceilings and atomic issuance

Status: Accepted for the P0 baseline · 2026-10-17

A durable authorization root has immutable, numbered permission revisions. A code or refresh family names the exact revision approved by its authorization transaction. Consent expansion creates a new revision and never enlarges old credentials. At redemption, intersect the revision, predecessor credential ceiling and current permissions/policy. Rotating a down-scoped refresh token preserves that smaller ceiling. Revoking the root disables all revisions and descendants.

Every access-token issuance retains tenant, issuer, principal kind, subject, client, one resource, root and revision. User and machine subjects use separate namespaces; machine subjects equal their client ID. Lifetimes are bounded by grant expiry, configured resource/client policy and, for refresh, the family's absolute deadline. Code expiry limits redemption, not the resulting access token's lifetime. Delegated tokens also inherit parent deadlines and revocation dependencies.

Services own the transaction through their consumer-owned unit-of-work port. The storage adapter must serialize code/family consumption and grant/policy state, enforce uniqueness, and atomically record consumption, successors, lineage and issuance audit. Signing happens before commit and the credential response is released only after durable commit. Any signing, storage, audit or commit failure returns no credentials. No compensating best-effort deletion.

Authenticated replay has a distinct outcome: commit code-lineage revocation or refresh-family/root revocation and audit, then return an invalid-credential response outside the transaction callback. Returning an error from the callback would roll back the required security action. Validate client, resource, sender binding and PKCE before letting a replay revoke anything. Retain narrow replay metadata after credential expiry for the required detection window.

`internal/services/tokens/ports.go` documents locking, single-callback execution and rollback obligations. A production adapter must prove those obligations under multiple connections/processes. The P0 memory double is test-only and cannot be a deployment fallback.

The initial P0 redemption prototype does not mint refresh tokens during code redemption; it tests code issuance and rotation of an already authorized refresh credential separately. P2 must add refresh issuance under the same transaction, offline-access policy, idle/absolute deadlines and lineage. It must also implement protocol error mapping, input hashing, full DPoP validation and real JOSE/KMS signing.

Evidence: grant immutability tests, token deadline tests and `tests/contract/issuance_test.go` cover expansion, current-permission loss, successor attenuation, races, replay, policy changes and failure injection. These are contract evidence, not durable database or protocol-conformance evidence.
