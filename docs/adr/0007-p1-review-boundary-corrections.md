# ADR 0007: P1 identity, redirect and delivery boundary corrections

Status: Accepted · 2026-10-18

The P1 review exposed seven defects in runtime-role validation, migration-history protection, signer readiness, audit correlation, output cancellation, public admission and client redirects. These corrections retain the canonical modular monolith, service-owned ports, immutable migration sources and existing dependency inventory. They support ADM-1/2/5, CLI-7, CORE-3 groundwork, LIFE-10 and OPS-1/4/6; they do not complete those production requirements.

## Database identity and effective privileges

Runtime credentials must authenticate as the configured restricted runtime login. Mayi rejects a different DSN user, startup `role`/`session_authorization` parameters and arbitrary `options`. Each physical connection additionally requires matching configured login, PostgreSQL `session_user` and `current_user`, as well as the existing ownership, role-membership, schema-history and forced-RLS checks. A privileged login that switches into a restricted role retains the ability to recover its original privileges and is not an acceptable runtime connection.

Migration and runtime validation both check effective table and column mutation privileges on the migration ledger. Direct revocation of a table grant does not remove inherited column grants. Migrations reject an unsafe result transactionally; the database administrator must remove unsafe grants or memberships. Mayi does not rewrite customer-owned group roles to repair them. Migration source strings/checksums remain unchanged.

This is compatible with bringing an existing PostgreSQL database, subject to a dedicated schema and restricted login. It is incompatible with a promise to accept arbitrary owner credentials, forced-owner poolers or provider connection options without compatibility review. Such a promise would contradict owner/runtime separation; it is not the current plan. Supabase, Neon and poolers remain unverified provider profiles.

## Distinct redirect semantics

A registered HTTPS web redirect is a client value, not a resource audience. Its own domain invariant accepts fixed query components and preserves the original bytes. The HTTP boundary invokes the same invariant; services enforce it for every caller. Fragments, credentials, malformed escapes, ambiguous authorities and unsupported native profiles remain rejected. This registration change does not implement P2 authorization-response construction or redemption matching, and does not change resource URI policy.

The architecture checker permits exactly `net/url` as a pure standard-library parser. It still rejects sockets, HTTP clients and other effectful networking in core layers. A package-name prefix ban that also forbids pure parsing is stricter than the architectural goal and would encourage a redundant URL parser. Positive and negative fixtures keep this allowance bounded.

## Signing availability

Startup and readiness refresh active-key metadata and reject an active version below Transit's `min_encryption_version`. Disabled old signing versions may still load and remain published for verification; raising the signing minimum must not remove their public keys. Missing or malformed minimum-version metadata fails closed.

Readiness checks metadata-read availability, key identity, non-exportability and the active version's configured eligibility. It does not sign a probe, mint a token or guarantee sign-path permission. A later policy change, outage or remote signing failure remains possible; issuance must fail without returning a credential. Requiring proof of successful signing while forbidding all signing probes would be contradictory. Actual signing is tested separately with the real Transit adapter, and operators must provision both metadata-read and sign permissions.

## Audit output and process shutdown

The persisted security audit record and exported integration envelope are separate contracts. Export schema version `1` includes `schema_version`, `event_id`, `tenant_id`, `issuer`, `type`, `actor`, `object`, `time`, and optional `grant_id`/`issuance_id`. Issuance IDs correlate to token `jti`; credentials and credential hashes remain excluded. Existing actor/object values retain their meaning rather than being repurposed as token identifiers. Consumers must tolerate additive fields and deduplicate by issuer/tenant/event ID. This foundation envelope is not an OpenID Shared Signals event and does not yet carry all ADM-5 context required by later live flows.

The JSON sink bounds the caller's entire wait to five seconds or earlier cancellation, including time waiting behind an earlier write. At most one underlying write per sink can be outstanding. Canceled, timed-out or failed delivery leaves the lease unacknowledged. The worker exits on a delivery failure; supervision can restart it after the output problem is repaired.

An arbitrary Go `io.Writer` has no cancellation operation. The underlying write may finish after cancellation or remain blocked until the writer returns or the process exits. A partial line or a late write can be followed by a retry. Guaranteeing that such a writer both stops immediately and is never closed by Mayi is impossible under that interface. Bounded worker shutdown is provided; durable remote acknowledgement, stronger framing/transport cancellation and exactly-once delivery are not claimed. A future remote transport must define its own timeout and acknowledgement semantics.

## Liveness and safe diagnostics

Exact `GET`/`HEAD /healthz` bypass public admission slots while retaining transport telemetry. Other routes retain admission and timeout bounds. Public traffic saturation therefore does not by itself fail process liveness; readiness can still fail or be rejected under overload. Operational routes must remain restricted at the deployment boundary. This is separate from proving availability under CPU, memory, logging or network exhaustion.

CLI failures expose fixed stage/reason labels and safe sentinel classifications. Raw upstream errors, connection strings, secrets and configuration paths are not retained in the returned diagnostic error. Operators can distinguish database configuration, connectivity, signer and migration stages without disclosing credentials.

Evidence: [regression integration tests](../../tests/integration/foundation_regression_test.go), [issuance and management tests](../../tests/integration/foundation_test.go), [sink tests](../../internal/adapters/outbound/events/json_test.go), [redirect tests](../../internal/domain/clients/redirect_test.go), [signer tests](../../internal/adapters/outbound/signing/ring_test.go), [CLI tests](../../internal/app/command_error_test.go), and [architecture fixtures](../../tools/checks/architecture_contracts_test.go).
