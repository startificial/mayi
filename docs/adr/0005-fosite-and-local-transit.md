# ADR 0005: Fosite protocol adapters and local Transit proof

Status: Accepted · 2026-10-17

## Decision

Select Fosite v0.49.0 (`653c812bc40cbda049857b432ad3346f1a53d42d`) as the OAuth/OIDC protocol engine. The maintainer explicitly prefers Fosite over adapting ZITADEL's default token writer. Use explicit handler composition, never `ComposeAllEnabled`. Keep application authorization, immutable grant ceilings, transactions, replay and signing behind the existing service-owned ports.

`internal/adapters/inbound/http/oauth.TokenHandler` implements Fosite's native `TokenEndpointHandler` extension. It maps authenticated client/proof context and bounded form values to the existing token service, and maps its committed result to a Fosite response. It has no database handle or authorization implementation. Do not register Fosite's state-mutating default code/refresh handlers alongside it. Native handler fixtures separately establish the library's S256, client assertion, session and OIDC behavior.

Fosite's stock `jwt.DefaultSigner` does not accept a direct opaque signer whose public method correctly returns a public key. Its default JWT profile also does not establish Mayi's access-token purpose contract. Do not return private keys from `Public()` or fork the dependency to accommodate this. The service's existing signer port uses reviewed JOSE v4 with a remote opaque signer and explicit `at+jwt`. Fosite internally uses JOSE v3; vendor types do not cross into services. Retain both exact, reviewed versions until Fosite upgrades its own API.

Use PostgreSQL 17.11 with pgx v5.11.0 for the real transaction proof. Serialize policy, credential/client, root grant and family state through commit; use tenant predicates, composite keys and forced RLS under a separate runtime role. Revisions are immutable. Callback execution is once only, with no implicit retries of signing or entropy effects.

Use a local OpenBao v2.7.1 Transit service for the P0 remote signing proof. Production keys must stay in an authenticated remote KMS/HSM or Transit deployment; there is no local private-key fallback. The P0 harness uses an ephemeral, loopback-only dev service with a scoped signing token, non-exportable ECDSA P-256 keys, no plaintext backup, explicit key versions and public-only JWKS. It builds source without the UI and strips unrelated environment settings. It neither uses AWS profiles nor calls AWS services.

## Comparison and consequences

Fosite provides explicit composition, custom sessions, custom token handlers and signer strategies without patching upstream. Executed tests cover code/S256, removed flows, redirect/verifier rejection, refresh correlation, private-key JWT replay, OIDC nonce/issuer/client audience and an actual service-owned issuance callback against PostgreSQL and Transit.

ZITADEL OIDC v3.51.16 (`8ae30e3cf6d7b38d7fb460c8931dde6a06e5d7bf`) was source-reviewed and its S256 primitive was probed. Its default token path writes through storage before JWT signing; code lookup also precedes parts of client authentication. Using those defaults would require a broader override of creation/lookup ordering to preserve Mayi's service contract. Its generic PKCE validator accepts plain. No complete ZITADEL integration was built; it is rejected for this project and absent from Mayi's module graph. This is an integration decision, not a claim that the library cannot be used securely.

Fosite has a substantially larger dependency graph. The actual selected graph contains 368 modules, including upstream test-only graphics/generator dependencies. The maintainer approved Zlib and WTFPL notices for those modules. CI still rejects their package reachability. Exact versions, root/nested notices, source access and package-level advisory dispositions are retained. `ory/x` and several support modules have explicit reviewed upgrades/security floors; upgrades require the same compatibility and license checks.

Neither engine provides Mayi's full policy, online revocation, DPoP, gateway trust profile or tenant isolation automatically. These remain application responsibilities. The selected extension demonstrably preserves the service's authorize-before-load and commit-before-response rules; it is not a production listener or complete OAuth server.

## Limits and follow-up

OpenBao API non-exportability is demonstrated, including root export refusal and rejected exportable-key configuration. A dev process is not an HSM: privileged operators/debuggers can inspect its memory. Production authentication, TLS, durable seal/storage, HA, hardware protection, key administration and release packaging are P1/P6 work. Rotation tests prove two remote key versions and overlapping public verification; publishing and retiring a multi-version JWKS remains P1.

The P0 exchange hook returns an authorization plan, never a credential. One same-name-scope recipient hop is demonstrated; authenticated gateway receipts, live token validation, atomic exchange lineage and general scope maps remain P4 gates under ADR 0004. No exchange topology is enabled by this decision. BYO database/provider support remains deferred.

Validation and exact limits are recorded in [the P0 report](../p0/protocol-spike.md). No conformance certification or production readiness is claimed.
