# P1: Tenant and persistence foundation

The foundation provides a runnable Go service with explicit external PostgreSQL configuration, migrations, tenant provisioning, tenant-scoped management, public keys, preview issuer discovery and an audit/outbox worker. Login, consent, token issuance endpoints and resource enforcement arrive in P2. This is a development foundation, not a usable or certified production authorization server.

## Run the isolated local stack

Use the pinned Go 1.27.0 toolchain and existing platform build prerequisites documented in the [P0 report](p0/protocol-spike.md). No additional dependency, container, package-manager install or license exception is needed.

```sh
go mod download all
go run ./tools/p0 -development
```

This builds the reviewed PostgreSQL/OpenBao source pins, creates a private disposable cluster and loopback Transit, and prints paths to a private environment file and JSON configuration. It creates separate database owner/runtime roles, two separate signing keys, scoped Transit credentials and independent administrator tokens. Keep that terminal open. In another terminal, run the printed commands to source the environment, migrate, provision `demo` and `demo2`, and serve. Everything is removed when the stack exits. Development HTTP and trust-authenticated private Unix sockets must not be used as a production deployment.

The server listens on `127.0.0.1:8080`. Local inspection endpoints are `/healthz`, `/readyz` and `/metrics`. Public issuer URLs remain HTTPS configuration values, even when inspecting local development over loopback HTTP. The development issuer is `https://auth.localhost/t/demo`.

## Bring an existing PostgreSQL database

1. Make a copy of [the example configuration](../deploy/example.json) outside version control. Set a fixed canonical HTTPS public origin, a loopback listen address, the runtime role, connection budget, Transit address and explicit tenant/key configuration. Keep `allow_insecure_loopback` false for normal deployments.
2. Have the database administrator create a schema-owner login and a distinct runtime login with `NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS`. Give the owner permission to create the `mayi` schema in the selected database. Do not grant the runtime membership in an owner or privileged role. An existing `mayi` schema without the reviewed migration ledger is rejected rather than adopted or overwritten.
3. Create a separate non-exportable `ecdsa-p256` Transit key for each tenant, with plaintext backup disabled. Give each Mayi Transit credential only read access to its configured key metadata and update access to its signing path. No root token, key-export permission or local private-key fallback is required. Set the configured `MAYI_…_TRANSIT_TOKEN` environment variables through your secret manager.
4. Run `go run ./cmd/mayi admin-token` once for each operator credential. Store the returned bearer token as a secret; put only its `sha256` in `administrators[].token_sha256`. Assign explicit permissions, not a wildcard. Do not commit the token or connection strings.
5. Set `MAYI_MIGRATION_DATABASE_URL` to the schema-owner DSN. Use `sslmode=verify-full` and the required trust roots for TCP connections. Run the commands below. Provisioning requires access to the configured Transit public key; it never exports private material.

```sh
go run ./cmd/mayi migrate -config /path/to/mayi.json
go run ./cmd/mayi provision -config /path/to/mayi.json -tenant example
```

6. In the server's separate environment, set `MAYI_DATABASE_URL` to the runtime DSN and supply its scoped Transit credentials. Exclude the migration credential. Start the server and, optionally, the audit collector worker:

```sh
go run ./cmd/mayi serve -config /path/to/mayi.json
go run ./cmd/mayi worker -config /path/to/mayi.json
```

7. Terminate public HTTPS at a locally trusted reverse proxy. Expose only the intended public and management routes; restrict management to operator access and keep `/metrics`, `/healthz` and `/readyz` on the operational network. Configure the proxy with the public host explicitly, including both well-known routing and tenant paths. Mayi ignores `Host`, `Forwarded` and `X-Forwarded-*` for issuer construction. It does not yet use client IP headers for authorization or rate limits.

Mayi owns only its schema and versioned migration history. Its migrations do not create databases, install extensions or change application/authentication tables. P1 is verified on the reviewed PostgreSQL 17.11 service. Supabase, Neon, other versions and transaction/session poolers need separate compatibility tests. No claim is made that a provider exposes the required role and migration privileges. Point authoritative reads/writes at the primary consistency boundary, not a stale replica.

The schema owner can administer signing metadata and provisioning and therefore remains trusted. The runtime's grants are an initial foundation, not an independently certified least-privilege production role for every future service. Migrations are transactional and checksummed; concurrent migrators serialize. There are no automatic destructive down migrations, P0 schema adoption, mixed-version guarantees or validated restore procedure yet.

## Management contract

All management requests use `Authorization: Bearer <43-character operator token>` and `Content-Type: application/json` for bodies. Authentication is header-only. No cookies, query tokens, reflected origins or client-supplied actor/issuer/tenant fields are accepted. Each trusted credential is tied to one configured tenant. Service authorization runs before protected storage access and mutations hold the same tenant policy lock used by issuance.

| Route | Permission | Behavior |
| --- | --- | --- |
| `GET /admin/t/{tenant}/policy` | `policy:read` | Read the versioned policy |
| `PUT /admin/t/{tenant}/policy` | `policy:write` | Compare the supplied version, update, increment version and audit atomically |
| `POST /admin/t/{tenant}/resources` | `resources:write` | Create a resource and described scope catalog within tenant lifetime/binding limits |
| `GET /admin/t/{tenant}/resources/{id}` | `resources:read` | Read one tenant-owned resource |
| `POST /admin/t/{tenant}/clients` | `clients:write` | Create a public HTTPS web client with exact redirects and registered resource references |
| `GET /admin/t/{tenant}/clients/{id}` | `clients:read` | Read one tenant-owned client |
| `POST /admin/t/{tenant}/keys/{version}/publish` | `keys:write` | Publish a preconfigured and startup-verified Transit version |
| `POST /admin/t/{tenant}/keys/{version}/activate` | `keys:write` | Activate only after the publication lead time; retain prior public keys |

Create-only resource/client endpoints return `409` on duplicates. No misleading general-purpose update/delete contract is exposed. Public-client registration is a P2 input model, not permission to use a nonexistent OAuth flow. Confidential credentials, native redirect exceptions and authenticated upstream users are not implemented by these records.

Resource body example:

```json
{
  "id": "api",
  "uri": "https://api.example.com",
  "name": "Example API",
  "scopes": [{"name": "read", "description": "Read your objects"}],
  "access_token_seconds": 300,
  "require_binding": true
}
```

Client body example:

```json
{
  "id": "web",
  "name": "Example app",
  "redirect_uris": ["https://app.example.com/callback"],
  "resources": ["api"],
  "access_token_seconds": 300,
  "enabled": true
}
```

Default tenant policy is version 1, maximum access-token lifetime 600 seconds, maximum grant lifetime 86400 seconds and required binding. Policy `PUT` takes `version`, `max_access_token_seconds`, `max_grant_seconds` and `require_binding`. A stale version returns `409`. Lifetime/binding limits govern P1 registration and are persisted/versioned; P2 must also apply them to actual grant creation, issuance and resource decisions before enabling those capabilities.

## Discovery and signing rotation

For issuer `https://auth.example.com/t/example`, the foundation preview is at `https://auth.example.com/.well-known/oauth-authorization-server/t/example`, with keys at `https://auth.example.com/t/example/jwks`. Metadata always returns the configured exact issuer and no enabled grants, scopes or fictional token/authorization endpoint. Unknown tenants have no route. The OpenID configuration endpoint remains absent. These intentionally limited metadata documents do not satisfy complete RFC 8414/OpenID conformance. See [ADR 0006](adr/0006-external-postgres-and-foundation-operations.md).

To rotate, create the next version through the separately controlled Transit administration boundary. Add it to the tenant's configured `key_versions` and roll configuration to all replicas; keep the currently active version available. Publish through the tenant's key API, verify both old and new keys are externally visible in JWKS, wait at least 60 seconds, then activate through the API. An early or unpublished activation returns `409`/`404` and leaves the active key unchanged. JWKS responses use `no-store`; old public keys remain indefinitely in P1. Do not delete Transit versions or raise the minimum decryption/signing version automatically. Emergency retirement and maximum-token-lifetime removal require the later operational gate.

Startup and readiness fail when the schema/role/issuer/active key is wrong or required Transit access fails. Startup checks non-exportability and public-key consistency. Readiness verifies active-key metadata with Transit without minting a token. Request data never selects a Transit host, key or version.

## Events, telemetry and checks

Audit records are append-only to the application. Each new record atomically inserts an outbox row, including P0 issuance/replay events when run with the expanded schema. A failed audit/outbox insert rolls back the state change. Workers claim bounded batches with expiring leases and attempt fencing. A failed or crashed delivery becomes eligible again; duplicates after an external write and before acknowledgement are expected. Collectors deduplicate by issuer/tenant/event ID. The JSON stdout sink omits token/code/secret values and credential hashes; it is not a durable remote SIEM acknowledgement.

The server bounds headers, bodies, request duration, idle connections and concurrent handling, and supports graceful shutdown. Structured logs contain generated request IDs, status and duration, never request URLs, bodies, credentials or raw upstream/database errors. Denials are warning events and server failures are error events for a collector to alert on. `/metrics` exposes bounded process request/error counters. Distributed rate limiting, full endpoint metrics/traces, remote alert delivery, external SIEM adapters, retention, HA/restore and production release packaging remain later gates.

```sh
go run ./tools/checks
go test -race -count=1 ./...
go vet ./...
go run ./tools/p0
```

CI runs the real-service harness in addition to ordinary tests. P1 evidence is in `tests/integration/foundation_test.go`, management/delivery authorization-order tests, strict HTTP credential/body tests and configuration/transport tests. The integration suite covers two tenants, owner/runtime separation, immutable issuers, transactional audit/outbox failure, retry fencing, actual rotated Transit signatures, public-key isolation and checksum tampering. Passing this suite is foundation evidence, not the full README verification gate.
