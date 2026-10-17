# Canonical repository structure

Mayi uses a modular monolith with ports and adapters. This is the target layout; the initial P0 domain/service contract, crypto adapter and composition packages now exist alongside documentation and CI tooling. No command/HTTP server or production storage/signer exists yet. Add feature directories when implementing their contents. Keep a single root Go module, `github.com/startificial/mayi`.

```text
.
├── AGENTS.md                       Engineering rules for every change
├── README.md                       Product requirements and document entrypoint
├── go.mod                          Single module and toolchain baseline
├── go.sum                          Generated when external Go modules are admitted
├── .github/workflows/ci.yml         Architecture, license, formatting and Go checks
├── cmd/
│   └── mayi/main.go                 Process startup only
├── internal/
│   ├── app/                        Composition root and process lifecycle
│   │   ├── config.go               Validate startup configuration
│   │   ├── server.go               Assemble HTTP application
│   │   └── worker.go               Assemble durable workers
│   ├── domain/                     Pure entities, values and invariants
│   │   ├── identity/               Subject, tenant, membership, assurance
│   │   ├── clients/                Client identity and registration rules
│   │   ├── resources/              Resource identifiers and permission ceilings
│   │   ├── grants/                 Roots, immutable revisions and attenuation
│   │   ├── tokens/                 Token purpose, lineage, expiry and binding
│   │   ├── policy/                 Pure policy evaluation
│   │   └── audit/                  Security-event values
│   ├── services/                   Reusable business use cases
│   │   ├── authorization/          Begin/approve/deny authorization
│   │   ├── authentication/         Login, identity linking, sessions and step-up
│   │   ├── clients/                Registration, metadata resolution and credentials
│   │   ├── grants/                 Grant queries, incremental approval and revoke
│   │   ├── tokens/                 Issue, refresh, introspect and revoke
│   │   ├── delegation/             Exchange and actor/permission attenuation
│   │   ├── federation/             Assertion and enterprise authorization
│   │   ├── resource/               Shared token/status/permission enforcement
│   │   ├── administration/         Tenant-scoped management operations
│   │   └── delivery/               Durable logout, audit and security-event delivery
│   └── adapters/
│       ├── inbound/
│       │   ├── http/               Thin endpoints, DTOs and error mapping
│       │   │   ├── oauth/          OAuth protocol-library integration
│       │   │   ├── oidc/           Discovery, UserInfo and logout
│       │   │   ├── admin/          Management routes
│       │   │   ├── selfservice/    Connected apps and session routes
│       │   │   └── middleware/    Identity, limits, CSRF and request correlation
│       │   ├── web/                Templates, assets and pure view models
│       │   ├── jobs/               Validate envelopes, invoke delivery services
│       │   └── cli/                Parse commands, invoke services
│       └── outbound/
│           ├── postgres/           Persistence ports, SQL and transaction adapter
│           │   ├── migrations/    Append-only schema migrations
│           │   ├── queries/       SQL source of truth
│           │   └── generated/     Generated DB bindings; never edit manually
│           ├── signing/            KMS/HSM implementations
│           ├── crypto/             Reviewed JOSE/proof primitives behind ports
│           ├── egress/             Restricted HTTP/DNS and destination policies
│           ├── identity/           Upstream OIDC; later SAML/workload adapters
│           ├── status/             Authenticated remote status transport for SDK
│           ├── events/             Audit/SIEM/security-event transports
│           └── telemetry/          Logging, metrics and tracing integrations
├── pkg/
│   └── resource/                   Public Go resource SDK facade and middleware
├── examples/                       BFF, native client, workload, gateway and MCP
├── tests/
│   ├── integration/                Real adapter and transaction behavior
│   ├── contract/                   Port contracts and interoperable fixtures
│   ├── e2e/                        Browser and multi-service flows
│   ├── conformance/                Pinned external protocol tests
│   ├── adversarial/                Security and cross-tenant cases
│   └── testdata/                   Synthetic fixtures, no production credentials
├── tools/
│   ├── checks/                     Standard-library-only policy checker and tests
│   ├── dependencies.json           Exact-version license evidence
│   └── license-policy.json         Machine-readable SPDX allowlist
├── specs/                          Pinned specifications and capability profiles
├── deploy/                         Reviewed deployment/configuration artifacts
└── docs/
    ├── implementation-plan.md
    ├── requirement-matrix.md
    ├── repository-structure.md
    ├── dependency-policy.md
    ├── architecture-enforcement.md
    └── adr/                        Material architectural decisions
```

## Dependency direction

| Package | May import | Must not import |
| --- | --- | --- |
| `internal/domain/**` | Other cohesive domain packages and pure standard-library facilities | Services, adapters, app, SDK, vendor libraries and I/O facilities |
| `internal/services/**` | Domain and explicit acyclic service contracts; non-I/O standard-library facilities | Concrete adapters, app, SDK, SQL/drivers, HTTP frameworks or cloud/protocol SDKs |
| `internal/adapters/inbound/**` | Service APIs, domain values and sibling inbound helpers | Outbound adapters, composition root or SQL/driver packages |
| `internal/adapters/inbound/web/**` | Pure standard-library rendering facilities and presentation helpers | Services, persistence and hidden network/process/filesystem I/O |
| `internal/adapters/outbound/**` | Service-owned ports, domain types and approved libraries | Inbound adapters, app or public SDK |
| `internal/app/**` | All internal layers | Public API consumers or examples |
| `cmd/mayi/**` | Composition root and startup standard-library facilities | Direct construction of business operations, handlers or database adapters |
| `pkg/resource/**` | Public SDK helpers, shared `services/resource`, domain values and the dedicated outbound status/crypto adapters | Server app, SQL/persistence, unrelated business services or admin implementation |

Adapters may use other adapters in their own direction for concrete infrastructure composition, such as an IdP client using restricted egress. Prefer wiring interfaces at the composition root when it avoids unnecessary coupling. Do not use a shared adapter as a path around an otherwise prohibited dependency.

The SDK is the one explicitly bounded secondary composition boundary: it can assemble its resource-validation service and status/crypto transports. It must not pull in the server's database or administrative runtime. Export SDK-owned types and map internal values before returning results.

## Service shape

A service package normally contains `service.go`, `ports.go`, `commands.go`, `results.go`, and focused `_test.go` files. Service interface placement in `ports.go` or `ports_<variant>.go` is enforced; the other filenames are conventions, not a demand to split tiny packages. Prefer operations such as `ApproveAuthorization`, `RefreshToken` and `RevokeGrant` over a generic CRUD layer.

Ports belong to their consumer. For example, a token service defines a narrow `GrantReader`, `CredentialUnitOfWork`, `Signer` and `ReplayStore`. The database adapter implements those contracts without leaking `sql.Tx`, `pgx.Tx` or generated rows into service signatures. Do not define one interface per concrete type without an actual boundary.

Pure grant/scoping rules belong in domain code and are called by services. Keep reusable orchestration in `services/`; do not place it in a handler, SDK middleware, SQL query helper or package called `utils`, `common`, `helpers` or `manager`.

## Protected resource access

The intended flow is:

```text
parse and bound external input
  -> authenticate and establish trusted tenant context
  -> service validates the operation
  -> authorize tenant/action/resource reference
     [minimal authorization projection if the decision requires it]
  -> load protected data through a tenant-scoped port
  -> enforce final object/version policy before disclosure or mutation
  -> atomic mutation and audit through unit of work
  -> service result -> response DTO or pure view model
```

Neither the initial policy decision nor a tenant ID supplied by the caller is enough to authorize arbitrary object access. Protect authorization projections themselves against cross-tenant queries and enumeration. Transactional checks must prevent a permission change between initial authorization and commit from granting unauthorized writes.

## Testing and enforcement

Keep domain/service tests next to their code; place database and end-to-end suites under `tests/`. Use `testdata` for intentionally invalid source/credential fixtures. Production code may not import test helpers. Generated production code follows the same dependency rules.

`go run ./tools/checks` enforces the [architecture CI rules](architecture-enforcement.md) and dependency license policy. The architecture gate analyzes source, public API type references, and the local production import graph, including generated/build-tagged source. It requires service-owned ports and adapter assertions, prevents hidden global wiring and ambient effects in pure layers, and checks the SDK's transitive isolation. Unit tests deliberately introduce violations and exercise legitimate constructor, sentinel-error, embedded-asset and generated-helper patterns. Authorization semantics, transport limits, transaction guarantees and service reuse still require behavior tests and review.

Do not create empty directories to mirror the diagram. The first production slice should introduce only its command, composition root, domain/service packages, and required adapters. A new layer or public package requires updating this document and its CI checks together.
