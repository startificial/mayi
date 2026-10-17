# Mayi engineering rules

These rules apply throughout this repository. Read [the requirements](README.md), [repository structure](docs/repository-structure.md), [implementation plan](docs/implementation-plan.md), and [dependency policy](docs/dependency-policy.md) before implementation. The structure document is the canonical package layout. Do not create a competing layout or relax these rules in a nested instruction file.

## Architecture

Use ports and adapters with dependencies pointing inward:

```text
entrypoints / composition -> inbound adapters -> services -> domain
entrypoints / composition -> outbound adapters -> service-owned ports
```

- **Keep route handlers thin.** They decode and validate wire input, obtain trusted identity context, invoke a service, and encode its result. They must not implement grants, policy, token lifecycle, transactions, queries, or business decisions.
- **Place reusable business logic in `internal/services/`.** Organize services by use case or bounded capability. Domain entities and pure invariants belong in `internal/domain/`; services orchestrate those rules and external effects through ports.
- **Reuse existing domain services before creating a parallel implementation.** Search existing services, invariants, and ports first. HTTP, CLI, workers, protocol callbacks, and SDK entrypoints must use the same applicable business rules.
- Services must not import concrete adapters, HTTP frameworks, database drivers, SQL APIs, cloud SDKs, or protocol-library request/session types. Domain packages must not perform network, database, filesystem, environment, process, or clock I/O.
- Declare service interfaces in the consuming service package's `ports.go` or `ports_<variant>.go`. Use domain/application values, not driver rows or vendor types. Do not create a universal repository, global service locator, or central interface dumping ground.
- Inbound adapters depend on service APIs. Outbound adapter roots implement service-owned interfaces and declare static conformance assertions. Adapter roots must not export competing port interfaces; infrastructure helpers such as generated SQL interfaces remain inside their adapter family.
- Wire service and concrete adapter constructors in `internal/app/`, using `New` or `NewService`. The bounded `pkg/resource` SDK and construction within an adapter's own family are the explicit exceptions. Cross-service calls use injected narrow contracts; avoid cycles and chains of pass-through wrappers.
- No production `init()` or package-level runtime state. Inject dependencies through constructors. The only package-variable exceptions are literal sentinel errors, static conformance assertions, and unexported read-only embedded assets in the composition or web layer.
- Keep clock, randomness, process output, reflection and I/O out of pure domain/service/presentation code. Supply time and other effects through explicit values or ports. Domain/service structs must not carry HTTP, serialization, ORM or validation-framework tags.
- Protocol-library storage hooks are adapters into narrowly scoped services, not a second authorization implementation. Never pass a general database handle into a protocol or HTTP handler.
- Keep public SDK exports small and stable. Public request/result types must not expose internal packages or database models. Reuse the shared resource-validation service through the documented SDK boundary.

## Validation and authorization

- **Validate external input at system boundaries.** HTTP bodies, headers, URL parameters, cookies, CLI arguments, jobs, configuration, assertions, metadata, upstream responses and event payloads are untrusted. Apply size/time limits, strict parsing and explicit allowed values.
- Boundary validation does not replace domain invariants. Services enforce semantic checks for every caller, including workers and direct in-process calls.
- **Perform authorization before loading or mutating protected resources.** Authenticate first, resolve trusted tenant/issuer context, validate the requested operation, and authorize the actor for that tenant/action/resource reference before reading the protected object.
- If authorization needs stored ownership or ACL data, use a dedicated, tenant-scoped authorization projection containing only the required decision metadata. Do not fetch the full object and authorize afterward. Identity/credential lookup for authentication is similarly narrow and purpose-specific.
- Apply final object policy before returning protected content or mutating it. Recheck policy versions and relevant state inside the mutation transaction or enforce equivalent atomic predicates to prevent authorization races.
- Services own authorization; route middleware is supplementary. Internal callers, background jobs and protocol hooks cannot bypass checks by avoiding HTTP.
- Repository methods require trusted tenant scope and object references. Use tenant predicates in SQL and composite constraints; row-level security is additional protection. Never infer authority from a request's tenant ID, an email domain, or possession of an object ID.
- Denied requests must not load protected payloads, mutate state, emit credentials or reveal object existence. Use authorization-order tests with ports that fail if called prematurely.

## Interfaces and presentation

- **Do not call the database directly from reusable interface components.** Templates, view models, UI components, request DTOs, serializers and middleware must not import persistence code or execute queries.
- Components render explicit view models. Handlers invoke services to obtain them; components must not resolve services or perform hidden I/O during rendering.
- Keep wire DTOs, domain entities, persistence records and UI view models distinct where their contracts differ. Translate at the adapter boundary; do not expose ORM/SQL or vendor models as public API contracts.
- Map typed service errors to protocol-specific responses in inbound adapters. Avoid string comparisons for error classification and never disclose secrets through errors.

## OAuth and consistency invariants

- Every access token binds one issuer, tenant, principal and resource. Check token purpose and exact audience before resource access; ID tokens are never API access tokens.
- Consent approves a durable grant revision. Codes and refresh families reference the exact approved transaction and permission ceiling; never query the latest grant to decide what an old credential may do.
- Refresh and exchange can only narrow authority. Preserve actor history, ancestry, binding and lifetime limits; reject unsupported exchange topologies.
- A service defines transaction boundaries through a unit-of-work port. The persistence adapter implements atomic consume/issue/audit operations. No transaction logic in handlers and no SQL in services.
- Recheck relevant grant/policy/credential versions at commit. Send tokens only after issuance state and audit commit. Do not hide partial failure with compensating best-effort deletes.
- Immediate revocation requires an authoritative status decision. Stale positive caches, local JWT checks and asynchronous events alone do not meet that guarantee. Fail closed when required authority/replay state is unavailable.
- All untrusted HTTP fetching uses the constrained egress adapter. Never follow token-controlled key URLs or bypass SSRF policy in a convenience client.
- Production private signing keys remain in KMS/HSM. Use reviewed cryptographic libraries; do not create cryptographic algorithms. Never log raw tokens, codes, assertions, cookies, secrets or private keys.

## Repository and dependency discipline

- Follow [the canonical layout](docs/repository-structure.md). Create directories when they contain real code; do not generate empty packages, speculative abstractions or duplicate implementations.
- Use one root Go module. New modules, workspaces, dependency ecosystems, vendored trees, downloaded executables and container dependencies require corresponding inventory and CI coverage before use.
- Allowed license identifiers are **MIT, Apache-2.0, 0BSD, BSD-2-Clause, BSD-3-Clause, PostgreSQL, ISC and MPL-2.0**. No blanket “permissive” exception. Unknown, missing or disallowed licenses fail admission.
- Apply the policy to direct and transitive dependencies and repository-selected development/build/test tools. Review exact versions, bundled code and notices; pin actions by immutable commit and tools/modules by exact version.
- Do not add a dependency merely for convenience. Check existing code and the standard library, then record why an added component is needed and its license evidence in `tools/dependencies.json`.
- Never bypass a license failure using `--ignore`, unreviewed exceptions, an unchecked download, a manifest omission or a misleading license label. Only a direct maintainer decision may change the allowlist.
- MPL-2.0 modules additionally require exact source-access inventory fields and distribution notices. Preserve covered-source rights and make modified covered files available when distributed; an unmodified upstream link does not cover local modifications. Test release packaging before shipping binaries.
- Retain required copyright, license and NOTICE material in distributed artifacts. A parent's acceptable license does not automatically cover its dependencies or bundled files.

## Tests and CI

- Run `go run ./tools/checks`, `go test -race ./...`, `go vet ./...` and formatting checks for applicable changes. Keep checks reproducible; do not weaken fixtures to make a failing change pass.
- Unit-test domain invariants and service decisions through fakes. Integration-test real persistence/transaction behavior. Contract-test adapter implementations. Use end-to-end and conformance tests for protocol interoperability.
- Every authorization change needs denial, foreign-tenant and call-order tests. Credential changes need replay/concurrency and revocation tests. Do not rely only on successful flows.
- The [architecture CI rules](docs/architecture-enforcement.md) check direct boundaries, the SDK's transitive package graph, cycles, port ownership, adapter assertions, constructor references, ambient effects, global state and public SDK type exposure. Generated/build-tagged source is included. No suppression directives are supported.
- Behavioral authorization ordering, meaningful validation and thin handlers are established by tests and review; passing static checks does not prove those properties. Use `go run ./tools/checks -only architecture` for the architecture gate alone.
- Update the requirement matrix with actual evidence. Keep planned, implemented and verified distinct. Preserve applicable spec revisions and conformance artifacts.
- CI, architecture, license-policy and inventory changes are security-sensitive and require careful review. Do not claim branch protection is enabled merely because a workflow exists.

## Change workflow

1. Identify requirement IDs, existing services and the owning layer.
2. Define or reuse the service operation and its authorization/transaction boundaries.
3. Implement domain rules, then adapters and thin entrypoints.
4. Add focused positive and adversarial tests; run the required checks.
5. Update relevant docs, dependency evidence and requirement status.
6. Report behavior changed, verification performed, and remaining limitations.

Record material changes to issuer identity, grant semantics, trust, persistence guarantees, package boundaries or public contracts in `docs/adr/`. Do not silently rewrite these decisions in implementation code.
