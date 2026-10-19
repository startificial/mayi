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

## Domain-driven design

- **Use ubiquitous language.** Use the same precise business terms in requirements, ADRs, Go APIs, persistence mappings, audit events and tests. Start with the vocabulary below and the pinned capability profiles. Qualify overloaded terms in new APIs; do not use `scope` interchangeably for permission names and tenant/issuer context, or `grant` interchangeably for a durable authorization and a protocol grant type. Translate protocol/vendor terminology at adapter boundaries. Record a material change in meaning in an ADR rather than silently redefining an existing term.
- **Define ownership by bounded context.** Within the canonical layers, group models and use cases by cohesive business capability and invariants, not by a database table, endpoint or vendor. Identify the owning context and its responsibilities before adding a concept. Package names alone do not establish a bounded context. Document new or changed context boundaries and their relationships in an ADR; retain the modular monolith and canonical layout unless an explicit architectural decision changes them.
- Each business rule has one authoritative owner. Reuse a domain rule only when its meaning and policy are the same in both contexts; similar field shapes do not establish shared semantics. For example, resource identifiers and client redirect destinations need their respective rules even though both are URIs. Do not turn `policy`, `administration` or a shared package into a second owner of another context's lifecycle rules.
- Cross-context collaboration uses narrow application contracts, explicit identifiers or intentional event contracts. Do not reach into another context's mutable aggregate internals or persistence implementation. Translate upstream identities, assertions and protocol-library models into local concepts through adapters; external schemas and a valid signature do not define local identity, trust or authority.
- **Keep domain behavior in the domain.** Entities have stable identity; value objects express meaningful values and enforce their own invariants. Put pure business decisions, permission attenuation and valid state transitions in domain constructors, methods or cohesive domain functions. Application services in `internal/services/` authorize the caller and orchestrate these rules, transactions and effects through ports. Do not duplicate domain decisions in handlers, SQL helpers or separate services. Database constraints and atomic predicates reinforce these rules.
- Define aggregate roots and boundaries from the invariants that must remain consistent together. A table or foreign-key graph is not automatically an aggregate; avoid both one aggregate per row and one tenant-wide object graph. Mutations go through the owning aggregate's behavior or explicit domain transition functions. Protect invariant-bearing state and mutable collections from unchecked caller mutation, and validate rehydrated state before business use.
- Make consistency boundaries explicit in the service-owned unit-of-work contract, including expected versions, lock order and conflict behavior where relevant. Cross-aggregate operations must state their required atomicity and use the existing issuance/revocation guarantees; do not split consume/issue/audit across eventual events to satisfy a generic DDD pattern. Never call external systems from a pure aggregate.
- Persistence ports express the owning use case's aggregate operations or narrow, tenant-scoped projections, not generic table CRUD or an ORM model. Read-only queries may use projections without constructing an aggregate, while preserving service authorization and final object policy. Query projections must not become an alternate mutation path.
- When domain events are needed, name them as business facts in the past tense and carry the identifiers and versions necessary to interpret them. Distinguish domain facts, security audit records and external integration envelopes; map between them explicitly. External delivery follows a successful state/audit commit through the outbox, with versioned contracts and idempotent consumers. Events do not replace authoritative revocation or required atomic checks.
- Use domain services only for a cohesive pure business operation that does not naturally belong to an entity or value object. Do not create a service, interface, repository, event bus, separate deployable, CQRS framework or event-sourced model merely to use a DDD pattern. Prefer the smallest explicit model that enforces the current requirements.
- Test business examples in the ubiquitous language: allowed and forbidden transitions, invariant preservation, authority narrowing, tenant isolation and concurrent version conflicts. Static package checks do not establish bounded-context cohesion or correct domain behavior; review must verify both.

### Shared vocabulary

These definitions describe Mayi's model; they do not imply that every capability is implemented. Keep them aligned with requirements, capability profiles and accepted ADRs.

| Term | Meaning and distinction |
| --- | --- |
| Tenant / issuer | A tenant is an isolation and policy boundary. Its issuer is the immutable configured authority identifier. Neither is derived from an email domain or request host. |
| Principal / subject / actor | A principal is a human or machine identity. The subject is the principal on whose behalf authority is exercised; actors record intermediaries acting in that chain. The presenting client is identified separately. These roles can coincide but are not interchangeable. |
| Registered resource / protected object | A registered resource identifies the intended API audience and its permission catalog. An object inside that API has resource-owned access policy; audience membership alone does not authorize object access. |
| Permission scope / tenant-issuer context | A permission scope is a resource-local permission name. Tenant/issuer context identifies the trusted isolation boundary for an operation. Equal permission names across resources do not imply equal authority. |
| Durable grant | Mayi's revocable authority record binding an issuer, tenant, principal, client and resource. It is distinct from an OAuth grant type or the credential presented to redeem that grant type. |
| Grant revision | An immutable snapshot of approved authority. Credentials reference the exact approved revision; later approval does not enlarge earlier credentials. Current policy and revocation can further restrict that authority. |
| Authorization transaction | The bounded authorization workflow and validated request/approval correlation. It is distinct from a database transaction, which provides atomic persistence. |
| Credential / refresh family | A credential is purpose-specific evidence presented to a protocol operation. A refresh family is the related rotation lineage with shared binding, revocation and absolute-lifetime constraints; neither is the durable grant itself. |
| Session | Authentication continuity and assurance state. Ending a session and revoking application grants are separate operations unless an explicit use case performs both. |

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
- Follow [the error contract and recovery strategy](docs/error-handling.md). Keep local codes/statuses/messages aligned with the catalog and contract tests; preserve endpoint-specific OAuth formats and challenges. Never expose raw error text or infer safe retries for one-use credentials from an HTTP status. New enabled endpoints need error, denial/non-enumeration and recovery evidence.

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
- Allowed license identifiers are **MIT, Apache-2.0, 0BSD, BSD-2-Clause, BSD-3-Clause, PostgreSQL, ISC, MPL-2.0, CC0-1.0, Unicode-DFS-2016, TCL, Spencer-94, Unlicense, Zlib, WTFPL and FSFUL**. No blanket “permissive” exception. Unknown, missing or disallowed licenses fail admission.
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

1. Identify requirement IDs, ubiquitous terms, existing domain rules/services, the owning bounded context and the owning layer.
2. Define or reuse the domain operation and service use case, including aggregate invariants and authorization/transaction boundaries. Record material context or vocabulary changes in an ADR.
3. Implement domain rules, then adapters and thin entrypoints.
4. Add focused positive and adversarial tests; run the required checks.
5. Update relevant docs, dependency evidence and requirement status.
6. Report behavior changed, verification performed, and remaining limitations.

Record material changes to issuer identity, grant semantics, trust, persistence guarantees, package boundaries or public contracts in `docs/adr/`. Do not silently rewrite these decisions in implementation code.
