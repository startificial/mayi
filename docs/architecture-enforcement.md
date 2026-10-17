# Ports and adapters enforcement in CI

The **Enforce ports and adapters** step in [CI](../.github/workflows/ci.yml) runs `go run ./tools/checks -only architecture`. It exits unsuccessfully on any violation. The same job checks dependency licenses, formatting, Go compilation/tests with race detection, and `go vet`. No new external checker dependency is required.

The checker implements the boundaries in [AGENTS.md](../AGENTS.md) and [the canonical layout](repository-structure.md). Tests include intentionally invalid source and permitted patterns. Rules cannot be suppressed through per-file comments or an exclusion list.

## Enforced rules

| Rule | Enforced behavior |
| --- | --- |
| Package placement | Go files must live in a documented layer. Production source symlinks are rejected because they can conceal unscanned code. |
| Dependency direction | Core code cannot import adapters, composition, SQL, networking or vendor libraries. Inbound code cannot import outbound implementations. Public SDK code cannot import persistence or administrative services. |
| Pure presentation | Web components cannot import services, domain business implementations, persistence or I/O packages. They render explicit view models. |
| Inbound dependencies | Third-party imports are limited to the candidate protocol-integration libraries. That architecture permission is not license admission; a selected version must separately pass the dependency gate. |
| Transitive SDK isolation | Every reachable local production package is checked against the SDK boundary, with the full offending import chain in the error. A permitted service/crypto/status helper cannot drag persistence or an unrelated service into the SDK. |
| Package cycles | The union of production imports must be acyclic, including edges in platform/build-tag variants. Missing or fixture-only imported production packages fail. |
| Consumer-owned ports | Service interfaces must be declared in `ports.go` or `ports_<variant>.go`. Outbound adapter roots cannot export their own competing interfaces. |
| Adapter conformance | Each outbound adapter family root must contain a static assertion against an interface actually declared in a service package. Go compilation checks that the concrete adapter implements it for the compiled target. |
| Composition | References to other packages' `New`/`NewService` service/adapter constructors are limited to `internal/app`, the bounded SDK, or an adapter's own family. Handlers and business services receive collaborators instead of constructing them. |
| Hidden runtime dependencies | Production `init()` and package-level runtime variables are rejected, subject to the narrow exceptions below. A blank variable cannot hide initializer execution. |
| Ambient effects | Pure layers cannot use I/O, process/runtime, reflection, or randomness packages; wall-clock/timer/global console references and built-in printing also fail. `time.Time` values and formatting strings remain allowed. |
| Domain/application contracts | Domain and service fields cannot carry `json`, `xml`, `yaml`, `db`, `gorm`, `bson`, `sql`, `form`, `query`, `header`, `validate` or `binding` tags. Map separate adapter DTOs instead. |
| Public SDK types | Exported SDK types, fields, function/method signatures and type parameters must not expose internal types, including through local type definitions or aliases across files/packages. Private implementation fields may retain internal state. |
| Import/directive bypasses | Production dot imports and `go:linkname` fail. Pure-layer side-effect imports fail except the special `embed` import for permitted UI assets. |

## Required implementation patterns

Declare outbound contracts in the consuming service:

```go
// internal/services/tokens/ports.go
package tokens

import "context"

type Signer interface {
    Sign(ctx context.Context, payload []byte) ([]byte, error)
}
```

The adapter root demonstrates that it implements that contract:

```go
// internal/adapters/outbound/signing/signer.go
// Alongside a concrete Signer type implementing tokens.Signer:
var _ tokens.Signer = (*Signer)(nil)
```

Assertions must be typed blank-variable declarations with either `(*LocalType)(nil)` or an empty `LocalType{}` value. They must not execute a constructor. Put the assertion in the adapter family root, not solely in a generated/helper subpackage. This is a minimum boundary check, not proof that every adapter operation has its own assertion or contract test.

Use `New` or `NewService` for service/adapter constructors. Composition supplies their collaborators. AST checks recognize these conventional constructor references; they do not infer whether an arbitrarily named function constructs an object. Do not rename a constructor to evade the rule. Same-package construction remains normal implementation work; reusable cross-package wiring belongs at the composition boundary.

Keep SQL-generated interfaces such as `DBTX` in `internal/adapters/outbound/postgres/generated`. Those infrastructure-only contracts may exist inside the adapter family; they must not become service ports or leak through a core dependency. Generated files still undergo import, global-state and other applicable checks.

## Narrow allowances

The global-state rule permits only:

- A single sentinel error initialized with `errors.New` and a literal string.
- A static typed conformance assertion using the forms above.
- An unexported `go:embed` string or `embed.FS` in `internal/app` or `internal/adapters/inbound/web`. Mutable embedded byte slices are rejected. Runtime template file loading belongs in composition; rendering receives prepared assets/templates.

Tests may use standard-library I/O and clocks to construct fixtures. Their local dependency direction still applies; database integration tests belong under `tests/`, rather than importing persistence into domain unit tests. Test files are excluded from the production dependency graph and production declaration rules.

`testdata/` directories contain fixtures and are not treated as production packages. An actual production import of a missing or fixture-only local package fails. Tooling/tests/examples have their own allowed layout; production code cannot depend on them.

## Analysis limits and review obligations

The AST scan is deliberately independent of active build tags. It analyzes all source variants and rejects cycles in their combined graph, even if a cycle would not compile under any single target. Avoid using platform conditionals to reverse layer direction. Production type definitions in alternative variants must follow the same boundaries.

The public API and constructor checks resolve syntax and local declarations, not arbitrary dataflow or reflection. They are conventions backed by negative tests, not a security sandbox. The normal Go compiler validates active-target types and interface assertions. Generated or platform-specific implementations need their own build/contract coverage when introduced.

CI cannot establish the following merely from imports, names or source layout:

- That a route is thin in behavior, or that equivalent business logic has not been duplicated.
- That every external value received sufficient semantic validation.
- That authorization happened before protected data access on every execution path.
- That authorization projections, tenant predicates, transaction races and revocation semantics are correct.

Keep these as service-level behavioral gates. Use denial tests whose protected-resource ports fail if called before successful authorization, foreign-tenant cases, meaningful input-validation cases, and transaction/concurrency tests. Do not replace them with checks for a function named `Authorize`, a magic annotation, or an arbitrary handler line limit.

The workflow is a CI failure gate. Repository branch protection must separately require **Architecture, licenses and Go checks** to prevent merges after failure. This implementation does not change GitHub branch protection or push the working tree.

## P0 service tooling and protocol boundary

`tools/p0/**` is a dedicated standard-library-only tooling boundary. It can perform I/O and start reviewed local service processes, but it cannot import application layers or external Go modules. CI fixtures reject either kind of import. This does not relax the production composition boundary in `internal/app`.

The Fosite token callback depends only on the token service and domain scope. Its committed service result becomes the response. The PostgreSQL adapter implements the service-owned unit-of-work, authorization and proof-replay ports with static assertions; the Transit and proof adapters likewise implement service-owned ports. No database handle crosses the inbound boundary. Tests prove authorization order, real policy/client/grant locks through remote signing, and no returned credential on transaction failure. These behavioral properties supplement the static architecture gate.
