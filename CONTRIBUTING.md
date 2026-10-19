# Contributing to Mayi

Contributions and practitioner feedback are welcome. Mayi is currently an experimental preview; read [SUPPORT.md](SUPPORT.md) for implemented boundaries and support limits. Use [the private security process](SECURITY.md) for suspected vulnerabilities rather than a public issue or pull request.

## Start with the problem

Search [existing issues](https://github.com/startificial/mayi/issues), services and ADRs before proposing another implementation. For a significant feature, new protocol profile, dependency or public API, open an issue describing the use case, requirement IDs, expected behavior and owning capability before writing a large change. Small fixes and documentation corrections can go directly to a pull request. Discuss technical decisions with specific examples and respect other contributors.

Read [AGENTS.md](AGENTS.md), [requirements](README.md), [the canonical package layout](docs/repository-structure.md), [the implementation plan](docs/implementation-plan.md) and [dependency policy](docs/dependency-policy.md). AGENTS.md applies to human and automated contributions. Keep the modular monolith, inward dependencies, thin handlers, service-owned ports and pure domain invariants; use the shared vocabulary rather than creating competing grant or authorization models.

## Development setup

1. Fork and clone the repository, create a focused branch, and use the exact Go toolchain in `go.mod`. The repository has one root module; do not add another module/workspace or an unreviewed tool installer.
2. Run `go mod download all`, then `go run ./tools/checks` before executing newly introduced dependency code. A dependency or tool change must already have the inventory and exact-version license evidence required by the policy; do not bypass admission to get a local build working.
3. Use [the foundation runbook](docs/p1-foundation.md) for the disposable local PostgreSQL/OpenBao environment and required platform build utilities. `go run ./tools/p0 -development` starts the reviewed development harness. Follow its output for lifecycle/cleanup. It must not point at production services or use real customer data. Do not use personal cloud credentials for repository tests.
4. Keep local credentials and generated material out of Git and public logs. Use synthetic users, tenants and objects in reproductions. See [error handling](docs/error-handling.md) for safe diagnostic information.

## Implement and verify

Keep each pull request focused on a behavior or documented decision. Reuse existing services and domain rules; validate external input, authorize before protected loads and keep required state/issuance/audit changes atomic. Material trust, authority, persistence or public-contract changes need an ADR. Keep implemented, planned and verified status distinct.

Run the applicable checks from the repository root:

```sh
go run ./tools/checks
go test -race ./...
go vet ./...
gofmt -l .
```

Formatting output must be empty; format changed Go files with `gofmt`. The workflow also runs the explicit error-contract suite and `go run ./tools/p0`, which builds the reviewed services and requires real PostgreSQL/OpenBao evidence. Ordinary `go test` may skip integration cases without that harness. Run it for persistence, transaction, signing and integration changes; do not describe a skipped suite as passed. Documentation-only changes normally need link/content review and repository checks, not new runtime tests.

Add focused positive and adversarial tests. Authorization changes require denial, foreign-tenant and call-order cases. Credential changes require replay/concurrency and revocation evidence. Error changes must preserve endpoint-specific protocol responses, safe recovery, redaction and the local catalog contracts. Architecture, dependency-policy and inventory changes need rejection fixtures as well as successful cases. Never weaken tests, add suppressions or bypass a failing gate to obtain a green build.

## Submit a pull request

Explain the concrete problem and resulting behavior, link requirement IDs/issues and relevant ADRs, and summarize verification plus material limitations. Include user-facing examples where useful; do not paste secrets or raw traces. Update the requirement matrix and operator/integration documentation when their contracts change. Preserve existing work when collaborating in a shared checkout.

Maintainers review scope, architecture, security, dependency evidence and tests. Review feedback or passing CI alone does not establish production readiness. Maintainers may defer work that does not fit the current phase; agree on the next step in the issue. Use public issues for ordinary bugs and questions and keep security reports private.

## Licensing and attribution

Mayi's first-party source and documentation are licensed under [Apache License 2.0](LICENSE), with project attribution in [NOTICE](NOTICE). By intentionally submitting a contribution for inclusion, you submit it under Apache-2.0 under its contribution terms unless you explicitly state otherwise; raise a differing license before submission so maintainers can assess it. Submit only material you have the right to contribute and retain existing attribution. No copyright assignment is required by this contribution guide.

Third-party source, generated assets and dependencies keep their own licenses. Read [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and the dependency policy before copying code or adding a tool. New components need exact pins, full applicable dependency review, inventory, retained notices and CI admission. Mayi's Apache license does not replace upstream terms or relax the allowlist, including the MPL corresponding-source obligations.

Before distributing a binary or image, complete and test release packaging with LICENSE, NOTICE and every applicable third-party notice/license/source-access obligation. A license file in the checkout alone does not verify the release artifact.
