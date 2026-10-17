# Dependency and tooling license policy

The permitted SPDX identifiers are **MIT, Apache-2.0, 0BSD, BSD-2-Clause, BSD-3-Clause, PostgreSQL and ISC**. BSD and PostgreSQL were explicitly added to the initial MIT/Apache rule; ISC was explicitly approved for CI tool dependencies. Unknown and unlisted licenses are rejected. Being open source or generally permissive is not sufficient.

The machine-readable source is [tools/license-policy.json](../tools/license-policy.json). [AGENTS.md](../AGENTS.md) defines the engineering rules. Changing the allowlist requires a direct maintainer decision; contributors must not loosen it to make a dependency pass.

## Scope

Apply the policy to direct and transitive Go modules, test/build tools, GitHub Actions and their bundled dependencies, copied code, generated runtime dependencies, frontend assets, and software added to deployment images. A service dependency such as PostgreSQL is a separate component from its client driver. A driver's license does not cover the database.

The CI workflow runs on GitHub's hosted platform. Its pre-existing operating system, runner runtime and system utilities are platform infrastructure, not packages this repository installs or redistributes. This gate does not certify every component of that hosted environment. Repository-selected actions, compiler and added tools are inventoried. Any requirement to certify the entire execution platform needs a separately inventoried runner image; do not claim the current workflow provides that audit.

Specifications linked as documentation are references, not bundled software. Do not copy specification text, test assets or code into a release without reviewing their applicable terms. This policy does not select a license for Mayi's own first-party source.

## Admission workflow

1. Explain why the component is needed and whether existing code or the standard library already provides it.
2. Pin the exact module version, tool version, action commit or deployment digest. Inspect upstream LICENSE/NOTICE files for that artifact, including nested or bundled code.
3. Resolve the complete dependency graph, including tests, tools and supported build configurations. Review each component independently; a parent's license does not cover children.
4. Record the component and its evidence in [tools/dependencies.json](../tools/dependencies.json). Go entries include module path/version, selected SPDX licenses, primary-source URL, review notes, and relative paths plus SHA-256 digests for license/notice evidence in downloaded module source.
5. For dual licensing, select an allowed branch only when that choice actually applies to all used code. Record the choice and keep its evidence. For cumulative obligations, every applicable license must be allowed. Do not encode an unchecked expression as a single accepted string.
6. Run the policy checker before executing newly introduced code. Retain required copyright, license and NOTICE content in release artifacts. Admission and redistribution obligations are separate checks.

An upgrade invalidates approval for the previous version. Re-review its complete graph and evidence. Modified license bytes, unknown modules, local replacements and stale inventory entries fail CI. No exceptions are currently configured.

## What CI enforces now

[The workflow](../.github/workflows/ci.yml) runs on pushes and pull requests with read-only repository permissions, immutable action pins and no persisted checkout credentials. It downloads module source for inspection, runs the policy gate, checks formatting, runs tests with the race detector, and runs `go vet`.

`go run ./tools/checks` uses only the Go standard library. It:

- Runs the [architecture gate](architecture-enforcement.md), including direct imports, the SDK's transitive dependencies, port/conformance rules, composition boundaries and public API type exposure, even for generated/build-tagged source.
- Resolves `go list -mod=readonly -m -json all`, requiring exact-version license evidence for every non-root module, including indirect modules. The inventory currently has no external Go modules.
- Verifies license evidence hashes against downloaded source, rejects missing/unapproved license labels and prevents evidence paths escaping their source root.
- Checks the running Go version and distribution license digest against the reviewed compiler record.
- Checks workflow action references against the exact reviewed commits and verifies checked-in license evidence for those action bundles.
- Rejects nested Go modules/workspaces, local module replacements, vendor/node_modules trees and recognized new dependency manifests that lack an implemented license-admission path.

The checker validates reviewed evidence; it does not guess legal terms from text or prove that a human review found every nested license. It does not fully parse arbitrary shell commands or certify arbitrary external executables/downloads hidden in a workflow. These are review obligations: no unrecorded installs, downloaded scripts, unapproved containers or new package ecosystems. Extend the inventory and checker before introducing them.

Workflow action references must use literal unquoted block-YAML `uses:` entries. This intentionally narrow format lets the checker reject expressions, mutable tags, local actions and unsupported action forms rather than guessing. Changes to workflow grammar require parser/tests changes together.

The checker's tests deliberately reject foreign-layer imports, hidden build-tag violations, unknown/disallowed licenses, changed license text, missing transitive approvals, unreviewed upgrades, replacements, path escapes and mutable action tags. These are meaningful policy tests even while the server is unimplemented.

GitHub branch protection is separate from this file. Configure **Architecture, licenses and Go checks** as a required PR check before relying on it as a merge gate; this change adds the workflow but does not alter repository hosting settings.

## Reviewed CI components

| Component | Pin | Evidence |
| --- | --- | --- |
| Go | `go1.27.0` | BSD-3-Clause distribution LICENSE; local and CI toolchains must match the recorded digest. [Upstream](https://go.dev/LICENSE) |
| actions/checkout | `3d3c42e5aac5ba805825da76410c181273ba90b1` / v7.0.1 | MIT root plus 24 upstream runtime dependency license records; MIT, Apache-2.0 and ISC. [Pinned license](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/LICENSE) |
| actions/setup-go | `924ae3a1cded613372ab5595356fb5720e22ba16` / v6.5.0 | MIT root plus 46 upstream runtime dependency license records; MIT, Apache-2.0, ISC and 0BSD. [Pinned license](https://github.com/actions/setup-go/blob/924ae3a1cded613372ab5595356fb5720e22ba16/LICENSE) |

The upstream cached records labeled `other` for HTTP client and concat-map contain MIT text; the retained evidence records the review. setup-go v7.0.0 was not selected because its bundle includes BlueOak-1.0.0, which is outside the allowlist. Disabling an action feature does not automatically remove bundled dependencies from review.

Full upstream evidence is retained under `tools/license-evidence/`. Review action upgrades before changing a pin. Neither `latest` nor an automated unreviewed dependency update is acceptable.

## Planned server dependencies

These are candidates, not admitted dependencies. No server library has been installed or added to the Go module yet.

| Candidate | Upstream root license checked | Admission status |
| --- | --- | --- |
| PostgreSQL | PostgreSQL License. [Source](https://www.postgresql.org/about/licence/) | Allowed license family; exact distribution/image and bundled components still need review. |
| pgx | MIT. [Source](https://github.com/jackc/pgx/blob/master/LICENSE) | Exact version and complete Go graph pending. |
| Ory Fosite | Apache-2.0. [Source](https://github.com/ory/fosite/blob/master/LICENSE) | Protocol spike and exact dependency graph pending. |
| ZITADEL OIDC | Apache-2.0. [Source](https://github.com/zitadel/oidc/blob/main/LICENSE) | Alternative candidate; exact dependency graph pending. |
| JOSE, telemetry, KMS, migrations, conformance tools and caches | Not selected | Must pass the same gate; a reference in the plan does not approve use. |

Do not adopt Redis or another optional cache by name alone: editions and versions can differ in license. The baseline needs no external cache. Likewise, containers, Helm dependencies and external conformance runners require inventory support before they are introduced.
