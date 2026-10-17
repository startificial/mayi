# Dependency and tooling license policy

The permitted SPDX identifiers are **MIT, Apache-2.0, 0BSD, BSD-2-Clause, BSD-3-Clause, PostgreSQL, ISC, MPL-2.0, CC0-1.0, Unicode-DFS-2016, TCL, Spencer-94, Unlicense, Zlib, WTFPL and FSFUL**. BSD and PostgreSQL were explicitly added to the initial MIT/Apache rule; ISC was explicitly approved for CI tool dependencies. MPL-2.0 was subsequently approved with license-notice and corresponding-source obligations. The maintainer explicitly approved the additional service/test-graph licenses and FSFUL with retained notices during P0. Unknown and unlisted licenses are rejected. Being open source or generally permissive is not sufficient.

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

An upgrade invalidates approval for the previous version. Re-review its complete graph and evidence. Modified license bytes, unknown modules, local replacements and stale inventory entries fail CI. No unreviewed exceptions are configured. Generated PostgreSQL build/output files use their explicit additional permissions where those allow the same PostgreSQL distribution terms; the selected branch and retained notices are recorded in the service inventory.

## MPL-2.0 notice and source access

Retain the complete [MPL 2.0 license text](../tools/license-evidence/MPL-2.0.txt), applicable copyright/NOTICE files, and [third-party distribution notice](../THIRD_PARTY_NOTICES.md). For every admitted unmodified MPL Go module, the inventory must contain `source_access.url` pointing to the exact Go module source archive and `source_access.modification_status` equal to `unmodified`. List the same `module@version` and archive link in the distribution notice. The gate rejects missing/mutable source offers, missing notices and modified/truncated retained license text.

A source link must actually remain available to recipients. Build/release packaging must include these materials and test source access before shipping binaries or images; the current workflow does not distribute a server. Forks or modifications to covered files need the corresponding modified source under MPL and a source-aware admission path; an unchanged upstream link does not cover those modifications. Local replacements remain rejected. Preserve recipients' MPL source rights in any executable distribution terms. See [Mozilla's distribution FAQ](https://www.mozilla.org/MPL/2.0/FAQ/), especially questions 8–10, and [license sections 3.1–3.4](https://www.mozilla.org/MPL/2.0/).

The selected Fosite graph includes unmodified MPL modules. The [P0 report](p0/protocol-spike.md) describes exact admission and execution evidence. Local OpenBao is a separate unmodified MPL service: its exact source tarball, compiled component source links and complete notices are retained in the service inventory and distribution notice. Modified sources remain unsupported by the current admission path.

## What CI enforces now

[The workflow](../.github/workflows/ci.yml) runs on pushes and pull requests with read-only repository permissions, immutable action pins and no persisted checkout credentials. It downloads module source for inspection, runs the policy gate, checks formatting, runs tests with the race detector, and runs `go vet`.

`go run ./tools/checks` uses only the Go standard library. It:

- Runs the [architecture gate](architecture-enforcement.md), including direct imports, the SDK's transitive dependencies, port/conformance rules, composition boundaries and public API type exposure, even for generated/build-tagged source.
- Resolves `go list -mod=readonly -m -json all`, requiring exact-version license evidence for every non-root module, including indirect modules. The selected P0 graph has 368 external modules, including visible upstream test-only modules.
- Verifies license evidence hashes against downloaded source, rejects missing/unapproved license labels and prevents evidence paths escaping their source root.
- Requires exact unmodified source access and distribution notice entries for MPL modules and verifies the retained full MPL text. Release packaging remains a separate required gate.
- Checks the running Go version and distribution license digest against the reviewed compiler record.
- Checks `tools/services.json` source pins, digests, service/component license labels and retained notices. The P0 runner verifies archive hashes and the actual OpenBao compiled module graph before building.
- Rejects reachability of explicitly forbidden unsafe upstream packages, including OpenPGP and unused graphics/generator packages, through the complete local production/test dependency graph. This is a static policy, not a vulnerability scanner.
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

## Selected P0 components

| Component | Pin | Evidence / scope |
| --- | --- | --- |
| Fosite | v0.49.0 | Apache-2.0 root; complete actual 368-module graph in `tools/dependencies.json`, including cumulative nested notices and exact MPL archives. Explicit application-service handlers; no default all-enabled composition. |
| JOSE | v3.0.5 and v4.1.6 | Apache-2.0 plus nested BSD notices. Fosite uses v3; Mayi's remote signer/proof adapter uses v4. No vendor models enter services. |
| pgx | v5.11.0 | MIT; real PostgreSQL transaction adapter and race/failure tests. |
| PostgreSQL | 17.11 official source, SHA-256 pinned | PostgreSQL, TCL, Spencer-94 and build-script notices; optional libraries disabled. Explicit output/additional-permission branches are recorded. |
| OpenBao | v2.7.1 exact source commit, SHA-256 pinned | Unmodified MPL-2.0 source without UI. Linux/macOS linked-module union (292 components) reviewed independently; no container or cloud deployment. |
| ZITADEL OIDC | Rejected | Source comparison only; absent from the selected graph. Approved Unlicense remains unused. |

The public OSV review and package-level dispositions are in `docs/p0/security-review.json`. Unused vulnerable upstream modules remain in the full graph and inventory; `tools/forbidden-packages.json` prevents their packages entering Mayi's production/test graph. The gate also forbids GLFW and XGB packages. It does not certify OpenBao/PostgreSQL binaries or replace fresh advisory review.

`go run ./tools/p0` is the mandatory CI integration gate. It builds hash-verified reviewed service sources with inherited platform compiler/make/Perl/Bison/Flex/shell utilities, starts private ephemeral services with an explicit environment allowlist, and requires real tests to run. No downloaded scripts, package-manager installs, arbitrary containers or frontend assets are added. Build caches are private local infrastructure, not distribution artifacts. The ordinary unit-test command may skip service tests; CI must also run this harness with its missing-service sentinel.

A Go module inventory covers all selected modules, including upstream test-graph modules introduced by Go resolution. The external service inventory covers every linked module in supported service builds plus their root/nested notices; it does not execute or redistribute upstream test suites, examples, website subtrees or UI bundles. These different build boundaries are explicit, rather than treating a root license as transitive approval.

Redis/optional caches, containers, deployment images, Helm dependencies and external conformance runners still require exact admission and checker coverage before use. Production binary/image release packaging must bundle required notices and preserve corresponding-source access; P0 does not distribute a server.

P1 reuses the exact admitted Go/service graph and platform prerequisites. The same source-built harness runs P0 and P1 integration tests; `-development` keeps only a private disposable instance of those services running for operator testing. It adds no container, dependency version or license exception. The runnable command is not a binary/image release; notice/source-access packaging remains mandatory before distribution.
