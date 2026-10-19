# Support and release status

Mayi is an **experimental development preview**. As of October 18, 2026, no releases have been published and no version is supported for production. The repository contains runnable development foundations and partial protocol work. A runnable server or passing CI does not establish complete OAuth/OIDC interoperability, certification or production readiness.

## Supported versions

| Version or reference | Security handling | Compatibility and support |
| --- | --- | --- |
| Current `main` | Reports accepted; best-effort triage and fixes on `main` under [SECURITY.md](SECURITY.md). | Development evaluation only; no compatibility or availability guarantee. Record the exact commit tested. |
| Older commits or forks | Reports accepted when they may identify an issue in Mayi; current-code impact is assessed. | No maintained historical branches or guaranteed backports. Fork operators own their deployment and updates. |
| Tagged preview releases | None published. | No preview release line is currently maintained. |
| Stable/production releases | None published. | No production support, LTS window or support SLA is offered. |

For future `v0` previews, the default will be best-effort fixes on `main` and the newest preview; older previews will not have guaranteed backports. Before any release is advertised, its release notes must identify the supported line, upgrade path, known limitations and any end-of-support date. A stable support policy and production readiness evidence must be published before a stable release is claimed. This support policy does not change the terms of [Apache-2.0](LICENSE).

## Preview limitations

- The [P2 core preview](docs/p2-core-authorization.md) implements live PAR/RAR, login/consent, token lifecycle, resource enforcement, connected applications and the reference BFF. Its [local evidence manifest](tests/conformance/p2-evidence.json) is not external certification or a production-support commitment. The documented configuration and narrow signing/resource-authority profiles apply.
- The Go resource SDK/BFF, complete machine-token path, delegation and embedded-session/browser compatibility must meet their respective implementation gates before use. Planned capabilities in the README and architecture are not a list of currently supported features.
- Supplying a PostgreSQL primary is supported by the development configuration. Managed-provider/pooler compatibility, arbitrary existing database schemas, production upgrades and recovery are not certified. Use the dedicated roles and schema/migration requirements in [the foundation runbook](docs/p1-foundation.md).
- Private signing-key handling and transaction tests have development evidence; production KMS/HSM deployment, HA, failover, restore, performance and operational monitoring gates remain open. Development fixtures are not production credentials or deployment templates.
- Audit records are append-only to the application role and have transactional outbox delivery. Stdout delivery is at least once, not a durable SIEM receipt or an independently protected immutable archive.
- Independent security assessment, full applicable conformance evidence and production release packaging remain gated. No OpenID/FAPI certification or OpenSSF badge is claimed.
- APIs, configuration and persistence schemas may change during development. Check matching migrations and exact source revisions, use disposable synthetic-data deployments, and do not assume mixed-version upgrades or downgrade safety.

Use non-production environments for evaluation. Current evidence lives in the [requirement matrix](docs/requirement-matrix.md), [implementation plan](docs/implementation-plan.md) and linked tests; an unchecked requirement remains planned. The P6 production gate is an exit condition, not an announced release date.

## Get help and give feedback

For non-security bugs, integration questions and proposals, use [GitHub Issues](https://github.com/startificial/mayi/issues). Search existing issues first. Include the exact commit, environment, sanitized configuration, expected result and a minimal reproduction. Follow [CONTRIBUTING.md](CONTRIBUTING.md) for changes and [the error guide](docs/error-handling.md) for safe diagnostics. Response times are best effort.

For a suspected vulnerability, use [the private security process](SECURITY.md), even if you are unsure of the impact. Do not attach secrets, customer data, raw URLs containing credentials or database dumps to public support requests.
