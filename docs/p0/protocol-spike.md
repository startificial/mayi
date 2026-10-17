# P0 protocol and transaction spike

2026-10-17 · P0 exit gates complete; production server remains planned

P0 selects **Fosite v0.49.0**, proves a thin service-owned token callback with actual PostgreSQL and remote OpenBao signing, and records the remaining protocol gaps. [ADR 0005](../adr/0005-fosite-and-local-transit.md) captures the selection, alternatives and limits. This is a runnable architecture/protocol prototype, not a deployed authorization server or completion of the README's 156 requirements.

## Fixed comparison

| Case | Fosite evidence | ZITADEL assessment / disposition |
| --- | --- | --- |
| Code and S256; removed flows | `TestFositeCodeS256AndGrantCorrelation`, `TestFositeRejectsMissingAndPlainPKCEAndRemovedFlows`, `TestFositeWrongVerifierAndRedirectFail` | S256 helper probed; generic method validator accepts plain. A stricter boundary is required. |
| Exact resource and immutable revision | Custom sessions preserve original resource/revision/binding through code and refresh; service tests reject mismatches; inbound callback requires one resource | Custom request/storage correlation is possible; not integrated. |
| Refresh and replay | Native correlation fixture plus service fixtures and multi-connection PostgreSQL rotation/replay tests | Storage hooks exist, but default token creation writes before signing. |
| Non-exportable signer | Real Transit ECDSA/JOSE signing, public JWKS, rotation overlap, export refusal and failure rollback | JOSE signing-key hook exists; default token writer ordering would still need overriding. |
| private_key_jwt | `TestFositePrivateKeyJWTInlineKeyAndReplay` verifies registered-key authentication and assertion reuse refusal | JWT-profile verifier available; full integration not run. |
| DPoP | Real signature/target/nonce/ath checks, atomic PostgreSQL replay and binding passed into the same issuance service | Custom proof/replay integration required; no complete native-support assumption. |
| Recipient exchange | Fosite custom-handler registry invokes a service planning hook; denial precedes subject load; root/revision/parent/lifetime/scope ceilings retained | Native exchange/storage interfaces exist, but rejected before full integration. |
| Basic OIDC | `TestFositeOIDCCodeNonceIssuerAndAudience` runs code redemption and verifies the signed ID token's nonce, issuer and sole RP audience | Native provider surfaces available; not integrated. |

Both candidates were pinned to exact source commits. Fosite: `653c812bc40cbda049857b432ad3346f1a53d42d`; ZITADEL: `8ae30e3cf6d7b38d7fb460c8931dde6a06e5d7bf`. Fosite is selected for explicit native extension points and the maintainer's preference. ZITADEL is not in the selected dependency graph; we did not build the workaround its default token path would require. The comparison does not claim equal full integrations were executed.

Pinned sources: [Fosite composition](https://github.com/ory/fosite/blob/653c812bc40cbda049857b432ad3346f1a53d42d/compose/compose.go), [refresh transactions](https://github.com/ory/fosite/blob/653c812bc40cbda049857b432ad3346f1a53d42d/handler/oauth2/flow_refresh.go), [signer](https://github.com/ory/fosite/blob/653c812bc40cbda049857b432ad3346f1a53d42d/token/jwt/jwt.go), [ZITADEL token writer](https://github.com/zitadel/oidc/blob/8ae30e3cf6d7b38d7fb460c8931dde6a06e5d7bf/pkg/op/token.go), [code exchange](https://github.com/zitadel/oidc/blob/8ae30e3cf6d7b38d7fb460c8931dde6a06e5d7bf/pkg/op/token_code.go).

## Executed application and infrastructure proof

The native Fosite memory store is used only in library fixtures. The selected application callback delegates to `internal/services/tokens.Service`; it never uses that memory store or a general database handle. Production composition is centralized in `internal/app`. No HTTP listener is enabled.

| Invariant / failure | Executable evidence | Limit |
| --- | --- | --- |
| Authorization before protected payload | Existing denial/call-order fixtures; service-owned Fosite callback; stale-policy and foreign-tenant database cases | HTTP authentication/session/routing middleware remains P1/P2. |
| Real remote signing and public key conversion | `TestRealSigningJWKSAndNonExportability`; ES256 signature verified with published public JWK; tenant/issuer/audience/purpose/revision checked | No hardware or production deployment certification. |
| Non-exportability and rotation | Root export refusal; exportable-key startup rejection; explicit v1/v2 signing and overlap verification | Dev memory can be inspected by privileged operators; multi-version discovery/JWKS publication remains P1. |
| Code race and exact lineage revocation | Two concurrent connections yield one issuance; authenticated replay durably invalidates that code's lineage; another code for the same root still works | Full exchange descendants are disabled until P4. |
| Refresh ceilings and reuse | Narrow scopes and usable hashed successors; idle/absolute deadlines retained, with SQL rejection of absolute lifetime expansion; reuse invalidates root/family and rejects descendants | Initial refresh-family issuance from consent is P2; prototype refresh families are seeded. |
| Current policy through commit | Tenant policy/share, client/share, grant/update and family/update locks; version-change and concurrent family-deadline recheck regression; NOWAIT tests while remote signing is paused | Future policy writers must lock tenant policy before grant/family state and avoid taking credential locks while holding the root; the issuance adapter takes policy, credential/client, root, then family. |
| SQL tenant and revision boundaries | Separate NOSUPERUSER/NOBYPASSRLS runtime role; no scope yields no rows; foreign-tenant reads denied; immutable revision trigger | Provisioning/admin APIs and full tenant key isolation are P1/P2. |
| Signing/audit/commit failure | Revoked real Transit credential; failing audit trigger; deferred commit trigger; all return no token and retain unconsumed credential/no issuance | Full host/zone failures and ambiguous commit acknowledgements need P6 operational drills. |
| Connection crash/retry | PostgreSQL backend terminated with an uncommitted consume; transaction cannot commit; retry succeeds once; further replay refused | Backend crash proof, not a full-cluster recovery/HA test. |
| DPoP | Signed ES256 proof; wrong method/URI/time/nonce/ath refused; same proof has one SQL replay winner; verified thumbprint binds issuance | Single configured ES256 profile; production nonce issuance, proxy URI normalization and resource middleware remain P3. |
| Exchange hook | `tests/contract/exchange_test.go`: service authorization before subject load, one-hop attenuation, original subject/root/revision/parent and deadline | Plan only; no exchange token, gateway receipt validation, online subject adapter or atomic exchange write yet. |
| Basic OIDC | Executed code-flow ID-token fixture with nonce and exact RP audience | Upstream login, consent, UserInfo, sessions and purpose-specific resource validator remain P2/P5. |

The [23 pinned specifications](../../specs/manifest.yaml), [profiles](../../specs/profiles.md), ADRs 0001–0005 and [threat model](../threat-model.md) establish the design baseline. `implemented_sections` stays empty because these isolated prototypes do not enable a complete server protocol profile.

## Reproduce and CI

From the repository root, using the reviewed Go 1.27.0 compiler:

```sh
go mod download all
go run ./tools/checks
go test -race -count=1 ./...
go vet ./...
go run ./tools/p0
```

Formatting must also pass `gofmt -l .` with no output. GitHub CI runs every command, including the mandatory service harness. Ordinary `go test` skips service-dependent tests when no harness environment is supplied; the harness sets `MAYI_P0_REQUIRED=1`, so missing services fail that gate.

`tools/p0` is standard-library-only and builds exact hash-verified PostgreSQL 17.11 and OpenBao 2.7.1 source archives. PostgreSQL excludes optional ICU/readline/compression/NLS dependencies and uses platform timezone data and platform mkdir/install. Its generated configure script uses approved FSFUL; the bundled X11 install-sh helper is not executed or distributed by Mayi. OpenBao uses CGO disabled and no UI tag; its actual compiled module graph must match the reviewed component inventory. The runner starts a fresh private Unix-socket database and loopback-only in-memory Transit server, strips unrelated environment settings, creates a scoped signer credential, runs race-enabled tests, then stops both processes. It never connects to a pre-existing application database or an AWS account. The pre-existing platform C compiler, make, Perl, Bison, Flex and shell are inherited infrastructure; no package-manager install or container image is added. [PostgreSQL 17 requires Bison/Flex](https://www.postgresql.org/docs/17/install-requirements.html), and the [hosted Ubuntu runner includes them](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md). Generated parser skeletons grant permission to distribute the resulting PostgreSQL program under its own terms; their notices must accompany any future binary distribution. P0 does not certify the licenses of the entire host platform.

Service source pins, hashes and notices are in [tools/services.json](../../tools/services.json); the Linux/macOS compiled OpenBao union has 292 reviewed components. Full service and module notices are retained under `tools/license-evidence/` and linked from [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md).

## Dependency and security outcome

The selected actual Fosite/JOSE/pgx graph has 368 inventoried modules. The initial Fosite-only lazy resolution of 83 modules in `fosite-module-review.json` remains historical preliminary evidence, not the final admission list. The current exact inventory is `tools/dependencies.json`. Reviewed support upgrades include `ory/x` v0.0.729 and `logex` v1.2.1; security floors are explicit. Go module and service license gates fail unknown labels, changed evidence, missing/stale module approvals and unreviewed compiled service components.

The maintainer approved CC0-1.0, Unicode-DFS-2016, TCL, Spencer-94, Unlicense, Zlib, WTFPL and FSFUL in addition to the prior allowlist, with retained notices. Unlicense is unused in the selected graph. Zlib/GLFW and WTFPL/XGB packages remain forbidden to compile, execute or distribute. No license exception is inferred from another module's license.

[Security review](security-review.json) records public OSV findings for the exact selected graph and their package reachability. Vulnerable upstream test-only modules remain visible in inventory; their package prefixes are forbidden by CI. The unmaintained `x/crypto/openpgp` packages are also forbidden. The current Mayi production/test graph reaches none of those packages. This static reachability gate is not a vulnerability suppression or an ongoing scanner, and it does not certify the external service binaries. Re-review graph/security changes before upgrades.

## P0 exit and remaining delivery

All four P0 exit gates are satisfied: protocol decision/graph admission; actual remote signing/JWKS/failure proof; real PostgreSQL transaction/race/replay/failure proof; and DPoP/OIDC/exchange extension demonstrations with explicit unsupported capabilities. The requirement matrix retains full requirements as Planned, with partial prototype evidence only.

P1 now owns process startup, tenant provisioning, migration lifecycle, production signer credentials/TLS/seal/storage, published discovery/JWKS, operational telemetry and packaging. P2 owns a complete login/consent/code/refresh/resource flow. P3 completes the DPoP deployment profile. P4 must implement and validate the exchange trust and persistence contract before enabling any exchange endpoint. Generic PoP exchange, cross-tenant/foreign-issuer exchange, impersonation, multi-hop exchange and undeclared rebinding are unsupported. BYO database/provider support remains deferred.
