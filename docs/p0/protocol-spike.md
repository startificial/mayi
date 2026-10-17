# P0 protocol and transaction spike

2026-10-17 · P0 in progress; initial contract implementation

This increment pins the normative baseline, resolves interpretation decisions, publishes the initial threat model and proves the application-level issuance transaction contract with test doubles. It does not select or enable a protocol engine. No external Go dependency has been admitted or executed in Mayi. No HTTP endpoint, PostgreSQL adapter, JOSE encoder or KMS integration exists yet.

## Evidence shipped

| Output | Evidence | Limit |
| --- | --- | --- |
| Normative baseline | [23 exact source pins](../../specs/manifest.yaml), with content digests and dates; CI validates required entries and immutable URL forms | Target sections are planned scope, not implementation/conformance claims; CI is offline and does not refetch bytes. |
| Issuer identity | ADR 0001; `internal/app/config_test.go` | Configuration derivation only; discovery/routing/key isolation still pending. |
| Authorization and grant ceilings | Immutable domain revisions and `tests/contract/issuance_test.go` | Current-permission input is supplied by the policy/storage port contract. No live resource integration yet. |
| S256 proof | `internal/adapters/outbound/crypto/pkce_test.go`, RFC 7636 vector and rejection cases | Not a complete authorization endpoint or DPoP validator. |
| Code and refresh transitions | Serialized one-winner tests, exact revision/resource binding, refresh-successor attenuation, replay mutation and cancellation/failure injection | Memory double only; not multi-connection database, crash-recovery or full descendant-cascade evidence. |
| Signer transaction boundary | Sign-before-commit and no-response-before-commit fixtures; signer, audit and commit failures return no credentials | Signer returns a synthetic marker. It is not a signature or evidence of actual KMS/JOSE support. |
| Threat and topology decisions | [Threat model](../threat-model.md), ADRs 0001–0004, [profiles](../../specs/profiles.md) | External review and recipient-exchange implementation remain pending. |
| MPL distribution admission | Retained full text, exact unmodified source archive requirement and notice rejection fixtures | No MPL module is in the Go graph yet. Release packaging and source availability must be tested before distribution. |

## Exact candidates inspected

| Candidate | Source revision | Source assessment |
| --- | --- | --- |
| Fosite v0.49.0 | `653c812bc40cbda049857b432ad3346f1a53d42d` | Explicit handler composition, custom sessions/strategies and transaction helper hooks make it the next runnable-spike candidate. No default all-enabled composition. |
| ZITADEL OIDC v3.51.16 | `8ae30e3cf6d7b38d7fb460c8931dde6a06e5d7bf` | Native OIDC and exchange surfaces. Default JWT creation calls storage before signing; prove a service-owned request transaction/custom response path before adoption. |

Fosite was initially blocked by its MPL dependency. The maintainer then approved MPL-2.0 with notice and source-access obligations. That license-family blocker is resolved; full version/graph admission remains a separate step. A fresh temporary module selecting only Fosite v0.49.0 resolved 83 modules. The preliminary [module source review](fosite-module-review.json) records exact versions, module sums and license-file hashes, including nested notices. Three selected modules carry MPL-2.0: `github.com/hashicorp/go-cleanhttp@v0.5.2`, `github.com/hashicorp/go-retryablehttp@v0.7.7` and `github.com/hashicorp/hcl@v1.0.0`. Mixed MIT/Apache YAML and nested font/JSON licenses are retained in the observations. No source was modified.

The review artifact is deliberately outside `tools/dependencies.json`: it is not approval to build these versions. Re-resolve the graph for the actual imports and tests, inspect all used/copied code, review security advisories and promote reviewed evidence before execution. Root license compatibility does not establish production suitability. ZITADEL's full dependency graph has not been reviewed yet.

## Fixed comparison cases and current classifications

Classifications below distinguish **source-supported** from **executed**. Both libraries still need the same executable adapter cases before selection.

| Case | Fosite source assessment | ZITADEL source assessment | Executed evidence now |
| --- | --- | --- | --- |
| Code plus S256; implicit/password refused | Configurable PKCE and explicit factory selection | Provider code flow; configure/guard capabilities explicitly | Mayi S256 primitive and code service; library adapters not run |
| Exactly one resource | Custom policy/session/audience enforcement required | Custom storage/policy checks required | Mayi exact-resource service rejection |
| Refresh concurrency/reuse | Rotation, revocation and transaction helper hooks; persistence must prove atomicity | Storage creation/rotation hooks; outer transaction/signing boundary needs proof | Mayi unit-of-work double only |
| Immutable consent revision | Custom request/session correlation into service-owned state | Custom request/storage correlation into service-owned state | Exact revision and historical ceiling tests |
| Non-exportable KMS signing | Custom JWT signer accepts an opaque signing strategy | Signing key adapter delegates to JOSE; default token path needs transaction proof | Synthetic signer failure/commit fixtures only |
| private_key_jwt | Client assertion/JWT integration exists | JWT profile/client assertion integration exists | Pending exact adapter and purpose-confusion cases |
| DPoP hooks and resource proof | Custom endpoint/proof integration required; no assumption of complete native support | Custom endpoint/proof integration required; no assumption of complete native support | Trusted binding-context equality only; signature/replay checks pending |
| Recipient token exchange | Custom grant handler/service integration required | TokenExchangeStorage and custom verification hooks exist | ADR 0004 only; disabled |
| Basic OIDC | Explicit OIDC factories/strategy | Native provider APIs | Pending nonce, ID-token/UserInfo purpose/audience and issuer tests |

Relevant pinned source: [Fosite composition](https://github.com/ory/fosite/blob/653c812bc40cbda049857b432ad3346f1a53d42d/compose/compose.go), [refresh transaction calls](https://github.com/ory/fosite/blob/653c812bc40cbda049857b432ad3346f1a53d42d/handler/oauth2/flow_refresh.go), [JWT signer](https://github.com/ory/fosite/blob/653c812bc40cbda049857b432ad3346f1a53d42d/token/jwt/jwt.go), [ZITADEL storage](https://github.com/zitadel/oidc/blob/8ae30e3cf6d7b38d7fb460c8931dde6a06e5d7bf/pkg/op/storage.go), [token creation](https://github.com/zitadel/oidc/blob/8ae30e3cf6d7b38d7fb460c8931dde6a06e5d7bf/pkg/op/token.go), [signer](https://github.com/zitadel/oidc/blob/8ae30e3cf6d7b38d7fb460c8931dde6a06e5d7bf/pkg/op/signer.go), and [exchange](https://github.com/zitadel/oidc/blob/8ae30e3cf6d7b38d7fb460c8931dde6a06e5d7bf/pkg/op/token_exchange.go).

## Remaining P0 exit gates

1. Admit the selected candidate's actual complete import/test graph and run the fixed comparison cases. Choose an engine through an ADR based on transaction/binding hooks and measured custom work, rather than feature claims.
2. Demonstrate real non-exportable KMS signing, public-key/JWKS conversion and signing failure rollback with the chosen integration. Select a deployment/KMS target and test credentials explicitly; no local production key fallback.
3. Prove the transaction contract with PostgreSQL, including consumed credential, root/family/policy locking, unique issuance IDs, successor scope/lifetime retention, descendants, audit failure and crash/retry behavior. That work bridges into P1.
4. Complete DPoP/exchange/OIDC hook demonstrations and record unsupported topologies. Update implementation evidence without declaring later README requirements Verified prematurely.

Bring-your-own database/provider support was discussed and deferred; this increment makes no Supabase/Neon compatibility claim and includes no provider-specific database configuration.

Run `go run ./tools/checks`, `go test -race -count=1 ./...` and `go vet ./...` for this increment. These commands are CI gates, not external conformance certification.
