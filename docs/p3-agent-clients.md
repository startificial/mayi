# P3 agent and unknown-client preview

P3 is **in progress**. The first slice implements native callback registration
and resource-owned metadata/Bearer challenges. P2 remains the complete core
authorization preview. [ADR 0025](adr/0025-p3-native-callbacks-and-resource-discovery.md)
records ownership and the exact capability boundary; [P3 evidence](../tests/conformance/p3-evidence.json)
links automated tests, without claiming certification.

## Native clients

Use the existing authenticated tenant administration client-creation endpoint.
Set `application_type` to `native` and `token_endpoint_auth_method` to `none`;
retain the registered resource and nonempty authorization_details_types allowlists.
Native clients cannot be machine clients or introspection clients and cannot gain
confidential status by choosing a claimed HTTPS callback. Omission of
application_type retains web behavior.

Supported native callback examples:

| Registration | Authorization request |
| --- | --- |
| `http://127.0.0.1/callback` | `http://127.0.0.1:54321/callback` |
| `http://[::1]/callback` | `http://[::1]:54321/callback` |
| `com.example.desktop:/callback` | Exact registered URI |
| `https://app.example/native/callback` | Exact registered URI |

Only the HTTP loopback port may vary. Register IPv4/IPv6 separately if using both.
`localhost`, alternate/mapped loopback forms, authority-bearing private schemes,
changed paths/queries and fragments fail. A private scheme's syntax is not proof
of ownership: the operator must review the publisher and platform registration.
Prefer claimed HTTPS where the platform supports it. Use an external browser;
these protocol fixtures do not certify native OS association or browser behavior.

Follow the [P2 PAR/RAR flow](p2-core-authorization.md#wire-flow), using the actual
runtime callback, unpredictable state and S256. That exact callback stays pinned
through consent and code issuance. A supplied redirect_uri at redemption must
equal the actual runtime callback, including its port, even when another port
would match the original registration. Invalid/expired/foreign requests fail
locally without an untrusted redirect. Restart authorization after an invalid or
ambiguous one-use exchange; do not automatically replay codes/refresh tokens.

Apply migration 15 with the separate owner role before starting the upgraded
runtime; follow the [foundation runbook](p1-foundation.md). Existing web clients
receive the web default. No schema owner credential belongs in the runtime.

## Resource discovery

The API uses the [public SDK metadata/challenge integration](../pkg/resource/README.md#resource-discovery-and-challenges).
Its own listener serves the document; Mayi's authorization server does not impersonate
the resource origin. An audience `https://api.example/tenant/a` has metadata at
`https://api.example/.well-known/oauth-protected-resource/tenant/a` and names the
configured tenant issuer. Keep the audience's escaped path and trailing slash.
GET/HEAD succeed only on the exact path without query; unsupported methods receive
405 and Allow, and other paths receive 404. Responses use no-store.

Metadata publishes selected public scopes, RAR types and header credential
transport. Configure those from the API's enforced public contract. It does not
fetch clients, authorize objects or reveal private registration/ACL data. Do not
advertise DPoP through this metadata helper until the remaining P3 binding profile
and tests are delivered.

Missing-credential challenges let a client discover metadata and the issuer.
Malformed transport, invalid token, insufficient public permission and unavailable
authority have distinct [recovery contracts](error-handling.md#p3-resource-challenges).
Every protected load/mutation still belongs inside WithAccess's guarded callback.

## Outstanding P3 work

- CIMD resolution, safe cache/conditional fetch and immutable metadata correlation.
- DCR, quotas and optional initial-access credentials using the same registration rules.
- Tenant policy for any-client, approved-host and administrator-approved registration.
- Complete DPoP token/resource, nonce, policy and copied-token interoperability evidence.
- Browser-held-token example using a non-exportable WebCrypto key.

Run `go run ./tools/checks`, `go test -race -count=1 ./...`, `go vet ./...`,
formatting checks and `go run ./tools/p0`. The real-service harness is required:
plain go test skips PostgreSQL/OpenBao tests when its explicit environment is absent.
