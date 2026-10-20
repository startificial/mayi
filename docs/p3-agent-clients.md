# P3 agent and unknown-client preview

P3 is **in progress**. Native callback registration, resource-owned discovery/challenges and the shared
ES256 DPoP sender-binding profile and bounded public DCR are implemented. P2 remains the complete core
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
fetch clients, authorize objects or reveal private registration/ACL data. DPoP metadata and nonce/challenge support are implemented by the second slice
below; browser CORS and the WebCrypto sample remain outstanding.

Missing-credential challenges let a client discover metadata and the issuer.
Malformed transport, invalid token, insufficient public permission and unavailable
authority have distinct [recovery contracts](error-handling.md#p3-resource-challenges).
Every protected load/mutation still belongs inside WithAccess's guarded callback.

## Outstanding P3 work

- CIMD resolution, safe cache/conditional fetch and immutable metadata correlation.
- Broader DCR interoperability and later registration management beyond the implemented public profile.
- CIMD tenant policy, including approved hosts; DCR open/admin-only admission is implemented.
- Browser-held-token example using a non-exportable WebCrypto key.

Run `go run ./tools/checks`, `go test -race -count=1 ./...`, `go vet ./...`,
formatting checks and `go run ./tools/p0`. The real-service harness is required:
plain go test skips PostgreSQL/OpenBao tests when its explicit environment is absent.

## ES256 DPoP sender binding

The second P3 slice implements the shared sender-binding profile in
[ADR 0026](adr/0026-p3-dpop-nonces-and-binding.md). Apply migrations 16–17 before the
upgraded runtime, using the separate owner connection. Existing client creation
accepts `dpop_bound_access_tokens: true`; tenant/resource require_binding also
continues to enforce binding. Missing proof authority fails closed on issuance,
refresh and subsequent online checks. DPoP is additional to client authentication.

For an interactive flow, include the SHA-256 public JWK thumbprint as dpop_jkt in
PAR, or send a DPoP proof header for that exact PAR endpoint. When both are
present they must match. Keep S256 and required typed RAR. The key stays fixed
through codes and refresh families. A token proof cannot introduce a new key for
an already approved authorization. Confidential machine requests can bind their
key at the token endpoint using their normal client authentication.

Every proof uses a fresh unpredictable jti, current iat, exact HTTP method and
public HTTPS target without query/fragment, typ dpop+jwt, alg ES256 and the public
P-256 JWK. No private JWK fields or token-controlled key URLs are accepted. At a
resource include ath = unpadded base64url(SHA-256(access token bytes)); token/PAR
proofs omit ath. Send access tokens using Authorization: DPoP with the DPoP header.
A copied token, a missing/wrong key or Bearer downgrade cannot reach payloads.

A valid proof without a current nonce receives use_dpop_nonce and DPoP-Nonce:
400 at token/PAR, or 401 with WWW-Authenticate: DPoP at the resource. On this exact
response only, retry with a freshly signed proof containing the returned nonce.
Cache nonce values separately by issuer/resource endpoint and key, never confuse
these with OIDC nonce/state, and reuse a current nonce with new proof IDs. Nonces
expire after one minute. Missing/invalid/stale nonce does not consume credentials
or call the protected payload. Shared state failure is 503, with no fallback.
Never automatically retry an ambiguous code/refresh response or reuse a proof JWT.

Resources use SDK Config.RequireDPoP and the same MetadataConfig.RequireDPoP
policy; optional-binding resources use WriteDPoPChallenge for DPoP requests.
Metadata advertises ES256 and whether binding is required. Cross-origin browser
CORS/header exposure and the non-exportable WebCrypto sample remain outstanding;
this protocol fixture is not a browser compatibility claim.

## Public dynamic client registration

Apply migration **18** with the separate owner connection before starting this
runtime. [ADR 0028](adr/0028-public-dynamic-client-registration.md) defines the
bounded RFC 7591 profile, atomic quota and admission-only policy semantics.
DCR is served at `POST /t/{tenant}/register` when both credential keys and an
upstream identity provider enable interactive authorization. That issuer's live
discovery advertises `registration_endpoint`; other tenants expose no DCR route.
The trusted public TLS proxy remains required, as for all Mayi endpoints.

New tenants deny dynamic registration. Read
`GET /admin/t/{tenant}/client-registration-policy` with `clients:read`, then use
`PUT` with `clients:write` and the returned version. For example:

```json
{
  "version": 1,
  "mode": "open",
  "resources": ["api"],
  "authorization_details_types": ["https://api.example/types/workflow/v1"],
  "max_clients": 100,
  "access_token_seconds": 300,
  "require_initial_access": false
}
```

The resources and profiles must already be registered in that tenant. A client
must select a nonempty subset of these explicit ceilings. They select vocabulary
and audience eligibility, not user/object permission. Successful PUT returns the
next version; stale versions fail with 409. To stop new registrations, PUT only
`version` and `mode: "admin_only"`. Existing credentials retain their existing
authority/revocation rules; revoke grants separately to cut off current access.

A registering public client sends Content-Type: application/json and:

```json
{
  "client_name": "Example agent",
  "application_type": "web",
  "redirect_uris": ["https://agent.example/callback"],
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "dpop_bound_access_tokens": true,
  "mayi_resource_ids": ["api"],
  "authorization_details_types": ["https://api.example/types/workflow/v1"]
}
```

`mayi_resource_ids` is Mayi's registration extension naming administrator-approved
resource IDs, not protected object IDs. `authorization_details_types` selects the
registered RAR vocabulary. Registration creates no object grant. The 201 JSON
response returns accepted metadata and a random `client_id`, with no client
secret or registration-management token. Responses are no-store. Unknown ordinary
metadata is ignored rather than echoed. This profile requires explicit public
authentication and both grant types; omitted/default confidential authentication,
software statements, remote keys and unsupported grant types fail. The server
always registers DPoP binding. Use `application_type: "native"` for the existing
native callback policy; no confidential or machine registrations are accepted.
Use the returned ID in the existing PAR/RAR/DPoP flow and obtain user consent.

For protected registration, generate a **separate** credential with
`go run ./cmd/mayi admin-token`, place only its `sha256` in the tenant's startup
`initial_registration_token_sha256`, restart every replica, and set the admission
policy's `require_initial_access: true`. Deliver the raw token securely out of
band; send it only as `Authorization: Bearer <token>` at registration. Never reuse
an administrator credential or use this token at resource/token endpoints.
A wrong supplied token fails even when initial access is optional. Remove/replace
the digest and restart every replica to revoke/rotate it; this slice provides no
dynamic token issuance or overlap window. A required credential without a
configured digest denies every registration.

All service-level attempts share a fixed 60/minute tenant budget. The cumulative
quota counts every successfully registered dynamic client, including disabled
clients. Failed transactions do not consume a slot; they still consume request
budget. Capacity exhaustion requires the operator to raise the quota or keep
registration closed; it is not solved by automatic retries. See the
[registration error/recovery contract](error-handling.md#p3-client-registration).
CIMD, its cache/digest/host policy and browser-held-token validation remain pending.
