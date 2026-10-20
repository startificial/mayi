# Resource enforcement

Construct a client with a trusted tenant, exact issuer/API audience, registered
typed profiles and a confidential resource-server credential authorized for
introspection. Supply a resource-owned `PermissionGuard` that checks current ACL
metadata before any payload read and holds those permissions stable through its
callback. Put every protected read/mutation inside `WithAccess`'s callback.

The SDK uses authenticated, constrained online introspection on every request.
It checks committed issuance, tenant/issuer/audience, expiry, typed object/action
authority, scope and sender binding before calling the permission guard. JWT and
opaque tokens follow the same authoritative cutoff. There is no stale positive
cache or offline availability fallback. ID tokens are not API access tokens.

Obtain a credential with `HeaderToken`; do not accept credentials from query/body,
WebSocket parameters or arbitrary forwarding headers. Validate application input
at the resource boundary too. For DPoP, pass the proof and configured public method
and target URI in `Request`; never derive those values from untrusted forwarded
headers. The AS verifies proof and replay state through the authenticated status
contract. Bound tokens cannot be used as bearer credentials.

Use `errors.Is(err, resource.ErrDenied)` for inactive/foreign/unapproved authority,
and `errors.Is(err, resource.ErrUnavailable)` for unavailable authoritative state.
Both prevent payload callbacks. Cancellation also preserves `context.Canceled` or
`context.DeadlineExceeded`; an error is not a transaction rollback guarantee.
Application callback errors retain their own classification. Do not log tokens,
proofs, credentials, introspection bodies or protected object details.

Map errors to the resource's protocol response. The P3 helper below supports
resource-owned metadata and Bearer/DPoP challenges, including nonce recovery.
Once revocation commits, the next fresh decision rejects the credential. An
already authorized operation may finish; long-running/high-impact operations need
an appropriate owner transaction boundary or another fresh decision.

See `TestP2PublicProtocolAndSDKEnforceObjectAuthorityAndImmediateCutoff` and the
reference BFF test in `tests/integration/live_protocol_test.go`. Run the real
fixture with `go run ./tools/p0`; plain `go test` skips database integrations when
its explicit local-service environment is absent.

## Resource discovery and challenges

Construct metadata from trusted resource deployment configuration and mount it on
that resource's listener. This example assumes the application already constructed
`validator` with its current-permission guard:

```go
metadata, err := resource.NewMetadata(resource.MetadataConfig{
    Issuer: "https://auth.example/t/a",
    Audience: "https://api.example/tenant/a",
    Name: "Example API",
    PermissionScopes: []string{"read"},
    AuthorizationDetailTypes: []string{"https://api.example/types/document/v1"},
})
if err != nil { return err }
mux.Handle(metadata.MetadataPath(), metadata)
mux.HandleFunc("GET /tenant/a/documents/{id}", func(w http.ResponseWriter, r *http.Request) {
    token, err := resource.HeaderToken(r)
    if err != nil {
        metadata.WriteChallenge(w, err)
        return
    }
    err = validator.WithAccess(r.Context(), token, resource.Request{
        Type: "https://api.example/types/document/v1",
        Identifier: r.PathValue("id"), Action: "read", Permission: "read",
    }, func(ctx context.Context, principal resource.Principal) error {
        // Load the protected payload here through the resource-owned guarded
        // context; return it to the handler only after the guard succeeds.
        return loadAuthorizedDocument(ctx, principal)
    })
    if err != nil {
        if errors.Is(err, resource.ErrInsufficientScope) {
            metadata.WriteChallenge(w, err, "read")
        } else {
            metadata.WriteChallenge(w, err)
        }
        return
    }
    // Encode the authorized application result here.
    w.WriteHeader(http.StatusNoContent)
})
```

The enclosing setup function handles the constructor error; names such as `mux`,
`validator` and `loadAuthorizedDocument` belong to the integrating application.
The executable protocol fixture is `TestP3ResourceChallengeDiscoveryAndOnlineCutoff`.
Never write a success/payload response inside a transaction callback before the
resource guard completes. Handle application callback errors with the application's
own safe error mapper; unrecognized errors passed to WriteChallenge become fixed 500.

For the audience above, MetadataURL returns
`https://api.example/.well-known/oauth-protected-resource/tenant/a`. Root and
path-based audiences, including separate resources on one host, get distinct
exact documents. Preserve escaped paths/trailing slashes when mounting routes.
Neither Host nor forwarded headers select the issuer, audience or challenge URL.
Only GET/HEAD with the exact path and no query is accepted. Metadata uses no-store,
selects public permissions/types and advertises only header credential transport;
it does not establish unknown-client trust or replace object policy.

SDK error recovery:

| Error | Response from WriteChallenge | Recovery |
| --- | --- | --- |
| ErrMissingCredential (or nil) | 401, metadata challenge, no OAuth error | Discover metadata, then initiate authorization. |
| ErrInvalidRequest | 400 invalid_request and metadata challenge | Fix malformed/duplicate/unsupported transport; query/body credentials are refused. |
| ErrDenied | 401 invalid_token and metadata challenge | Obtain valid authority for this exact issuer/audience. No object-existence detail is provided. |
| ErrInsufficientScope | 403 insufficient_scope; optional configured public scope | Start a fresh PAR/consent flow for that permission. This never overrides current ACLs. |
| ErrUnavailable | 503 temporarily_unavailable, no auth challenge | Fail closed. A bounded retry of a read may be appropriate; this is no rollback guarantee. |
| Other application error | Fixed 500 server_error, no auth challenge | Use the resource's own safe error handling. No raw error is returned. |

The specific transport/scope sentinels also satisfy errors.Is(err, ErrDenied),
so check them first when supplying your own response mapper. Permission hints must
be distinct configured public scopes; unknown or malformed hints fail safely with
500. No object identifiers, tokens, assertions or raw dependency errors enter a
response. Use WriteDPoPChallenge for DPoP requests at an optional-binding resource;
required-binding metadata defaults to DPoP. Step-up remains a later profile.


## DPoP proof and nonce handling

Set Config.RequireDPoP and MetadataConfig.RequireDPoP to the same enforced API
policy. The former rejects unbound tokens even if an introspection response is
otherwise valid; the latter advertises dpop_bound_access_tokens_required, ES256
and an empty bearer_methods_supported list. Optional-binding metadata advertises
ES256 plus header Bearer transport. The API must always reject bound credentials
used without a matching proof, independently of its optional binding policy.

Use HeaderToken, pass the DPoP header as Request.Proof, and supply the actual
method and public target URL from trusted routing/configuration. A query may be
present on that target; it is excluded from htu comparison. Never construct the
public authority from arbitrary Host/Forwarded/X-Forwarded-* headers. Proof htu
must omit query and fragment; method/path/key/ath/replay checks remain mandatory.
No public key URL from a proof is fetched. The supported proof algorithm is ES256.

The SDK delegates signature and shared nonce/replay verification through the
resource's authenticated online status contract. Handle a nonce before generic
denial:

```go
var nonce *resource.NonceChallenge
if errors.As(err, &nonce) {
    metadata.WriteDPoPChallenge(w, err)
    return
}
```

WriteChallenge also recognizes this error automatically. A nonce challenge sends
401 use_dpop_nonce, WWW-Authenticate: DPoP with algs and resource_metadata, and
DPoP-Nonce. No protected callback has run. The client can retry this explicit
challenge with a newly signed proof containing the nonce and a fresh jti. A nonce
can accompany new proofs until expiry, but a proof JWT is single-use across
replicas. Missing/wrong proofs use invalid_dpop_proof; inactive/revoked authority
stays invalid_token. NonceChallenge also matches ErrDenied for existing callers.
Unavailable shared state is ErrUnavailable/503 without a misleading auth challenge.

Keep nonce caches separate by issuer/resource endpoint and proof key. A token/PAR
nonce does not replace a resource nonce or an OIDC nonce. This profile requires
PAR to prebind interactive code/refresh credentials; changing or losing the key
requires reauthorization. Opaque and JWT access tokens use the same checks.

Cross-origin browser deployments must explicitly allow their intended origins
and expose DPoP-Nonce and WWW-Authenticate through their own CORS response policy.
This slice does not enable wildcard credentialed CORS or claim browser sample
compatibility. A timeout/5xx still does not authorize replay of a one-use code,
refresh token or already submitted proof.
