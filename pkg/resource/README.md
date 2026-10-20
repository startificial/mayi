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
resource-owned metadata and Bearer challenges; complete DPoP challenge/nonce
profiles remain outstanding.
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
response. The helper currently emits Bearer challenges; the remaining P3 DPoP and
step-up profiles require their own evidence before advertisement.
