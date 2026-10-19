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

Map errors to the resource's protocol response. P3 completes discoverable resource
metadata and challenge profiles; this preview does not claim those surfaces.
Once revocation commits, the next fresh decision rejects the credential. An
already authorized operation may finish; long-running/high-impact operations need
an appropriate owner transaction boundary or another fresh decision.

See `TestP2PublicProtocolAndSDKEnforceObjectAuthorityAndImmediateCutoff` and the
reference BFF test in `tests/integration/live_protocol_test.go`. Run the real
fixture with `go run ./tools/p0`; plain `go test` skips database integrations when
its explicit local-service environment is absent.
