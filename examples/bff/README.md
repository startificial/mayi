# Go reference BFF

This application uses Mayi's public PAR, authorization, token and JWKS endpoints.
It keeps access/refresh/ID tokens server-side and gives the browser a hardened
opaque cookie. Login/consent require a top-level navigation; P5 supplies the
separate embedded-session/handoff implementation.

Register a confidential web client with `client_secret_basic`, the exact redirect
`https://your-app.example/callback`, your resource and your registered object type.
Generate its secret through `POST /admin/t/{tenant}/clients/{id}/secret`; the value
is returned once. The example requests object `123`, action `read`, permission
scope `read`, plus `openid offline_access`. The resource must implement those
semantics, expose `GET /documents/{id}`, and enforce current permissions and the
token ceiling with the public resource SDK. The user should have read permission
for both `123` and `124` to demonstrate that consent still limits the app to `123`.

Supply these environment variables from your local secret manager or deployment:

| Variable | Value |
| --- | --- |
| `BFF_TENANT` | Configured Mayi tenant ID |
| `BFF_ISSUER` | Exact issuer, such as `https://auth.example/t/a` |
| `BFF_CLIENT_ID`, `BFF_CLIENT_SECRET` | Registered client and generated secret |
| `BFF_ORIGIN` | Application HTTPS origin, with no trailing slash |
| `BFF_RESOURCE` | Exact registered API audience |
| `BFF_OBJECT_TYPE` | Resource-owned versioned object/action type URI |
| `BFF_ENCRYPTION_KEY` | A secret, random 32-byte key encoded as unpadded base64url |

Run `go run ./examples/bff`. It listens on `127.0.0.1:8081`; put it behind the
application's same-origin HTTPS reverse proxy. Route `/login`, `/callback`,
`/documents/*` and `/logout` to it. Visit `/login`; the callback returns to
`/documents/123`. `/documents/124` must fail. Logout is a same-origin POST with an
exact `Origin` header; it ends this application's session, not the Mayi grant.
No CORS origins are reflected or enabled by this example.

For an existing Go backend, compose `app.New` into its router instead of running
the standalone command. The example has its own package boundary and imports no
privileged Mayi code. Other backend languages can implement the same public wire
contract: server-side PAR/S256, browser-bound state and nonce, single code exchange,
ID-token validation, encrypted application session, serialized refresh and fixed
API forwarding. Browser code receives no OAuth credential or PKCE verifier.

The included store is an intentionally bounded single-process reference. Restart
invalidates all sessions. A durable/multi-replica integration must replace it with
a store that authenticates the cookie before exposing encrypted state, serializes
one session across replicas, maintains monotonic generations and durably records
the refresh claim before network I/O. Never retry an old refresh token after a
timeout or lost response; require sign-in again if its outcome is uncertain.

Encryption uses AES-256-GCM with a fresh standard-library nonce and AAD bound to
tenant, issuer, client, audience, session, purpose, generation, key and envelope
version. Changing any binding fails decryption. Retain old keys only for bounded
decryption during rotation and coordinate the per-key message budget across
replicas. AAD contains identifiers and supplies integrity, not confidentiality or
whole-record rollback protection. See [ADR 0023](../../docs/adr/0023-p2-live-lifecycle-and-bff-encryption.md).

`go test -race ./examples/bff/...` covers encryption/context substitution, rotation
and serialized/uncertain refresh. `go run ./tools/p0` additionally runs the real
PostgreSQL/OpenBao BFF and resource integration fixture. These are application and
protocol tests; they do not claim embedded-browser compatibility or production
readiness.
