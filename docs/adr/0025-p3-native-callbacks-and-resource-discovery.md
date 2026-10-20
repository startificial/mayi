# ADR 0025: Native callbacks and resource-owned discovery

Status: Accepted. First P3 implementation slice; P3 remains in progress.

## Ownership and contracts

Client registration owns application type and callback matching. The existing
administration service remains the only registration mutation path in this slice;
no DCR endpoint or CIMD fetch is enabled. Authorization reuses that client's
callback rule during PAR and every subsequent registration recheck. Native
applications are public (`none`), including those using claimed HTTPS redirects.
Application type does not prove publisher ownership or confer trust.

`domain/clients` selects web or native rules. Omitted application type retains
the web default. Web and native claimed-HTTPS callbacks compare exact bytes.
Native HTTP callbacks allow exactly IPv4 `127.0.0.1` or IPv6 `[::1]`; registration
may omit a port and authorization may supply any valid port. Only the port varies:
host/address family, escaped path and fixed query bytes remain exact. DNS names,
alternate numeric forms, mapped addresses and wildcard hosts are refused.
Private callbacks require a lowercase reverse-domain scheme with one slash and
no authority. Their complete callback matches exactly. Reserved authorization
response query members are rejected for both registration types.

The actual requested callback is immutable in PAR, the authorization transaction
and the code. The native port exception applies only to matching registration;
code redemption still compares the actual original URI exactly when supplied.
S256, one-use codes, required RAR/PAR, audience, refresh rotation and authoritative
revocation are unchanged. Browser consent uses a narrowly derived CSP destination;
custom schemes require a scheme source because CSP has no host for those URIs.
This source does not replace exact service callback checks or make consent frameable.

Migration 15 stores `application_type` and reinforces the public-only native rule
in PostgreSQL. Existing registrations retain web type. The migration is explicit
and runtime startup validates its ledger; runtime never migrates on startup.

## Resource discovery and failures

The registered resource is an API audience; a protected object inside that API
keeps its separate resource-owned policy. The existing resource context owns a
bounded public capability projection. `services/resource` validates and snapshots
the projection and public permission hints; the bounded `pkg/resource` boundary
composes it and maps JSON/HTTP. No database, ACL lookup or server administrative
runtime is added to the SDK.

RFC 9728 metadata is served by the resource's own listener. Its HTTPS URL inserts
`/.well-known/oauth-protected-resource` before the audience's exact escaped path.
Separate audiences on one origin have separate documents. Deployment configuration
sets the exact resource and issuer; request Host/forwarding headers cannot change
them. Metadata advertises only explicitly public scopes/types and header transport.
Signed metadata, multiple-AS selection, DPoP algorithm/required advertisement and
metadata fetching are outside this slice.

Resource HTTP failures retain their own OAuth shape, without the server's local
management envelope. Missing credentials receive 401 with discovery and no error;
malformed/duplicate/unsupported credential transport receives 400 invalid_request;
invalid/foreign/inactive or object-denied authority receives generic 401
invalid_token. Insufficient permission scope is a typed denial established only
after valid local audience/tenant/credential/object ceilings, before any protected
payload or current-permission load. It receives 403 insufficient_scope with an
optional explicitly configured public scope hint. Unknown object ACLs never become
scope hints. Unavailable authority receives 503 without an authentication challenge;
unclassified application errors receive fixed 500. No error text or token is echoed.

## Evidence and remaining scope

`tests/conformance/p3-evidence.json` links native domain, consent-response/CSP,
real PostgreSQL/OpenBao PAR/consent/redemption, SDK transport/challenge, metadata
isolation, service authorization-order and current ACL/revocation fixtures. CI
checks test references and normative pins, then runs their behavior tests. Traceability
does not prove all RFC sections, native OS associations or browser compatibility.

Unknown-client CIMD/cache/digest coordination, DCR/quotas/initial access credentials,
tenant client policy, remaining token/resource DPoP/nonce evidence and the browser
WebCrypto sample remain P3 work. This change adds no dependency, tool or license
exception and makes no complete P3, MCP or production conformance claim.
