# ADR 0028: bounded public dynamic client registration

Status: accepted for the P3 experimental preview.

## Ownership and decision

The client-registration capability continues to use `domain/clients` for client
and callback invariants and `services/administration` for registry mutations.
Public registration and administrator creation invoke one shared registration
validation operation; protocol handlers do not decide catalog eligibility.
The new client-registration admission policy is distinct from tenant token
policy and durable grants. It neither establishes publisher trust nor grants
user/object authority. This retains the modular monolith and canonical layout.

Expose RFC 7591 `POST /t/{tenant}/register` only when interactive authorization is
configured. Discovery advertises the same configured endpoint. The implemented
profile accepts public web/native interactive clients with explicit `none`
authentication and `authorization_code` plus `refresh_token`. It requires
DPoP and retains PAR, S256, typed RAR, user consent, exact callback binding,
immutable revisions, online revocation and rotating refresh families.
Unsupported confidential/machine registration, software statements and client
management remain separate capabilities. This is not full RFC/OIDC registration
or MCP interoperability certification. Missing authentication metadata selects
RFC 7591's unsupported confidential default and is rejected; the profile also
requires an explicit grant list to avoid silently expanding a client's request.

## Admission and consistency

An absent stored registration policy means version 1 `admin_only`. An operator
with `clients:write` may publish `open` policy with bounded resource-ID/RAR-type
ceilings, token lifetime, a cumulative dynamic-registration quota and optional
initial-access requirement. `clients:read` permits its protected projection.
Updates compare the exact policy version under the tenant coordination lock.
Every registration rechecks the current admission policy, quota, resource/profile
registrations and token-policy ceilings under that same lock; client, immutable
provenance, security audit and outbox commit together. Failed commit returns no
client. Disabling registration affects new admissions, not existing grants;
use grant revocation for immediate authority cutoff.

The quota counts all successful dynamic registrations, including disabled
clients. There is no automatic expiry or quota-reclamation endpoint in this
slice. Runtime privileges cannot update/delete provenance to recycle capacity.
The shared PostgreSQL request budget permits 60 service-level attempts per tenant
per minute, independent of attacker-selected IDs or credentials. It commits
before the registration transaction; denial/rollback does not refund attempts.
Malformed wire requests remain subject to bounded parsing and process deadlines.
Dependency failures fail closed.

An optional initial-access token is a separately generated 256-bit credential
whose SHA-256 digest is trusted tenant startup configuration. It cannot reuse an
administrator or another tenant's configured credential. Verification uses a
constant-time comparison. The token authorizes registration only, is never
returned in a response/audit, and never creates confidential authentication or
publisher trust. Rotate/revoke it by replacing/removing its digest and restarting
all replicas. A supplied invalid token is rejected even under anonymous admission.
No registration-management token is issued; RFC 7592 remains P7.

## Untrusted presentation and remaining work

Names are self-declared, callbacks select no authority, and registration never
skips consent. Consent explicitly distinguishes registration from publisher
verification and displays the actual callback. Unknown ordinary metadata is
ignored and not reflected; ambiguous duplicate/case-aliased members, nulls,
oversized bodies and unsupported security metadata are rejected.

CIMD resolution, constrained-fetch caching/digest correlation and approved-host
admission are still outstanding. An alleged DCR `client_uri`, name or callback
cannot substitute for verified CIMD host control. The open/admin-only DCR policy
must not be presented as completion of CLI-14's CIMD-host policy.

Apply additive migration 18 with the separate owner role before the upgraded
runtime. No dependency, tool or license change is required. Executable evidence
is in `tests/conformance/p3-evidence.json`, including real PostgreSQL concurrency,
audit rollback, initial-access failures and use of the existing live OAuth flow.
