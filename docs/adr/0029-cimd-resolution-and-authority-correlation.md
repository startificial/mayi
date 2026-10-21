# ADR 0029: CIMD resolution, shared caching and host policy

Status: accepted for the P3 experimental public-client profile.

## Ownership and trust

CIMD extends the client registry capability implemented by
`services/administration`; it reuses the same client/vocabulary/lifetime
validation and tenant management unit of work as operator registration and DCR.
`domain/clients` owns exact URL identity, host admission, callback exceptions and
the accepted-configuration fingerprint. The existing credential, authorization
and token services consume narrow metadata-resolution contracts. HTTP fetching
and parsing belong to `outbound/egress`; PostgreSQL implements shared cache/CAS
and authority persistence. This preserves the canonical modular monolith.

All HTTPS URL client IDs in this implementation are reserved for CIMD. Ordinary
administrator-created and DCR IDs cannot enter that namespace. Accept only an
exact ASCII HTTPS DNS URL up to 2048 bytes, with a path, absent/default 443 port,
no query, fragment, userinfo, backslash or decoded dot segments. Literal IPs and
noncanonical hosts are rejected. This is a deliberately bounded -02 profile,
not a claim that the draft forbids all other URL forms.

The public profile requires explicit `token_endpoint_auth_method: none` and
`authorization_code` plus `refresh_token`, with query/code response and mandatory
DPoP, PAR, S256 and typed RAR. It rejects shared secrets, key metadata,
private_key_jwt, software statements and unsupported security fields rather than
silently enabling them. Previously registered confidential clients retain the
existing private_key_jwt capability; confidential CIMD is not implemented here.
Self-declared names do not establish publisher reputation or authentication.
Consent shows the fetched HTTPS metadata host, exact client ID and actual callback.

## Admission and callbacks

The tenant's versioned CIMD policy has `any`, exact `hosts`, and `admin_only`
modes. The default is administrator-only with no approved URLs. Host rules do
not imply subdomain or suffix approval. Administrator approvals identify the
entire exact URL, including path and explicit :443. The policy also bounds
resource/RAR vocabulary, lifetime and cumulative CIMD registrations. Those
ceilings establish catalog eligibility, never subject/object permission.

Web callbacks must be same-origin with the metadata document. Native and
cross-origin callbacks require an exact administrator-reviewed exception for
that exact client URL, then still obey the existing application callback rules.
The native loopback port exception applies only after this registration check;
the actual runtime callback remains pinned in PAR and the code.

Restrictive configured CIMD admission cannot be bypassed with public DCR. Close
DCR before setting `hosts` or `admin_only` (otherwise 409); opening DCR while
those modes are configured is denied. `any` permits the separate DCR opt-in and
its own quotas/initial credential. Existing DCR registrations retain ADR 0028's
admission-only semantics; use grant revocation for their current authority.

## Fetching and cache semantics

Every untrusted fetch uses the existing constrained transport with no development
loopback exception: DNS answers are checked, actual connections dial approved
literals, TLS checks the original host, environment proxies and redirects are
refused, and private/reserved/mapped/link-local destinations fail. The profile
allows application/json only, a 32 KiB body, bounded headers/time, 16 JSON nesting
levels and a token-count limit. Duplicate/case-aliased members, malformed input,
identity mismatch and unsupported security metadata fail. Unknown ordinary
metadata is ignored, not displayed or fetched.

The shared PostgreSQL cache contains only successfully validated known metadata
and bounded HTTP validators. Honor max-age/s-maxage, Age/Date/Expires, no-cache,
no-store and private, with a five-minute upper bound and no heuristic freshness.
Unsupported Vary and Set-Cookie disable reusable storage. No-cache retains a
validated representation for conditional requests but never serves it as fresh.
No-store/private remove the reusable document, validators and freshness. They do
not erase the registry's accepted security configuration or the immutable
request/credential correlation required by the authorization workflow. Those
records are application security state, not a fallback HTTP cache. Do not promise
zero application retention based on HTTP cache directives.

At critical presentation, approval, denial redirect and credential redemption,
revalidate even a still-fresh cache. Use If-None-Match, otherwise
If-Modified-Since. A 304 is usable only for an already validated representation
and a sent validator; unsolicited 304 and every redirect fail. The -02 draft's
200-only wording and the plan's conditional-fetch requirement need this explicit
HTTP-cache interpretation. It is recorded in the pinned specification profile;
no full external conformance claim is made. Missing freshness on 304 gives no
new reusable lifetime. Error/invalid responses are never cached; a failed fetch
purges the prior reusable entry and does not fall back to stale positive data.

## Consistency and lifecycle

A tenant-shared 600/minute budget precedes cache/network access. Host admission
precedes loading client/cache state. Fetch outside database locks; then recheck
the policy version, exact client, enabled state, cache generation, quota and
catalog inside the tenant coordination lock. A late response cannot overwrite a
newer replica result or a policy change. No callback is retried inside a unit of
work. Successful configuration/cache changes and required lifecycle audit/outbox
commit atomically; a failed audit returns no admitted client.

Fingerprint the accepted name, callbacks, application type, server-assigned
catalog/lifetime and policy version with SHA-256, then bind it to a monotonic
accepted-metadata revision. A later restoration of an earlier document cannot
resurrect old credentials. Cache generation and accepted revision are distinct: a
304 changes cache state without invalidating unchanged authority. PAR and the authorization
transaction pin that digest; codes, refresh credentials and issuances retain it.
Final guarded decisions and issuance check the current digest and policy version
under the existing tenant lock. A detected change prevents old workflows/codes
from silently adopting new metadata. Rejected redemption consumes no credential.
Online status rejects an old issuance after accepted metadata changes or a
policy-version change. Restore metadata dependencies and start fresh authorization;
revoking prior grants may be necessary when changing the allowed vocabulary.

CIMD policy changes intentionally invalidate existing CIMD credentials until new
authorization. This differs from DCR's static registration admission and is part
of the CIMD public contract. Existing local JWT-only checks are still insufficient
for immediate cutoff; the resource SDK's authoritative online decision is required.

Resource/type binding rows remain immutable. CIMD retains historical bindings
and separately projects its current accepted catalog; all auth/registration
queries use that current projection. Long URL plus long RAR type keys use a
SHA-256 index component to fit PostgreSQL's btree limit. This does not replace
full-string tenant/client/type comparisons or make digests client identities.

Apply additive migration 19 with the separate owner connection. No dependency,
tool, extension or license is added. P3 evidence separates synthetic metadata
transport fixtures from real PostgreSQL/OpenBao/protocol behavior, and retains
separate constrained-transport/cache wire tests. Browser-held-token and broader
interoperability/certification gates remain outstanding.
