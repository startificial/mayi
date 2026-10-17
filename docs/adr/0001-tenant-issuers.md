# ADR 0001: Immutable tenant issuers

Status: Accepted for the P0 baseline · 2026-10-17

Each tenant receives a stable, opaque identifier and the issuer `https://<configured-origin>/t/<tenant-id>`. Issuers are immutable after provisioning. Renaming an organization changes its display name, never its issuer. Moving an issuer is a separate migration with explicit client/resource reconfiguration; it is not a redirect or alias.

The origin comes from validated deployment configuration. HTTP `Host`, `Forwarded`, email domains, tenant slugs and caller-supplied tenant IDs cannot select authority. Resolve the route to a provisioned tenant and compare the exact configured issuer. Every credential, grant, key, trust configuration and storage query carries that tenant scope. Two tenants never share an authorization namespace accidentally.

OAuth metadata for a path issuer follows RFC 8414's well-known path insertion rules; OIDC discovery follows OIDC Discovery's issuer-path rules. They must return identical issuer values even though the discovery paths differ. Endpoints and metadata never derive origin from an inbound request.

Evidence: `internal/app/config_test.go` exercises stable distinct issuer derivation and rejects ambiguous/insecure configuration. `tests/contract/issuance_test.go` rejects tenant and issuer mismatches before reading grant payloads. PostgreSQL tenant constraints, key isolation, routing and discovery are P1 work and remain unverified.

Related: ADM-1, ADM-2, DISC-1, DISC-2, RES-8; [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414#section-3).
