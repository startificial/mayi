# ADR 0016: Developer error contracts and recovery

Status: Accepted design; local JSON foundation implemented, full P2 coverage pending.

## Decision

Keep errors owned by their bounded capability. Domain/application errors contain no HTTP or protocol-library types. Inbound adapters translate typed errors into endpoint-specific responses; no universal wire wrapper or central business-error registry is introduced.

Preserve the existing local JSON `error` codes and statuses. Add a fixed safe `message` and an optional generated `request_id` matching the response header. Clients must tolerate additive fields and must not classify by message. The transport helper admits only documented code/status combinations and falls back to a fixed HTTP 500 on a programming error. It never accepts raw exception text as a public description. The local catalog is a transport contract, not a competing domain model.

OAuth responses, authorized redirects, resource challenges, introspection and revocation retain their standard-specific contracts. Do not insert local envelope fields into Fosite responses or expose credential/tenant/object existence through diagnostic detail. Do not suggest automatic replay of one-use credentials or infer rollback from a timeout/5xx.

## Evidence and delivery gate

[The strategy and troubleshooting guide](../error-handling.md) defines the compatibility, validation, recovery and future Go SDK contracts. [The catalog](../error-catalog.json) documents current local responses. HTTP contract tests compare definitions and documentation and test fallback, correlation, headers, redaction and wrapped service-error mappings; CI runs them explicitly and in the full race suite. No dependency is added.

CORE-13 begins with this P2 foundation; resource challenge/discovery extensions retain their P3 acceptance. The P2 preview cannot exit without tested error contracts and safe recovery examples for every enabled surface. The public SDK, field diagnostics, complete OAuth mapping and full audit correlation remain pending until their runtime evidence exists.
