# ADR 0002: Authoritative online resource decisions

Status: Accepted for the P0 baseline · 2026-10-17

The supported strict profile makes a fresh authoritative authorization decision for every protected request. A JWT establishes a signed permission ceiling; it is insufficient by itself to prove that the grant, user, client, actor, family or token remains active. Local permission evaluation intersects that ceiling with current resource permissions.

PostgreSQL is the initial authority. Read revocation status from the authoritative consistency boundary, not an asynchronous replica. The revocation operation commits its state and audit before acknowledging success. A resource decision that begins after that acknowledgement must observe the revocation. An operation authorized before revocation may already have begun; the system cannot undo an earlier disclosure. Long-running streams and operations require explicit reauthorization/cancellation contracts.

Resource/AS partitions, unavailable replay state and ambiguous status fail closed. Do not add positive caches, replica reads or offline JWT fallback to this profile. Push events may accelerate disconnects or eviction but cannot replace authoritative status. A future availability-oriented profile must state its bounded staleness separately and cannot advertise immediate revocation.

Keep online calls regional and measure the latency budget. OPS-3 is a performance objective, not permission to weaken this consistency contract. Preserve data residency when choosing authority placement.

Evidence: P0 fixtures reject a revoked root and a policy-version mismatch and serialize issuance/replay in a transaction double. They do not implement the resource SDK, status endpoint, cross-replica linearizability, streams or the latency target. Those remain P1–P6 work.

Related: GRANT-2, GRANT-9, LIFE-9, DEL-6, FED-9, OPS-3.
