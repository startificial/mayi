# ADR 0021: PostgreSQL resource authority and atomic consent

Status: Accepted for the first P2 resource adapter. Public PAR/browser cutover and resource enforcement remain separate gates.

The maintainer selected PostgreSQL as the first resource-owner integration, after considering HTTP coordination. The authorization context continues to own consent; the resource owns current object permissions and safe display names. This decision does not make Mayi the owner of application ACL policy.

## Consistency boundary

A lock held on a separate database connection cannot prove it remained held through an independent Mayi commit when connections fail. Checking the connection before or after commit does not close that interval. A plain HTTP boolean or expiring lease has the same problem. The first supported PostgreSQL integration therefore requires the resource-owned projection and Mayi tables in the **same PostgreSQL database**, with different schemas and owners. Both the resource read locks and Mayi consent writes use one physical transaction. Separate databases, asynchronously copied ACLs and uncoordinated HTTP authorities are unsupported by this adapter.

`postgres.ResourceConsent` implements the authorization service's existing authority port. After the service's initial authorized, effect-free read has finished, it acquires one pooled connection, sets exact tenant/issuer/resource RLS context, locks the principal/resource authority root, checks every requested tuple, and then locks only the requested label rows. Labels never include object bodies. Missing, foreign, disabled or forbidden authority returns the same denial without reading labels.

The authority invokes its callback once with a context carrying cancellation and a private transaction-enlistment value. The service propagates that context unchanged to its final unit of work; it never inspects an adapter value or receives a driver handle. The matching PostgreSQL store enlists once, repeats session/policy/workflow authorization, performs the existing presentation or approval operation, and commits that same transaction. A different store/scope or second enlistment is rejected. The authority rejects success without a confirmed commit. Loss of the resource connection makes the Mayi commit fail too. Raw credentials and views are returned only after this boundary succeeds.

This refines ADR 0019's pool-acquisition rule: no Mayi **policy/workflow lock** is held while acquiring the resource guard. One connection now owns the resource guard and final Mayi unit of work, avoiding both nested pool acquisition and a distributed atomicity claim. No new service, universal repository or second consent implementation is introduced.

## Owner contract and privileges

The resource owner installs [deploy/resource-authority.sql](../../deploy/resource-authority.sql) with its own migration role. It is not a Mayi migration or runtime provisioning operation. The three tables expose authority roots, permission decision metadata and display labels. Tenant, issuer and resource are explicit predicates and forced RLS boundaries.

Permission writers lock the principal/resource root first and update their source ACL and this authoritative projection synchronously in the same transaction. Database triggers require that root and advance its permission generation for permission insert/update/delete and authority changes. Label writes conflict with the exact locked display rows. Use the documented lock order: authority roots in stable order, permission rows, labels in type/identifier order; if an application transaction also touches Mayi, acquire Mayi coordination locks afterward. Retry deadlock-aborted owner transactions as whole transactions, never callbacks containing external effects.

The Mayi runtime receives SELECT and only UPDATE on inert lock-marker columns, because PostgreSQL requires an UPDATE privilege for locking SELECTs. It receives no ACL, identity, enabled, version or label-content write privilege, schema ownership, TRUNCATE or trigger privilege. Startup checks reject missing contract tables, missing coordination triggers, unforced RLS and excessive runtime privileges. Operators with ownership can change the trust boundary and must preserve the contract. Mayi does not certify an arbitrary application ACL schema or managed-provider/pooler configuration.

Tenant configuration may list exact `resource_authorities` audiences. Browser composition wires only those audiences; an empty list keeps resource consent closed. This setting alone does not enable PAR/RAR browser routes or advertise capabilities.

## Scaling and failure behavior

Readers share principal/resource root locks; unrelated principals can change permissions independently. An ACL write waits only for guarded operations concerning that principal/resource. Display changes wait for readers of the same object. The guard has bounded connection/statement/lock timeouts and holds no locks during a user's time reading the consent page. Approval reacquires current state and compares it with the immutable first presentation.

This favors correctness and a small reference deployment. Hot principals, label updates and pool saturation can cause contention or unavailability. A network-partitioned or slow authority fails closed. A commit response lost after database commit remains an uncertain outcome; do not automatically retry one-use workflows. Supporting independent resource databases or a polyglot HTTP fleet needs a separately reviewed durable coordination/fencing protocol and recovery evidence. It is not accomplished by replacing SQL with a remote permission check.

## Evidence and limits

`tests/integration/resource_consent_test.go` exercises the real restricted runtime, a one-connection pool, permission-before-label denial, foreign scope, root/label locks, permission generation, approval, connection termination and startup privilege/trigger/RLS rejection. Existing authorization tests retain denial, immutable presentation, audit rollback and concurrent approval coverage. No new dependency or license exception is added. This does not establish public protocol interoperability or the P2 resource SDK exit condition.

References: [PostgreSQL locking](https://www.postgresql.org/docs/17/explicit-locking.html) and [locking SELECT privileges](https://www.postgresql.org/docs/17/sql-select.html).
