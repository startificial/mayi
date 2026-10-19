# ADR 0019: Resource-owned guarded consent display

Status: Implemented application/display foundation · 2026-10-18 · Production resource adapter and object approval remain pending

## Ownership and trust

The resource owns current object permissions and safe display metadata. Mayi owns request correlation, authentication, consent/session binding and durable grant approval. Registering a type or holding a pushed reference does not authorize reading an object title. Add `authorization.ObjectConsentProjection` as an immutable, bounded display/correlation value: exact workflow hash, client, authenticated subject, nonzero resource permission version, exact requested ceiling and one safe label for every requested type/object. Its constructor rejects missing/extra/duplicate/foreign display entries and invalid labels. The value checks structure and exact correlation; constructing it does not authenticate its supplier or prove permission.

The consuming authorization service owns `ObjectConsentAuthority`. Its input contains only trusted tenant/issuer/subject, client/workflow correlation and requested tuples. It excludes session credentials, CSRF, state, redirect and object payloads. The provider must authorize every requested tuple using narrow authoritative metadata **before** reading labels, return generic denial for absent/foreign/forbidden objects, then hold current permission/display state stable through the synchronous callback and its Mayi commit. No retries, asynchronous callbacks or cached positive decisions are permitted. Any remote implementation needs equivalent resource-owned coordination; a version string or a final HTTP boolean check alone cannot prevent a permission change before commit. Resource writers must participate in the same guard.

There is no production implementation or wire contract for that provider in this slice. `app.NewObjectAuthorization` requires an explicit integration, while the existing server's `NewAuthorization` supplies none and remains closed to object display. The PostgreSQL fixture is a separate authoritative resource owner used only for integration tests, not a Mayi permission cache or a supported deployment adapter. A production adapter requires its own trust, bounded transport/egress, outage and race evidence before server composition selects it.

## Read, guard, recheck and bind

Reuse `PrepareConsent` and the existing authorization store/unit of work:

1. Authenticate the session/member and authorize the workflow/browser reference through the existing narrow projection. A transaction-local recheck precedes loading the request snapshot.
2. Validate pending state, exact tenant/browser/session correlation, lifetime, current client/resource/type vocabulary, tenant policy and nonempty typed authority with PAR provenance. The initial transaction finishes without session binding, audit or other effects for object requests.
3. Acquire the resource guard outside any Mayi transaction/pool connection. The resource authorizes the complete requested tuples before returning a minimal display projection.
4. While that guard remains held, open a fresh Mayi transaction, repeat session/reference/policy/registration checks, and compare the immutable request/policy/PAR snapshot and projection correlation again. A session or policy change during resource acquisition must deny.
5. Bind the consent session and audit/outbox atomically using the existing operation. Return the display only after this commit and successful provider return. The guard spans commit and is released on success, denial or failure.

There is no external call while a Mayi coordination lock or pool connection is held. Do not add resource writers that acquire Mayi locks and then the resource guard: preserve resource guard → final Mayi transaction order to avoid cycles. Provider callbacks are trusted infrastructure contracts; the service rejects missing/repeated callbacks and swallowed callback errors but cannot undo a commit if a broken provider reports failure after the callback completed. Such an outcome returns no display and is uncertain, consistent with the existing recovery strategy.

The service emits only requested objects/actions, preserving their order and full type/identifier relationship. Names come from the authorized resource projection; action names/descriptions come from registered immutable vocabulary. It does not display the user's other authorized objects or extra actions. The web component renders these explicit values with HTML escaping and visible type/identifier references. The handler only maps the service result to the view model.

## Approval and recovery gate

`DecisionAvailable` is false for this object display. The page offers no approval/denial submission for an unavailable decision; the service's `Decide` independently continues to reject all typed requests. Rendering is not approval evidence. Scope-only preview fixtures retain their existing behavior until the universally required RAR/PAR cutover; they are not a compatibility mode.

The next slice must persist the exact displayed ceiling/projection version as immutable consent evidence and connect current resource authorization through the approval commit, reusing the existing atomic workflow/revision/code/audit path. A permission/version change must not silently approve a different display or widen authority. Then complete production provider/endpoint composition, mandatory cutover, token propagation and enforcement. No public PAR route, object code issuance, discovery capability or full requirement completion follows from this display slice.

Permission, session and policy denial returns no display or new binding. Commit/audit/provider failure returns no display; a failed provider response after a successful callback can leave a committed session binding. Do not infer rollback or retry safety from an HTTP status. There is no new local error code or enabled endpoint; future provider/protocol errors follow the existing [error strategy](../error-handling.md).

## Evidence and limits

Domain tests cover immutable labels, exact ceiling/workflow/client/subject correlation and missing/extra/foreign displays. Service tests cover authentication before payload/provider access, resource denial before display, final session/policy/registration/expiry checks, projection substitution, no entropy/approval, commit failure and provider callback contract failures. Web tests cover escaped labels/actions, visible exact references and unavailable decisions.

Real PostgreSQL tests implement authoritative resource-owned permission/label rows in an isolated fixture schema. Shared row locks block `FOR UPDATE NOWAIT` permission/display changes while the guard spans the final Mayi commit; the callback observes committed session binding before the resource guard releases. Fresh permission loss denies before label reads. Foreign/missing/forbidden references, session revocation during guard acquisition and audit/outbox failure yield no returned display and no partial binding. These tests do not establish a production external-resource protocol, browser/provider interoperability or object token enforcement.

No dependency, tool, license exception or schema migration is added. Package ownership and the canonical layout remain unchanged. This is partial RES-10/GRANT-1 evidence; the P2 exit demonstration and full specification conformance remain pending.
