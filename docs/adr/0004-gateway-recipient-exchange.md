# ADR 0004: Explicit resource-recipient exchange profile

Status: Accepted design; disabled pending P4 proof · 2026-10-17

Mayi supports a gateway receiving a token whose audience is the gateway. It does not require the gateway to possess the end user's DPoP private key. The gateway verifies the original HTTP request and proof at its own resource boundary, authenticates independently to Mayi as a confidential client and presents the incoming token for an explicitly permitted downstream exchange.

The exchange service must verify the subject token's signature/purpose/status, exact receiving audience, tenant, root/revision and ancestry. A versioned administrative edge must connect this authenticated gateway client, incoming resource and downstream resource. The edge limits scope mapping, operations, actor authority, hop count, lifetime and sender-binding method. Possession of a subject token alone is insufficient. An optional actor token is verified for its own purpose and may further restrict authority; it cannot replace authenticated client identity.

Rebinding to the gateway's key requires a fresh proof by that key on the exchange request. The new audience is one declared downstream resource, the original user remains the subject, and the current authenticated gateway is the outer actor. Preserve earlier actors, parent ID, revocation dependencies and root/revision. Compare resource-specific scopes only through the approved attenuation map. Reject loops, undeclared edges, unexpected actor identities, increased authority and overlong lifetimes.

This profile trusts the gateway to enforce the user's original request proof and intended operation. A malicious authorized gateway can misuse authority within its declared edge; sender binding does not remove that trust. Use a narrower operation/context assertion or transaction-token profile if the deployment requires verifiable per-operation intent. That is a separate profile with its own fixtures.

Generic proof-of-possession exchange, cross-tenant exchange, arbitrary foreign issuers, browser clients presenting another resource's token and undeclared rebinding are disabled. RFC 8693 plus RFC 9449 alone does not define or prove this topology.

Required P4 evidence: live root-status lookup; proof-key possession; recipient/audience checks; allowed-edge and scope-map tests; ancestor revocation; bounded actor chains; gateway-to-resource end-to-end interoperability and denial cases. P0 has not implemented this flow. This ADR resolves the trust model without advertising the capability.
