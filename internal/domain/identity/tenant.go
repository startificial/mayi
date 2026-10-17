// Package identity contains tenant identity and public signing-key values.
package identity

// PublicKey contains public P-256 coordinates only. Private material never
// crosses the signing port. Version identifies a pinned Transit key version.
type PublicKey struct {
	ID, X, Y string
	Version  int
}
