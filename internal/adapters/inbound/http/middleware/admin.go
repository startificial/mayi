// Package middleware establishes trusted management identity at the httptransport.
package middleware

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	httptransport "github.com/startificial/mayi/internal/adapters/inbound/http"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/administration"
	"net/http"
	"slices"
	"strings"
)

type Credential struct {
	SHA256 string
	Actor  administration.Actor
}
type credential struct {
	digest [32]byte
	actor  administration.Actor
}
type Credentials struct{ entries []credential }
type actorKey struct{}

func New(entries []Credential) (*Credentials, error) {
	if len(entries) == 0 || len(entries) > 256 {
		return nil, administration.ErrInvalid
	}
	c := &Credentials{}
	seen := map[string]bool{}
	for _, entry := range entries {
		bytes, err := hex.DecodeString(entry.SHA256)
		canonical := hex.EncodeToString(bytes)
		if err != nil || len(bytes) != 32 || seen[canonical] || !entry.Actor.Scope.Valid() || entry.Actor.ID == "" {
			return nil, administration.ErrInvalid
		}
		seen[canonical] = true
		var digest [32]byte
		copy(digest[:], bytes)
		actor := entry.Actor
		actor.Permissions = slices.Clone(actor.Permissions)
		c.entries = append(c.entries, credential{digest, actor})
	}
	return c, nil
}
func Actor(r *http.Request) administration.Actor {
	actor, _ := r.Context().Value(actorKey{}).(administration.Actor)
	return actor
}
func (c *Credentials) Protect(scope grants.Scope, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			httptransport.Error(w, 403, "forbidden")
			return
		}
		values := r.Header.Values("Authorization")
		if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || len(values[0]) != 50 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mayi-admin"`)
			httptransport.Error(w, 401, "invalid_token")
			return
		}
		digest := sha256.Sum256([]byte(strings.TrimPrefix(values[0], "Bearer ")))
		var actor administration.Actor
		for _, entry := range c.entries {
			if subtle.ConstantTimeCompare(digest[:], entry.digest[:]) == 1 {
				actor = entry.actor
			}
		}
		if actor.ID == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mayi-admin"`)
			httptransport.Error(w, 401, "invalid_token")
			return
		}
		if actor.Scope != scope {
			httptransport.Error(w, 403, "forbidden")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorKey{}, actor)))
	})
}
