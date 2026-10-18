package identity

import (
	"strings"
	"time"

	"github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
)

// SessionLifetime is the fixed absolute cap of the initial login preview.
// Configurable idle/absolute policy is a later P2 capability.
const SessionLifetime = time.Hour

// Login is the short-lived, single-attempt correlation to one configured IdP
// and one authorization transaction. Only hashes of browser secrets persist.
type Login struct {
	TenantIssuer                                                                                 grants.Scope
	ProviderID, ProviderHash, StateHash, BrowserHash, AuthorizationHash, NonceHash, VerifierHash string
	CreatedAt, ExpiresAt                                                                         time.Time
}

func (l Login) Valid() bool {
	return l.TenantIssuer.Valid() && resources.ValidID(l.ProviderID) && authorization.ValidHandleHash(l.ProviderHash) &&
		authorization.ValidHandleHash(l.StateHash) && authorization.ValidHandleHash(l.BrowserHash) &&
		authorization.ValidHandleHash(l.AuthorizationHash) && authorization.ValidHandleHash(l.NonceHash) &&
		authorization.ValidHandleHash(l.VerifierHash) && !l.CreatedAt.IsZero() && l.ExpiresAt.After(l.CreatedAt) &&
		!l.ExpiresAt.After(l.CreatedAt.Add(5*time.Minute))
}

func (l Login) ActiveAt(now time.Time) bool {
	return l.Valid() && !now.Before(l.CreatedAt) && now.Before(l.ExpiresAt)
}

// Assertion contains identity evidence, never a local authorization decision.
// The upstream issuer/subject pair must be explicitly mapped by the operator.
type Assertion struct {
	Issuer, Subject string
	AuthenticatedAt time.Time
}

func (a Assertion) ValidAt(now time.Time) bool {
	if len(a.Issuer) == 0 || len(a.Issuer) > 2048 || len(a.Subject) == 0 || len(a.Subject) > 255 || strings.TrimSpace(a.Subject) != a.Subject {
		return false
	}
	for _, r := range a.Subject {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return !a.AuthenticatedAt.IsZero() && !a.AuthenticatedAt.After(now.Add(30*time.Second)) && !a.AuthenticatedAt.Before(now.Add(-5*time.Minute))
}
