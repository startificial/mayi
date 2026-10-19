package grants

import (
	"context"
	domain "github.com/startificial/mayi/internal/domain/grants"
	"time"
)

type Clock interface{ Now() time.Time }
type BrowserProof struct {
	Scope                    domain.Scope
	SessionHash, BrowserHash string
}
type Summary struct {
	ID, ClientID, Resource, Subject string
	Revision                        uint64
	Scopes                          []string
	Objects                         domain.ObjectCeiling
	ExpiresAt                       time.Time
	TokensIssued                    uint64
	LastIssuedAt                    *time.Time
	LastUsedAt                      *time.Time
	TokenChecks                     uint64
}
type Operator struct {
	Scope       domain.Scope
	ID          string
	Permissions []string
}
type Store interface {
	WithUserGrants(context.Context, BrowserProof, time.Time, func(UserGrants) error) error
	RevokeAdministrator(context.Context, domain.Scope, string, string, string) error
	ListAdministrator(context.Context, domain.Scope, string, int) ([]Summary, error)
}
type UserGrants interface {
	List(context.Context) ([]Summary, error)
	// Owned authenticates only the caller's grant reference, without loading its
	// permissions or resource payload. Revoke requires this decision under lock.
	Owned(context.Context, string) (bool, error)
	Revoke(context.Context, string) error
}
