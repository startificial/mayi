package authentication

import (
	"context"
	"github.com/startificial/mayi/internal/domain/grants"
	"time"
)

type SessionProof struct {
	Scope                    grants.Scope
	SessionHash, BrowserHash string
}
type SessionInfo struct {
	Reference                        string
	Current                          bool
	CreatedAt, LastUsedAt, ExpiresAt time.Time
}
type SessionControlStore interface {
	TouchSession(context.Context, SessionProof, time.Time) error
	ListSessions(context.Context, SessionProof, time.Time) ([]SessionInfo, error)
	RevokeSession(context.Context, SessionProof, string, time.Time) error
}
