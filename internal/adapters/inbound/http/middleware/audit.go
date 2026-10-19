package middleware

import (
	"context"
	transport "github.com/startificial/mayi/internal/adapters/inbound/http"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/delivery"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

type Audit struct {
	security *delivery.Security
	peers    *Admission
	scopes   map[string]grants.Scope
	logger   *slog.Logger
}

func NewAudit(service *delivery.Security, scopes []grants.Scope, proxies []string, logger *slog.Logger) (*Audit, error) {
	if service == nil || logger == nil || len(proxies) > 16 {
		return nil, delivery.ErrUnavailable
	}
	peers := &Admission{}
	for _, raw := range proxies {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p != p.Masked() {
			return nil, delivery.ErrUnavailable
		}
		peers.trusted = append(peers.trusted, p)
	}
	values := map[string]grants.Scope{}
	for _, scope := range scopes {
		if !scope.Valid() {
			return nil, delivery.ErrUnavailable
		}
		values[scope.TenantID] = scope
	}
	return &Audit{service, peers, values, logger}, nil
}
func (a *Audit) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, err := a.peers.peer(r)
		ctx := delivery.WithRequestMetadata(r.Context(), delivery.RequestMetadata{IP: peer, UserAgent: r.UserAgent()})
		r = r.WithContext(ctx)
		out := &response{ResponseWriter: w}
		if err != nil {
			transport.Error(out, 400, "invalid_request")
		} else {
			next.ServeHTTP(out, r)
		}
		if out.status < 400 {
			return
		}
		segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		operation := "authorization"
		tenant := ""
		if len(segments) >= 2 && segments[0] == "t" {
			tenant = segments[1]
			if len(segments) > 2 {
				switch segments[2] {
				case "token", "par", "revoke":
					operation = "token"
				case "introspect":
					operation = "introspection"
				case "session", "sessions", "grants", "connected-apps":
					operation = "session"
				}
			}
		} else if len(segments) >= 3 && segments[0] == "admin" && segments[1] == "t" {
			tenant = segments[2]
			operation = "administration"
		}
		scope, ok := a.scopes[tenant]
		if !ok {
			return
		}
		auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if err := a.security.Denied(auditCtx, scope, operation, out.status); err != nil {
			a.logger.ErrorContext(ctx, "security_audit_unavailable", "request_id", delivery.Metadata(ctx).RequestID)
		}
	})
}
