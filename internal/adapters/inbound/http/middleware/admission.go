package middleware

import (
	"errors"
	transport "github.com/startificial/mayi/internal/adapters/inbound/http"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/authentication"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

type Admission struct {
	service authentication.RequestAdmission
	trusted []netip.Prefix
}

func NewAdmission(service authentication.RequestAdmission, proxies []string) (*Admission, error) {
	if service == nil || len(proxies) > 16 {
		return nil, authentication.ErrUnavailable
	}
	a := &Admission{service: service}
	for _, raw := range proxies {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() {
			return nil, authentication.ErrUnavailable
		}
		a.trusted = append(a.trusted, prefix)
	}
	return a, nil
}
func (a *Admission) trustedPeer(ip netip.Addr) bool {
	for _, p := range a.trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
func (a *Admission) peer(r *http.Request) (string, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", authentication.ErrDenied
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return "", authentication.ErrDenied
	}
	ip = ip.Unmap()
	if !a.trustedPeer(ip) || r.Header.Get("X-Forwarded-For") == "" {
		return ip.String(), nil
	}
	if len(r.Header.Values("X-Forwarded-For")) != 1 || len(r.Header.Get("X-Forwarded-For")) > 2048 {
		return "", authentication.ErrDenied
	}
	values := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	if len(values) > 16 {
		return "", authentication.ErrDenied
	}
	parsed := make([]netip.Addr, len(values))
	for i, v := range values {
		address, err := netip.ParseAddr(strings.TrimSpace(v))
		if err != nil || address.Zone() != "" {
			return "", authentication.ErrDenied
		}
		parsed[i] = address.Unmap()
	}
	for i := len(parsed) - 1; i >= 0 && a.trustedPeer(ip); i-- {
		ip = parsed[i]
	}
	return ip.String(), nil
}
func (a *Admission) Protect(scope grants.Scope, operation string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, err := a.peer(r)
		if err != nil {
			transport.Error(w, 400, "invalid_request")
			return
		}
		err = a.service.Check(r.Context(), scope, operation, "ip", peer)
		if err != nil {
			var limit *authentication.LimitError
			if errors.As(err, &limit) {
				w.Header().Set("Retry-After", strconv.Itoa(limit.RetryAfterSeconds))
				if operation == "login" {
					transport.Error(w, 429, "rate_limited")
				} else {
					transport.JSON(w, 429, struct {
						Error string `json:"error"`
					}{"temporarily_unavailable"})
				}
			} else {
				transport.Error(w, 503, "temporarily_unavailable")
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}
