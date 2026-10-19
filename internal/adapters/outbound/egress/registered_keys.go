package egress

import (
	"context"
	"github.com/startificial/mayi/internal/services/clients"
)

var _ clients.KeyTransport = (*RegisteredKeys)(nil)

// RegisteredKeys accepts only the registry-owned URL passed after client
// selection. The common egress policy still resolves/filters every destination.
type RegisteredKeys struct{ allowLoopback bool }

func NewRegisteredKeys(allowLoopback bool) *RegisteredKeys { return &RegisteredKeys{allowLoopback} }
func (r *RegisteredKeys) FetchKeys(ctx context.Context, url string) ([]byte, error) {
	c, err := New(Config{URLs: []string{url}, AllowLoopbackHTTP: r.allowLoopback})
	if err != nil {
		return nil, err
	}
	return c.GetJSON(ctx, url)
}
