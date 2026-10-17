package postgres

import (
	"context"
	"github.com/startificial/mayi/internal/services/health"
)

var _ health.Database = (*Store)(nil)
var _ health.KeyState = (*Store)(nil)

func (s *Store) CheckHealth(ctx context.Context) error { return s.pool.Ping(ctx) }
