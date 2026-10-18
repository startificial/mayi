package app

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/startificial/mayi/internal/adapters/outbound/postgres"
	"strings"
	"time"
)

var ErrDatabaseUnavailable = errors.New("database connection unavailable")

func databaseConfig(dsn string, c Config, runtime bool) (*pgxpool.Config, error) {
	if dsn == "" || len(dsn) > 8192 {
		return nil, postgres.ErrDatabaseConfiguration
	}
	p, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, postgres.ErrDatabaseConfiguration
	}
	local := func(host string) bool { return host == "127.0.0.1" || host == "::1" || strings.HasPrefix(host, "/") }
	secure := func(host string, t *tls.Config) bool {
		return c.AllowInsecureLoopback && local(host) || t != nil && !t.InsecureSkipVerify && t.ServerName != ""
	}
	if !secure(p.ConnConfig.Host, p.ConnConfig.TLSConfig) {
		return nil, postgres.ErrDatabaseConfiguration
	}
	for _, fallback := range p.ConnConfig.Fallbacks {
		if !secure(fallback.Host, fallback.TLSConfig) {
			return nil, postgres.ErrDatabaseConfiguration
		}
	}
	p.MaxConns = c.DatabaseMaxConnections
	p.MinConns = 0
	p.ConnConfig.ConnectTimeout = 5 * time.Second
	p.ConnConfig.RuntimeParams["application_name"] = "mayi"
	p.ConnConfig.RuntimeParams["search_path"] = "pg_catalog"
	p.ConnConfig.RuntimeParams["statement_timeout"] = "10000"
	p.ConnConfig.RuntimeParams["lock_timeout"] = "5000"
	p.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "15000"
	if runtime {
		if p.ConnConfig.User != c.RuntimeRole {
			return nil, postgres.ErrDatabaseConfiguration
		}
		for name := range p.ConnConfig.RuntimeParams {
			if strings.EqualFold(name, "role") || strings.EqualFold(name, "session_authorization") || strings.EqualFold(name, "options") {
				return nil, postgres.ErrDatabaseConfiguration
			}
		}
		p.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			return postgres.ValidateRuntime(ctx, conn, c.RuntimeRole)
		}
	}
	return p, nil
}
func openDatabase(ctx context.Context, dsn string, c Config, runtime bool) (*pgxpool.Pool, error) {
	p, err := databaseConfig(dsn, c, runtime)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, p)
	if err != nil {
		return nil, postgres.ErrDatabaseConfiguration
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		if errors.Is(err, postgres.ErrDatabaseConfiguration) {
			return nil, postgres.ErrDatabaseConfiguration
		}
		return nil, ErrDatabaseUnavailable
	}
	return pool, nil
}
