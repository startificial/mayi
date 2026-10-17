package app

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/startificial/mayi/internal/adapters/outbound/events"
	"github.com/startificial/mayi/internal/adapters/outbound/postgres"
	"github.com/startificial/mayi/internal/services/delivery"
	"io"
	"time"
)

func runWorker(ctx context.Context, c Config, pool *pgxpool.Pool, output io.Writer) error {
	store, err := postgres.New(pool)
	if err != nil {
		return err
	}
	sink, err := events.New(output)
	if err != nil {
		return err
	}
	services := make([]*delivery.Service, 0, len(c.Tenants))
	for _, t := range c.Tenants {
		scope, _ := NewIssuerScope(c.PublicOrigin, t.ID)
		service, err := delivery.New(store, sink, systemClock{}, scope)
		if err != nil {
			return err
		}
		services = append(services, service)
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		for i, t := range c.Tenants {
			scope, _ := NewIssuerScope(c.PublicOrigin, t.ID)
			if _, err := services[i].Drain(ctx, scope, 100); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
