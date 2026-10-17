package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/startificial/mayi/internal/adapters/outbound/postgres"
	"github.com/startificial/mayi/internal/services/administration"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"
)

var ErrCommand = errors.New("Mayi command failed; check configuration, database roles/migrations and Transit availability")

// Run is the composition entrypoint. Operator-only commands never share the
// migration credential with the server or worker connection pool.
func Run(ctx context.Context, args []string, lookup func(string) string, output, errorOutput io.Writer) error {
	if len(args) == 0 || lookup == nil || output == nil || errorOutput == nil {
		return ErrConfiguration
	}
	if args[0] == "admin-token" {
		if len(args) != 1 {
			return ErrConfiguration
		}
		var bytes [32]byte
		if _, err := rand.Read(bytes[:]); err != nil {
			return ErrCommand
		}
		token := base64.RawURLEncoding.EncodeToString(bytes[:])
		digest := sha256.Sum256([]byte(token))
		return json.NewEncoder(output).Encode(struct {
			Token  string `json:"token"`
			SHA256 string `json:"sha256"`
		}{token, hex.EncodeToString(digest[:])})
	}
	if args[0] != "serve" && args[0] != "migrate" && args[0] != "provision" && args[0] != "worker" {
		return ErrConfiguration
	}
	flags := flag.NewFlagSet("mayi "+args[0], flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	path := flags.String("config", "", "path to strict JSON configuration")
	tenantID := flags.String("tenant", "", "configured tenant to provision")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *path == "" || args[0] != "provision" && *tenantID != "" {
		return ErrConfiguration
	}
	c, err := LoadConfig(*path)
	if err != nil {
		return err
	}
	owner := args[0] == "migrate" || args[0] == "provision"
	env := "MAYI_DATABASE_URL"
	if owner {
		env = "MAYI_MIGRATION_DATABASE_URL"
	}
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pool, err := openDatabase(startup, lookup(env), c, !owner)
	if err != nil {
		return ErrCommand
	}
	defer pool.Close()
	switch args[0] {
	case "migrate":
		if err := postgres.ApplyMigrations(startup, pool, c.RuntimeRole); err != nil {
			return ErrCommand
		}
		_, err = fmt.Fprintln(output, "Mayi migrations applied")
		return err
	case "provision":
		for _, t := range c.Tenants {
			if t.ID == *tenantID {
				store, err := postgres.New(pool)
				if err != nil {
					return ErrCommand
				}
				ring, err := newRing(startup, c, t, store, lookup)
				if err != nil {
					return ErrCommand
				}
				scope, _ := NewIssuerScope(c.PublicOrigin, t.ID)
				service, err := administration.New(store, ring, systemClock{})
				if err != nil {
					return ErrCommand
				}
				actor := administration.Actor{ID: "operator", Scope: scope, Permissions: []string{"tenants:provision"}}
				if err := service.ProvisionTenant(startup, actor, scope, t.InitialKeyVersion); err != nil {
					return ErrCommand
				}
				_, err = fmt.Fprintln(output, "Tenant provisioned")
				return err
			}
		}
		return ErrConfiguration
	case "worker":
		if err := runWorker(ctx, c, pool, output); err != nil && ctx.Err() == nil {
			return ErrCommand
		}
		return nil
	case "serve":
		logger := slog.New(slog.NewJSONHandler(errorOutput, nil))
		server, err := NewServer(startup, c, pool, lookup, logger)
		if err != nil {
			return ErrCommand
		}
		listener, err := net.Listen("tcp", server.Addr)
		if err != nil {
			return ErrCommand
		}
		logger.Info("server_started", "stage", "P1-foundation", "listen", server.Addr)
		done := make(chan error, 1)
		go func() { done <- server.Serve(listener) }()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return ErrCommand
			}
			return nil
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := server.Shutdown(shutdown); err != nil {
				_ = server.Close()
			}
			<-done
			return nil
		}
	}
	return ErrConfiguration
}
