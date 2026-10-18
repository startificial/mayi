package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/startificial/mayi/internal/adapters/outbound/postgres"
	"github.com/startificial/mayi/internal/services/administration"
)

func TestCommandErrorsKeepSafeStageAndClassification(t *testing.T) {
	for _, tc := range []struct {
		cause  error
		reason string
	}{
		{postgres.ErrDatabaseConfiguration, "database_configuration"},
		{ErrDatabaseUnavailable, "database_unavailable"},
		{administration.ErrConflict, "conflict"},
		{context.DeadlineExceeded, "deadline_exceeded"},
		{context.Canceled, "canceled"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			err := commandFailure("database_connect", fmt.Errorf("secret-password: %w", tc.cause))
			if err.Error() != "Mayi command failed: stage=database_connect reason="+tc.reason || !errors.Is(err, ErrCommand) || !errors.Is(err, tc.cause) {
				t.Fatal(err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("raw error leaked")
			}
		})
	}
	raw := errors.New("postgres://user:secret@private-host/database")
	err := commandFailure("server_setup", raw)
	if err.Error() != "Mayi command failed: stage=server_setup reason=operation_failed" || errors.Is(err, raw) {
		t.Fatal("unsafe cause retained", err)
	}
	if commandFailure("server_setup", nil) != nil {
		t.Fatal("successful command returned an error")
	}
}

func TestRunReportsConfigurationStageWithoutPath(t *testing.T) {
	err := Run(context.Background(), []string{"serve", "-config", "/missing/private-secret/config.json"}, func(string) string { return "" }, io.Discard, io.Discard)
	if err == nil || err.Error() != "Mayi command failed: stage=config_load reason=configuration" {
		t.Fatal(err)
	}
}
