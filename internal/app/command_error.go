package app

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/adapters/outbound/postgres"
	"github.com/startificial/mayi/internal/services/administration"
	"github.com/startificial/mayi/internal/services/delivery"
	"github.com/startificial/mayi/internal/services/tokens"
)

// CommandError exposes only fixed stage/reason labels. Upstream error messages,
// configuration paths, DSNs, headers and credentials are never retained.
type CommandError struct {
	stage, reason string
	kind          error
}

func (e *CommandError) Error() string {
	return "Mayi command failed: stage=" + e.stage + " reason=" + e.reason
}
func (e *CommandError) Unwrap() []error {
	if e.kind == nil {
		return []error{ErrCommand}
	}
	return []error{ErrCommand, e.kind}
}
func commandFailure(stage string, cause error) error {
	if cause == nil {
		return nil
	}
	reason := "operation_failed"
	var kind error
	for _, candidate := range []struct {
		err    error
		reason string
	}{
		{context.DeadlineExceeded, "deadline_exceeded"}, {context.Canceled, "canceled"},
		{postgres.ErrDatabaseConfiguration, "database_configuration"}, {ErrDatabaseUnavailable, "database_unavailable"},
		{ErrConfiguration, "configuration"}, {administration.ErrConflict, "conflict"}, {administration.ErrInvalid, "invalid_input"},
		{administration.ErrDenied, "permission_denied"}, {administration.ErrNotFound, "not_found"},
		{administration.ErrUnavailable, "management_unavailable"}, {delivery.ErrUnavailable, "delivery_unavailable"}, {tokens.ErrUnavailable, "signer_unavailable"},
	} {
		if errors.Is(cause, candidate.err) {
			reason = candidate.reason
			kind = candidate.err
			break
		}
	}
	return &CommandError{stage: stage, reason: reason, kind: kind}
}
