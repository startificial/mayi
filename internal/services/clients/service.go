// Package clients owns registered client authentication and secret lifecycle.
package clients

import (
	"context"
	"errors"
	domain "github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	"slices"
	"time"
)

var ErrDenied = errors.New("client authentication denied")
var ErrUnavailable = errors.New("client authentication unavailable")

type Service struct {
	metadata   ClientMetadataResolver
	store      Store
	clock      Clock
	assertions AssertionVerifier
	secrets    Secrets
	scope      grants.Scope
	admission  AuthenticationAdmission
}
type Proof struct{ ClientID, Method, Secret, Assertion, Audience, Operation string }
type Principal struct {
	Resources []string
	Client    domain.Client
	Version   uint64
	Scopes    []string
}
type Operator struct {
	Scope       grants.Scope
	ID          string
	Permissions []string
}

func New(store Store, c Clock, a AssertionVerifier, secrets Secrets, scope grants.Scope, admission AuthenticationAdmission, metadata ...ClientMetadataResolver) (*Service, error) {
	if len(metadata) > 1 || len(metadata) == 1 && metadata[0] == nil || admission == nil || store == nil || c == nil || a == nil || secrets == nil || !scope.Valid() {
		return nil, ErrUnavailable
	}
	s := &Service{store: store, clock: c, assertions: a, secrets: secrets, scope: scope, admission: admission}
	if len(metadata) == 1 {
		s.metadata = metadata[0]
	}
	return s, nil
}
func (s *Service) Authenticate(ctx context.Context, p Proof) (Principal, error) {
	if !domain.ValidClientID(p.ClientID) || len(p.Secret) > 256 || len(p.Assertion) > 16384 || p.Method != "none" && p.Method != "client_secret_basic" && p.Method != "private_key_jwt" {
		return Principal{}, ErrDenied
	}
	operation := p.Operation
	if operation == "" {
		operation = "token"
	}
	if operation != "token" && operation != "introspection" {
		return Principal{}, ErrDenied
	}
	if err := s.admission.Check(ctx, s.scope, operation, "client", "authentication:"+p.ClientID); err != nil {
		return Principal{}, err
	}
	var resolved domain.Client
	if _, cimd := domain.MetadataURL(p.ClientID); cimd {
		if s.metadata == nil {
			return Principal{}, ErrDenied
		}
		var err error
		resolved, err = s.metadata.ResolveClient(ctx, s.scope, p.ClientID, false)
		if err != nil {
			if errors.Is(err, domain.ErrMetadataDenied) {
				return Principal{}, ErrDenied
			}
			return Principal{}, ErrUnavailable
		}
	}
	a, err := s.store.Authentication(ctx, s.scope, p.ClientID)
	if err != nil {
		if errors.Is(err, ErrDenied) {
			return Principal{}, ErrDenied
		}
		return Principal{}, ErrUnavailable
	}
	if resolved.ID != "" && (a.Client.MetadataDigest != resolved.MetadataDigest || a.Client.MetadataPolicyVersion != resolved.MetadataPolicyVersion) {
		return Principal{}, ErrDenied
	}
	method := a.Client.AuthMethod
	if method == "" {
		method = "none"
	}
	if !a.Client.Enabled || a.Client.ID != p.ClientID || method != p.Method || a.Version == 0 {
		return Principal{}, ErrDenied
	}
	switch method {
	case "none":
		if p.Secret != "" || p.Assertion != "" || a.Client.Machine {
			return Principal{}, ErrDenied
		}
	case "client_secret_basic":
		if p.Secret == "" || p.Assertion != "" {
			return Principal{}, ErrDenied
		}
		digest, err := s.secrets.DigestClientSecret(p.Secret)
		if err != nil {
			return Principal{}, ErrDenied
		}
		valid := false
		for _, h := range a.SecretHashes {
			if s.secrets.Matches(h.Hash, digest) && s.clock.Now().Before(h.ExpiresAt) {
				valid = true
			}
		}
		if !valid {
			return Principal{}, ErrDenied
		}
	case "private_key_jwt":
		if p.Secret != "" || p.Assertion == "" {
			return Principal{}, ErrDenied
		}
		assertion, err := s.assertions.VerifyClientAssertion(ctx, p.Assertion, p.ClientID, p.Audience, a.JWKS, a.JWKSURI, s.clock.Now())
		if err != nil {
			if errors.Is(err, ErrUnavailable) {
				return Principal{}, ErrUnavailable
			}
			return Principal{}, ErrDenied
		}
		if err := s.store.ConsumeAssertion(ctx, s.scope, p.ClientID, assertion.ID, assertion.ExpiresAt); err != nil {
			if !errors.Is(err, ErrDenied) {
				return Principal{}, ErrUnavailable
			}
			return Principal{}, ErrDenied
		}
	}
	return Principal{Client: a.Client, Version: a.Version, Resources: slices.Clone(a.Resources), Scopes: slices.Clone(a.Scopes)}, nil
}

// Rotate returns fresh generated material only after old-secret retirement,
// bounded overlap, version invalidation and audit commit atomically.
func (s *Service) Rotate(ctx context.Context, actor Operator, client string, overlap time.Duration) (string, error) {
	if actor.Scope != s.scope || !resources.ValidID(actor.ID) || !slices.Contains(actor.Permissions, "clients:write") {
		return "", ErrDenied
	}
	if !domain.ValidClientID(client) || overlap < 0 || overlap > 24*time.Hour {
		return "", ErrDenied
	}
	secret, hash, err := s.secrets.NewClientSecret(ctx)
	if err != nil {
		return "", ErrUnavailable
	}
	now := s.clock.Now()
	if err := s.store.RotateSecret(ctx, s.scope, client, hash, now.Add(365*24*time.Hour), now.Add(overlap), actor.ID); err != nil {
		return "", ErrUnavailable
	}
	return secret, nil
}

func (s *Service) ConfigureKeys(ctx context.Context, actor Operator, client, inline, uri string) error {
	if actor.Scope != s.scope || !resources.ValidID(actor.ID) || !slices.Contains(actor.Permissions, "clients:write") {
		return ErrDenied
	}
	if !domain.ValidClientID(client) || (inline == "") == (uri == "") || len(inline) > 32768 || uri != "" && !resources.ValidURI(uri) {
		return ErrDenied
	}
	if err := s.assertions.ValidateKeys(ctx, inline, uri); err != nil {
		return err
	}
	return s.store.ConfigureKeys(ctx, s.scope, client, inline, uri, actor.ID)
}
