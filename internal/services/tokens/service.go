// Package tokens orchestrates credential redemption through consumer-owned ports.
// P0 establishes the transaction contract; no network endpoint uses it yet.
package tokens

import (
	"context"
	"errors"
	"time"

	"github.com/startificial/mayi/internal/domain/grants"
	domaintokens "github.com/startificial/mayi/internal/domain/tokens"
)

var ErrInvalidCredential = errors.New("invalid credential")
var ErrUnavailable = errors.New("issuance unavailable")

const AuthorizationCode = "authorization_code"
const RefreshToken = "refresh_token"

// Caller must be built from authenticated client and verified sender-proof context
// by an adapter. These fields are not accepted as claims from external input.
type Caller struct {
	Scope                       grants.Scope
	ClientID, BindingThumbprint string
}
type Command struct {
	Caller                                   Caller
	Kind, CredentialHash, Resource, Verifier string
	RedirectURI                              string
	Scopes                                   []string
}
type Credential struct {
	Scope                                   grants.Scope
	Hash, Kind, ClientID, Resource, GrantID string
	Revision                                uint64
	PKCEChallenge, BindingThumbprint        string
	RedirectURI                             string
	CeilingScopes                           []string
	ObjectCeiling                           grants.ObjectCeiling
	IssuedAt                                time.Time
	ExpiresAt                               time.Time
	FamilyDeadline                          time.Time
	OriginCode, FamilyID, ParentIssuanceID  string
	Consumed                                bool
}
type GrantState struct {
	Revision              grants.Revision
	CurrentScopes         []string
	CurrentObjectCeiling  grants.ObjectCeiling
	Revoked               bool
	PolicyVersion         uint64
	AuthorizationDeadline time.Time
}
type Material struct{ ID, RefreshSecret, RefreshHash string }
type Issuance struct {
	Claims      domaintokens.AccessClaims
	RefreshHash string
}
type Result struct {
	AccessToken, RefreshToken string
	Claims                    domaintokens.AccessClaims
}
type Service struct {
	policy   Authorizer
	clock    Clock
	pkce     PKCEVerifier
	signer   Signer
	material MaterialSource
	store    UnitOfWork
	lifetime time.Duration
}

func New(policy Authorizer, clock Clock, pkce PKCEVerifier, signer Signer, material MaterialSource, store UnitOfWork, lifetime time.Duration) (*Service, error) {
	if policy == nil || clock == nil || pkce == nil || signer == nil || material == nil || store == nil || lifetime <= 0 || lifetime > 15*time.Minute {
		return nil, ErrUnavailable
	}
	return &Service{policy: policy, clock: clock, pkce: pkce, signer: signer, material: material, store: store, lifetime: lifetime}, nil
}

func (s *Service) Redeem(ctx context.Context, cmd Command) (Result, error) {
	if !cmd.Caller.Scope.Valid() || cmd.Caller.ClientID == "" || cmd.CredentialHash == "" || len(cmd.CredentialHash) > 256 || cmd.Resource == "" || len(cmd.Resource) > 2048 || !grants.ValidScopes(cmd.Scopes) || (cmd.Kind != AuthorizationCode && cmd.Kind != RefreshToken) {
		return Result{}, ErrInvalidCredential
	}
	version, err := s.policy.AuthorizeRedemption(ctx, cmd.Caller, cmd.CredentialHash)
	if err != nil || version == 0 {
		return Result{}, ErrInvalidCredential
	}
	var result Result
	replay := false
	err = s.store.Run(ctx, cmd.Caller.Scope, func(tx Transaction) error {
		credential, err := tx.Credential(ctx, cmd.CredentialHash)
		if err != nil {
			return err
		}
		now := s.clock.Now()
		if credential.Scope != cmd.Caller.Scope || credential.Hash != cmd.CredentialHash || credential.ClientID != cmd.Caller.ClientID || credential.Kind != cmd.Kind || credential.Resource != cmd.Resource || credential.BindingThumbprint != cmd.Caller.BindingThumbprint {
			return ErrInvalidCredential
		}
		// Validate possession before allowing a replay to revoke anything.
		if cmd.Kind == AuthorizationCode {
			if credential.RedirectURI == "" || (cmd.RedirectURI != "" && cmd.RedirectURI != credential.RedirectURI) {
				return ErrInvalidCredential
			}
			if err := s.pkce.VerifyS256(credential.PKCEChallenge, cmd.Verifier); err != nil {
				return ErrInvalidCredential
			}
		}
		if credential.Consumed {
			if err := tx.RevokeReplay(ctx, credential); err != nil {
				return err
			}
			replay = true
			return nil // Commit revocation; returning an error here would roll it back.
		}
		if now.IsZero() || !credential.ExpiresAt.After(now) || credential.IssuedAt.IsZero() || credential.IssuedAt.After(now) {
			return ErrInvalidCredential
		}
		if cmd.Kind == AuthorizationCode && (!credential.ExpiresAt.After(credential.IssuedAt) || credential.ExpiresAt.After(credential.IssuedAt.Add(60*time.Second))) {
			return ErrInvalidCredential
		}
		if !credential.ObjectCeiling.IsZero() {
			return ErrInvalidCredential
		}
		state, err := tx.GrantRevision(ctx, credential.GrantID, credential.Revision)
		if err != nil {
			return err
		}
		spec := state.Revision.Snapshot()
		if !spec.ObjectCeiling.IsZero() || !state.CurrentObjectCeiling.IsZero() {
			return ErrInvalidCredential
		}
		if state.Revoked || state.PolicyVersion != version || spec.Scope != credential.Scope || spec.GrantID != credential.GrantID || spec.Number != credential.Revision || spec.ClientID != credential.ClientID || spec.Resource != credential.Resource {
			return ErrInvalidCredential
		}
		effective, err := state.Revision.Narrow(state.CurrentScopes, cmd.Scopes, credential.CeilingScopes)
		if err != nil || len(effective) == 0 {
			return ErrInvalidCredential
		}
		material, err := s.material.NewMaterial(ctx)
		if err != nil {
			return err
		}
		deadlines := []time.Time{state.AuthorizationDeadline}
		if cmd.Kind == RefreshToken {
			deadlines = append(deadlines, credential.FamilyDeadline)
		}
		claims, err := domaintokens.Derive(state.Revision, effective, effective, material.ID, credential.BindingThumbprint, now, s.lifetime, deadlines...)
		if err != nil {
			return ErrInvalidCredential
		}
		if cmd.Kind == RefreshToken && (material.RefreshSecret == "" || material.RefreshHash == "" || material.RefreshHash == credential.Hash || material.RefreshSecret == material.RefreshHash) {
			return ErrUnavailable
		}
		token, err := s.signer.SignAccessToken(ctx, claims)
		if err != nil {
			return err
		}
		afterSigning := s.clock.Now()
		if afterSigning.Before(now) || !afterSigning.Before(claims.ExpiresAt) {
			return ErrUnavailable
		}
		if !afterSigning.Before(credential.ExpiresAt) {
			return ErrInvalidCredential
		}
		if token == "" {
			return ErrUnavailable
		}
		issuance := Issuance{Claims: claims}
		if cmd.Kind == RefreshToken {
			issuance.RefreshHash = material.RefreshHash
		}
		if err := tx.CommitIssuance(ctx, credential, issuance); err != nil {
			return err
		}
		result = Result{AccessToken: token, Claims: claims}
		if cmd.Kind == RefreshToken {
			result.RefreshToken = material.RefreshSecret
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrInvalidCredential) {
			return Result{}, ErrInvalidCredential
		}
		return Result{}, ErrUnavailable
	}
	if replay {
		return Result{}, ErrInvalidCredential
	}
	if result.AccessToken == "" {
		return Result{}, ErrUnavailable
	}
	return result, nil
}
