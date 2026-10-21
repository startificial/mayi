// Package tokens orchestrates credential redemption through consumer-owned ports.
// P0 establishes the transaction contract; no network endpoint uses it yet.
package tokens

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/services/authentication"
	"time"

	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	domaintokens "github.com/startificial/mayi/internal/domain/tokens"
)

var ErrInvalidDetails = errors.New("invalid token authorization details")
var ErrInvalidScope = errors.New("invalid token scopes")
var ErrInvalidCredential = errors.New("invalid credential")
var ErrUnavailable = errors.New("issuance unavailable")

const AuthorizationCode = "authorization_code"
const RefreshToken = "refresh_token"

// Caller must be built from authenticated client and verified sender-proof context
// by an adapter. These fields are not accepted as claims from external input.
type Caller struct {
	ClientMetadataDigest        string
	AuthenticationVersion       uint64
	Scope                       grants.Scope
	ClientID, BindingThumbprint string
}
type Command struct {
	OIDCRequested, OfflineRequested, WireScopesSpecified bool
	Caller                                               Caller
	Kind, CredentialHash, Resource, Verifier             string
	RedirectURI                                          string
	Scopes                                               []string
	Objects                                              []grants.ObjectDetail
}
type Credential struct {
	ClientMetadataDigest                    string
	ClientAuthenticationVersion             uint64
	Scope                                   grants.Scope
	Hash, Kind, ClientID, Resource, GrantID string
	Revision                                uint64
	PKCEChallenge, BindingThumbprint        string
	RedirectURI                             string
	CeilingScopes                           []string
	// ObjectBound is the narrow presence projection used before proof checks.
	// Possession checks need no object identifiers in this lookup.
	ObjectBound                            bool
	IssuedAt                               time.Time
	ExpiresAt                              time.Time
	FamilyDeadline                         time.Time
	OriginCode, FamilyID, ParentIssuanceID string
	Consumed                               bool
}
type GrantState struct {
	SigningKeyVersion                          int
	Opaque, OIDC, OfflineAccess                bool
	Nonce                                      string
	AuthenticatedAt                            time.Time
	RefreshIdleSeconds, RefreshAbsoluteSeconds int
	ObjectProfiles                             []resources.ObjectProfile
	MaxAccessTokenSeconds                      int
	Revision                                   grants.Revision
	CurrentScopes                              []string
	CurrentObjectCeiling                       grants.ObjectCeiling
	Revoked                                    bool
	PolicyVersion                              uint64
	AuthorizationDeadline                      time.Time
}
type Material struct{ ID, RefreshSecret, RefreshHash, AccessSecret, AccessHash string }
type RefreshFamily struct {
	ID          string
	Deadline    time.Time
	IdleSeconds int
}
type Issuance struct {
	NewFamily   RefreshFamily
	TokenHash   string
	Claims      domaintokens.AccessClaims
	RefreshHash string
}
type Result struct {
	OIDC, OfflineAccess                bool
	AccessToken, RefreshToken, IDToken string
	Claims                             domaintokens.AccessClaims
	ObjectProfiles                     []resources.ObjectProfile
}
type Service struct {
	metadata  ClientMetadataResolver
	policy    Authorizer
	clock     Clock
	pkce      PKCEVerifier
	signer    Signer
	material  MaterialSource
	store     UnitOfWork
	lifetime  time.Duration
	admission UsageAdmission
}

func New(policy Authorizer, clock Clock, pkce PKCEVerifier, signer Signer, material MaterialSource, store UnitOfWork, lifetime time.Duration, admission UsageAdmission, metadata ...ClientMetadataResolver) (*Service, error) {
	if len(metadata) > 1 || len(metadata) == 1 && metadata[0] == nil || admission == nil || policy == nil || clock == nil || pkce == nil || signer == nil || material == nil || store == nil || lifetime <= 0 || lifetime > 15*time.Minute {
		return nil, ErrUnavailable
	}
	s := &Service{policy: policy, clock: clock, pkce: pkce, signer: signer, material: material, store: store, lifetime: lifetime, admission: admission}
	if len(metadata) == 1 {
		s.metadata = metadata[0]
	}
	return s, nil
}

func (s *Service) Redeem(ctx context.Context, cmd Command) (Result, error) {
	if !cmd.Caller.Scope.Valid() || cmd.Caller.ClientID == "" || cmd.CredentialHash == "" || len(cmd.CredentialHash) > 256 || cmd.Resource != "" && !resources.ValidURI(cmd.Resource) || !grants.ValidScopes(cmd.Scopes) || (cmd.Kind != AuthorizationCode && cmd.Kind != RefreshToken) {
		return Result{}, ErrInvalidCredential
	}
	if err := s.admission.Check(ctx, cmd.Caller.Scope, "token", "client", cmd.Caller.ClientID); err != nil {
		return Result{}, err
	}
	if _, cimd := clients.MetadataURL(cmd.Caller.ClientID); cimd {
		if s.metadata == nil {
			return Result{}, ErrInvalidCredential
		}
		c, err := s.metadata.ResolveClient(ctx, cmd.Caller.Scope, cmd.Caller.ClientID, true)
		if err != nil {
			if errors.Is(err, clients.ErrMetadataDenied) {
				return Result{}, ErrInvalidCredential
			}
			return Result{}, ErrUnavailable
		}
		if c.ID != cmd.Caller.ClientID || !c.Valid() {
			return Result{}, ErrInvalidCredential
		}
		cmd.Caller.ClientMetadataDigest = c.MetadataDigest
	} else if cmd.Caller.ClientMetadataDigest != "" {
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
		if credential.ClientMetadataDigest != cmd.Caller.ClientMetadataDigest || cmd.Caller.AuthenticationVersion != 0 && credential.ClientAuthenticationVersion != cmd.Caller.AuthenticationVersion || credential.Scope != cmd.Caller.Scope || credential.Hash != cmd.CredentialHash || credential.ClientID != cmd.Caller.ClientID || credential.Kind != cmd.Kind || cmd.Resource != "" && credential.Resource != cmd.Resource || credential.BindingThumbprint != cmd.Caller.BindingThumbprint {
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
		// An omitted resource inherits only this authenticated credential's bound
		// audience; it never consults a user's latest grant or a deployment default.
		if cmd.Resource == "" {
			cmd.Resource = credential.Resource
		}
		if !resources.ValidURI(cmd.Resource) {
			return ErrInvalidCredential
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
		if !credential.ObjectBound {
			return ErrInvalidCredential
		}
		credentialObjects, err := tx.CredentialObjects(ctx, credential)
		if err != nil {
			return err
		}
		if !credentialObjects.BoundTo(cmd.Caller.Scope, cmd.Resource) || len(credentialObjects.Snapshot().Details) == 0 {
			return ErrInvalidCredential
		}
		state, err := tx.GrantRevision(ctx, credential.GrantID, credential.Revision)
		if err != nil {
			return err
		}
		if cmd.OIDCRequested && !state.OIDC || cmd.OfflineRequested && !state.OfflineAccess {
			return ErrInvalidCredential
		}
		if cmd.Kind == RefreshToken && state.RefreshIdleSeconds > 0 && !now.Before(credential.IssuedAt.Add(time.Duration(state.RefreshIdleSeconds)*time.Second)) {
			return ErrInvalidCredential
		}
		spec := state.Revision.Snapshot()
		if credential.ObjectBound != !spec.ObjectCeiling.IsZero() || credential.ObjectBound != !state.CurrentObjectCeiling.IsZero() {
			return ErrInvalidCredential
		}
		var objects grants.ObjectCeiling
		if credential.ObjectBound {
			for _, c := range []grants.ObjectCeiling{spec.ObjectCeiling, state.CurrentObjectCeiling, credentialObjects} {
				cs := c.Snapshot()
				if _, err := resources.ValidateObjectRequest(cmd.Caller.Scope, cmd.Resource, state.ObjectProfiles, cs.Details); err != nil {
					return ErrInvalidCredential
				}
			}
			objects, err = spec.ObjectCeiling.Narrow(state.CurrentObjectCeiling, cmd.Objects, credentialObjects)
			if err != nil || len(objects.Snapshot().Details) == 0 {
				if cmd.Objects != nil {
					return errors.Join(ErrInvalidCredential, ErrInvalidDetails)
				}
				return ErrInvalidCredential
			}
		}
		if state.Revoked || state.PolicyVersion != version || spec.Scope != credential.Scope || spec.GrantID != credential.GrantID || spec.Number != credential.Revision || spec.ClientID != credential.ClientID || spec.Resource != credential.Resource {
			return ErrInvalidCredential
		}
		effective, err := state.Revision.Narrow(state.CurrentScopes, cmd.Scopes, credential.CeilingScopes)
		if err != nil || len(effective) == 0 {
			if len(cmd.Scopes) > 0 {
				return errors.Join(ErrInvalidCredential, ErrInvalidScope)
			}
			return ErrInvalidCredential
		}
		if err := s.admission.CheckUsing(ctx, tx, cmd.Caller.Scope, "token", "user", spec.Subject); err != nil {
			return err
		}
		material, err := s.material.NewMaterial(ctx)
		if err != nil {
			return err
		}
		deadlines := []time.Time{state.AuthorizationDeadline}
		if cmd.Kind == RefreshToken {
			deadlines = append(deadlines, credential.FamilyDeadline)
		}
		lifetime := s.lifetime
		if state.MaxAccessTokenSeconds > 0 && time.Duration(state.MaxAccessTokenSeconds)*time.Second < lifetime {
			lifetime = time.Duration(state.MaxAccessTokenSeconds) * time.Second
		}
		claims, err := domaintokens.DeriveObjects(state.Revision, effective, effective, objects, material.ID, credential.BindingThumbprint, now, lifetime, deadlines...)
		if err != nil {
			return ErrInvalidCredential
		}
		claims.SigningKeyVersion = state.SigningKeyVersion
		claims.AuthenticatedAt = state.AuthenticatedAt
		refresh := (cmd.Kind == RefreshToken || cmd.Kind == AuthorizationCode && state.OfflineAccess) && (!cmd.WireScopesSpecified || cmd.OfflineRequested)
		if refresh && (material.RefreshSecret == "" || material.RefreshHash == "" || material.RefreshHash == credential.Hash || material.RefreshSecret == material.RefreshHash) {
			return ErrUnavailable
		}
		issuance := Issuance{Claims: claims}
		if refresh {
			issuance.RefreshHash = material.RefreshHash
		}
		if cmd.Kind == AuthorizationCode && refresh {
			if state.RefreshIdleSeconds < 60 || state.RefreshAbsoluteSeconds < state.RefreshIdleSeconds {
				return ErrUnavailable
			}
			deadline := now.Add(time.Duration(state.RefreshAbsoluteSeconds) * time.Second)
			for _, cap := range []time.Time{spec.ExpiresAt, state.AuthorizationDeadline} {
				if cap.Before(deadline) {
					deadline = cap
				}
			}
			if !deadline.After(now) {
				return ErrInvalidCredential
			}
			issuance.NewFamily = RefreshFamily{ID: "f-" + material.ID, Deadline: deadline, IdleSeconds: state.RefreshIdleSeconds}
		}
		var token string
		if state.Opaque {
			if material.AccessSecret == "" || material.AccessHash == "" || material.AccessSecret == material.AccessHash {
				return ErrUnavailable
			}
			token = material.AccessSecret
			issuance.TokenHash = material.AccessHash
		} else {
			token, err = s.signer.SignAccessToken(ctx, claims)
			if err != nil {
				return err
			}
			issuance.TokenHash = s.material.DigestAccessToken(token)
		}
		var idToken string
		if cmd.Kind == AuthorizationCode && state.OIDC && (!cmd.WireScopesSpecified || cmd.OIDCRequested) {
			idSigner, ok := s.signer.(IdentitySigner)
			if !ok || state.Nonce == "" || state.AuthenticatedAt.IsZero() {
				return ErrUnavailable
			}
			idToken, err = idSigner.SignIdentityToken(ctx, domaintokens.IdentityClaims{Scope: claims.Scope, Subject: claims.Subject, ClientID: claims.ClientID, Nonce: state.Nonce, ID: claims.ID, AuthenticatedAt: state.AuthenticatedAt, IssuedAt: now, ExpiresAt: claims.ExpiresAt, SigningKeyVersion: claims.SigningKeyVersion})
			if err != nil || idToken == "" {
				return ErrUnavailable
			}
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

		if err := tx.CommitIssuance(ctx, credential, issuance); err != nil {
			return err
		}
		result = Result{AccessToken: token, IDToken: idToken, Claims: claims, ObjectProfiles: state.ObjectProfiles, OIDC: state.OIDC && (!cmd.WireScopesSpecified || cmd.OIDCRequested), OfflineAccess: refresh && state.OfflineAccess}
		if refresh {
			result.RefreshToken = material.RefreshSecret
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrInvalidDetails) || errors.Is(err, ErrInvalidScope) {
			return Result{}, err
		}
		if errors.Is(err, authentication.ErrLimited) {
			return Result{}, err
		}
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
