package tokens

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/resources"
	domain "github.com/startificial/mayi/internal/domain/tokens"
	"time"
)

type MachineService struct {
	store     MachineStore
	clock     Clock
	material  MaterialSource
	signer    Signer
	admission UsageAdmission
}

func NewMachine(store MachineStore, c Clock, m MaterialSource, s Signer, admission UsageAdmission) (*MachineService, error) {
	if admission == nil || store == nil || c == nil || m == nil || s == nil {
		return nil, ErrUnavailable
	}
	return &MachineService{store, c, m, s, admission}, nil
}
func (s *MachineService) Issue(ctx context.Context, cmd Command) (Result, error) {
	if !cmd.Caller.Scope.Valid() || cmd.Caller.AuthenticationVersion == 0 || !resources.ValidURI(cmd.Resource) || !grants.ValidScopes(cmd.Scopes) || cmd.OIDCRequested || cmd.OfflineRequested {
		return Result{}, ErrInvalidCredential
	}
	if err := s.admission.Check(ctx, cmd.Caller.Scope, "token", "client", cmd.Caller.ClientID); err != nil {
		return Result{}, err
	}
	var result Result
	err := s.store.RunMachine(ctx, cmd.Caller, cmd.Resource, func(tx MachineTransaction) error {
		p, err := tx.MachinePolicy(ctx)
		if err != nil {
			return err
		}
		if p.RequireBinding && cmd.Caller.BindingThumbprint == "" || p.AccessSeconds < 60 || p.AccessSeconds > 900 || p.GrantSeconds < p.AccessSeconds || p.SigningVersion < 1 {
			return ErrInvalidCredential
		}
		if _, err := resources.ValidateObjectRequest(cmd.Caller.Scope, cmd.Resource, p.Profiles, p.Ceiling.Snapshot().Details); err != nil {
			return ErrInvalidCredential
		}
		objects, err := p.Ceiling.Narrow(p.Ceiling, cmd.Objects)
		if err != nil || len(objects.Snapshot().Details) == 0 {
			return errors.Join(ErrInvalidCredential, ErrInvalidDetails)
		}
		now := s.clock.Now()
		m, err := s.material.NewMaterial(ctx)
		if err != nil {
			return err
		}
		rev, err := grants.NewRevision(grants.RevisionSpec{Scope: cmd.Caller.Scope, GrantID: "m-" + m.ID, Number: 1, ClientID: cmd.Caller.ClientID, Subject: cmd.Caller.ClientID, PrincipalType: "machine", Resource: cmd.Resource, Scopes: p.Scopes, ObjectCeiling: objects, ExpiresAt: now.Add(time.Duration(p.GrantSeconds) * time.Second)})
		if err != nil {
			return ErrInvalidCredential
		}
		claims, err := domain.DeriveObjects(rev, p.Scopes, cmd.Scopes, objects, m.ID, cmd.Caller.BindingThumbprint, now, time.Duration(p.AccessSeconds)*time.Second)
		if err != nil {
			return ErrInvalidCredential
		}
		claims.SigningKeyVersion = p.SigningVersion
		var token, hash string
		if p.Opaque {
			token = m.AccessSecret
			hash = m.AccessHash
		} else {
			token, err = s.signer.SignAccessToken(ctx, claims)
			hash = s.material.DigestAccessToken(token)
		}
		if err != nil || token == "" || hash == "" || !s.clock.Now().Before(claims.ExpiresAt) {
			return ErrUnavailable
		}
		if err := tx.CommitMachine(ctx, Issuance{Claims: claims, TokenHash: hash}); err != nil {
			return err
		}
		result = Result{AccessToken: token, Claims: claims, ObjectProfiles: p.Profiles}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	return result, nil
}
