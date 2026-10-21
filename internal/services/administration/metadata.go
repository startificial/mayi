package administration

import (
	"context"
	"errors"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"time"
)

type Metadata struct {
	store     Store
	transport MetadataTransport
	admission MetadataAdmission
	clock     Clock
	scope     grants.Scope
}

func NewMetadata(store Store, transport MetadataTransport, admission MetadataAdmission, clock Clock, scope grants.Scope) (*Metadata, error) {
	if store == nil || transport == nil || admission == nil || clock == nil || !scope.Valid() {
		return nil, ErrUnavailable
	}
	return &Metadata{store, transport, admission, clock, scope}, nil
}

func (s *Service) MetadataPolicy(ctx context.Context, actor Actor, scope grants.Scope) (clients.MetadataPolicy, error) {
	if err := authorize(actor, scope, "clients:read"); err != nil {
		return clients.MetadataPolicy{}, err
	}
	var result clients.MetadataPolicy
	err := s.store.RunManagement(ctx, scope, func(tx Transaction) error { var err error; result, err = tx.MetadataPolicy(ctx); return err })
	if err != nil {
		return clients.MetadataPolicy{}, err
	}
	return result, nil
}
func (s *Service) SetMetadataPolicy(ctx context.Context, actor Actor, scope grants.Scope, p clients.MetadataPolicy) (clients.MetadataPolicy, error) {
	if err := authorize(actor, scope, "clients:write"); err != nil {
		return clients.MetadataPolicy{}, err
	}
	if !p.Valid() || p.Version >= 1<<63-1 {
		return clients.MetadataPolicy{}, ErrInvalid
	}
	err := s.store.RunManagement(ctx, scope, func(tx Transaction) error {
		old, err := tx.MetadataPolicy(ctx)
		if err != nil {
			return err
		}
		if old.Version != p.Version {
			return ErrConflict
		}
		if p.Mode != "any" {
			registration, err := tx.RegistrationPolicy(ctx)
			if err != nil {
				return err
			}
			if registration.Mode == "open" {
				return ErrConflict
			}
		}
		if p.Enabled() {
			// Reuse registry vocabulary/lifetime validation; this value is never
			// inserted or treated as an approved remote client.
			c, ok := (clients.RegistrationPolicy{Version: 1, Mode: "open", Resources: p.Resources, AuthorizationDetailsTypes: p.AuthorizationDetailsTypes, MaxClients: p.MaxClients, AccessTokenSeconds: p.AccessTokenSeconds}).Client("metadata", clients.PublicRegistration{Name: "Metadata ceiling", RedirectURIs: []string{"https://metadata.example/callback"}, Resources: p.Resources, AuthorizationDetailsTypes: p.AuthorizationDetailsTypes})
			if !ok {
				return ErrInvalid
			}
			if err := validateClientRegistration(ctx, tx, scope, c); err != nil {
				return err
			}
		}
		p.Version++
		if err := tx.SetMetadataPolicy(ctx, p); err != nil {
			return err
		}
		return tx.Audit(ctx, "client_metadata_policy_updated", actor.ID, "cimd")
	})
	if err != nil {
		return clients.MetadataPolicy{}, err
	}
	return p, nil
}

// ResolveClient revalidates even a fresh cache at critical consent/redemption
// boundaries when fresh is true. No network operation holds a database lock.
func (s *Metadata) ResolveClient(ctx context.Context, scope grants.Scope, id string, fresh bool) (result clients.Client, resultErr error) {
	defer func() {
		if resultErr != nil {
			if isMetadataDenied(resultErr) {
				resultErr = errors.Join(clients.ErrMetadataDenied, resultErr)
			} else {
				resultErr = errors.Join(clients.ErrMetadataUnavailable, resultErr)
			}
		}
	}()

	if scope != s.scope {
		return clients.Client{}, ErrDenied
	}
	if _, ok := clients.MetadataURL(id); !ok {
		return clients.Client{}, ErrDenied
	}
	allowed, err := s.admission.AdmitMetadata(ctx, scope)
	if err != nil {
		return clients.Client{}, ErrUnavailable
	}
	if !allowed {
		return clients.Client{}, ErrRegistrationLimited
	}
	var p clients.MetadataPolicy
	var state MetadataState
	err = s.store.RunManagement(ctx, scope, func(tx Transaction) error {
		var err error
		p, err = tx.MetadataPolicy(ctx)
		if err != nil {
			return err
		}
		if !p.Allows(id) {
			return ErrDenied
		}
		state, err = tx.MetadataState(ctx, id)
		if err != nil {
			return err
		}
		if state.Generation != 0 && !state.Client.Enabled {
			return ErrDenied
		}
		return nil
	})
	if err != nil {
		return clients.Client{}, err
	}
	now := s.clock.Now()
	if now.IsZero() {
		return clients.Client{}, ErrUnavailable
	}
	if !fresh && state.Document != nil && now.Before(state.FreshUntil) && state.Client.MetadataPolicyVersion == p.Version {
		c, ok := p.Client(*state.Document)
		if !ok || c.MetadataDigest != state.ContentDigest {
			return clients.Client{}, ErrDenied
		}
		c.MetadataDigest, ok = clients.RevisionedMetadataDigest(c.MetadataDigest, state.AuthorityRevision)
		if !ok || c.MetadataDigest != state.Client.MetadataDigest {
			return clients.Client{}, ErrDenied
		}
		c.AuthenticationVersion = state.Client.AuthenticationVersion
		return c, nil
	}
	validators := MetadataValidators{}
	if state.Document != nil && state.Client.MetadataPolicyVersion == p.Version {
		validators = state.Validators
	}
	response, err := s.transport.FetchMetadata(ctx, id, validators)
	if err != nil {
		// An error is never cached or allowed to revive a positive cache entry.
		purgeErr := s.store.RunManagement(ctx, scope, func(tx Transaction) error { return tx.PurgeMetadataCache(ctx, id, state.Generation) })
		if purgeErr != nil {
			return clients.Client{}, ErrUnavailable
		}
		if errors.Is(err, ErrInvalid) || errors.Is(err, ErrDenied) {
			return clients.Client{}, ErrInvalid
		}
		return clients.Client{}, ErrUnavailable
	}
	d := response.Document
	if response.NotModified {
		if state.Document == nil || validators == (MetadataValidators{}) {
			return clients.Client{}, ErrDenied
		}
		d = *state.Document
	}
	c, ok := p.Client(d)
	if !ok || c.ID != id {
		if err := s.store.RunManagement(ctx, scope, func(tx Transaction) error { return tx.PurgeMetadataCache(ctx, id, state.Generation) }); err != nil {
			return clients.Client{}, ErrUnavailable
		}
		return clients.Client{}, ErrInvalid
	}
	if response.FreshFor < 0 || response.FreshFor > 5*time.Minute {
		return clients.Client{}, ErrUnavailable
	}
	contentDigest := c.MetadataDigest
	revision := state.AuthorityRevision
	if state.ContentDigest != contentDigest {
		revision++
	}
	c.MetadataDigest, ok = clients.RevisionedMetadataDigest(contentDigest, revision)
	if !ok {
		return clients.Client{}, ErrUnavailable
	}
	next := MetadataState{Generation: state.Generation + 1, Client: c, ContentDigest: contentDigest, AuthorityRevision: revision}
	if !response.NoStore {
		next.Document = &d
		next.Validators = response.Validators
		if response.NotModified {
			if next.Validators.ETag == "" {
				next.Validators.ETag = validators.ETag
			}
			if next.Validators.LastModified == "" {
				next.Validators.LastModified = validators.LastModified
			}
		}
		next.FreshUntil = s.clock.Now().Add(response.FreshFor)
	}
	err = s.store.RunManagement(ctx, scope, func(tx Transaction) error {
		current, err := tx.MetadataPolicy(ctx)
		if err != nil {
			return err
		}
		if !current.Valid() || current.Version != p.Version || !current.Allows(id) {
			return ErrDenied
		}
		old, err := tx.MetadataState(ctx, id)
		if err != nil {
			return err
		}
		if old.Generation != state.Generation {
			return ErrConflict
		}
		if old.Generation != 0 && !old.Client.Enabled {
			return ErrDenied
		}
		if old.Generation == 0 {
			count, err := tx.MetadataClientCount(ctx)
			if err != nil {
				return err
			}
			if count >= p.MaxClients {
				return ErrRegistrationQuota
			}
		}
		if err := validateClientRegistration(ctx, tx, scope, c); err != nil {
			return err
		}
		if err := tx.SaveMetadata(ctx, state.Generation, next); err != nil {
			return err
		}
		// A 304/cache refresh is not an authority change and needs no duplicate
		// lifecycle event. New/changed accepted configuration is always audited.
		if old.Client.MetadataDigest != c.MetadataDigest {
			return tx.Audit(ctx, "client_metadata_resolved", id, id)
		}
		return nil
	})
	if err != nil {
		return clients.Client{}, err
	}
	c.AuthenticationVersion = state.Client.AuthenticationVersion
	if c.AuthenticationVersion == 0 {
		c.AuthenticationVersion = 1
	}
	return c, nil
}

// Resolver errors cross bounded contexts through fixed typed classifications.
func isMetadataDenied(err error) bool {
	return errors.Is(err, ErrDenied) || errors.Is(err, ErrInvalid) || errors.Is(err, ErrConflict) || errors.Is(err, ErrRegistrationQuota)
}
