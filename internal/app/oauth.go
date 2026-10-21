package app

import (
	"context"
	"encoding/base64"
	"github.com/startificial/mayi/internal/adapters/inbound/http/oauth"
	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"github.com/startificial/mayi/internal/adapters/outbound/egress"
	"github.com/startificial/mayi/internal/adapters/outbound/postgres"
	"github.com/startificial/mayi/internal/adapters/outbound/signing"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/administration"
	"github.com/startificial/mayi/internal/services/authentication"
	"github.com/startificial/mayi/internal/services/authorization"
	clientservice "github.com/startificial/mayi/internal/services/clients"
	"github.com/startificial/mayi/internal/services/tokens"
	"time"
)

func credentialHasher(t TenantConfig, lookup func(string) string) (*cryptoadapter.SecretHasher, error) {
	if lookup == nil {
		return nil, ErrConfiguration
	}
	var keys []cryptoadapter.HashKey
	for _, k := range t.CredentialKeys {
		b, err := base64.RawURLEncoding.DecodeString(lookup(k.SecretEnv))
		if err != nil || len(b) != 32 {
			return nil, ErrConfiguration
		}
		keys = append(keys, cryptoadapter.HashKey{Version: k.Version, Key: b, Active: k.Active})
	}
	return cryptoadapter.NewSecretHasher(keys)
}
func newClientAuthentication(c Config, scope grants.Scope, store *postgres.Store, h *cryptoadapter.SecretHasher) (*clientservice.Service, error) {
	secrets, err := cryptoadapter.NewClientSecrets(scope, h)
	if err != nil {
		return nil, err
	}
	keys := egress.NewRegisteredKeys(c.AllowInsecureLoopback)
	assertions, err := cryptoadapter.NewClientAssertions(keys)
	if err != nil {
		return nil, err
	}
	admission, err := authentication.NewAdmission(store, c.BudgetRules())
	if err != nil {
		return nil, err
	}
	metadata, err := newMetadata(scope, store)
	if err != nil {
		return nil, err
	}
	return clientservice.New(store, systemClock{}, assertions, secrets, scope, admission, metadata)
}
func newAuthorization(ctx context.Context, t TenantConfig, scope grants.Scope, store *postgres.Store, h *cryptoadapter.SecretHasher) (*authorization.Service, error) {
	source, err := cryptoadapter.NewKeyedAuthorizationSource(scope, h)
	if err != nil {
		return nil, err
	}
	var authority authorization.ObjectConsentAuthority
	if len(t.ResourceAuthorities) > 0 {
		var owners []postgres.ResourceConsentConfig
		for _, uri := range t.ResourceAuthorities {
			owners = append(owners, postgres.ResourceConsentConfig{Scope: scope, Resource: uri})
		}
		value, err := postgres.NewResourceConsent(store, owners)
		if err != nil {
			return nil, err
		}
		if err := value.Check(ctx); err != nil {
			return nil, err
		}
		authority = value
	}
	metadata, err := newMetadata(scope, store)
	if err != nil {
		return nil, err
	}
	return authorization.New(store, systemClock{}, source, authority, metadata)
}
func newProtocol(ctx context.Context, c Config, t TenantConfig, scope grants.Scope, store *postgres.Store, ring *signing.Ring, lookup func(string) string) (*oauth.Protocol, error) {
	admission, err := authentication.NewAdmission(store, c.BudgetRules())
	if err != nil {
		return nil, err
	}
	hash, err := credentialHasher(t, lookup)
	if err != nil {
		return nil, err
	}
	client, err := newClientAuthentication(c, scope, store, hash)
	if err != nil {
		return nil, err
	}
	consent, err := newAuthorization(ctx, t, scope, store, hash)
	if err != nil {
		return nil, err
	}
	material, err := cryptoadapter.NewKeyedMaterialSource(scope, hash, tokens.RefreshToken)
	if err != nil {
		return nil, err
	}
	metadata, err := newMetadata(scope, store)
	if err != nil {
		return nil, err
	}
	issuance, err := tokens.New(store, systemClock{}, cryptoadapter.New(), ring, material, store, 5*time.Minute, admission, metadata)
	if err != nil {
		return nil, err
	}
	machine, err := tokens.NewMachine(store, systemClock{}, material, ring, admission)
	if err != nil {
		return nil, err
	}

	proofs, err := newProofs(scope, store, hash)
	if err != nil {
		return nil, err
	}
	status, err := tokens.NewStatus(store, hash, material, proofs, admission)
	if err != nil {
		return nil, err
	}
	return oauth.NewProtocol(scope, client, consent, issuance, machine, status, hash, proofs)
}

func newProofs(scope grants.Scope, store *postgres.Store, hash *cryptoadapter.SecretHasher) (*tokens.ProofService, error) {
	nonceSource, err := cryptoadapter.NewProofNonces(scope, hash)
	if err != nil {
		return nil, err
	}
	return tokens.NewProofs(cryptoadapter.NewDPoP(), store, store, nonceSource, systemClock{})
}

func newMetadata(scope grants.Scope, store *postgres.Store) (*administration.Metadata, error) {
	return administration.NewMetadata(store, egress.NewMetadata(), store, systemClock{}, scope)
}
