package administration

import (
	"context"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/identity"
	"github.com/startificial/mayi/internal/domain/policy"
	"github.com/startificial/mayi/internal/domain/resources"
	"time"
)

type Clock interface{ Now() time.Time }
type KeyCatalog interface {
	PublicKey(context.Context, grants.Scope, int) (identity.PublicKey, error)
}

// RunManagement serializes tenant policy and mutations with token issuance's
// policy lock. The callback runs once; state, audit and outbox commit together.
type Store interface {
	RunManagement(context.Context, grants.Scope, func(Transaction) error) error
	// ProvisionTenant is available only through the explicit local operator
	// capability. Runtime database credentials cannot insert a tenant.
	ProvisionTenant(context.Context, grants.Scope, identity.PublicKey, policy.Tenant, string) error
}
type Transaction interface {
	RegistrationTransaction
	Policy(context.Context) (policy.Tenant, error)
	SetPolicy(context.Context, policy.Tenant) error
	Resource(context.Context, string) (resources.Resource, error)
	CreateResource(context.Context, resources.Resource) error
	RegisterObjectProfile(context.Context, string, resources.ObjectProfile) error
	ObjectProfile(context.Context, string, string) (resources.ObjectProfile, error)
	// ClientObjectProfile resolves a type only within the proposed client's
	// allowed resources, under the same tenant guard as client creation.
	ClientObjectProfile(context.Context, string, []string) (resources.ObjectProfile, error)
	Client(context.Context, string) (clients.Client, error)
	CreateClient(context.Context, clients.Client) error
	PublishKey(context.Context, identity.PublicKey, time.Time) error
	ActivateKey(context.Context, int, time.Time, time.Duration) error
	Audit(context.Context, string, string, string) error
}
