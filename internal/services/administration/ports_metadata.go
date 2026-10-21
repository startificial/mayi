package administration

import (
	"context"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"time"
)

type MetadataValidators struct{ ETag, LastModified string }
type MetadataResponse struct {
	Document             clients.MetadataDocument
	Validators           MetadataValidators
	NotModified, NoStore bool
	FreshFor             time.Duration
}
type MetadataTransport interface {
	FetchMetadata(context.Context, string, MetadataValidators) (MetadataResponse, error)
}
type MetadataAdmission interface {
	AdmitMetadata(context.Context, grants.Scope) (bool, error)
}

// Only successfully validated documents are eligible for this shared cache.
// NoStore retains no document or validators in MetadataState. The registry's
// accepted client configuration and credential correlations are security state,
// not a reusable HTTP response cache; every use still resolves/revalidates.
type MetadataState struct {
	Generation        uint64
	AuthorityRevision uint64
	ContentDigest     string
	Client            clients.Client
	Document          *clients.MetadataDocument
	Validators        MetadataValidators
	FreshUntil        time.Time
}
type MetadataTransaction interface {
	MetadataPolicy(context.Context) (clients.MetadataPolicy, error)
	SetMetadataPolicy(context.Context, clients.MetadataPolicy) error
	MetadataState(context.Context, string) (MetadataState, error)
	MetadataClientCount(context.Context) (int, error)
	// Expected generation and the current policy version must match. Replacing
	// registration and cache, including purge, commits with the audit/outbox.
	SaveMetadata(context.Context, uint64, MetadataState) error
	PurgeMetadataCache(context.Context, string, uint64) error
}
