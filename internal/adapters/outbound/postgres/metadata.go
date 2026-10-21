package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/administration"
	"github.com/startificial/mayi/internal/services/authentication"
	"time"
)

var _ administration.MetadataAdmission = (*Store)(nil)

func (s *Store) AdmitMetadata(ctx context.Context, scope grants.Scope) (bool, error) {
	return s.ConsumeBudget(ctx, scope, authentication.Budget{Operation: "cimd", Dimension: "client", Key: "tenant-cimd", Limit: 600, WindowSeconds: 60})
}

type redirectApprovalRecord struct {
	Client    string   `json:"client_id"`
	Redirects []string `json:"redirect_uris"`
}
type metadataRecord struct {
	ID          string   `json:"client_id"`
	Name        string   `json:"client_name"`
	Application string   `json:"application_type"`
	Redirects   []string `json:"redirect_uris"`
	Types       []string `json:"authorization_details_types"`
}

func (m *management) MetadataPolicy(ctx context.Context) (clients.MetadataPolicy, error) {
	var p clients.MetadataPolicy
	var approvals []byte
	err := m.tx.QueryRow(ctx, `SELECT version,mode,hosts,approved_clients,resources,authorization_details_types,redirect_approvals,max_clients,access_token_seconds FROM mayi.client_metadata_policies WHERE tenant_id=$1`, m.scope.TenantID).Scan(&p.Version, &p.Mode, &p.Hosts, &p.ApprovedClients, &p.Resources, &p.AuthorizationDetailsTypes, &approvals, &p.MaxClients, &p.AccessTokenSeconds)
	if errors.Is(err, pgx.ErrNoRows) {
		return clients.DefaultMetadataPolicy(), nil
	}
	if err != nil {
		return p, classifyManagement(err)
	}
	var wire []redirectApprovalRecord
	if json.Unmarshal(approvals, &wire) != nil {
		return clients.MetadataPolicy{}, administration.ErrUnavailable
	}
	for _, a := range wire {
		p.RedirectApprovals = append(p.RedirectApprovals, clients.RedirectApproval{ClientID: a.Client, RedirectURIs: a.Redirects})
	}
	if !p.Valid() {
		return clients.MetadataPolicy{}, administration.ErrUnavailable
	}
	return p, nil
}
func (m *management) SetMetadataPolicy(ctx context.Context, p clients.MetadataPolicy) error {
	if !p.Valid() {
		return administration.ErrInvalid
	}
	wire := []redirectApprovalRecord{}
	for _, a := range p.RedirectApprovals {
		wire = append(wire, redirectApprovalRecord{a.ClientID, a.RedirectURIs})
	}
	approvals, err := json.Marshal(wire)
	if err != nil {
		return administration.ErrInvalid
	}
	list := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return v
	}
	_, err = m.tx.Exec(ctx, `INSERT INTO mayi.client_metadata_policies(tenant_id,version,mode,hosts,approved_clients,resources,authorization_details_types,redirect_approvals,max_clients,access_token_seconds) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
 ON CONFLICT(tenant_id) DO UPDATE SET version=excluded.version,mode=excluded.mode,hosts=excluded.hosts,approved_clients=excluded.approved_clients,resources=excluded.resources,authorization_details_types=excluded.authorization_details_types,redirect_approvals=excluded.redirect_approvals,max_clients=excluded.max_clients,access_token_seconds=excluded.access_token_seconds`, m.scope.TenantID, p.Version, p.Mode, list(p.Hosts), list(p.ApprovedClients), list(p.Resources), list(p.AuthorizationDetailsTypes), approvals, p.MaxClients, p.AccessTokenSeconds)
	return classifyManagement(err)
}
func (m *management) MetadataState(ctx context.Context, id string) (administration.MetadataState, error) {
	var state administration.MetadataState
	var cache []byte
	var until *time.Time
	err := m.tx.QueryRow(ctx, `SELECT generation,cache_document,etag,last_modified,fresh_until,content_digest,authority_revision FROM mayi.client_metadata_state WHERE tenant_id=$1 AND client_id=$2`, m.scope.TenantID, id).Scan(&state.Generation, &cache, &state.Validators.ETag, &state.Validators.LastModified, &until, &state.ContentDigest, &state.AuthorityRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if err := m.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mayi.clients WHERE tenant_id=$1 AND client_id=$2)`, m.scope.TenantID, id).Scan(&exists); err != nil {
			return state, classifyManagement(err)
		}
		if exists {
			return state, administration.ErrConflict
		}
		return state, nil
	}
	if err != nil {
		return state, classifyManagement(err)
	}
	state.Client, err = m.Client(ctx, id)
	if err != nil {
		return state, err
	}
	if len(cache) > 0 && string(cache) != "null" {
		var record metadataRecord
		if len(cache) > 32768 || json.Unmarshal(cache, &record) != nil {
			return state, administration.ErrUnavailable
		}
		state.Document = &clients.MetadataDocument{ClientID: record.ID, Name: record.Name, ApplicationType: record.Application, RedirectURIs: record.Redirects, AuthorizationDetailsTypes: record.Types}
	}
	if until != nil {
		state.FreshUntil = *until
	}
	return state, nil
}
func (m *management) MetadataClientCount(ctx context.Context) (int, error) {
	var n int
	err := m.tx.QueryRow(ctx, `SELECT count(*) FROM mayi.client_metadata_state WHERE tenant_id=$1`, m.scope.TenantID).Scan(&n)
	return n, classifyManagement(err)
}
func (m *management) SaveMetadata(ctx context.Context, expected uint64, state administration.MetadataState) error {
	c := state.Client
	if !c.Valid() || state.Generation != expected+1 {
		return administration.ErrInvalid
	}
	if expected == 0 {
		if err := m.CreateClient(ctx, c); err != nil {
			return err
		}
	} else {
		var digest string
		var generation uint64
		if err := m.tx.QueryRow(ctx, `SELECT c.metadata_digest,s.generation FROM mayi.clients c JOIN mayi.client_metadata_state s USING(tenant_id,client_id) WHERE c.tenant_id=$1 AND c.client_id=$2 AND c.enabled FOR UPDATE OF c,s`, m.scope.TenantID, c.ID).Scan(&digest, &generation); err != nil || generation != expected {
			return administration.ErrConflict
		}
		if _, err := m.tx.Exec(ctx, `UPDATE mayi.clients SET name=$3,redirect_uris=$4,application_type=$5,access_token_seconds=$6,metadata_digest=$7,metadata_policy_version=$8,metadata_resources=$9,metadata_types=$10 WHERE tenant_id=$1 AND client_id=$2 AND enabled AND metadata_digest=$11`, m.scope.TenantID, c.ID, c.Name, c.RedirectURIs, c.EffectiveApplicationType(), c.AccessTokenSeconds, c.MetadataDigest, c.MetadataPolicyVersion, c.Resources, c.AuthorizationDetailsTypes, digest); err != nil {
			return err
		}
		if err := m.createClientVocabulary(ctx, c); err != nil {
			return err
		}
	}
	var cache any
	var until any
	if state.Document != nil {
		d := state.Document
		b, err := json.Marshal(metadataRecord{d.ClientID, d.Name, d.ApplicationType, d.RedirectURIs, d.AuthorizationDetailsTypes})
		if err != nil {
			return administration.ErrInvalid
		}
		cache = b
		until = state.FreshUntil
	}
	_, err := m.tx.Exec(ctx, `INSERT INTO mayi.client_metadata_state(tenant_id,client_id,generation,cache_document,etag,last_modified,fresh_until,content_digest,authority_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
 ON CONFLICT(tenant_id,client_id) DO UPDATE SET generation=excluded.generation,cache_document=excluded.cache_document,etag=excluded.etag,last_modified=excluded.last_modified,fresh_until=excluded.fresh_until,content_digest=excluded.content_digest,authority_revision=excluded.authority_revision`, m.scope.TenantID, c.ID, state.Generation, cache, state.Validators.ETag, state.Validators.LastModified, until, state.ContentDigest, state.AuthorityRevision)
	return classifyManagement(err)
}
func (m *management) PurgeMetadataCache(ctx context.Context, id string, generation uint64) error {
	_, err := m.tx.Exec(ctx, `UPDATE mayi.client_metadata_state SET cache_document=NULL,etag='',last_modified='',fresh_until=NULL WHERE tenant_id=$1 AND client_id=$2 AND generation=$3`, m.scope.TenantID, id, generation)
	return classifyManagement(err)
}
