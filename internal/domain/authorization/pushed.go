package authorization

import (
	"slices"
	"time"

	"github.com/startificial/mayi/internal/domain/resources"
)

const PushedLifetime = 90 * time.Second

// PushedSpec is an immutable request plus its one-use transition. Only the
// reference hash persists; neither a raw reference nor a fetchable URI does.
type PushedSpec struct {
	ID, ReferenceHash, AuthorizationHash string
	Request                              Request
	PolicyVersion                        uint64
	CreatedAt, ExpiresAt, ConsumedAt     time.Time
}

type PushedRequest struct{ spec PushedSpec }

func NewPushed(s PushedSpec) (PushedRequest, error) {
	if !resources.ValidID(s.ID) || !ValidHandleHash(s.ReferenceHash) || !s.Request.Valid() || !s.Request.PinnedMetadata() || s.Request.ObjectCeiling.IsZero() || len(s.Request.State) < 16 || s.PolicyVersion == 0 || s.CreatedAt.IsZero() || !s.ExpiresAt.After(s.CreatedAt) || s.ExpiresAt.After(s.CreatedAt.Add(PushedLifetime)) {
		return PushedRequest{}, ErrInvalid
	}
	if s.AuthorizationHash == "" {
		if !s.ConsumedAt.IsZero() {
			return PushedRequest{}, ErrInvalid
		}
	} else if !ValidHandleHash(s.AuthorizationHash) || s.AuthorizationHash == s.ReferenceHash || s.ConsumedAt.IsZero() || s.ConsumedAt.Before(s.CreatedAt) || !s.ConsumedAt.Before(s.ExpiresAt) {
		return PushedRequest{}, ErrInvalid
	}
	s.Request.PermissionScopes = slices.Clone(s.Request.PermissionScopes)
	return PushedRequest{spec: s}, nil
}

func (p PushedRequest) Snapshot() PushedSpec {
	s := p.spec
	s.Request.PermissionScopes = slices.Clone(s.Request.PermissionScopes)
	return s
}

func (p PushedRequest) ActiveAt(now time.Time) bool {
	_, err := NewPushed(p.spec)
	return err == nil && p.spec.AuthorizationHash == "" && !now.Before(p.spec.CreatedAt) && now.Before(p.spec.ExpiresAt)
}

// Begin copies the exact pushed request into a new browser workflow. There is
// no front-channel replacement request or independently supplied permission set.
func (p PushedRequest) Begin(id, handleHash, browserHash, csrfHash string, now time.Time) (PushedRequest, Transaction, error) {
	if !p.ActiveAt(now) || handleHash == p.spec.ReferenceHash || csrfHash == p.spec.ReferenceHash || handleHash == csrfHash {
		return PushedRequest{}, Transaction{}, ErrInvalid
	}
	w, err := New(Spec{ID: id, HandleHash: handleHash, BrowserBindingHash: browserHash, CSRFHash: csrfHash, Request: p.spec.Request, PushedRequestHash: p.spec.ReferenceHash, PolicyVersion: p.spec.PolicyVersion, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), Status: Pending})
	if err != nil {
		return PushedRequest{}, Transaction{}, err
	}
	s := p.Snapshot()
	s.AuthorizationHash, s.ConsumedAt = handleHash, now
	next, err := NewPushed(s)
	return next, w, err
}

// Equal preserves exact request correlation, including ordered scope bytes;
// object authority retains the domain's exact tuple-set semantics.
func (r Request) Equal(other Request) bool {
	return r.ClientMetadataDigest == other.ClientMetadataDigest && r.OIDC == other.OIDC && r.OfflineAccess == other.OfflineAccess && r.Nonce == other.Nonce && r.TenantIssuer == other.TenantIssuer && r.ClientID == other.ClientID && r.RedirectURI == other.RedirectURI && r.ResourceURI == other.ResourceURI && r.PKCEChallenge == other.PKCEChallenge && r.BindingThumbprint == other.BindingThumbprint && r.State == other.State && slices.Equal(r.PermissionScopes, other.PermissionScopes) && r.ObjectCeiling.Equal(other.ObjectCeiling)
}
