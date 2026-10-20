// Package authorization owns the bounded consent workflow, not the durable grant lifecycle.
package authorization

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/domain/policy"
	"github.com/startificial/mayi/internal/domain/resources"
)

var ErrInvalid = errors.New("invalid authorization transaction")

const Pending = "pending"
const Approved = "approved"
const Denied = "denied"

// Request preserves the client's exact redirect and permission ceiling. S256 is
// the only accepted PKCE method; adapters must reject other methods before mapping.
type Request struct {
	OIDC, OfflineAccess                                                         bool
	Nonce                                                                       string
	TenantIssuer                                                                grants.Scope
	ClientID, RedirectURI, ResourceURI, PKCEChallenge, BindingThumbprint, State string
	PermissionScopes                                                            []string
	ObjectCeiling                                                               grants.ObjectCeiling
}

func (r Request) Valid() bool {
	if r.OIDC && (len(r.Nonce) < 16 || len(r.Nonce) > 256) || !r.OIDC && r.Nonce != "" {
		return false
	}
	for _, c := range r.Nonce {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}

	if !r.TenantIssuer.Valid() || !resources.ValidID(r.ClientID) || !clients.ValidApplicationRedirect("native", r.RedirectURI) || !resources.ValidURI(r.ResourceURI) || !digestValue(r.PKCEChallenge) || r.BindingThumbprint != "" && !digestValue(r.BindingThumbprint) || len(r.State) > 1024 || !grants.ValidScopes(r.PermissionScopes) || len(r.PermissionScopes) == 0 {
		return false
	}
	for _, c := range r.State {
		if c < 0x20 || c >= 0x7f {
			return false
		}
	}
	if !r.ObjectCeiling.BoundTo(r.TenantIssuer, r.ResourceURI) || len(r.ObjectCeiling.Snapshot().Details) == 0 {
		return false
	}
	return true
}
func digestValue(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == s
}
func ValidHandleHash(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

// Registration is a current, use-case-scoped projection of the three existing
// owners' values. It does not own their lifecycle or mutate their internals.
type Registration struct {
	Client         clients.Client
	Resource       resources.Resource
	Policy         policy.Tenant
	ObjectProfiles []resources.ObjectProfile
}

// MatchesObjectRegistration checks the request against current registered
// client/resource vocabulary only. It neither verifies PAR provenance nor
// authorizes the principal/object, and must not be used alone for consent.
func (r Request) MatchesObjectRegistration(current Registration) bool {
	if !r.matchesRegistration(current) || r.ObjectCeiling.IsZero() || len(current.ObjectProfiles) == 0 || len(current.ObjectProfiles) > clients.MaxAuthorizationDetailsTypes {
		return false
	}
	for _, profile := range current.ObjectProfiles {
		if !current.Client.AllowsObjectProfile(current.Resource, profile) {
			return false
		}
	}
	_, err := resources.ValidateObjectRequest(r.TenantIssuer, r.ResourceURI, current.ObjectProfiles, r.ObjectCeiling.Snapshot().Details)
	return err == nil
}

func (r Request) matchesRegistration(current Registration) bool {
	if !r.Valid() || !current.Client.Valid() || !current.Resource.Valid() || !current.Policy.Valid() || !current.Client.Enabled || current.Client.ID != r.ClientID || current.Resource.URI != r.ResourceURI || !current.Client.AllowsRedirect(r.RedirectURI) || !slices.Contains(current.Client.Resources, current.Resource.ID) {
		return false
	}
	if (current.Policy.RequireBinding || current.Resource.RequireBinding || current.Client.RequireBinding) && r.BindingThumbprint == "" {
		return false
	}
	return current.Resource.AllowsUserScopes(r.PermissionScopes)
}

type Spec struct {
	Revision                                                         uint64
	ID, HandleHash, BrowserBindingHash, CSRFHash, ConsentSessionHash string
	PushedRequestHash                                                string
	Request                                                          Request
	PolicyVersion                                                    uint64
	CreatedAt, ExpiresAt                                             time.Time
	Status, Subject, GrantID, CodeHash                               string
}

// Transaction protects its request snapshot and terminal transition from aliasing.
type Transaction struct{ spec Spec }

func New(spec Spec) (Transaction, error) {
	if spec.Revision == 0 {
		spec.Revision = 1
	}
	if spec.Revision > 1<<63-1 {
		return Transaction{}, ErrInvalid
	}
	if !ValidHandleHash(spec.PushedRequestHash) || spec.PushedRequestHash == spec.HandleHash || spec.PushedRequestHash == spec.CSRFHash {
		return Transaction{}, ErrInvalid
	}
	if !resources.ValidID(spec.ID) || !ValidHandleHash(spec.HandleHash) || !ValidHandleHash(spec.BrowserBindingHash) || !ValidHandleHash(spec.CSRFHash) || !spec.Request.Valid() || spec.ConsentSessionHash != "" && !ValidHandleHash(spec.ConsentSessionHash) || spec.PolicyVersion == 0 || spec.CreatedAt.IsZero() || !spec.ExpiresAt.After(spec.CreatedAt) || spec.ExpiresAt.After(spec.CreatedAt.Add(5*time.Minute)) {
		return Transaction{}, ErrInvalid
	}
	switch spec.Status {
	case Pending, Denied:
		if spec.Status == Denied && spec.ConsentSessionHash == "" {
			return Transaction{}, ErrInvalid
		}
		if spec.Subject != "" || spec.GrantID != "" || spec.CodeHash != "" {
			return Transaction{}, ErrInvalid
		}
	case Approved:
		if !ValidHandleHash(spec.CodeHash) || spec.ConsentSessionHash == "" {
			return Transaction{}, ErrInvalid
		}
		reference := grants.RevisionSpec{Scope: spec.Request.TenantIssuer, GrantID: spec.GrantID, Number: spec.Revision, ClientID: spec.Request.ClientID, Subject: spec.Subject, PrincipalType: "user", Resource: spec.Request.ResourceURI}
		if !reference.ValidReferences() {
			return Transaction{}, ErrInvalid
		}
	default:
		return Transaction{}, ErrInvalid
	}
	spec.Request.PermissionScopes = slices.Clone(spec.Request.PermissionScopes)
	return Transaction{spec: spec}, nil
}
func (t Transaction) Snapshot() Spec {
	s := t.spec
	s.Request.PermissionScopes = slices.Clone(s.Request.PermissionScopes)
	return s
}
func (t Transaction) Decide(approve bool, subject, grantID, codeHash string, now time.Time, grantLifetime time.Duration) (Transaction, grants.Revision, error) {
	return t.decide(approve, subject, grantID, codeHash, now, grantLifetime, nil)
}
func (t Transaction) decide(approve bool, subject, grantID, codeHash string, now time.Time, grantLifetime time.Duration, previous *grants.Revision) (Transaction, grants.Revision, error) {
	s := t.Snapshot()
	if _, err := New(s); err != nil || s.Status != Pending || s.ConsentSessionHash == "" || now.Before(s.CreatedAt) || !now.Before(s.ExpiresAt) {
		return Transaction{}, grants.Revision{}, ErrInvalid
	}
	if !approve {
		s.Status = Denied
		next, err := New(s)
		return next, grants.Revision{}, err
	}
	if grantLifetime <= 0 || grantLifetime > 366*24*time.Hour {
		return Transaction{}, grants.Revision{}, ErrInvalid
	}
	revision, err := grants.NewRevision(grants.RevisionSpec{Scope: s.Request.TenantIssuer, GrantID: grantID, Number: 1, ClientID: s.Request.ClientID, Subject: subject, PrincipalType: "user", Resource: s.Request.ResourceURI, Scopes: s.Request.PermissionScopes, ObjectCeiling: s.Request.ObjectCeiling, ExpiresAt: now.Add(grantLifetime)})
	if err != nil {
		return Transaction{}, grants.Revision{}, ErrInvalid
	}
	if previous != nil {
		if !now.Before(previous.Snapshot().ExpiresAt) {
			return Transaction{}, grants.Revision{}, ErrInvalid
		}
		revision, err = previous.Extend(revision.Snapshot())
		if err != nil {
			return Transaction{}, grants.Revision{}, ErrInvalid
		}
	}
	s.Revision = revision.Snapshot().Number
	grantID = revision.Snapshot().GrantID
	s.Status = Approved
	s.Subject = subject
	s.GrantID = grantID
	s.CodeHash = codeHash
	next, err := New(s)
	return next, revision, err
}

// BindSession pins the account/session used for consent presentation. A new
// login in the same browser cannot silently approve another session's request.
func (t Transaction) BindSession(hash string, now time.Time) (Transaction, error) {
	s := t.Snapshot()
	if !ValidHandleHash(hash) || s.Status != Pending || now.Before(s.CreatedAt) || !now.Before(s.ExpiresAt) || s.ConsentSessionHash != "" && s.ConsentSessionHash != hash {
		return Transaction{}, ErrInvalid
	}
	s.ConsentSessionHash = hash
	return New(s)
}
