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
	TenantIssuer                                                                grants.Scope
	ClientID, RedirectURI, ResourceURI, PKCEChallenge, BindingThumbprint, State string
	PermissionScopes                                                            []string
}

func (r Request) Valid() bool {
	if !r.TenantIssuer.Valid() || !resources.ValidID(r.ClientID) || !clients.ValidAuthorizationRedirect(r.RedirectURI) || !resources.ValidURI(r.ResourceURI) || !digestValue(r.PKCEChallenge) || r.BindingThumbprint != "" && !digestValue(r.BindingThumbprint) || len(r.State) > 1024 || !grants.ValidScopes(r.PermissionScopes) || len(r.PermissionScopes) == 0 {
		return false
	}
	for _, c := range r.State {
		if c < 0x20 || c >= 0x7f {
			return false
		}
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
	Client   clients.Client
	Resource resources.Resource
	Policy   policy.Tenant
}

func (r Request) AllowedBy(current Registration) bool {
	if !r.Valid() || !current.Client.Valid() || !current.Resource.Valid() || !current.Policy.Valid() || !current.Client.Enabled || current.Client.ID != r.ClientID || current.Resource.URI != r.ResourceURI || !slices.Contains(current.Client.RedirectURIs, r.RedirectURI) || !slices.Contains(current.Client.Resources, current.Resource.ID) {
		return false
	}
	if (current.Policy.RequireBinding || current.Resource.RequireBinding) && r.BindingThumbprint == "" {
		return false
	}
	for _, name := range r.PermissionScopes {
		found := false
		for _, scope := range current.Resource.Scopes {
			if scope.Name == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type Spec struct {
	ID, HandleHash, BrowserBindingHash, CSRFHash, ConsentSessionHash string
	Request                                                          Request
	PolicyVersion                                                    uint64
	CreatedAt, ExpiresAt                                             time.Time
	Status, Subject, GrantID, CodeHash                               string
}

// Transaction protects its request snapshot and terminal transition from aliasing.
type Transaction struct{ spec Spec }

func New(spec Spec) (Transaction, error) {
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
		reference := grants.RevisionSpec{Scope: spec.Request.TenantIssuer, GrantID: spec.GrantID, Number: 1, ClientID: spec.Request.ClientID, Subject: spec.Subject, PrincipalType: "user", Resource: spec.Request.ResourceURI}
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
	revision, err := grants.NewRevision(grants.RevisionSpec{Scope: s.Request.TenantIssuer, GrantID: grantID, Number: 1, ClientID: s.Request.ClientID, Subject: subject, PrincipalType: "user", Resource: s.Request.ResourceURI, Scopes: s.Request.PermissionScopes, ExpiresAt: now.Add(grantLifetime)})
	if err != nil {
		return Transaction{}, grants.Revision{}, ErrInvalid
	}
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
