// Package selfservice maps bounded browser messages to authentication and
// authorization use cases. It holds no persistence or protocol lifecycle state.
package selfservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	httptransport "github.com/startificial/mayi/internal/adapters/inbound/http"
	"github.com/startificial/mayi/internal/adapters/inbound/web"
	domain "github.com/startificial/mayi/internal/domain/authorization"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/domain/grants"
	"github.com/startificial/mayi/internal/services/authentication"
	"github.com/startificial/mayi/internal/services/authorization"
)

type Handler struct {
	login                        *authentication.Service
	consent                      *authorization.Service
	scope                        grants.Scope
	origin, upstreamIssuer, base string
}

func New(login *authentication.Service, consent *authorization.Service, scope grants.Scope, upstreamIssuer string) (*Handler, error) {
	u, err := url.Parse(scope.Issuer)
	if err != nil || !scope.Valid() || login == nil || consent == nil {
		return nil, authentication.ErrUnavailable
	}
	return &Handler{login, consent, scope, u.Scheme + "://" + u.Host, upstreamIssuer, u.Path}, nil
}

type flowCookie struct {
	Handle, CSRF, State, Nonce, Verifier string
	CreatedAt, ExpiresAt                 time.Time
}

func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func secret() (string, error) {
	var b [32]byte
	_, err := rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:]), err
}
func validSecret(s string) bool {
	b, e := base64.RawURLEncoding.DecodeString(s)
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == s
}
func (h *Handler) name(kind string) string { return "__Host-mayi-" + kind + "-" + h.scope.TenantID }
func (h *Handler) cookie(r *http.Request, kind string) (string, error) {
	value := ""
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == h.name(kind) {
			count++
			value = c.Value
		}
	}
	if count != 1 || len(value) > 2048 {
		return "", authentication.ErrDenied
	}
	return value, nil
}
func (h *Handler) set(w http.ResponseWriter, kind, value string, seconds int) {
	http.SetCookie(w, &http.Cookie{Name: h.name(kind), Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: seconds})
}
func (h *Handler) flow(r *http.Request) (flowCookie, string, error) {
	var f flowCookie
	raw, err := h.cookie(r, "flow")
	if err != nil {
		return f, "", err
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return f, "", authentication.ErrDenied
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&f) != nil || d.Decode(&struct{}{}) != io.EOF || !validSecret(f.Handle) || !validSecret(f.CSRF) || !validSecret(f.State) || !validSecret(f.Nonce) || !validSecret(f.Verifier) {
		return flowCookie{}, "", authentication.ErrDenied
	}
	browser, err := h.cookie(r, "browser")
	if err != nil || !validSecret(browser) {
		return flowCookie{}, "", authentication.ErrDenied
	}
	return f, digest(browser), nil
}
func headers(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", pagePolicy(""))
}

func pagePolicy(formOrigin string) string {
	forms := "'self'"
	if formOrigin != "" {
		forms += " " + formOrigin
	}
	return "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action " + forms + "; require-trusted-types-for 'script'; trusted-types 'none'"
}

// Form-submission redirects retain the initiating document's form-action
// constraints. Permit only the already authorized registered client's origin.
func consentPolicy(redirect string) (string, error) {
	if !clients.ValidAuthorizationRedirect(redirect) {
		return "", authorization.ErrInvalid
	}
	u, err := url.Parse(redirect)
	if err != nil {
		return "", err
	}
	return pagePolicy(u.Scheme + "://" + u.Host), nil
}
func (h *Handler) failure(w http.ResponseWriter, err error) {
	status := 400
	code := "invalid_request"
	if errors.Is(err, authentication.ErrUnavailable) || errors.Is(err, authorization.ErrUnavailable) {
		status = 503
		code = "temporarily_unavailable"
	}
	httptransport.Error(w, status, code)
}
func single(raw string, allowed ...string) (url.Values, error) {
	if len(raw) > 8192 {
		return nil, authentication.ErrDenied
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil, authentication.ErrDenied
	}
	for key, vs := range values {
		ok := false
		for _, a := range allowed {
			if a == key {
				ok = true
			}
		}
		if !ok || len(vs) != 1 {
			return nil, authentication.ErrDenied
		}
	}
	return values, nil
}
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	headers(w)
	if r.Method != http.MethodGet || r.Header.Get("Sec-Fetch-Dest") == "iframe" || r.Header.Get("Sec-Fetch-Dest") == "frame" {
		h.failure(w, authentication.ErrDenied)
		return
	}
	v, err := single(r.URL.RawQuery, "client_id", "response_type", "redirect_uri", "resource", "scope", "state", "code_challenge", "code_challenge_method", "dpop_jkt")
	if err != nil || v.Get("response_type") != "code" || v.Get("code_challenge_method") != "S256" || len(v.Get("state")) < 16 {
		h.failure(w, authentication.ErrDenied)
		return
	}
	request := domain.Request{TenantIssuer: h.scope, ClientID: v.Get("client_id"), RedirectURI: v.Get("redirect_uri"), ResourceURI: v.Get("resource"), PermissionScopes: strings.Split(v.Get("scope"), " "), State: v.Get("state"), PKCEChallenge: v.Get("code_challenge"), BindingThumbprint: v.Get("dpop_jkt")}
	if !request.Valid() {
		h.failure(w, authentication.ErrDenied)
		return
	}
	browser, err := h.cookie(r, "browser")
	if err != nil || !validSecret(browser) {
		browser, err = secret()
		if err != nil {
			h.failure(w, authentication.ErrUnavailable)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	begun, err := h.consent.Begin(ctx, request, digest(browser))
	if err != nil {
		h.failure(w, err)
		return
	}
	challenge, err := h.login.Start(ctx, authentication.Start{BrowserHash: digest(browser), AuthorizationHash: digest(begun.Handle), ExpiresAt: begun.ExpiresAt})
	if err != nil {
		h.failure(w, err)
		return
	}
	f := flowCookie{begun.Handle, begun.CSRFToken, challenge.State, challenge.Nonce, challenge.Verifier, challenge.CreatedAt, challenge.ExpiresAt}
	data, err := json.Marshal(f)
	if err != nil {
		h.failure(w, authentication.ErrUnavailable)
		return
	}
	h.set(w, "browser", browser, 3600)
	h.set(w, "flow", base64.RawURLEncoding.EncodeToString(data), 300)
	http.Redirect(w, r, challenge.URL, http.StatusSeeOther)
}
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	headers(w)
	if r.Method != http.MethodGet || r.Header.Get("Sec-Fetch-Dest") == "iframe" || r.Header.Get("Sec-Fetch-Dest") == "frame" {
		h.failure(w, authentication.ErrDenied)
		return
	}
	v, err := single(r.URL.RawQuery, "state", "code", "iss", "error")
	f, browserHash, flowErr := h.flow(r)
	if err != nil || flowErr != nil || v.Get("error") != "" || v.Get("iss") != "" && v.Get("iss") != h.upstreamIssuer || subtle.ConstantTimeCompare([]byte(v.Get("state")), []byte(f.State)) != 1 {
		h.failure(w, authentication.ErrDenied)
		return
	}
	previous, _ := h.cookie(r, "session")
	previousHash := ""
	if validSecret(previous) {
		previousHash = digest(previous)
	}
	session, err := h.login.Complete(r.Context(), authentication.Callback{State: f.State, Nonce: f.Nonce, Verifier: f.Verifier, Code: v.Get("code"), BrowserHash: browserHash, AuthorizationHash: digest(f.Handle), PreviousSessionHash: previousHash, CreatedAt: f.CreatedAt, ExpiresAt: f.ExpiresAt})
	if err != nil {
		h.set(w, "flow", "", -1)
		h.failure(w, err)
		return
	}
	h.set(w, "session", session.Handle, session.LifetimeSeconds)
	if browser, err := h.cookie(r, "browser"); err == nil {
		h.set(w, "browser", browser, session.LifetimeSeconds)
	}
	http.Redirect(w, r, h.base+"/consent", http.StatusSeeOther)
}
func (h *Handler) proof(r *http.Request) (flowCookie, authorization.AccessProof, error) {
	f, browserHash, err := h.flow(r)
	if err != nil {
		return f, authorization.AccessProof{}, err
	}
	session, err := h.cookie(r, "session")
	if err != nil || !validSecret(session) {
		return f, authorization.AccessProof{}, authentication.ErrDenied
	}
	return f, authorization.AccessProof{TenantIssuer: h.scope, SessionHash: digest(session), BrowserBindingHash: browserHash, AuthorizationHash: digest(f.Handle)}, nil
}
func (h *Handler) Consent(w http.ResponseWriter, r *http.Request) {
	headers(w)
	if r.Method != http.MethodGet {
		h.failure(w, authentication.ErrDenied)
		return
	}
	if r.URL.RawQuery != "" {
		h.failure(w, authentication.ErrDenied)
		return
	}
	f, proof, err := h.proof(r)
	if err != nil {
		h.failure(w, err)
		return
	}
	view, err := h.consent.PrepareConsent(r.Context(), proof)
	if err != nil {
		h.failure(w, err)
		return
	}
	policy, err := consentPolicy(view.RedirectURI)
	if err != nil {
		h.failure(w, authentication.ErrUnavailable)
		return
	}
	w.Header().Set("Content-Security-Policy", policy)
	model := web.Consent{ClientName: view.ClientName, ClientID: view.ClientID, ResourceName: view.ResourceName, ResourceURI: view.ResourceURI, RedirectURI: view.RedirectURI, CSRF: f.CSRF, Action: h.base + "/consent", LogoutAction: h.base + "/session/end", DecisionAvailable: view.DecisionAvailable}
	for _, p := range view.PermissionScopes {
		model.Permissions = append(model.Permissions, web.Permission{Name: p.Name, Description: p.Description})
	}
	for _, object := range view.Objects {
		item := web.ConsentObject{Type: object.Type, Identifier: object.Identifier, Name: object.Name}
		for _, action := range object.Actions {
			item.Actions = append(item.Actions, web.Permission{Name: action.Name, Description: action.Description})
		}
		model.Objects = append(model.Objects, item)
	}
	page, err := web.ConsentPage(model)
	if err != nil {
		h.failure(w, authentication.ErrUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(page)
}
func (h *Handler) sameOrigin(r *http.Request) bool {
	return len(r.Header.Values("Origin")) == 1 && r.Header.Get("Origin") == h.origin && (r.Header.Get("Sec-Fetch-Site") == "" || r.Header.Get("Sec-Fetch-Site") == "same-origin")
}
func (h *Handler) Decide(w http.ResponseWriter, r *http.Request) {
	headers(w)
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || !h.sameOrigin(r) || r.URL.RawQuery != "" {
		h.failure(w, authentication.ErrDenied)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		h.failure(w, authentication.ErrDenied)
		return
	}
	v, err := single(string(data), "csrf", "decision")
	if err != nil || !validSecret(v.Get("csrf")) || v.Get("decision") != "approve" && v.Get("decision") != "deny" {
		h.failure(w, authentication.ErrDenied)
		return
	}
	_, proof, err := h.proof(r)
	if err != nil {
		h.failure(w, err)
		return
	}
	proof.CSRFHash = digest(v.Get("csrf"))
	result, err := h.consent.Decide(r.Context(), authorization.Decision{Approve: v.Get("decision") == "approve", Proof: proof})
	if err != nil {
		h.failure(w, err)
		return
	}
	redirect, err := responseRedirect(result, h.scope.Issuer)
	if err != nil {
		h.failure(w, authentication.ErrUnavailable)
		return
	}
	policy, err := consentPolicy(result.RedirectURI)
	if err != nil {
		h.failure(w, authentication.ErrUnavailable)
		return
	}
	w.Header().Set("Content-Security-Policy", policy)
	h.set(w, "flow", "", -1)
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

// Preserve registered fixed-query bytes, including ordering, repeated values
// and escape spelling. They may carry an application signature. The domain has
// already excluded collisions with OAuth response parameter names.
func responseRedirect(result authorization.DecisionResult, issuer string) (string, error) {
	u, err := url.Parse(result.RedirectURI)
	if err != nil {
		return "", err
	}
	q := url.Values{"state": {result.State}, "iss": {issuer}}
	if result.Code != "" {
		q.Set("code", result.Code)
	} else {
		q.Set("error", "access_denied")
	}
	separator := "?"
	if u.RawQuery != "" {
		separator = "&"
	} else if u.ForceQuery {
		separator = ""
	}
	return result.RedirectURI + separator + q.Encode(), nil
}
func (h *Handler) EndSession(w http.ResponseWriter, r *http.Request) {
	headers(w)
	if !h.sameOrigin(r) || r.URL.RawQuery != "" || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		h.failure(w, authentication.ErrDenied)
		return
	}
	// A session can be ended after the consent workflow has expired. Exact Origin
	// and browser/session proof protect this mutation; ending it revokes no grants.
	browser, e1 := h.cookie(r, "browser")
	session, e2 := h.cookie(r, "session")
	if e1 != nil || e2 != nil || !validSecret(browser) || !validSecret(session) {
		h.failure(w, authentication.ErrDenied)
		return
	}
	if err := h.login.End(r.Context(), digest(session), digest(browser)); err != nil {
		h.failure(w, err)
		return
	}
	h.set(w, "session", "", -1)
	h.set(w, "flow", "", -1)
	w.WriteHeader(http.StatusNoContent)
}
