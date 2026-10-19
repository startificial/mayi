package http

import (
	"context"
	"github.com/startificial/mayi/examples/bff/services"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Handler struct {
	sessions *services.Service
	login    *services.Login
	origin   string
}

func New(sessions *services.Service, login *services.Login, origin string) (*Handler, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || sessions == nil || login == nil {
		return nil, services.ErrSession
	}
	return &Handler{sessions, login, origin}, nil
}
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", h.begin)
	mux.HandleFunc("GET /callback", h.callback)
	mux.HandleFunc("GET /documents/{id}", h.read)
	mux.HandleFunc("POST /logout", h.end)
	return mux
}
func headers(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
}
func cookie(w http.ResponseWriter, name, value string, seconds int) {
	http.SetCookie(w, &http.Cookie{Name: "__Host-bff-" + name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: seconds})
}
func readCookie(r *http.Request, name string) (string, bool) {
	values := r.CookiesNamed("__Host-bff-" + name)
	if len(values) != 1 || len(values[0].Value) > 256 {
		return "", false
	}
	return values[0].Value, values[0].Value != ""
}
func fail(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"request_denied"}`))
}
func (h *Handler) begin(w http.ResponseWriter, r *http.Request) {
	headers(w)
	if r.Method != "GET" || r.URL.RawQuery != "" || r.Header.Get("Sec-Fetch-Dest") == "iframe" || r.Header.Get("Sec-Fetch-Dest") == "frame" {
		fail(w, 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	destination, flow, err := h.login.Begin(ctx)
	if err != nil {
		fail(w, 503)
		return
	}
	cookie(w, "login", flow, 300)
	http.Redirect(w, r, destination, 303)
}
func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	headers(w)
	if r.Method != "GET" || len(r.URL.RawQuery) > 8192 {
		fail(w, 400)
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q) != 3 {
		fail(w, 400)
		return
	}
	for key, v := range q {
		if len(v) != 1 || key != "code" && key != "state" && key != "iss" {
			fail(w, 400)
			return
		}
	}
	flow, ok := readCookie(r, "login")
	if !ok {
		fail(w, 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	session, err := h.login.Complete(ctx, flow, q.Get("state"), q.Get("code"), q.Get("iss"))
	cookie(w, "login", "", -1)
	if err != nil {
		fail(w, 400)
		return
	}
	cookie(w, "session", session, 3600)
	http.Redirect(w, r, "/documents/123", 303)
}
func (h *Handler) read(w http.ResponseWriter, r *http.Request) {
	headers(w)
	if r.Method != "GET" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" {
		fail(w, 400)
		return
	}
	session, ok := readCookie(r, "session")
	if !ok {
		fail(w, 401)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	body, err := h.sessions.ReadObject(ctx, session, r.PathValue("id"))
	if err != nil {
		fail(w, 403)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
func (h *Handler) end(w http.ResponseWriter, r *http.Request) {
	headers(w)
	if r.Method != "POST" || r.URL.RawQuery != "" || len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != h.origin || r.ContentLength != 0 || strings.Contains(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		fail(w, 400)
		return
	}
	session, ok := readCookie(r, "session")
	if !ok {
		fail(w, 401)
		return
	}
	if err := h.sessions.End(r.Context(), session); err != nil {
		fail(w, 400)
		return
	}
	cookie(w, "session", "", -1)
	w.WriteHeader(204)
}
