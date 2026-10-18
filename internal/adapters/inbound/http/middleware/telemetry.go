package middleware

import (
	"crypto/rand"
	"encoding/hex"
	httptransport "github.com/startificial/mayi/internal/adapters/inbound/http"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

type Telemetry struct {
	logger   *slog.Logger
	requests atomic.Uint64
	errors   atomic.Uint64
	slots    chan struct{}
}

func NewTelemetry(logger *slog.Logger) *Telemetry {
	return &Telemetry{logger: logger, slots: make(chan struct{}, 100)}
}

type response struct {
	http.ResponseWriter
	status int
}

func (w *response) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
		w.ResponseWriter.WriteHeader(code)
	}
}
func (w *response) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}

// Wrap applies public admission control and observes the admitted request.
func (t *Telemetry) Wrap(next http.Handler) http.Handler {
	observed := t.Observe(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case t.slots <- struct{}{}:
			defer func() { <-t.slots }()
		default:
			t.requests.Add(1)
			t.errors.Add(1)
			httptransport.Error(w, 503, "temporarily_unavailable")
			return
		}
		observed.ServeHTTP(w, r)
	})
}

// Observe records transport telemetry without consuming public admission slots.
// Composition uses this only for the constant-time liveness operation.
func (t *Telemetry) Observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.requests.Add(1)
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			httptransport.Error(w, 503, "temporarily_unavailable")
			return
		}
		requestID := hex.EncodeToString(id[:])
		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		started := time.Now()
		out := &response{ResponseWriter: w}
		next.ServeHTTP(out, r)
		if out.status == 0 {
			out.status = 200
		}
		level := slog.LevelInfo
		message := "http_request"
		if out.status == 401 || out.status == 403 {
			level = slog.LevelWarn
			message = "security_denial"
		}
		if out.status >= 500 {
			t.errors.Add(1)
			level = slog.LevelError
			message = "request_failed"
		}
		// Request targets, headers, bodies and raw errors are deliberately absent.
		t.logger.Log(r.Context(), level, message, "request_id", requestID, "status", out.status, "duration_ms", time.Since(started).Milliseconds())
	})
}
func (t *Telemetry) Metrics(w http.ResponseWriter, _ *http.Request) {
	httptransport.JSON(w, 200, struct {
		Requests uint64 `json:"requests_total"`
		Errors   uint64 `json:"errors_total"`
	}{t.requests.Load(), t.errors.Load()})
}
