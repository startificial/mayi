package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/startificial/mayi/internal/adapters/outbound/egress/httpclient"
	"github.com/startificial/mayi/internal/domain/clients"
	"github.com/startificial/mayi/internal/services/administration"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var _ administration.MetadataTransport = (*Metadata)(nil)

// Metadata always uses the public constrained transport. Development loopback
// exceptions for administrator-configured IdPs/keys do not apply to CIMD.
type Metadata struct{}

func NewMetadata() *Metadata { return &Metadata{} }
func (*Metadata) FetchMetadata(ctx context.Context, id string, v administration.MetadataValidators) (administration.MetadataResponse, error) {
	if _, ok := clients.MetadataURL(id); !ok {
		return administration.MetadataResponse{}, administration.ErrInvalid
	}
	c, err := httpclient.New(httpclient.Config{URLs: []string{id}})
	if err != nil {
		return administration.MetadataResponse{}, administration.ErrInvalid
	}
	return fetchMetadata(ctx, c, id, v)
}
func fetchMetadata(ctx context.Context, c *http.Client, id string, v administration.MetadataValidators) (administration.MetadataResponse, error) {
	var result administration.MetadataResponse
	if !validValidator(v.ETag, true) || !validValidator(v.LastModified, false) {
		return result, administration.ErrInvalid
	}
	r, err := http.NewRequestWithContext(ctx, "GET", id, nil)
	if err != nil {
		return result, administration.ErrInvalid
	}
	r.Header.Set("Accept", "application/json")
	if v.ETag != "" {
		r.Header.Set("If-None-Match", v.ETag)
	} else if v.LastModified != "" {
		r.Header.Set("If-Modified-Since", v.LastModified)
	}
	started := time.Now()
	response, err := c.Do(r)
	if err != nil {
		if errors.Is(err, httpclient.ErrDenied) {
			return result, administration.ErrInvalid
		}
		return result, administration.ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == 304 {
		if v == (administration.MetadataValidators{}) {
			return result, administration.ErrInvalid
		}
		result.NotModified = true
	} else if response.StatusCode != 200 {
		if response.StatusCode >= 500 {
			return result, administration.ErrUnavailable
		}
		return result, administration.ErrInvalid
	} else {
		media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || media != "application/json" || len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Encoding") != "" {
			return result, administration.ErrInvalid
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 32769))
		if err != nil || len(body) > 32768 {
			return result, administration.ErrInvalid
		}
		result.Document, err = decodeMetadata(body)
		if err != nil || result.Document.ClientID != id {
			return administration.MetadataResponse{}, administration.ErrInvalid
		}
	}
	result.Validators = administration.MetadataValidators{ETag: response.Header.Get("ETag"), LastModified: response.Header.Get("Last-Modified")}
	if len(response.Header.Values("ETag")) > 1 || len(response.Header.Values("Last-Modified")) > 1 || !validValidator(result.Validators.ETag, true) || !validValidator(result.Validators.LastModified, false) {
		return administration.MetadataResponse{}, administration.ErrInvalid
	}
	result.NoStore, result.FreshFor = metadataCache(response.Header, started, time.Now())
	return result, nil
}
func validValidator(s string, etag bool) bool {
	if s == "" {
		return true
	}
	if len(s) > 512 {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	if etag {
		value := strings.TrimPrefix(s, "W/")
		return len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' && !strings.Contains(value[1:len(value)-1], "\"")
	}
	_, err := http.ParseTime(s)
	return err == nil
}

func metadataCache(h http.Header, started, now time.Time) (bool, time.Duration) {
	noStore, noCache := false, false
	age, ttl := 0, -1
	seen := map[string]bool{}
	for _, line := range h.Values("Cache-Control") {
		for _, part := range strings.Split(line, ",") {
			name, value, hasValue := strings.Cut(strings.TrimSpace(part), "=")
			name = strings.ToLower(strings.TrimSpace(name))
			switch name {
			case "no-store", "private":
				noStore = true
			case "no-cache":
				noCache = true
			case "max-age", "s-maxage":
				if seen[name] {
					noCache = true
				}
				seen[name] = true
				parsed := strings.TrimSpace(value)
				if strings.HasPrefix(parsed, "\"") && strings.HasSuffix(parsed, "\"") && len(parsed) >= 2 {
					parsed = parsed[1 : len(parsed)-1]
				}
				n, err := cacheSeconds(parsed)
				if !hasValue || err != nil || n < 0 || n > 2147483647 {
					noCache = true
				} else if ttl < 0 || name == "s-maxage" || !seen["s-maxage"] {
					ttl = n
				}
			}
		}
	}
	if h.Get("Age") != "" {
		n, err := cacheSeconds(h.Get("Age"))
		if err != nil || n < 0 || n > 2147483647 || len(h.Values("Age")) != 1 {
			noCache = true
		} else {
			age = n
		}
	}
	if date, err := http.ParseTime(h.Get("Date")); err == nil {
		apparent := now.Sub(date)
		if apparent > time.Duration(age)*time.Second {
			age = int(apparent / time.Second)
		}
		if date.After(now.Add(time.Minute)) {
			noCache = true
		}
		if ttl < 0 {
			if expires, err := http.ParseTime(h.Get("Expires")); err == nil {
				ttl = int(expires.Sub(date) / time.Second)
			}
		}
	}
	for _, line := range h.Values("Vary") {
		for _, name := range strings.Split(line, ",") {
			if !strings.EqualFold(strings.TrimSpace(name), "Accept") {
				noStore = true
			}
		}
	}
	if h.Get("Set-Cookie") != "" {
		noStore = true
	}
	if noStore || noCache || ttl <= 0 {
		return noStore, 0
	}
	seconds := ttl - age
	if seconds < 0 {
		seconds = 0
	}
	if seconds > 300 {
		seconds = 300
	}
	remaining := time.Duration(seconds)*time.Second - now.Sub(started)
	if remaining < 0 {
		remaining = 0
	}
	if remaining > 5*time.Minute {
		remaining = 5 * time.Minute
	}
	return false, remaining
}

func decodeMetadata(body []byte) (clients.MetadataDocument, error) {
	var result clients.MetadataDocument
	if !utf8.Valid(body) {
		return result, administration.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(body))
	depth, count := 0, 0
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return result, administration.ErrInvalid
		}
		count++
		if count > 4096 {
			return result, administration.ErrInvalid
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
			if depth > 16 {
				return result, administration.ErrInvalid
			}
		}
	}
	d = json.NewDecoder(bytes.NewReader(body))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return result, administration.ErrInvalid
	}
	fields := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return result, administration.ErrInvalid
		}
		key, ok := token.(string)
		lower := strings.ToLower(key)
		if !ok || seen[lower] {
			return result, administration.ErrInvalid
		}
		seen[lower] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return result, administration.ErrInvalid
		}
		switch lower {
		case "client_secret", "client_secret_expires_at", "jwks", "jwks_uri", "software_statement", "scope", "request_uris", "sector_identifier_uri":
			return result, administration.ErrInvalid
		case "client_id", "client_name", "application_type", "redirect_uris", "token_endpoint_auth_method", "grant_types", "response_types", "dpop_bound_access_tokens", "authorization_details_types":
			if key != lower || bytes.Equal(value, []byte("null")) {
				return result, administration.ErrInvalid
			}
			fields[key] = value
		}
	}
	if _, err := d.Token(); err != nil || d.Decode(&struct{}{}) != io.EOF {
		return result, administration.ErrInvalid
	}
	var dto struct {
		ID          string   `json:"client_id"`
		Name        string   `json:"client_name"`
		Application string   `json:"application_type"`
		Redirects   []string `json:"redirect_uris"`
		Auth        string   `json:"token_endpoint_auth_method"`
		Grants      []string `json:"grant_types"`
		Responses   []string `json:"response_types"`
		Types       []string `json:"authorization_details_types"`
		Binding     *bool    `json:"dpop_bound_access_tokens"`
	}
	b, _ := json.Marshal(fields)
	if json.Unmarshal(b, &dto) != nil || dto.Auth != "none" || dto.Binding != nil && !*dto.Binding {
		return result, administration.ErrInvalid
	}
	if len(dto.Grants) != 2 || (len(dto.Grants) > 2 || !containsOnly(dto.Grants, []string{"authorization_code", "refresh_token"}) || !contains(dto.Grants, "authorization_code")) {
		return result, administration.ErrInvalid
	}
	if len(dto.Responses) > 0 && (len(dto.Responses) != 1 || dto.Responses[0] != "code") {
		return result, administration.ErrInvalid
	}
	return clients.MetadataDocument{ClientID: dto.ID, Name: dto.Name, ApplicationType: dto.Application, RedirectURIs: dto.Redirects, AuthorizationDetailsTypes: dto.Types}, nil
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func containsOnly(values, allowed []string) bool {
	seen := map[string]bool{}
	for _, v := range values {
		if seen[v] || !contains(allowed, v) {
			return false
		}
		seen[v] = true
	}
	return true
}

func cacheSeconds(s string) (int, error) {
	if len(s) == 0 || len(s) > 10 {
		return 0, administration.ErrInvalid
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, administration.ErrInvalid
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n > 2147483647 {
		return 0, administration.ErrInvalid
	}
	return n, nil
}
