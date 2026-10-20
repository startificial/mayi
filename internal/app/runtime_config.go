package app

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/startificial/mayi/internal/domain/resources"
	"github.com/startificial/mayi/internal/services/authentication"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var ErrConfiguration = errors.New("invalid Mayi configuration")

type Config struct {
	RateLimits             []BudgetRuleConfig `json:"rate_limits,omitempty"`
	TrustedProxies         []string           `json:"trusted_proxies,omitempty"`
	PublicOrigin           string             `json:"public_origin"`
	ListenAddress          string             `json:"listen_address"`
	RuntimeRole            string             `json:"runtime_role"`
	DatabaseMaxConnections int32              `json:"database_max_connections"`
	AllowInsecureLoopback  bool               `json:"allow_insecure_loopback"`
	TransitAddress         string             `json:"transit_address"`
	Tenants                []TenantConfig     `json:"tenants"`
}
type BudgetRuleConfig struct {
	Operation     string `json:"operation"`
	Dimension     string `json:"dimension"`
	Limit         int    `json:"limit"`
	WindowSeconds int    `json:"window_seconds"`
}

func (c Config) BudgetRules() []authentication.BudgetRule {
	if len(c.RateLimits) == 0 {
		return authentication.DefaultBudgetRules()
	}
	result := []authentication.BudgetRule{}
	for _, r := range c.RateLimits {
		result = append(result, authentication.BudgetRule{Operation: r.Operation, Dimension: r.Dimension, Limit: r.Limit, WindowSeconds: r.WindowSeconds})
	}
	return result
}

type ResourceBindingConfig struct {
	ID       string `json:"id"`
	Resource string `json:"resource"`
}

type TenantConfig struct {
	InitialRegistrationTokenSHA256 string                  `json:"initial_registration_token_sha256,omitempty"`
	ResourceBindings               []ResourceBindingConfig `json:"resource_bindings,omitempty"`
	ID                             string                  `json:"id"`
	CredentialKeys                 []CredentialKeyConfig   `json:"credential_keys,omitempty"`
	ResourceAuthorities            []string                `json:"resource_authorities,omitempty"`
	KeyName                        string                  `json:"key_name"`
	KeyVersions                    []int                   `json:"key_versions"`
	InitialKeyVersion              int                     `json:"initial_key_version"`
	TransitTokenEnv                string                  `json:"transit_token_env"`
	Administrators                 []AdministratorConfig   `json:"administrators"`
	IdentityProvider               *IdentityProviderConfig `json:"identity_provider,omitempty"`
}

// Provider trust is explicit startup configuration. Changing an issuer, client
// or endpoint requires a new ID and new operator-owned identity mappings.
type IdentityProviderConfig struct {
	ID                    string `json:"id"`
	Issuer                string `json:"issuer"`
	ClientID              string `json:"client_id"`
	ClientSecretEnv       string `json:"client_secret_env"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	SigningAlgorithm      string `json:"signing_algorithm"`
}
type AdministratorConfig struct {
	ID          string   `json:"id"`
	TokenSHA256 string   `json:"token_sha256"`
	Permissions []string `json:"permissions"`
}

func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, ErrConfiguration
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(data) > 1<<20 {
		return Config{}, ErrConfiguration
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var c Config
	if d.Decode(&c) != nil || d.Decode(&struct{}{}) != io.EOF {
		return Config{}, ErrConfiguration
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}
func (c Config) Validate() error {
	if !authentication.ValidBudgetRules(c.BudgetRules()) || len(c.TrustedProxies) > 16 {
		return ErrConfiguration
	}
	for _, raw := range c.TrustedProxies {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() {
			return ErrConfiguration
		}
	}

	// P1 binds only to loopback. A locally trusted TLS proxy owns the public
	// origin; no Host/Forwarded header can change tenant or issuer identity.
	host, port, err := net.SplitHostPort(c.ListenAddress)
	if err != nil || port == "" || (host != "127.0.0.1" && host != "::1") || c.DatabaseMaxConnections < 2 || c.DatabaseMaxConnections > 100 || len(c.Tenants) == 0 || len(c.Tenants) > 32 || !regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`).MatchString(c.RuntimeRole) {
		return ErrConfiguration
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return ErrConfiguration
	}
	transit, err := url.Parse(c.TransitAddress)
	if err != nil || transit.Hostname() == "" || transit.User != nil || transit.Path != "" || transit.RawQuery != "" || transit.ForceQuery || transit.Fragment != "" || transit.Opaque != "" || (transit.Scheme != "https" && !(c.AllowInsecureLoopback && transit.Scheme == "http" && (transit.Hostname() == "127.0.0.1" || transit.Hostname() == "::1"))) {
		return ErrConfiguration
	}
	seenTenants := map[string]bool{}
	seenKeys := map[string]bool{}
	seenTokens := map[string]bool{}
	allowed := []string{"policy:read", "policy:write", "resources:read", "resources:write", "clients:read", "clients:write", "keys:write", "grants:write", "grants:read"}
	for _, t := range c.Tenants {
		if _, err := NewIssuerScope(c.PublicOrigin, t.ID); err != nil {
			return ErrConfiguration
		}
		if seenTenants[t.ID] || seenKeys[t.KeyName] || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`).MatchString(t.KeyName) || !regexp.MustCompile(`^MAYI_[A-Z0-9_]{1,80}$`).MatchString(t.TransitTokenEnv) || len(t.KeyVersions) == 0 || len(t.KeyVersions) > 16 || !slices.Contains(t.KeyVersions, t.InitialKeyVersion) || len(t.Administrators) == 0 || len(t.Administrators) > 8 {
			return ErrConfiguration
		}
		if len(t.CredentialKeys) > 8 || t.IdentityProvider != nil && len(t.CredentialKeys) == 0 {
			return ErrConfiguration
		}
		active := 0
		versions := map[int]bool{}
		for _, k := range t.CredentialKeys {
			if k.Version < 1 || k.Version > 9999 || versions[k.Version] || !regexp.MustCompile(`^MAYI_[A-Z0-9_]{1,80}$`).MatchString(k.SecretEnv) {
				return ErrConfiguration
			}
			versions[k.Version] = true
			if k.Active {
				active++
			}
		}
		if len(t.CredentialKeys) > 0 && active != 1 {
			return ErrConfiguration
		}
		if len(t.ResourceBindings) > 32 {
			return ErrConfiguration
		}
		seenBindings := map[string]bool{}
		for _, binding := range t.ResourceBindings {
			if !resources.ValidID(binding.ID) || !resources.ValidURI(binding.Resource) || seenBindings[binding.ID] {
				return ErrConfiguration
			}
			seenBindings[binding.ID] = true
		}
		if len(t.ResourceAuthorities) > 32 {
			return ErrConfiguration
		}
		seenResources := map[string]bool{}
		for _, uri := range t.ResourceAuthorities {
			if !resources.ValidURI(uri) || seenResources[uri] {
				return ErrConfiguration
			}
			seenResources[uri] = true
		}
		seenTenants[t.ID] = true
		if t.IdentityProvider != nil {
			if err := validateIdentityProvider(c, t.IdentityProvider); err != nil {
				return err
			}
		}
		seenKeys[t.KeyName] = true
		seenVersions := map[int]bool{}
		for _, v := range t.KeyVersions {
			if v < 1 || seenVersions[v] {
				return ErrConfiguration
			}
			seenVersions[v] = true
		}
		if t.InitialRegistrationTokenSHA256 != "" {
			digest, err := hex.DecodeString(t.InitialRegistrationTokenSHA256)
			if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != t.InitialRegistrationTokenSHA256 || seenTokens[t.InitialRegistrationTokenSHA256] {
				return ErrConfiguration
			}
			seenTokens[t.InitialRegistrationTokenSHA256] = true
		}
		seenActors := map[string]bool{}
		for _, a := range t.Administrators {
			if _, err := NewIssuerScope(c.PublicOrigin, a.ID); err != nil || seenActors[a.ID] {
				return ErrConfiguration
			}
			seenActors[a.ID] = true
			digest, err := hex.DecodeString(a.TokenSHA256)
			if err != nil || len(digest) != 32 || strings.ToLower(a.TokenSHA256) != a.TokenSHA256 || seenTokens[a.TokenSHA256] || len(a.Permissions) == 0 || len(a.Permissions) > len(allowed) {
				return ErrConfiguration
			}
			seenTokens[a.TokenSHA256] = true
			seenPermissions := map[string]bool{}
			for _, p := range a.Permissions {
				if !slices.Contains(allowed, p) || seenPermissions[p] {
					return ErrConfiguration
				}
				seenPermissions[p] = true
			}
		}
	}
	return nil
}

func validateIdentityProvider(c Config, p *IdentityProviderConfig) error {
	if _, err := NewIssuerScope(c.PublicOrigin, p.ID); err != nil || p.ClientID == "" || len(p.ClientID) > 255 || !regexp.MustCompile(`^MAYI_[A-Z0-9_]{1,80}$`).MatchString(p.ClientSecretEnv) || !slices.Contains([]string{"ES256", "RS256", "PS256"}, p.SigningAlgorithm) {
		return ErrConfiguration
	}
	for _, raw := range []string{p.Issuer, p.AuthorizationEndpoint, p.TokenEndpoint, p.JWKSURI} {
		u, e := url.Parse(raw)
		if e != nil || len(raw) > 2048 || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != raw || strings.HasSuffix(raw, "/") || u.Scheme != "https" && !(c.AllowInsecureLoopback && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
			return ErrConfiguration
		}
	}
	return nil
}

type CredentialKeyConfig struct {
	Version   int    `json:"version"`
	SecretEnv string `json:"secret_env"`
	Active    bool   `json:"active"`
}
