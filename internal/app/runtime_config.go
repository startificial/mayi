package app

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var ErrConfiguration = errors.New("invalid Mayi configuration")

type Config struct {
	PublicOrigin           string         `json:"public_origin"`
	ListenAddress          string         `json:"listen_address"`
	RuntimeRole            string         `json:"runtime_role"`
	DatabaseMaxConnections int32          `json:"database_max_connections"`
	AllowInsecureLoopback  bool           `json:"allow_insecure_loopback"`
	TransitAddress         string         `json:"transit_address"`
	Tenants                []TenantConfig `json:"tenants"`
}
type TenantConfig struct {
	ID                string                `json:"id"`
	KeyName           string                `json:"key_name"`
	KeyVersions       []int                 `json:"key_versions"`
	InitialKeyVersion int                   `json:"initial_key_version"`
	TransitTokenEnv   string                `json:"transit_token_env"`
	Administrators    []AdministratorConfig `json:"administrators"`
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
	allowed := []string{"policy:read", "policy:write", "resources:read", "resources:write", "clients:read", "clients:write", "keys:write"}
	for _, t := range c.Tenants {
		if _, err := NewIssuerScope(c.PublicOrigin, t.ID); err != nil {
			return ErrConfiguration
		}
		if seenTenants[t.ID] || seenKeys[t.KeyName] || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`).MatchString(t.KeyName) || !regexp.MustCompile(`^MAYI_[A-Z0-9_]{1,80}$`).MatchString(t.TransitTokenEnv) || len(t.KeyVersions) == 0 || len(t.KeyVersions) > 16 || !slices.Contains(t.KeyVersions, t.InitialKeyVersion) || len(t.Administrators) == 0 || len(t.Administrators) > 8 {
			return ErrConfiguration
		}
		seenTenants[t.ID] = true
		seenKeys[t.KeyName] = true
		seenVersions := map[int]bool{}
		for _, v := range t.KeyVersions {
			if v < 1 || seenVersions[v] {
				return ErrConfiguration
			}
			seenVersions[v] = true
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
