package app

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func validConfig() Config {
	return Config{PublicOrigin: "https://auth.example", ListenAddress: "127.0.0.1:8080", RuntimeRole: "mayi_runtime", DatabaseMaxConnections: 5, TransitAddress: "https://bao.example", Tenants: []TenantConfig{{ID: "a", KeyName: "mayi-a", KeyVersions: []int{1}, InitialKeyVersion: 1, TransitTokenEnv: "MAYI_A_TRANSIT_TOKEN", Administrators: []AdministratorConfig{{ID: "admin", TokenSHA256: strings.Repeat("ab", 32), Permissions: []string{"policy:read"}}}}}}
}

func TestRegistrationCredentialCannotReuseAdministratorOrTenantTokens(t *testing.T) {
	c := validConfig()
	c.Tenants[0].InitialRegistrationTokenSHA256 = strings.Repeat("ef", 32)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"raw-secret", strings.Repeat("EF", 32), c.Tenants[0].Administrators[0].TokenSHA256} {
		c.Tenants[0].InitialRegistrationTokenSHA256 = bad
		if c.Validate() == nil {
			t.Fatal("unsafe registration credential admitted")
		}
	}
	c = validConfig()
	b := c.Tenants[0]
	b.ID = "b"
	b.KeyName = "mayi-b"
	b.Administrators = []AdministratorConfig{{ID: "admin", TokenSHA256: strings.Repeat("cd", 32), Permissions: []string{"clients:read"}}}
	b.InitialRegistrationTokenSHA256 = strings.Repeat("ef", 32)
	c.Tenants[0].InitialRegistrationTokenSHA256 = b.InitialRegistrationTokenSHA256
	c.Tenants = append(c.Tenants, b)
	if c.Validate() == nil {
		t.Fatal("shared tenant registration credential admitted")
	}
}
func TestConfigRejectsSharedCredentialsAndTenantKeys(t *testing.T) {
	for _, mode := range []string{"public listener", "duplicate tenant", "shared key", "shared admin token", "unknown permission", "duplicate version", "missing initial version", "untrusted env"} {
		t.Run(mode, func(t *testing.T) {
			c := validConfig()
			b := c.Tenants[0]
			b.ID = "b"
			b.KeyName = "mayi-b"
			b.Administrators = []AdministratorConfig{{ID: "admin", TokenSHA256: strings.Repeat("cd", 32), Permissions: []string{"policy:read"}}}
			c.Tenants = append(c.Tenants, b)
			switch mode {
			case "public listener":
				c.ListenAddress = "0.0.0.0:8080"
			case "duplicate tenant":
				c.Tenants[1].ID = "a"
			case "shared key":
				c.Tenants[1].KeyName = c.Tenants[0].KeyName
			case "shared admin token":
				c.Tenants[1].Administrators[0].TokenSHA256 = c.Tenants[0].Administrators[0].TokenSHA256
			case "unknown permission":
				c.Tenants[1].Administrators[0].Permissions = []string{"*"}
			case "duplicate version":
				c.Tenants[0].KeyVersions = []int{1, 1}
			case "missing initial version":
				c.Tenants[0].InitialKeyVersion = 2
			case "untrusted env":
				c.Tenants[0].TransitTokenEnv = "UNRELATED_SECRET"
			}
			if c.Validate() == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}
func TestDatabaseRequiresVerifiedTLSOrExplicitLocalDevelopment(t *testing.T) {
	c := validConfig()
	for _, dsn := range []string{"host=db.example user=mayi_runtime sslmode=disable", "host=db.example user=mayi_runtime sslmode=prefer", "host=db.example user=mayi_runtime sslmode=require", "host=db.example user=mayi_runtime sslmode=verify-ca"} {
		if _, err := databaseConfig(dsn, c, false); err == nil {
			t.Fatal("unverified TLS allowed")
		}
	}
	if _, err := databaseConfig("host=db.example user=mayi_runtime sslmode=verify-full", c, false); err != nil {
		t.Fatal(err)
	}
	c.AllowInsecureLoopback = true
	if _, err := databaseConfig("host=/tmp/mayi-private user=mayi_runtime sslmode=disable", c, false); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseConfig("host=db.example user=mayi_runtime sslmode=disable", c, false); err == nil {
		t.Fatal("remote insecure connection allowed")
	}
}
func TestAdminTokenIsRandomAndOnlyItsHashGoesInConfig(t *testing.T) {
	var a, b bytes.Buffer
	if err := Run(context.Background(), []string{"admin-token"}, func(string) string { return "" }, &a, &b); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Token string `json:"token"`
		Hash  string `json:"sha256"`
	}
	if json.Unmarshal(a.Bytes(), &v) != nil || len(v.Token) != 43 || len(v.Hash) != 64 || b.Len() != 0 {
		t.Fatal("invalid credential output")
	}
}

func TestRuntimeRequiresItsOwnLoginWithoutRoleOverrides(t *testing.T) {
	c := validConfig()
	c.AllowInsecureLoopback = true
	for _, dsn := range []string{
		"host=127.0.0.1 user=owner sslmode=disable role=mayi_runtime",
		"host=127.0.0.1 user=mayi_runtime sslmode=disable role=mayi_runtime",
		"host=127.0.0.1 user=mayi_runtime sslmode=disable session_authorization=mayi_runtime",
		"host=127.0.0.1 user=mayi_runtime sslmode=disable options='-c role=mayi_runtime'",
	} {
		if _, err := databaseConfig(dsn, c, true); err == nil {
			t.Fatal("privileged or overridden runtime identity accepted")
		}
	}
	if _, err := databaseConfig("host=127.0.0.1 user=mayi_runtime sslmode=disable", c, true); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseConfig("host=127.0.0.1 user=owner sslmode=disable", c, false); err != nil {
		t.Fatal("explicit owner command rejected", err)
	}
}
