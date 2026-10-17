package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// developmentStack reuses the exact reviewed service sources and private
// lifecycle. The runtime gets scoped credentials; no dev root token is written
// into the application environment. All data disappears when this process exits.
func developmentStack(ctx context.Context, root, session, socket, address, pgdir string, env []string) error {
	if err := run(ctx, root, env, io.Discard, filepath.Join(pgdir, "psql"), "-h", socket, "-U", "mayi_test", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", `CREATE ROLE mayi_owner LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS; CREATE ROLE mayi_runtime LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS; GRANT CREATE ON DATABASE postgres TO mayi_owner`); err != nil {
		return err
	}
	call := func(method, path string, input any, result any) error {
		body, err := json.Marshal(input)
		if err != nil {
			return err
		}
		r, err := http.NewRequestWithContext(ctx, method, address+"/v1/"+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		r.Header.Set("X-Vault-Token", "mayi-isolated-test-only")
		r.Header.Set("Content-Type", "application/json")
		response, err := (&http.Client{Timeout: 3 * time.Second}).Do(r)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != 200 && response.StatusCode != 204 {
			return fmt.Errorf("local stack bootstrap failed")
		}
		if result != nil {
			return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(result)
		}
		return nil
	}
	if err := call("POST", "sys/mounts/transit", map[string]string{"type": "transit"}, nil); err != nil {
		return err
	}
	var tenants []any
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	var environment strings.Builder
	fmt.Fprintf(&environment, "export MAYI_DATABASE_URL=%s\nexport MAYI_MIGRATION_DATABASE_URL=%s\n", quote("host="+socket+" user=mayi_runtime dbname=postgres sslmode=disable"), quote("host="+socket+" user=mayi_owner dbname=postgres sslmode=disable"))
	for _, id := range []string{"demo", "demo2"} {
		key := "mayi-" + id
		if err := call("POST", "transit/keys/"+key, map[string]any{"type": "ecdsa-p256", "exportable": false, "allow_plaintext_backup": false}, nil); err != nil {
			return err
		}
		policy := `path "transit/keys/` + key + `" { capabilities = ["read"] } path "transit/sign/` + key + `" { capabilities = ["update"] }`
		if err := call("PUT", "sys/policies/acl/"+key, map[string]string{"policy": policy}, nil); err != nil {
			return err
		}
		var token struct {
			Auth struct {
				Token string `json:"client_token"`
			} `json:"auth"`
		}
		if err := call("POST", "auth/token/create", map[string]any{"policies": []string{key}, "no_default_policy": true, "ttl": "8h"}, &token); err != nil {
			return err
		}
		var entropy [32]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return err
		}
		admin := base64.RawURLEncoding.EncodeToString(entropy[:])
		digest := sha256.Sum256([]byte(admin))
		envName := "MAYI_" + strings.ToUpper(id) + "_TRANSIT_TOKEN"
		fmt.Fprintf(&environment, "export %s=%s\nexport MAYI_%s_ADMIN_TOKEN=%s\n", envName, quote(token.Auth.Token), strings.ToUpper(id), quote(admin))
		tenants = append(tenants, map[string]any{"id": id, "key_name": key, "key_versions": []int{1}, "initial_key_version": 1, "transit_token_env": envName, "administrators": []any{map[string]any{"id": "operator", "token_sha256": hex.EncodeToString(digest[:]), "permissions": []string{"policy:read", "policy:write", "resources:read", "resources:write", "clients:read", "clients:write", "keys:write"}}}})
	}
	config := map[string]any{"public_origin": "https://auth.localhost", "listen_address": "127.0.0.1:8080", "runtime_role": "mayi_runtime", "database_max_connections": 6, "allow_insecure_loopback": true, "transit_address": address, "tenants": tenants}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	configPath := filepath.Join(session, "config.json")
	envPath := filepath.Join(session, "environment.sh")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(envPath, []byte(environment.String()), 0600); err != nil {
		return err
	}
	fmt.Printf("Isolated local stack ready; data is removed on exit. In another terminal:\nsource %s\ngo run ./cmd/mayi migrate -config %s\ngo run ./cmd/mayi provision -config %s -tenant demo\ngo run ./cmd/mayi provision -config %s -tenant demo2\nenv -u MAYI_MIGRATION_DATABASE_URL go run ./cmd/mayi serve -config %s\n", envPath, configPath, configPath, configPath, configPath)
	<-ctx.Done()
	return nil
}
