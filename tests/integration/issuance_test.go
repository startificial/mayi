package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/startificial/mayi/internal/adapters/inbound/http/oauth"
	cryptoadapter "github.com/startificial/mayi/internal/adapters/outbound/crypto"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/startificial/mayi/internal/adapters/outbound/postgres"
	"github.com/startificial/mayi/internal/adapters/outbound/postgres/migrations"
	"github.com/startificial/mayi/internal/adapters/outbound/signing"
	"github.com/startificial/mayi/internal/app"
	"github.com/startificial/mayi/internal/domain/grants"
	domain "github.com/startificial/mayi/internal/domain/tokens"
	"github.com/startificial/mayi/internal/services/tokens"
)

const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

type clock struct{}

func (clock) Now() time.Time { return time.Now() }

type environment struct {
	admin, db                   *pgxpool.Pool
	store                       *postgres.Store
	signer                      *signing.Transit
	service                     *tokens.Service
	scope                       grants.Scope
	address, token, signerToken string
}

func needed(t *testing.T) {
	t.Helper()
	if os.Getenv("MAYI_P0_POSTGRES") == "" || os.Getenv("MAYI_P0_TRANSIT") == "" {
		if os.Getenv("MAYI_P0_REQUIRED") == "1" {
			t.Fatal("P0 services required; run go run ./tools/p0")
		}
		t.Skip("run go run ./tools/p0 for isolated real services")
	}
}
func request(t *testing.T, address, token, method, path string, body any, status int) []byte {
	t.Helper()
	var b bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&b).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	r, err := http.NewRequest(method, address+"/v1/"+path, &b)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Vault-Token", token)
	r.Header.Set("Content-Type", "application/json")
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	result, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != status {
		t.Fatalf("%s %s: status %d (expected %d)", method, path, resp.StatusCode, status)
	}
	return result
}
func setup(t *testing.T) *environment {
	t.Helper()
	needed(t)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, os.Getenv("MAYI_P0_POSTGRES"))
	if err != nil {
		t.Fatal(err)
	}
	// This suite is deliberately serial and uses only the harness's fresh cluster.
	_, err = admin.Exec(ctx, `DROP SCHEMA IF EXISTS mayi CASCADE; DROP ROLE IF EXISTS mayi_runtime; CREATE ROLE mayi_runtime LOGIN NOSUPERUSER NOBYPASSRLS`)
	if err != nil {
		t.Fatal(err)
	}
	// The shared adapter always targets the current additive schema. Keep the
	// original P0 behavioral fixtures, but run them against every migration.
	for _, source := range []string{migrations.Initial, migrations.Foundation, migrations.Authorization, migrations.Authentication, migrations.ObjectCeilings, migrations.ObjectProfiles, migrations.ClientObjectTypes, migrations.Pushed, migrations.ObjectPresentations} {
		if _, err := admin.Exec(ctx, source); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `GRANT USAGE ON SCHEMA mayi TO mayi_runtime; GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA mayi TO mayi_runtime; GRANT USAGE ON ALL SEQUENCES IN SCHEMA mayi TO mayi_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA mayi TO mayi_runtime; REVOKE INSERT,UPDATE ON mayi.grant_revisions FROM mayi_runtime`); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(os.Getenv("MAYI_P0_POSTGRES"))
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = "mayi_runtime"
	config.MaxConns = 6
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close(); admin.Close() })
	store, err := postgres.New(db)
	if err != nil {
		t.Fatal(err)
	}
	scope := grants.Scope{TenantID: "a", Issuer: "https://auth.example/t/a"}
	address := os.Getenv("MAYI_P0_TRANSIT")
	token := os.Getenv("MAYI_P0_TRANSIT_TOKEN")
	// Mount is shared only within this ephemeral process. A unique key per test
	// avoids coupling rotation or policy failures to previous test outcomes.
	mounts := request(t, address, token, "GET", "sys/mounts", nil, 200)
	if !bytes.Contains(mounts, []byte(`"transit/"`)) {
		request(t, address, token, "POST", "sys/mounts/transit", map[string]string{"type": "transit"}, 204)
	}
	name := "p0-" + fmt.Sprint(time.Now().UnixNano())
	request(t, address, token, "POST", "transit/keys/"+name, map[string]any{"type": "ecdsa-p256", "exportable": false, "allow_plaintext_backup": false}, 200)
	policy := fmt.Sprintf(`path "transit/keys/%s" { capabilities = ["read"] } path "transit/sign/%s" { capabilities = ["update"] }`, name, name)
	request(t, address, token, "PUT", "sys/policies/acl/"+name, map[string]string{"policy": policy}, 204)
	raw := request(t, address, token, "POST", "auth/token/create", map[string]any{"policies": []string{name}, "no_default_policy": true, "ttl": "10m"}, 200)
	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	signer, err := signing.New(ctx, signing.Config{Address: address, Key: name, Token: result.Auth.ClientToken, Version: 1, Scope: scope, AllowLoopbackHTTP: true}, &http.Client{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := app.NewIssuance(store, clock{}, signer, cryptoadapter.NewMaterialSource(), store, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	e := &environment{admin: admin, db: db, store: store, signer: signer, service: service, scope: scope, address: address, token: token, signerToken: result.Auth.ClientToken}
	e.exec(t, `INSERT INTO mayi.tenants VALUES('a','https://auth.example/t/a',1),('b','https://auth.example/t/b',1); INSERT INTO mayi.clients(tenant_id,client_id,name,redirect_uris,access_token_seconds) VALUES('a','client','Test client',ARRAY['https://client.example/cb'],300),('b','client','Test client',ARRAY['https://client.example/cb'],300);
 INSERT INTO mayi.tenant_policies VALUES('a',600,3600,false),('b',600,3600,false);
 INSERT INTO mayi.resources VALUES('a','api','https://api.example','Test API',300,false),('b','api','https://api.example','Test API',300,false);
 INSERT INTO mayi.resource_scopes VALUES('a','api','read','Read items'),('a','api','write','Write items'),('b','api','read','Read items');
 INSERT INTO mayi.client_resources VALUES('a','client','api'),('b','client','api');
 INSERT INTO mayi.resource_object_profiles VALUES('a','api','https://api.example','https://api.example/types/fixture/v1','object-actions-v1','{"read":"Read items","write":"Write items"}'),('b','api','https://api.example','https://api.example/types/fixture/v1','object-actions-v1','{"read":"Read items"}');
 INSERT INTO mayi.client_object_types VALUES('a','client','api','https://api.example/types/fixture/v1'),('b','client','api','https://api.example/types/fixture/v1');
 INSERT INTO mayi.grants(tenant_id,grant_id,client_id,subject,principal_type,resource,current_scopes,expires_at) VALUES('a','grant','client','user:alice','user','https://api.example',ARRAY['read','write'],clock_timestamp()+interval '1 hour'),('b','grant','client','user:bob','user','https://api.example',ARRAY['read'],clock_timestamp()+interval '1 hour');
 INSERT INTO mayi.grant_revisions VALUES('a','grant',1,ARRAY['read','write'],clock_timestamp()+interval '1 hour'),('b','grant',1,ARRAY['read'],clock_timestamp()+interval '1 hour')`)
	e.code(t, "code")
	return e
}
func (e *environment) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := e.admin.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}
func (e *environment) code(t *testing.T, hash string) {
	e.exec(t, `INSERT INTO mayi.credentials(tenant_id,hash,kind,grant_id,revision,resource,client_id,ceiling_scopes,issued_at,expires_at,pkce_challenge,redirect_uri,binding_thumbprint,origin_code)
 VALUES('a',$1,'authorization_code','grant',1,'https://api.example','client',ARRAY['read','write'],clock_timestamp()-interval '1 second',clock_timestamp()+interval '50 seconds',$2,'https://client.example/cb','binding',$1)`, hash, challenge)
}
func (e *environment) command(hash string) tokens.Command {
	return tokens.Command{Caller: tokens.Caller{Scope: e.scope, ClientID: "client", BindingThumbprint: "binding"}, Kind: tokens.AuthorizationCode, CredentialHash: hash, Resource: "https://api.example", Verifier: verifier, RedirectURI: "https://client.example/cb", Scopes: []string{"read"}}
}
func (e *environment) refresh(t *testing.T) {
	e.exec(t, `INSERT INTO mayi.refresh_families VALUES('a','family','grant',1,'code',clock_timestamp()+interval '10 minutes',120,false);
 INSERT INTO mayi.credentials(tenant_id,hash,kind,grant_id,revision,resource,client_id,ceiling_scopes,issued_at,expires_at,binding_thumbprint,origin_code,family_id)
 VALUES('a','refresh','refresh_token','grant',1,'https://api.example','client',ARRAY['read'],clock_timestamp()-interval '1 second',clock_timestamp()+interval '60 seconds','binding','code','family')`)
}
func TestRealSigningJWKSAndNonExportability(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	response, err := e.service.Redeem(ctx, e.command("code"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := e.signer.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	var keys jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	if len(keys.Keys) != 1 || !keys.Keys[0].IsPublic() || bytes.Contains(raw, []byte(`"d":`)) {
		t.Fatal("JWKS contains private material")
	}
	parsed, err := jwt.ParseSigned(response.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	var claims jwt.Claims
	var extra map[string]any
	if err := parsed.Claims(keys.Keys[0].Key, &claims, &extra); err != nil {
		t.Fatal(err)
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{Issuer: e.scope.Issuer, Subject: "user:alice", AnyAudience: jwt.Audience{"https://api.example"}, Time: time.Now()}, 0); err != nil {
		t.Fatal(err)
	}
	if parsed.Headers[0].ExtraHeaders["typ"] != "at+jwt" || extra["grant_revision"] != float64(1) || extra["tenant_id"] != "a" {
		t.Fatal("lost purpose/grant/tenant")
	}
	confirmation, ok := extra["cnf"].(map[string]any)
	if !ok || confirmation["jkt"] != "binding" || extra["client_id"] != "client" || extra["scope"] != "read" || extra["principal_type"] != "user" || extra["grant_id"] != "grant" || parsed.Headers[0].KeyID != keys.Keys[0].KeyID {
		t.Fatal("wire token lost client, binding, authority or key identity")
	}
	keyName := strings.Split(keys.Keys[0].KeyID, ".v")[0]
	request(t, e.address, e.token, "POST", "transit/keys/"+keyName+"/rotate", nil, 200)
	newer, err := signing.New(ctx, signing.Config{Address: e.address, Key: keyName, Token: e.token, Version: 2, Scope: e.scope, AllowLoopbackHTTP: true}, &http.Client{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := newer.SignAccessToken(ctx, response.Claims)
	if err != nil {
		t.Fatal(err)
	}
	rotatedKeys, err := newer.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	var next jose.JSONWebKeySet
	if err := json.Unmarshal(rotatedKeys, &next); err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.ParseSigned(rotated, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.Claims(next.Keys[0].Key, &jwt.Claims{}); err != nil {
		t.Fatal(err)
	}
	if next.Keys[0].KeyID == keys.Keys[0].KeyID {
		t.Fatal("rotation reused key ID")
	}
	if err := parsed.Claims(keys.Keys[0].Key, &jwt.Claims{}); err != nil {
		t.Fatal("old public key no longer verifies overlap token", err)
	}
	// Even the dev root token cannot export a key created as non-exportable.
	request(t, e.address, e.token, "GET", "transit/export/signing-key/"+keyName, nil, 400)
	request(t, e.address, e.token, "POST", "transit/keys/exportable", map[string]any{"type": "ecdsa-p256", "exportable": true}, 200)
	if _, err := signing.New(ctx, signing.Config{Address: e.address, Key: "exportable", Token: e.token, Version: 1, Scope: e.scope, AllowLoopbackHTTP: true}, &http.Client{Timeout: time.Second}); err == nil {
		t.Fatal("exportable key accepted")
	}
}
func TestRealConcurrentCodeOneWinnerAndReplayInvalidation(t *testing.T) {
	e := setup(t)
	var group sync.WaitGroup
	results := make(chan error, 2)
	for n := 0; n < 2; n++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := e.service.Redeem(context.Background(), e.command("code"))
			results <- err
		}()
	}
	group.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, tokens.ErrInvalidCredential) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatalf("winners %d", success)
	}
	var issued, revoked int
	if err := e.admin.QueryRow(context.Background(), `SELECT count(*),count(*) FILTER(WHERE revoked) FROM mayi.issuances`).Scan(&issued, &revoked); err != nil {
		t.Fatal(err)
	}
	if issued != 1 || revoked != 1 {
		t.Fatal("replay invalidation not durable")
	}
	e.code(t, "other-code")
	if _, err := e.service.Redeem(context.Background(), e.command("other-code")); err != nil {
		t.Fatal("code replay revoked unrelated lineage", err)
	}
}
func TestRealRefreshScopeLifetimeAndFamilyReplay(t *testing.T) {
	e := setup(t)
	e.refresh(t)
	if _, err := e.admin.Exec(context.Background(), `UPDATE mayi.refresh_families SET absolute_deadline=absolute_deadline+interval '1 minute' WHERE tenant_id='a'`); err == nil {
		t.Fatal("family absolute lifetime extended")
	}
	cmd := e.command("refresh")
	cmd.Kind = tokens.RefreshToken
	cmd.Scopes = []string{"write"}
	if _, err := e.service.Redeem(context.Background(), cmd); !errors.Is(err, tokens.ErrInvalidCredential) {
		t.Fatal("scope expansion accepted")
	}
	cmd.Scopes = []string{"read"}
	response, err := e.service.Redeem(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	if response.RefreshToken == "" {
		t.Fatal("no refresh successor")
	}
	var hash string
	var scopes []string
	var within bool
	if err := e.admin.QueryRow(context.Background(), `SELECT c.hash,c.ceiling_scopes,c.expires_at<=f.absolute_deadline AND c.expires_at<=c.issued_at+interval '121 seconds' FROM mayi.credentials c JOIN mayi.refresh_families f USING(tenant_id,family_id) WHERE c.hash<>'refresh' AND c.kind='refresh_token'`).Scan(&hash, &scopes, &within); err != nil {
		t.Fatal(err)
	}
	if !within || strings.Join(scopes, " ") != "read" || hash == response.RefreshToken {
		t.Fatal("successor ceiling/deadline/plaintext violation")
	}
	expectedHash := sha256.Sum256([]byte(response.RefreshToken))
	if hex.EncodeToString(expectedHash[:]) != hash {
		t.Fatal("persisted hash does not redeem the returned refresh secret")
	}
	next := cmd
	next.CredentialHash = hash
	descendant, err := e.service.Redeem(context.Background(), next)
	if err != nil {
		t.Fatal("refresh successor cannot redeem", err)
	}
	descendantHash := sha256.Sum256([]byte(descendant.RefreshToken))
	if _, err := e.service.Redeem(context.Background(), cmd); !errors.Is(err, tokens.ErrInvalidCredential) {
		t.Fatal("replay accepted")
	}
	cmd.CredentialHash = hex.EncodeToString(descendantHash[:])
	if _, err := e.service.Redeem(context.Background(), cmd); !errors.Is(err, tokens.ErrInvalidCredential) {
		t.Fatal("descendant survived family replay")
	}
}

type failingSigner struct{}

func (failingSigner) SignAccessToken(context.Context, domain.AccessClaims) (string, error) {
	return "", errors.New("remote signing unavailable")
}
func TestRealSigningAuditAndCommitFailuresRollback(t *testing.T) {
	for _, mode := range []string{"signing", "audit", "commit"} {
		t.Run(mode, func(t *testing.T) {
			e := setup(t)
			signer := tokens.Signer(e.signer)
			if mode == "signing" {
				signer = failingSigner{}
			}
			if mode == "audit" {
				e.exec(t, `CREATE FUNCTION mayi.fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'audit unavailable'; END$$; CREATE TRIGGER fail BEFORE INSERT ON mayi.audit_events FOR EACH ROW EXECUTE FUNCTION mayi.fail_audit()`)
			}
			if mode == "commit" {
				e.exec(t, `CREATE FUNCTION mayi.fail_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'commit unavailable'; END$$; CREATE CONSTRAINT TRIGGER fail AFTER INSERT ON mayi.issuances DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION mayi.fail_commit()`)
			}
			s, err := app.NewIssuance(e.store, clock{}, signer, cryptoadapter.NewMaterialSource(), e.store, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			response, err := s.Redeem(context.Background(), e.command("code"))
			if !errors.Is(err, tokens.ErrUnavailable) || response.AccessToken != "" {
				t.Fatal("failure exposed credential", err)
			}
			var consumed bool
			var count int
			if err := e.admin.QueryRow(context.Background(), `SELECT consumed,(SELECT count(*) FROM mayi.issuances) FROM mayi.credentials WHERE tenant_id='a' AND hash='code'`).Scan(&consumed, &count); err != nil {
				t.Fatal(err)
			}
			if consumed || count != 0 {
				t.Fatal("partial commit")
			}
		})
	}
}
func TestRealTenantRLSAndPolicyChange(t *testing.T) {
	e := setup(t)
	if _, err := e.admin.Exec(context.Background(), `UPDATE mayi.grant_revisions SET scopes=ARRAY['expanded'] WHERE tenant_id='a'`); err == nil {
		t.Fatal("immutable revision changed")
	}
	var count int
	if err := e.db.QueryRow(context.Background(), `SELECT count(*) FROM mayi.credentials`).Scan(&count); err != nil || count != 0 {
		t.Fatal("unscoped query exposed rows", err)
	}
	tx, err := e.db.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(context.Background(), `SELECT set_config('mayi.tenant_id','b',true)`); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(context.Background(), `SELECT count(*) FROM mayi.credentials WHERE tenant_id='a'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("RLS tenant escape", err)
	}
	cmd := e.command("code")
	cmd.Caller.Scope = grants.Scope{TenantID: "b", Issuer: "https://auth.example/t/b"}
	if _, err := e.service.Redeem(context.Background(), cmd); !errors.Is(err, tokens.ErrInvalidCredential) {
		t.Fatal("foreign tenant accepted")
	}
	policy := &changingPolicy{e: e, t: t}
	s, err := app.NewIssuance(policy, clock{}, e.signer, cryptoadapter.NewMaterialSource(), e.store, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Redeem(context.Background(), e.command("code")); !errors.Is(err, tokens.ErrInvalidCredential) {
		t.Fatal("stale policy accepted")
	}
}

type changingPolicy struct {
	e *environment
	t *testing.T
}

func (p *changingPolicy) AuthorizeRedemption(ctx context.Context, c tokens.Caller, h string) (uint64, error) {
	v, err := p.e.store.AuthorizeRedemption(ctx, c, h)
	if err != nil {
		return 0, err
	}
	p.e.exec(p.t, `UPDATE mayi.tenants SET policy_version=policy_version+1 WHERE tenant_id='a'`)
	return v, nil
}
func TestRealConnectionLossRollsBackAndRetryWins(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	tx, err := e.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('mayi.tenant_id','a',true); UPDATE mayi.credentials SET consumed=true WHERE tenant_id='a' AND hash='code'`); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err == nil {
		t.Fatal("terminated connection committed")
	}
	if _, err := e.service.Redeem(ctx, e.command("code")); err != nil {
		t.Fatal("retry after aborted transaction failed", err)
	}
	if _, err := e.service.Redeem(ctx, e.command("code")); !errors.Is(err, tokens.ErrInvalidCredential) {
		t.Fatal("retry duplicated committed issuance")
	}
}

type blockedSigner struct {
	inner   tokens.Signer
	entered chan struct{}
	release chan struct{}
}

func (s *blockedSigner) SignAccessToken(ctx context.Context, c domain.AccessClaims) (string, error) {
	close(s.entered)
	select {
	case <-s.release:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	return s.inner.SignAccessToken(ctx, c)
}
func TestRealGrantAndPolicyLocksCoverSigningThroughCommit(t *testing.T) {
	e := setup(t)
	blocked := &blockedSigner{inner: e.signer, entered: make(chan struct{}), release: make(chan struct{})}
	service, err := app.NewIssuance(e.store, clock{}, blocked, cryptoadapter.NewMaterialSource(), e.store, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := service.Redeem(context.Background(), e.command("code")); done <- err }()
	select {
	case <-blocked.entered:
	case err := <-done:
		t.Fatal("issuance failed before signing", err)
	case <-time.After(5 * time.Second):
		t.Fatal("issuance did not reach signing")
	}
	// Both administrative changes require locks held throughout the remote call.
	for _, sql := range []string{`SELECT grant_id FROM mayi.grants WHERE tenant_id='a' FOR UPDATE NOWAIT`, `SELECT tenant_id FROM mayi.tenants WHERE tenant_id='a' FOR UPDATE NOWAIT`, `SELECT client_id FROM mayi.clients WHERE tenant_id='a' FOR UPDATE NOWAIT`} {
		tx, err := e.admin.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(context.Background(), sql); err == nil {
			t.Error("authorization state was not locked through signing")
		}
		_ = tx.Rollback(context.Background())
	}
	close(blocked.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	e.code(t, "next")
	e.exec(t, `UPDATE mayi.grants SET revoked=true WHERE tenant_id='a' AND grant_id='grant'`)
	if _, err := e.service.Redeem(context.Background(), e.command("next")); !errors.Is(err, tokens.ErrInvalidCredential) {
		t.Fatal("revocation did not prevent next issuance")
	}
}
func TestRealRemoteSigningFailureRollsBack(t *testing.T) {
	e := setup(t)
	request(t, e.address, e.token, "POST", "auth/token/revoke", map[string]string{"token": e.signerToken}, 204)
	result, err := e.service.Redeem(context.Background(), e.command("code"))
	if !errors.Is(err, tokens.ErrUnavailable) || result.AccessToken != "" {
		t.Fatal("revoked remote signer did not fail closed")
	}
	var consumed bool
	if err := e.admin.QueryRow(context.Background(), `SELECT consumed FROM mayi.credentials WHERE tenant_id='a' AND hash='code'`).Scan(&consumed); err != nil || consumed {
		t.Fatal("remote failure consumed code", err)
	}
}

func TestFositeServiceHandlerRealAtomicIssuance(t *testing.T) {
	e := setup(t)
	digest := sha256.Sum256([]byte("raw-code-never-stored"))
	e.code(t, hex.EncodeToString(digest[:]))
	handler, err := app.NewTokenHandler(e.scope, e.service)
	if err != nil {
		t.Fatal(err)
	}
	config := &fosite.Config{}
	config.TokenEndpointHandlers.Append(handler)
	registry := storage.NewMemoryStore()
	registry.Clients["client"] = &fosite.DefaultClient{ID: "client", Public: true, GrantTypes: []string{tokens.AuthorizationCode}, Scopes: []string{"read"}}
	provider := fosite.NewOAuth2Provider(registry, config)
	form := url.Values{"grant_type": {tokens.AuthorizationCode}, "client_id": {"client"}, "scope": {"read"}, "code": {"raw-code-never-stored"}, "resource": {"https://api.example"}, "code_verifier": {verifier}, "redirect_uri": {"https://client.example/cb"}}
	ctx := oauth.WithCaller(context.Background(), tokens.Caller{Scope: e.scope, ClientID: "client", BindingThumbprint: "binding"})
	redeem := func() (fosite.AccessResponder, error) {
		wire := httptest.NewRequest(http.MethodPost, e.scope.Issuer+"/token", strings.NewReader(form.Encode()))
		wire.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req, err := provider.NewAccessRequest(ctx, wire, &fosite.DefaultSession{})
		if err != nil {
			return nil, err
		}
		return provider.NewAccessResponse(ctx, req)
	}
	response, err := redeem()
	if err != nil {
		t.Fatal(err)
	}
	if response.GetAccessToken() == "" || response.GetTokenType() != "DPoP" {
		t.Fatal("Fosite response lost signed/bound token")
	}
	if _, err := redeem(); !errors.Is(err, fosite.ErrInvalidGrant) {
		t.Fatal("Fosite replay escaped service", err)
	}
}

func TestRealCodeReplayRevokesDerivedRefreshLineage(t *testing.T) {
	e := setup(t)
	e.refresh(t)
	if _, err := e.service.Redeem(context.Background(), e.command("code")); err != nil {
		t.Fatal(err)
	}
	cmd := e.command("refresh")
	cmd.Kind = tokens.RefreshToken
	next, err := e.service.Redeem(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.service.Redeem(context.Background(), e.command("code")); !errors.Is(err, tokens.ErrInvalidCredential) {
		t.Fatal("code replay accepted")
	}
	hash := sha256.Sum256([]byte(next.RefreshToken))
	cmd.CredentialHash = hex.EncodeToString(hash[:])
	if _, err := e.service.Redeem(context.Background(), cmd); !errors.Is(err, tokens.ErrInvalidCredential) {
		t.Fatal("code-derived refresh survived replay")
	}
	e.code(t, "independent-code")
	if _, err := e.service.Redeem(context.Background(), e.command("independent-code")); err != nil {
		t.Fatal("independent code lineage revoked", err)
	}
}

type afterCredentialStore struct {
	inner tokens.UnitOfWork
	after func()
}

func (s afterCredentialStore) Run(ctx context.Context, scope grants.Scope, fn func(tokens.Transaction) error) error {
	return s.inner.Run(ctx, scope, func(tx tokens.Transaction) error { return fn(afterCredentialTx{Transaction: tx, after: s.after}) })
}

type afterCredentialTx struct {
	tokens.Transaction
	after func()
}

func (t afterCredentialTx) Credential(ctx context.Context, hash string) (tokens.Credential, error) {
	c, err := t.Transaction.Credential(ctx, hash)
	if err == nil {
		t.after()
	}
	return c, err
}
func TestRealFamilyDeadlineRecheckedAfterGrantLock(t *testing.T) {
	e := setup(t)
	e.refresh(t)
	store := afterCredentialStore{inner: e.store, after: func() {
		e.exec(t, `BEGIN; SELECT grant_id FROM mayi.grants WHERE tenant_id='a' AND grant_id='grant' FOR UPDATE; UPDATE mayi.refresh_families SET absolute_deadline=clock_timestamp()+interval '20 seconds' WHERE tenant_id='a' AND family_id='family'; COMMIT`)
	}}
	service, err := app.NewIssuance(e.store, clock{}, e.signer, cryptoadapter.NewMaterialSource(), store, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cmd := e.command("refresh")
	cmd.Kind = tokens.RefreshToken
	result, err := service.Redeem(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	var deadline time.Time
	if err := e.admin.QueryRow(context.Background(), `SELECT absolute_deadline FROM mayi.refresh_families WHERE tenant_id='a' AND family_id='family'`).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	if result.Claims.ExpiresAt.After(deadline) {
		t.Fatal("family deadline changed before its lock but was not rechecked")
	}
}
