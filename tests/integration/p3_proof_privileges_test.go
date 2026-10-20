package integration_test

import (
	"context"
	"strings"
	"testing"
)

func TestP3ProofCleanupCannotDeleteActiveOrForeignState(t *testing.T) {
	e := setupFoundationDatabase(t)
	ctx := context.Background()
	if _, err := e.admin.Exec(ctx, `INSERT INTO mayi.tenants VALUES('a','https://auth.example/t/a',1),('b','https://auth.example/t/b',1);
 INSERT INTO mayi.proof_nonces SELECT t,'token','https://auth.example/t/'||t||'/token',repeat('a',43),repeat(h,64),clock_timestamp()+offset_value
 FROM (VALUES('a','a',interval '1 hour'),('a','b',interval '-1 hour'),('b','c',interval '-1 hour')) v(t,h,offset_value);
 INSERT INTO mayi.proof_replays SELECT t,repeat('a',43),id,clock_timestamp()+offset_value
 FROM (VALUES('a','active-proof-123456',interval '1 hour'),('a','expired-proof-12345',interval '-1 hour'),('b','foreign-proof-12345',interval '-1 hour')) v(t,id,offset_value);`); err != nil {
		t.Fatal(err)
	}
	conn, err := e.db.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	for _, table := range []string{"proof_nonces", "proof_replays"} {
		for _, operation := range []string{"DELETE FROM ", "UPDATE "} {
			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('mayi.tenant_id','a',true)`); err != nil {
				t.Fatal(err)
			}
			statement := operation + "mayi." + table
			if strings.HasPrefix(operation, "UPDATE") {
				statement += " SET expires_at=clock_timestamp()+interval '1 hour'"
			}
			_, err = tx.Exec(ctx, statement)
			_ = tx.Rollback(ctx)
			if err == nil {
				t.Fatal("runtime could alter active proof state", operation, table)
			}
		}
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('mayi.tenant_id','a',true); SELECT mayi.cleanup_expired_proof_state()`); err != nil {
		t.Fatal("expired-only cleanup failed", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"proof_nonces", "proof_replays"} {
		var active, foreign int
		if err := e.admin.QueryRow(ctx, "SELECT count(*) FILTER(WHERE tenant_id='a'),count(*) FILTER(WHERE tenant_id='b') FROM mayi."+table).Scan(&active, &foreign); err != nil || active != 1 || foreign != 1 {
			t.Fatal("cleanup altered active or foreign proof state", table, active, foreign, err)
		}
	}
}
