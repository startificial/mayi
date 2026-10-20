package migrations

const ProofStatePrivileges = `
CREATE FUNCTION mayi.cleanup_expired_proof_state() RETURNS void LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 DELETE FROM mayi.proof_nonces WHERE tenant_id=current_setting('mayi.tenant_id',true)
 AND nonce_hash IN (SELECT nonce_hash FROM mayi.proof_nonces
  WHERE tenant_id=current_setting('mayi.tenant_id',true) AND expires_at<=clock_timestamp()
  ORDER BY expires_at,nonce_hash LIMIT 100 FOR UPDATE SKIP LOCKED);
 DELETE FROM mayi.proof_replays WHERE tenant_id=current_setting('mayi.tenant_id',true)
 AND (thumbprint,proof_id) IN (SELECT thumbprint,proof_id FROM mayi.proof_replays
  WHERE tenant_id=current_setting('mayi.tenant_id',true) AND expires_at<=clock_timestamp()
  ORDER BY expires_at,thumbprint,proof_id LIMIT 100 FOR UPDATE SKIP LOCKED);
END$$;
REVOKE ALL ON FUNCTION mayi.cleanup_expired_proof_state() FROM PUBLIC;
`
