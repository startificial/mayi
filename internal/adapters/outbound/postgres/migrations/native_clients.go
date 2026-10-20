package migrations

const NativeClients = `
ALTER TABLE mayi.clients ADD COLUMN application_type text NOT NULL DEFAULT 'web'
 CHECK(application_type IN ('web','native'));
ALTER TABLE mayi.clients ADD CONSTRAINT public_native_client
 CHECK(application_type<>'native' OR (NOT machine AND NOT introspection AND auth_method='none'));
`
