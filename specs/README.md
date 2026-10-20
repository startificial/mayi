# Normative baseline

[manifest.yaml](manifest.yaml) pins exact source bytes with per-document retrieval dates (the initial baseline on 2026-10-17; required RFC 9396/RFC 9126 additions on 2026-10-18 and RFC 6750/RFC 9728 additions on 2026-10-19): document URL, revision/commit, SHA-256, retrieval date, target sections and known Mayi profile differences. It uses the JSON subset of YAML 1.2 to keep validation within the standard library.

`target_sections` identifies planned review/implementation scope. Empty `implemented_sections` remains a pending conformance claim even where limited HTTP previews exist. RFC 9396/RFC 9126 have bounded P2 evidence; RFC 8252 callback sections and RFC 6750/RFC 9728 resource sections have partial P3 evidence. A hash or structural CI check is not a conformance claim. Update implemented sections only with executable adapter fixtures and requirement evidence. Drafts deferred to P7/P8 are pinned in their delivery phase rather than guessed now.

Run `go run ./tools/checks -only specifications` to reject missing, duplicate, unversioned or malformed source pins offline. The gate validates metadata and immutable URL forms; it does not fetch the network or certify the hashes against remote content. For an upgrade, fetch the exact URL, hash the response body bytes without normalization, inspect the normative diff, update fixtures and deviations, and record the decision. Source availability and upstream errata remain review obligations. Normative text is referenced rather than redistributed.

MCP authorization is split across four pinned 2026-07-28 source pages. The enterprise extension is pinned separately to an exact `ext-auth` commit. OIDC Core/Discovery explicitly select errata set 2. OAuth 2.1 selects draft -16; the requirements README's older citation remains historical.

[profiles.md](profiles.md) resolves the README interpretations and defines the intended capability boundaries. Nothing in that document enables a server feature automatically.
