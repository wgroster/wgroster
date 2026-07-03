# wgroster — project guide for Claude Code

Self-service WireGuard configuration portal: LDAP (or local-admin) login,
admin-managed **endpoints** (concentrators) and **machines**, and a live status
dashboard fed by `wg show dump` uploads. The portal is the **source of truth**;
it never connects to or configures concentrators — agents on each concentrator
push status and optionally pull the expected peer list.

Global preferences (git, language, etc.) live in the user's `~/.claude/CLAUDE.md`
and apply here too. This file only adds project-specific guidance.

## Commands

```sh
# Build
go build ./...

# Checks (run all three before proposing a commit)
gofmt -l .        # must print nothing
go vet ./...
go test ./...

# Run locally (dev): uses ./config.yaml + ./data/wg-portal.db, listens on :8484.
# Dev config has local_admin admin/admin and points ldap at the real server.
go run ./cmd/wgroster -config config.yaml

# Generate a bcrypt hash for local_admin.password_hash
go run ./cmd/wgroster -hash-password
```

Tailwind CSS is **prebuilt** and committed at `internal/web/static/app.css`.
After changing any template's CSS classes, regenerate it (otherwise new classes
have no styles):

```sh
tailwindcss -i tailwind.input.css -o internal/web/static/app.css --minify
```

## Architecture

Everything is a single Go binary; the web layer is server-rendered HTML +
htmx (no SPA, no build step for JS). Packages under `internal/`:

- `config` — YAML config loading and validation (`config.go`).
- `store` — SQLite persistence (pure-Go `modernc.org/sqlite`). One file per
  concern (`machines.go`, `endpoints.go`, `status.go`, `profiles.go`, …).
- `ldap` — OpenLDAP bind, admin-group membership, profile (name/photo) lookup.
- `ipam` — global client address pool + next-free suggestion.
- `wg` — generates client/concentrator configs (`config.go`) and parses
  `wg show dump` (`dump.go`).
- `geoip` — optional offline MaxMind lookups for the peer drawer.
- `auth` — server-side sessions (HMAC-signed cookie holds only the sid) + CSRF.
- `web` — HTTP handlers, middleware, templates, embedded static assets. Routes
  are all wired in `server.go`'s `Handler()`.

Templates live in `internal/web/templates/`; full pages and partials are
registered in `render.go` (`fullPages` / `partials`). Template funcs (e.g.
`initial`, `ago`, `since`, `humanBytes`) are defined there too.

## Domain model

- **Endpoint** = a WireGuard concentrator (hub). Has a public key, `host:port`,
  `AllowedIPs`, and a rotatable **upload token** used by its agent for the
  machine-to-machine API (`/api/endpoints/{id}/status`, `/expected-peers`,
  `/config`). Token auth returns 404 (not 403) on mismatch so ids can't be
  enumerated.
- **Machine** = a user device with one global VPN IP (from the pool) linked to
  one or more endpoints. Users add machines (pending); admins approve/assign
  IP+endpoints. `owner_name` is a cached LDAP `cn`; `user_profile` caches the
  name+photo (see LDAP section).
- Config generation is in `internal/wg/config.go`: `ClientConfig` (per machine)
  and `ConcentratorConfig` (per endpoint). The portal never knows any private
  key, so generated configs emit a `<...PRIVATE_KEY>` placeholder.

## Conventions & gotchas

- **SQLite**: schema is a single `CREATE TABLE IF NOT EXISTS` block in
  `store.go`; add new columns as idempotent `ALTER TABLE` in the migration loop
  right after it (guarded against "duplicate column name"). `SetMaxOpenConns(1)`
  — writes are serialized; keep queries simple.
- **Security posture** (do not regress): strict CSP with self-hosted assets and
  **no inline script/style** (`img-src 'self' data:` covers avatars/QR); all
  mutating routes require a CSRF token; login rejects cross-origin POSTs; secrets
  (tokens, hashes, photos) live only in the 0600 DB. Fields written line-by-line
  into wg configs are rejected if they contain control chars (config injection).
- **LDAP profiles**: name (`name_attr`, default `cn`) and photo (`photo_attr`,
  default `jpegPhoto`) are cached in `user_profile` and served at
  `/avatar/{uid}`. The logged-in user's own profile is read at login via their
  bind; other users are resolved lazily in the background from the admin
  machines list — with `search_bind_dn` if set, otherwise **anonymously**. All
  of it degrades gracefully to the login + initial badge when unavailable.
- **Handlers**: return generic 500s via `s.serverError` (never leak SQL/paths);
  redirect with `redirectMsg(w, r, path, "ok"|"err", msg)`; record admin actions
  with `s.audit`.
- **Tests**: `internal/web/integration_test.go` drives the real handler stack
  against a temp SQLite DB (`testServer` helper, local-admin session). Add
  behavior tests there; store-level tests use `newTestStore`.

## Verifying UI changes

`go run ./cmd/wgroster -config config.yaml` then hit `http://localhost:8484`
(login `admin`/`admin`). The dev DB is seeded and points at the real LDAP, so
directory names/photos populate on the machines page. Before killing a dev
server you started, confirm the PID is the wgroster binary you launched.
