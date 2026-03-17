# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Goal

POC investigating **Rauthy** as a self-hosted IdP replacement for AWS Cognito. The key architectural change is that the user's active role is embedded in the JWT at token-issuance time (as a Rauthy custom user attribute), rather than being re-verified on every Hasura request.

## Architecture

```
Browser (HTML/JS)
  │  ROPC credentials → role-validator → Rauthy /oidc/token
  │  or refresh_token → role-validator → Rauthy /oidc/token
  ▼
Rauthy (IdP) ─── custom user attributes → JWT flat claims (active_role, active_branch_id)
  │  RS256 JWT
  ▼
Hasura :8090 (GraphQL) — claims_map extracts x-hasura-* from flat claims
  │  SQL
  ▼
PostgreSQL :5432
  │
role-validator :3300  ← updates Rauthy user attributes on role switch
```

## Key design decisions

- **No action script**: Active role lives as a Rauthy custom user attribute (`active_role`, `active_branch_id`). Updated via Rauthy admin API (`PUT /auth/v1/users/{id}/attr`) on role switch. No external HTTP call per token issuance.
- **ROPC login**: role-validator proxies credentials to `POST /oidc/token` with `grant_type=password`. Returns tokens directly — no PKCE code exchange needed.
- **Custom scope `hasura`**: Rauthy scope configured to embed `active_role`, `active_branch_id`, `allowed_roles` attributes into access tokens (`attr_include_access`).
- **Flat JWT claims**: Rauthy emits claims directly at the top level (no `https://hasura.io/jwt/claims` namespace). Hasura uses `claims_map` with JSONPath to extract headers.
- **RS256 signing**: Configured per client (`access_token_alg: RS256`) so Hasura can verify via JWKS at `/oidc/certs`.
- **Access token TTL: 5 minutes**. Bounds how long a switched role stays active.
- **Role switching flow**: frontend calls `POST /switch-role` → role-validator updates Rauthy user attributes → frontend calls `POST /api/refresh` → new access token with updated claims.
- **App DB only**: PostgreSQL only stores the `app` database. Rauthy uses SQLite (in `rauthy_data` Docker volume).

## Services

| Service | Port | Purpose |
|---------|------|---------|
| `postgres` | 5433 | App DB (branches, users, user_branch_roles) |
| `rauthy` | 8880 | IdP — OIDC/OAuth2, token issuance, custom attributes |
| `role-validator` | 3300 | Validates role switches, updates Rauthy attributes, proxies login/refresh |
| `setup` | — | One-shot Node.js script; configures Rauthy + seeds DB |
| `hasura` | 8090 | GraphQL API; trusts role from JWT claim |
| `hasura-setup` | — | One-shot: applies Hasura table tracking + permissions |
| `frontend` | 3301 | Static nginx serving `frontend/index.html` |

## Running

```bash
docker compose up
# Wait for the 'setup' service to print "=== Setup complete ===" (~60-90s on first run)
# Then open http://localhost:3301
```

Test credentials: `alice@poc.local / Password1!` and `bob@poc.local / Password1!`
Rauthy admin UI: `http://localhost:8880` → `admin@localhost / 123SuperSafe` (DEV_MODE)
Hasura console: `http://localhost:8090/console` → admin secret: `adminsecret`

To force a clean re-setup:
```bash
docker compose down -v   # removes volumes including Rauthy SQLite DB
docker compose up
```

To iterate on just the role-validator:
```bash
docker compose up --build role-validator
```

## Codebase structure

```
docker-compose.yml          Orchestrates all services
postgres/
  init.sql                  Creates 'app' DB + schema (branches, users, roles, user_active_roles)
role-validator/
  src/index.js              Express app — /api/login, /api/refresh, /switch-role, /roles
  Dockerfile
scripts/
  setup-rauthy.js           One-shot setup: Rauthy config + DB seed + config.json
  setup-hasura.js           Phase 2: applies Hasura table tracking + permissions
  package.json
frontend/
  index.html                Single-page ROPC demo
  config.json               Written by setup script; NOT in git (gitignored)
zitadel/
  action.js                 (Legacy — not used with Rauthy)
```

## Rauthy admin API

- Base URL: `http://rauthy:8080/auth/v1` (internal Docker network)
- Auth header: `Authorization: API-Key bootstrap$<secret>`
- Create user: `POST /auth/v1/users`
- Set password: `PUT /auth/v1/users/{id}` (include `"password"` field)
- Set attributes: `PUT /auth/v1/users/{id}/attr` → `{"values": [{"key": "...", "value": ...}]}`
- Create attribute definition: `POST /auth/v1/users/attr`
- Create scope: `POST /auth/v1/scopes` → `{"scope": "hasura", "attr_include_access": [...]}`
- Create client: `POST /auth/v1/clients`

## Hasura JWT config

```json
{
  "type": "RS256",
  "jwk_url": "http://rauthy:8080/oidc/certs",
  "claims_map": {
    "x-hasura-default-role":  {"path": "$.active_role"},
    "x-hasura-allowed-roles": {"path": "$.allowed_roles"},
    "x-hasura-user-id":       {"path": "$.sub"},
    "x-hasura-branch-id":     {"path": "$.active_branch_id"}
  }
}
```

Permissions check `x-hasura-branch-id` from the token rather than re-querying `user_branch_roles` on every request.

## Known rough edges / investigation points

- `allowed_roles` attribute is stored as a JSON array in Rauthy — verify it appears as an array (not string) in the JWT
- ROPC with `grant_type=password` must be confirmed to return `refresh_token` (client needs `refresh_token` in `flows_enabled`)
- Rauthy's `DEV_MODE=true` sets admin password to `123SuperSafe` regardless of `BOOTSTRAP_ADMIN_PASSWORD_PLAIN`
- The `user_active_roles` table in PostgreSQL is unused (kept from Zitadel POC) — can be dropped
- `frontend/config.json` is regenerated on every setup run and should be gitignored
