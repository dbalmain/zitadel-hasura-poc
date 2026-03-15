# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Goal

POC demonstrating a switch from AWS Cognito to an internal self-hosted IdP (Zitadel). The key architectural change is that the user's active role is embedded in the JWT at token-issuance time, rather than being re-verified on every Hasura request.

## Architecture

```
Browser (HTML/JS)
  │  OIDC PKCE / refresh_token
  ▼
Zitadel (IdP) ─── preAccessTokenCreation Action ──→ role-validator :3000
  │  JWT with https://hasura.io/jwt/claims
  ▼
Hasura :8090 (GraphQL)
  │  SQL
  ▼
PostgreSQL :5432 (shared by app + Zitadel)
```

## Key design decisions

- **Zitadel Action** (`zitadel/action.js`): runs server-side on every access token issuance. Calls `role-validator /active-role/:userId`, then injects `x-hasura-default-role`, `x-hasura-allowed-roles`, `x-hasura-user-id`, and `x-hasura-branch-id` into the `https://hasura.io/jwt/claims` namespace.
- **role-validator** (`role-validator/src/index.js`): Node.js/Express. Two key endpoints: `POST /switch-role` (validates role in app DB, stores in `user_active_roles`), and `GET /active-role/:userId` (read by Zitadel Action). No Zitadel API credentials needed.
- **JWT access tokens**: Zitadel OIDC app is configured with `accessTokenType: OIDC_TOKEN_TYPE_JWT` so Hasura can verify tokens directly via the JWKS endpoint.
- **Access token TTL: 5 minutes**. Bounds how long a revoked role stays active.
- **Role switching flow**: frontend calls `POST /switch-role` → calls `POST /oauth/v2/token` with `grant_type=refresh_token` → new access token with updated role claim.
- **Shared PostgreSQL**: Zitadel uses the `zitadel` database; the app uses the `app` database. Both on the same Postgres instance.

## Services

| Service | Port | Purpose |
|---------|------|---------|
| `postgres` | 5432 | App DB + Zitadel DB |
| `zitadel` | 8080 | IdP — OIDC/OAuth2, token issuance, Actions |
| `role-validator` | 3000 | Validates role switches, stores active role, queried by Action |
| `setup` | — | One-shot Node.js script; configures Zitadel + seeds DB |
| `hasura` | 8090 | GraphQL API; trusts role from JWT claim |
| `frontend` | 3001 | Static nginx serving `frontend/index.html` |

## Running

```bash
docker compose up
# Wait for the 'setup' service to print "=== Setup complete ===" (~60-90s on first run)
# Then open http://localhost:3001
```

Test credentials written by the setup script: `alice@poc.local / Password1!`
Zitadel admin console: `http://localhost:8080` → `admin@poc.local / Password1!`
Hasura console: `http://localhost:8090/console` → admin secret: `adminsecret`

To force a clean re-setup (e.g. after changing the Action script):
```bash
docker compose down -v   # removes volumes including zitadel DB
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
  init.sql                  Creates 'app' DB + schema; seeds branch data
role-validator/
  src/index.js              Express app — /active-role, /switch-role, /roles
  Dockerfile
zitadel/
  action.js                 Zitadel Action script (registered by setup script)
scripts/
  setup-zitadel.js          One-shot setup: Zitadel config + DB seed + Hasura metadata
  package.json
hasura/
  metadata/                 YAML metadata (tables + permissions) — applied by setup script
frontend/
  index.html                Single-page PKCE demo
  config.json               Written by setup script; NOT in git (gitignore it)
```

## Zitadel Action notes

- Flow: `FLOW_TYPE_COMPLEMENT_TOKEN` (2), Trigger: `TRIGGER_TYPE_PRE_ACCESS_TOKEN_CREATION` (3)
- Script is in `zitadel/action.js` and registered via the setup script
- To update after first run: paste the updated script into Zitadel Console > Actions, or re-run setup with fresh volumes
- Action calls `http://role-validator:3000/active-role/:userId` — this works because both are on the same Docker network. `ZITADEL_ACTIONS_HTTP_DENYLIST=""` disables the default private-IP deny list.
- Zitadel's JS runtime (goja) is synchronous — `require("zitadel/http").fetch(...)` is a blocking call

## Hasura JWT config

```json
{
  "type": "RS256",
  "jwk_url": "http://zitadel:8080/oauth/v2/keys",
  "claims_namespace": "https://hasura.io/jwt/claims"
}
```

Permissions check `x-hasura-branch-id` from the token (set `_eq: X-Hasura-Branch-Id` in filters) rather than re-querying the `user_branch_roles` table on every request.

## Known rough edges / TODO

- The `setup` service is not idempotent for Zitadel Action binding (it skips "already exists" errors, but the action script is not updated on re-run unless volumes are wiped)
- Zitadel Management API paths are based on v1 REST; if the image version changes the paths may shift
- `frontend/config.json` is regenerated on every setup run and should be gitignored
