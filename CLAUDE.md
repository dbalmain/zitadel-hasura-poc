# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Goal

POC investigating **Ory Kratos + Rust Security Proxy** as a replacement for AWS Cognito. Phase 3 of a series:
- Phase 1: Zitadel (role in JWT, IdP-level)
- Phase 2: Rauthy (role as user attribute in IdP)
- **Phase 3 (current):** Kratos for identity, Rust SP for session management — role stored per-session in Postgres, SP mints 30s Hasura JWTs on demand.

**Key architectural shift:** Active role is per-session in Postgres (not in the IdP). Two browser sessions for the same user can hold different roles simultaneously. Role switches update only the session row — zero IdP calls.

## Architecture

```
Browser (HTML/JS)
  │  Auth API → POST /api/login, /api/logout, /api/switch-role, /api/roles
  │  Password  → POST /api/forgot-password, /api/forgot-password/verify, /api/forgot-password/reset
  │  GraphQL   → POST /graphql  (SP proxies to Hasura, injects JWT)
  ▼
Security Proxy (Rust/axum) :3300
  │  - Session cookie: HttpOnly, SameSite=Strict
  │  - Validates session against Postgres sessions table
  │  - Mints 30s RS256 Hasura JWTs on each proxied request
  │  - Calls Kratos public/admin APIs for auth flows
  │  - Exposes GET /.well-known/jwks.json (Hasura trusts this)
  ▼                              ▼
Kratos :4433/:4434           Hasura :8090
(public/admin API)           (trusts SP JWKS, not Kratos)
  │
Mailpit :8025 (web) / :1025 (SMTP)
  │
PostgreSQL :5432
  ├── app  DB: branches, users, user_branch_roles, sessions
  └── kratos DB: managed entirely by Kratos
```

**Key design decisions:**
- The SP is the sole JWT issuer for Hasura. Hasura has no knowledge of Kratos.
- Role switching only updates the session row — zero IdP calls, zero global side effects.
- Two browser sessions for the same user can hold different roles simultaneously.
- Password recovery uses Kratos's native code flow (6-digit code in email, entered in our UI).
- In-memory map in the SP tracks recovery flow state (TTL = 15 min).
- RSA key pair generated on SP startup; short JWT TTL (30s) minimises the impact if the SP restarts.

## Services

| Service | Port | Purpose |
|---------|------|---------|
| `postgres` | 5433 | App DB (branches, users, user_branch_roles, sessions) + kratos DB |
| `kratos` | 4433/4434 | IdP — identity storage, authentication, recovery codes |
| `mailpit` | 8025/1025 | Dev mail server — catch recovery emails |
| `security-proxy` | 3300 | Rust/axum: session management, JWT minting, GraphQL proxy |
| `setup` | — | One-shot Node.js: creates Kratos identities + seeds app DB |
| `hasura` | 8090 | GraphQL API; trusts SP's JWKS |
| `hasura-setup` | — | One-shot: applies Hasura table tracking + permissions |
| `frontend` | 3301 | Static nginx serving `frontend/index.html` |

## Running

```bash
docker compose up
# Wait for setup to print "=== Setup complete ===" (~90s on first run due to Rust build cache miss)
# Subsequent code-only rebuilds: ~30s
# Then open http://localhost:3301
```

Test credentials (all passwords: `TestPassword1!`):
- `alice@poc.local` — branch-1 & branch-2 (coordinator + user on both)
- `charlie@poc.local` — branch-1 user
- `diana@poc.local` — branch-1 user
- `eve@poc.local` — branch-2 user
- `frank@poc.local` — branch-2 (coordinator + user)

Kratos admin UI: accessible via API only (no built-in UI)
Hasura console: `http://localhost:8090/console` → admin secret: `adminsecret`
Mailpit web UI: `http://localhost:8025` (recovery code emails appear here)

To force clean re-setup:
```bash
docker compose down -v
docker compose up
```

To iterate on just the security-proxy:
```bash
docker compose up --build security-proxy
```

## Codebase Structure

```
docker-compose.yml              Orchestrates all services
postgres/
  init.sql                      Creates app + kratos DBs; app schema (branches, users, sessions)
kratos/
  kratos.yml                    Kratos config (DB, SMTP, code recovery, native flows)
  identity.schema.json          Identity schema (email only)
security-proxy/
  Cargo.toml                    Rust dependencies
  Dockerfile                    Cargo Chef multi-stage (fast rebuilds)
  src/
    main.rs                     Entry point — AppState, router, bind
    config.rs                   Config::from_env()
    error.rs                    AppError → axum Response
    state.rs                    AppState { db, kratos, jwt_keys, recovery_store, ... }
    db.rs                       Session CRUD, get_user_roles, has_role
    jwt.rs                      JwtKeys::generate(), mint_hasura_jwt(), jwks_document()
    kratos.rs                   Typed wrappers: login, revoke_session, recovery, settings flows
    session.rs                  Session struct, SESSION_COOKIE_NAME
    recovery.rs                 RecoveryStore (DashMap) — maps opaque tokens to Kratos state
    routes/
      mod.rs                    Router assembly + CORS + CookieManager layers
      health.rs                 GET /health
      jwks.rs                   GET /.well-known/jwks.json
      auth.rs                   /api/login, /api/logout, /api/me, /api/roles,
                                /api/switch-role, /api/forgot-password,
                                /api/forgot-password/verify, /api/forgot-password/reset
      graphql.rs                POST /graphql — proxy + JWT injection
scripts/
  setup-kratos.js               Creates Kratos identities + seeds app DB + writes config.json
  setup-hasura.js               Phase 2: applies Hasura table tracking + permissions
  package.json                  Just needs pg
frontend/
  index.html                    SPA — cookie-based auth, role switching, forgot-password flow
  config.json                   Written by setup; gitignored. Contains { securityProxyUrl }
hasura/
  metadata/                     Hasura metadata YAML (reference only; state managed via API)
```

## SP API Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | /api/login | — | `{email, password}` → create session, set cookie |
| POST | /api/logout | cookie | Delete session, clear cookie |
| GET | /api/me | cookie | `{user_id, email, active_role, active_branch_id}` |
| GET | /api/roles | cookie | `{roles: [{role, branch_id, branch_name}]}` |
| POST | /api/switch-role | cookie | `{role, branch_id}` → update session row only |
| POST | /api/forgot-password | — | `{email}` → always 200; returns `{recovery_token}` |
| POST | /api/forgot-password/verify | — | `{recovery_token, code}` → `{reset_token}` |
| POST | /api/forgot-password/reset | — | `{reset_token, new_password}` → set via Kratos settings |
| POST | /graphql | cookie | Proxy to Hasura with minted JWT |
| GET | /.well-known/jwks.json | — | SP's RSA public key |
| GET | /health | — | `{"status":"ok"}` |

## Hasura JWT Config

The SP mints JWTs with the standard `https://hasura.io/jwt/claims` namespace — no `claims_map` needed:

```yaml
HASURA_GRAPHQL_JWT_SECRET: >
  {"type":"RS256","jwk_url":"http://security-proxy:3300/.well-known/jwks.json"}
```

JWT payload from SP (30-second TTL):
```json
{
  "sub": "user-uuid",
  "exp": 1234567890,
  "iat": 1234567860,
  "iss": "security-proxy",
  "https://hasura.io/jwt/claims": {
    "x-hasura-default-role": "branch-coordinator",
    "x-hasura-allowed-roles": ["branch-coordinator"],
    "x-hasura-user-id": "user-uuid",
    "x-hasura-branch-id": "branch-1"
  }
}
```

## Sessions Table (app DB)

```sql
CREATE TABLE sessions (
  id                TEXT PRIMARY KEY,  -- UUID in HttpOnly cookie
  user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  active_role       TEXT NOT NULL,     -- kebab-case: "branch-coordinator", "user"
  active_branch_id  TEXT NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at        TIMESTAMPTZ NOT NULL,  -- 8 hours from creation
  kratos_session_id TEXT                   -- for logout propagation
);
```

Role names are stored in kebab-case (matching Hasura permission role names). No conversion needed in the SP.

## Kratos Flow Details (SP ↔ Kratos, server-to-server)

**Login (native API flow):**
```
GET  /self-service/login/api           → { ui: { action } }
POST <action>  { method:"password", identifier, password }
               → { session: { id, identity: { id } }, session_token }
```

**Forgot password (native code recovery):**
```
GET  /self-service/recovery/api        → { ui: { action } }
POST <action>  { method:"code", email }  → state:"sent_email", updated action
  [SP stores: recovery_token → action_url]
POST <action>  { method:"code", code }   → { session_token }
  [SP stores: reset_token → session_token]
GET  /self-service/settings/api        X-Session-Token: <token>  → { ui: { action } }
POST <action>  { method:"password", password }  → state:"success"
```

## Known Rough Edges

- RSA key generated on SP startup — if SP restarts, existing Hasura JWT verifications fail until JWKS re-cached (max ~60s based on `Cache-Control: max-age=60` on JWKS endpoint)
- `user_active_roles` table dropped; `sessions` replaces it
- Kratos `--watch-courier` flag required for email delivery in dev mode
- `frontend/config.json` is regenerated on every setup run and is gitignored
