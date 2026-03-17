# Hasura Security Proxy — POC

A proof-of-concept for securing [Hasura](https://hasura.io/) with session-based role management, using [Ory Kratos](https://www.ory.sh/kratos/) for identity and a Rust/axum security proxy for session and JWT management.

## Architecture

```
Browser
  │  Auth & GraphQL → Security Proxy :3300
  ▼
Security Proxy (Rust/axum)
  │  - Issues HttpOnly session cookies
  │  - Stores active role per session in Postgres
  │  - Mints short-lived (30s) RS256 JWTs on each proxied GraphQL request
  │  - Calls Kratos for login and password recovery
  ├── Kratos :4433/:4434   (identity & authentication)
  ├── Hasura :8090          (GraphQL — trusts SP's JWKS endpoint)
  └── PostgreSQL :5433      (app data + sessions)
```

**Key design properties:**
- Role switching updates only the session row — no IdP calls, no effect on other sessions
- Two browser sessions for the same user can hold different active roles simultaneously
- Hasura has no direct knowledge of Kratos; it only trusts JWTs issued by the security proxy

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) with the Compose plugin (`docker compose version`)

## Running

```bash
docker compose up
```

The first run takes a few minutes while the Rust security proxy compiles. Subsequent runs are fast (dependencies are cached in a Docker layer).

Wait until you see:

```
setup-1  | === Setup complete ===
```

Then open **http://localhost:3301**.

## Test credentials

All passwords: `TestPassword1!`

| User | Branch | Role(s) |
|------|--------|---------|
| alice@poc.local | Northern Branch | branch-coordinator, user |
| alice@poc.local | Southern Branch | branch-coordinator, user |
| charlie@poc.local | Northern Branch | user |
| diana@poc.local | Northern Branch | user |
| eve@poc.local | Southern Branch | user |
| frank@poc.local | Southern Branch | branch-coordinator, user |

Branch isolation example: alice as `branch-coordinator` on Northern Branch sees alice, charlie, and diana. Switching to Southern Branch shows alice, eve, and frank.

## Useful URLs

| URL | What it is |
|-----|-----------|
| http://localhost:3301 | Frontend |
| http://localhost:8025 | Mailpit — view recovery code emails |
| http://localhost:8090/console | Hasura console (admin secret: `adminsecret`) |

## Trying the forgot-password flow

1. Click **Forgot password?** on the login screen and enter a user's email
2. Open Mailpit at http://localhost:8025 and copy the 6-digit code
3. Enter the code, then choose a new password

## Resetting to a clean state

```bash
docker compose down -v   # removes the Postgres volume
docker compose up
```

## Security proxy API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/login` | — | `{email, password}` → set session cookie |
| POST | `/api/logout` | cookie | Clear session |
| GET | `/api/me` | cookie | Current user and active role |
| GET | `/api/roles` | cookie | All roles available to the user |
| POST | `/api/switch-role` | cookie | `{role, branch_id}` → update session |
| POST | `/api/forgot-password` | — | `{email}` → send recovery code |
| POST | `/api/forgot-password/verify` | — | `{recovery_token, code}` → verify code |
| POST | `/api/forgot-password/reset` | — | `{reset_token, new_password}` → set password |
| POST | `/graphql` | cookie | Proxy to Hasura with a fresh JWT |
| GET | `/.well-known/jwks.json` | — | RSA public key (Hasura fetches this) |
| GET | `/health` | — | `{status: "ok"}` |
