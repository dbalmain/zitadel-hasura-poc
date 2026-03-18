-- Create databases
CREATE DATABASE app;
CREATE DATABASE kratos;  -- Managed entirely by Kratos
CREATE DATABASE zitadel;  -- Managed entirely by Zitadel

\c app

-- Branches represent service orgs within the system
CREATE TABLE branches (
  id   TEXT PRIMARY KEY,
  name TEXT NOT NULL
);

-- Users are keyed by their Kratos identity ID
CREATE TABLE users (
  id    TEXT PRIMARY KEY,  -- Kratos identity UUID
  email TEXT UNIQUE NOT NULL
);

-- Role assignments: a user can hold one or more roles on one or more branches
CREATE TABLE user_branch_roles (
  user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  branch_id TEXT NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  role      TEXT NOT NULL,  -- kebab-case: "branch-coordinator", "user"
  PRIMARY KEY (user_id, branch_id, role)
);

-- Per-session state: active role stored here, not in the IdP
CREATE TABLE sessions (
  id                TEXT        PRIMARY KEY,  -- UUID stored in HttpOnly cookie
  user_id           TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  active_role       TEXT        NOT NULL,
  active_branch_id  TEXT        NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at        TIMESTAMPTZ NOT NULL,
  kratos_session_id TEXT                      -- for logout propagation
);

CREATE INDEX sessions_user_id_idx ON sessions(user_id);
CREATE INDEX sessions_expires_idx ON sessions(expires_at);

-- Seed data: two branches
INSERT INTO branches (id, name) VALUES
  ('branch-1', 'Northern Branch'),
  ('branch-2', 'Southern Branch');

-- Test users and roles are inserted by setup-kratos.js once Kratos identity IDs are known.
