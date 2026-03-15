-- App database (Zitadel manages its own 'zitadel' database via the admin credentials)
CREATE DATABASE app;

\c app

-- Branches represent service orgs within the system
CREATE TABLE branches (
  id   TEXT PRIMARY KEY,
  name TEXT NOT NULL
);

-- Users are keyed by their Zitadel subject ID (set during setup/first login)
CREATE TABLE users (
  id    TEXT PRIMARY KEY,  -- Zitadel subject ID
  email TEXT UNIQUE NOT NULL
);

-- Role assignments: a user can hold a role on one or more branches
CREATE TABLE user_branch_roles (
  user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  branch_id TEXT NOT NULL REFERENCES branches(id) ON DELETE CASCADE,
  role      TEXT NOT NULL,
  PRIMARY KEY (user_id, branch_id, role)
);

-- Tracks the currently active role for each user, written by role-validator
-- and read by the Zitadel Action at token issuance time
CREATE TABLE user_active_roles (
  user_id   TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  role      TEXT,
  branch_id TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed data: two branches
INSERT INTO branches (id, name) VALUES
  ('branch-1', 'Northern Branch'),
  ('branch-2', 'Southern Branch');

-- Test users are inserted by the setup script once Zitadel subject IDs are known.
-- See scripts/setup-zitadel.js.
