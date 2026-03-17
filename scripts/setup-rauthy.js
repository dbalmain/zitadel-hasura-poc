/**
 * Phase 1 setup for the Rauthy + Hasura POC.
 *
 * What it does:
 *   1. Waits for Rauthy to be healthy
 *   2. Creates custom user attribute definitions (active_role, active_branch_id, allowed_roles)
 *   3. Creates a custom scope 'hasura' that includes those attributes in access tokens
 *   4. Creates an OIDC client (poc-app) with RS256 signing and password+refresh flows
 *   5. Creates test users alice and bob in Rauthy, sets their passwords and attributes
 *   6. Seeds the app DB (branches, users, user_branch_roles)
 *   7. Writes frontend/config.json
 *
 * Phase 2 (Hasura metadata) is in setup-hasura.js and runs after Hasura starts.
 */

const { Pool } = require('pg');

const RAUTHY_URL = process.env.RAUTHY_URL || 'http://rauthy:8080';
const RAUTHY_API_KEY = process.env.RAUTHY_API_KEY;
const APP_DB_URL = process.env.APP_DB_URL || 'postgres://postgres:postgres@postgres:5432/app';
const FRONTEND_CONFIG = '/frontend/config.json';

const pool = new Pool({ connectionString: APP_DB_URL });

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForRauthy() {
  console.log('Waiting for Rauthy HTTP endpoint...');
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`${RAUTHY_URL}/health`);
      if (res.ok) {
        console.log('✓ Rauthy is up');
        return;
      }
    } catch {}
    await sleep(3000);
  }
  throw new Error('Rauthy did not become healthy after 3 minutes');
}

// All admin API calls use the bootstrap API key.
async function rauthyAdmin(method, path, body) {
  const opts = {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `API-Key ${RAUTHY_API_KEY}`,
    },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(`${RAUTHY_URL}${path}`, opts);
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

// Return parsed body, or throw on non-2xx (unless it's a known 409/conflict).
async function rauthyCreate(path, body, description) {
  const { status, body: data } = await rauthyAdmin('POST', path, body);
  if (status === 409 || (status === 400 && JSON.stringify(data).includes('already'))) {
    console.log(`  (already exists, skipping): ${description}`);
    return null;
  }
  if (status < 200 || status >= 300) {
    throw new Error(`${description} failed (${status}): ${JSON.stringify(data)}`);
  }
  console.log(`  ✓ ${description}`);
  return data;
}

// ---------------------------------------------------------------------------
// Step 1 – Custom user attribute definitions
// ---------------------------------------------------------------------------

async function createAttributeDefinitions() {
  console.log('\nCreating custom attribute definitions...');
  const attrs = ['active_role', 'active_branch_id', 'allowed_roles'];
  for (const name of attrs) {
    await rauthyCreate('/auth/v1/users/attr', { name }, `attribute: ${name}`);
  }
}

// ---------------------------------------------------------------------------
// Step 2 – Custom scope 'hasura' that embeds those attributes in access tokens
// ---------------------------------------------------------------------------

async function createHasuraScope() {
  console.log('\nCreating custom scope "hasura"...');
  // First check if it already exists
  const { status, body: existing } = await rauthyAdmin('GET', '/auth/v1/scopes');
  if (status === 200 && Array.isArray(existing)) {
    const found = existing.find((s) => s.name === 'hasura' || s.scope === 'hasura' || s.id === 'hasura');
    if (found) {
      console.log('  (already exists, skipping): scope hasura');
      return;
    }
  }
  await rauthyCreate(
    '/auth/v1/scopes',
    {
      scope: 'hasura',
      attr_include_access: ['active_role', 'active_branch_id', 'allowed_roles'],
    },
    'scope: hasura'
  );
}

// ---------------------------------------------------------------------------
// Step 3 – OIDC client
// ---------------------------------------------------------------------------

async function createOidcClient() {
  console.log('\nCreating OIDC client "poc-app"...');
  // Check if it already exists
  const { status } = await rauthyAdmin('GET', '/auth/v1/clients/poc-app');
  if (status !== 200) {
    await rauthyCreate(
      '/auth/v1/clients',
      {
        id: 'poc-app',
        name: 'POC App',
        enabled: true,
        confidential: false,
        redirect_uris: ['http://localhost:3301/callback'],
        post_logout_redirect_uris: ['http://localhost:3301'],
        force_mfa: false,
      },
      'client: poc-app'
    );
  } else {
    console.log('  (already exists): client poc-app');
  }

  // Always PUT to ensure flows, alg, and scopes are set correctly.
  // Rauthy silently drops unknown fields on POST, so we must use PUT after creation.
  const { status: putStatus, body: putBody } = await rauthyAdmin('PUT', '/auth/v1/clients/poc-app', {
    id: 'poc-app',
    name: 'POC App',
    enabled: true,
    confidential: false,
    redirect_uris: ['http://localhost:3301/callback'],
    post_logout_redirect_uris: ['http://localhost:3301'],
    allowed_origins: ['http://localhost:3301', 'http://localhost:3300'],
    flows_enabled: ['authorization_code', 'password', 'refresh_token'],
    access_token_alg: 'RS256',
    id_token_alg: 'RS256',
    auth_code_lifetime: 60,
    access_token_lifetime: 300,
    scopes: ['openid', 'email', 'profile', 'hasura'],
    default_scopes: ['openid', 'email', 'profile', 'hasura'],
    force_mfa: false,
  });
  if (putStatus < 200 || putStatus >= 300) {
    throw new Error(`client PUT failed (${putStatus}): ${JSON.stringify(putBody)}`);
  }
  console.log('  ✓ client poc-app configured (password flow, RS256, hasura scope)');
}

// ---------------------------------------------------------------------------
// Step 4 – Users
// ---------------------------------------------------------------------------

async function createUser(email, givenName, familyName) {
  // Check if user already exists by listing and filtering
  const { status: listStatus, body: listBody } = await rauthyAdmin('GET', '/auth/v1/users');
  if (listStatus === 200 && Array.isArray(listBody)) {
    const existing = listBody.find((u) => u.email === email);
    if (existing) {
      console.log(`  (already exists): ${email} — id: ${existing.id}`);
      return existing.id;
    }
  }

  const { status, body } = await rauthyAdmin('POST', '/auth/v1/users', {
    email,
    given_name: givenName,
    family_name: familyName,
    language: 'en',
    roles: [],
    groups: [],
  });
  if (status < 200 || status >= 300) {
    throw new Error(`Create user ${email} failed (${status}): ${JSON.stringify(body)}`);
  }
  const userId = body.id || body.user_id;
  console.log(`  ✓ Created user ${email} — id: ${userId}`);
  return userId;
}

async function setUserPassword(userId, email, password) {
  // Force-set password via the update user endpoint
  const { status, body } = await rauthyAdmin('PUT', `/auth/v1/users/${userId}`, {
    email,
    given_name: email.split('@')[0],
    family_name: 'User',
    language: 'en',
    password,
    roles: [],
    groups: [],
    enabled: true,
    email_verified: true,
  });
  if (status < 200 || status >= 300) {
    throw new Error(`Set password for ${email} failed (${status}): ${JSON.stringify(body)}`);
  }
  console.log(`  ✓ Password set for ${email}`);
}

async function setUserAttributes(userId, attrs) {
  // attrs is an object like { active_role: 'branch-coordinator', ... }
  const values = Object.entries(attrs).map(([key, value]) => ({ key, value }));
  const { status, body } = await rauthyAdmin('PUT', `/auth/v1/users/${userId}/attr`, { values });
  if (status < 200 || status >= 300) {
    throw new Error(`Set attributes for user ${userId} failed (${status}): ${JSON.stringify(body)}`);
  }
  console.log(`  ✓ Attributes set for user ${userId}: ${Object.keys(attrs).join(', ')}`);
}

// ---------------------------------------------------------------------------
// Step 5 – Seed app DB
// ---------------------------------------------------------------------------

async function seedAppDb(aliceId, bobId) {
  console.log('\nSeeding app DB...');
  const client = await pool.connect();
  try {
    // Branches
    await client.query(`
      INSERT INTO branches (id, name) VALUES
        ('branch-1', 'Branch One'),
        ('branch-2', 'Branch Two')
      ON CONFLICT (id) DO NOTHING
    `);
    console.log('  ✓ Branches seeded');

    // Users (keyed by Rauthy subject ID = JWT sub)
    await client.query(`
      INSERT INTO users (id, email) VALUES
        ($1, 'alice@poc.local'),
        ($2, 'bob@poc.local')
      ON CONFLICT (id) DO NOTHING
    `, [aliceId, bobId]);
    console.log('  ✓ Users seeded');

    // Role assignments
    // Alice: BRANCH_COORDINATOR + USER on both branches
    // Bob: USER on branch-1 only
    await client.query(`
      INSERT INTO user_branch_roles (user_id, branch_id, role) VALUES
        ($1, 'branch-1', 'BRANCH_COORDINATOR'),
        ($1, 'branch-1', 'USER'),
        ($1, 'branch-2', 'BRANCH_COORDINATOR'),
        ($1, 'branch-2', 'USER'),
        ($2, 'branch-1', 'USER')
      ON CONFLICT DO NOTHING
    `, [aliceId, bobId]);
    console.log('  ✓ Role assignments seeded');
  } finally {
    client.release();
  }
}

// ---------------------------------------------------------------------------
// Step 6 – Write frontend/config.json
// ---------------------------------------------------------------------------

async function writeConfig() {
  const config = {
    roleValidatorUrl: 'http://localhost:3300',
    hasuraUrl: 'http://localhost:8090/v1/graphql',
  };
  require('fs').writeFileSync(FRONTEND_CONFIG, JSON.stringify(config, null, 2));
  console.log(`\n✓ Wrote ${FRONTEND_CONFIG}`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('=== Rauthy + Hasura POC Setup ===\n');

  await waitForRauthy();

  await createAttributeDefinitions();
  await createHasuraScope();
  await createOidcClient();

  console.log('\nCreating users...');
  const aliceId = await createUser('alice@poc.local', 'Alice', 'POC');
  const bobId   = await createUser('bob@poc.local',   'Bob',   'POC');

  console.log('\nSetting passwords...');
  await setUserPassword(aliceId, 'alice@poc.local', 'TestPassword1!');
  await setUserPassword(bobId,   'bob@poc.local',   'TestPassword1!');

  console.log('\nSetting user attributes...');
  await setUserAttributes(aliceId, {
    active_role:      'branch-coordinator',
    active_branch_id: 'branch-1',
    allowed_roles:    ['branch-coordinator', 'user'],
  });
  await setUserAttributes(bobId, {
    active_role:      'user',
    active_branch_id: 'branch-1',
    allowed_roles:    ['user'],
  });

  await seedAppDb(aliceId, bobId);
  await writeConfig();

  console.log('\n=== Setup complete ===');
  console.log('Test credentials: alice@poc.local / TestPassword1!');
  console.log('Rauthy admin:     admin@localhost  / 123SuperSafe  (DEV_MODE override)');
  console.log('Open:             http://localhost:3301');
}

main().catch((err) => {
  console.error('\nSetup failed:', err.message);
  process.exit(1);
});
