/**
 * Phase 1 setup — creates Kratos identities and seeds the app DB.
 * Runs after Kratos and Postgres are healthy.
 */

const { Client } = require('pg');
const fs = require('fs');

const KRATOS_ADMIN_URL = process.env.KRATOS_ADMIN_URL || 'http://kratos:4434';
const APP_DB_URL = process.env.APP_DB_URL || 'postgres://postgres:postgres@postgres:5432/app';

async function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForKratos() {
  console.log('Waiting for Kratos admin API...');
  for (let i = 0; i < 40; i++) {
    try {
      const res = await fetch(`${KRATOS_ADMIN_URL}/health/ready`);
      if (res.ok) {
        console.log('✓ Kratos is up');
        return;
      }
    } catch {}
    await wait(3000);
  }
  throw new Error('Kratos did not become healthy after 120 seconds');
}

async function kratosAdmin(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(`${KRATOS_ADMIN_URL}${path}`, opts);
  const text = await res.text();
  if (!res.ok) throw new Error(`Kratos ${method} ${path} => ${res.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}

async function createIdentity(email, password) {
  const identity = await kratosAdmin('POST', '/admin/identities', {
    schema_id: 'default',
    traits: { email },
    credentials: {
      password: { config: { password } },
    },
  });
  return identity.id;
}

async function main() {
  console.log('=== Kratos + DB Setup ===\n');

  await waitForKratos();

  // Create Kratos identities and collect their UUIDs
  const PASSWORD = 'TestPassword1!';
  console.log('Creating Kratos identities...');

  const users = {
    alice:   await createIdentity('alice@poc.local', PASSWORD),
    charlie: await createIdentity('charlie@poc.local', PASSWORD),
    diana:   await createIdentity('diana@poc.local', PASSWORD),
    eve:     await createIdentity('eve@poc.local', PASSWORD),
    frank:   await createIdentity('frank@poc.local', PASSWORD),
  };

  console.log('✓ Identities created:');
  for (const [name, id] of Object.entries(users)) {
    console.log(`  ${name}: ${id}`);
  }

  // Seed app DB
  const db = new Client({ connectionString: APP_DB_URL });
  await db.connect();

  console.log('\nSeeding app database...');

  // Insert users (keyed by Kratos identity ID)
  for (const [name, id] of Object.entries(users)) {
    const email = `${name}@poc.local`;
    await db.query(
      'INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING',
      [id, email]
    );
  }
  console.log('✓ Users inserted');

  // Insert role assignments:
  //
  //  User    | branch-1                        | branch-2
  //  --------|--------------------------------|--------------------------------
  //  alice   | branch-coordinator, user        | branch-coordinator, user
  //  charlie | user                            | —
  //  diana   | user                            | —
  //  eve     | —                               | user
  //  frank   | —                               | branch-coordinator, user
  //
  // Role names use kebab-case (matches Hasura permission role names)

  const roleAssignments = [
    [users.alice,   'branch-1', 'branch-coordinator'],
    [users.alice,   'branch-1', 'user'],
    [users.alice,   'branch-2', 'branch-coordinator'],
    [users.alice,   'branch-2', 'user'],
    [users.charlie, 'branch-1', 'user'],
    [users.diana,   'branch-1', 'user'],
    [users.eve,     'branch-2', 'user'],
    [users.frank,   'branch-2', 'branch-coordinator'],
    [users.frank,   'branch-2', 'user'],
  ];

  for (const [userId, branchId, role] of roleAssignments) {
    await db.query(
      'INSERT INTO user_branch_roles (user_id, branch_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
      [userId, branchId, role]
    );
  }
  console.log('✓ Role assignments inserted');

  await db.end();

  // Write frontend config — only the SP URL is needed now
  const config = {
    securityProxyUrl: 'http://localhost:3300',
  };
  fs.writeFileSync('/frontend/config.json', JSON.stringify(config, null, 2));
  console.log('✓ Frontend config written');

  console.log('\n=== Setup complete ===');
  console.log('\nTest credentials (all passwords: TestPassword1!):');
  console.log('  alice@poc.local   — branch-1 & branch-2 (coordinator + user)');
  console.log('  charlie@poc.local — branch-1 (user)');
  console.log('  diana@poc.local   — branch-1 (user)');
  console.log('  eve@poc.local     — branch-2 (user)');
  console.log('  frank@poc.local   — branch-2 (coordinator + user)');
  console.log('\nMailpit web UI: http://localhost:8025');
}

main().catch((err) => {
  console.error('\nSetup failed:', err.message);
  process.exit(1);
});
