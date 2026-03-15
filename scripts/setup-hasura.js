/**
 * Phase 2 setup — applies Hasura table tracking and permissions.
 * Runs AFTER Hasura has started (which itself depends on setup completing).
 */

const HASURA_ENDPOINT = process.env.HASURA_ENDPOINT || 'http://hasura:8080';
const HASURA_ADMIN_SECRET = process.env.HASURA_ADMIN_SECRET || 'adminsecret';

async function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function hasuraQuery(payload) {
  const res = await fetch(`${HASURA_ENDPOINT}/v1/metadata`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-hasura-admin-secret': HASURA_ADMIN_SECRET,
    },
    body: JSON.stringify(payload),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Hasura ${res.status}: ${text}`);
  return JSON.parse(text);
}

async function waitForHasura() {
  console.log('Waiting for Hasura...');
  for (let i = 0; i < 30; i++) {
    try {
      const res = await fetch(`${HASURA_ENDPOINT}/healthz`);
      if (res.ok) { console.log('✓ Hasura is up'); return; }
    } catch {}
    await wait(3000);
  }
  throw new Error('Hasura did not become healthy after 90 seconds');
}

async function main() {
  console.log('=== Hasura Metadata Setup ===\n');
  await waitForHasura();

  const tables = ['branches', 'users', 'user_branch_roles', 'user_active_roles'];
  for (const table of tables) {
    try {
      await hasuraQuery({
        type: 'pg_track_table',
        args: { source: 'default', table: { schema: 'public', name: table } },
      });
    } catch (err) {
      if (!err.message.toLowerCase().includes('already tracked')) throw err;
    }
  }
  console.log('✓ Tables tracked');

  async function permit(table, role, filter, columns) {
    try {
      await hasuraQuery({
        type: 'pg_create_select_permission',
        args: {
          source: 'default',
          table: { schema: 'public', name: table },
          role,
          permission: { columns, filter },
        },
      });
    } catch (err) {
      if (!err.message.toLowerCase().includes('already exists')) throw err;
    }
  }

  const byUserId   = { id:        { _eq: 'X-Hasura-User-Id'  } };
  const byBranchId = { branch_id: { _eq: 'X-Hasura-Branch-Id' } };
  const ownRoles   = { user_id:   { _eq: 'X-Hasura-User-Id'  } };

  await permit('branches',          'user',               {},          ['id', 'name']);
  await permit('branches',          'branch-coordinator', {},          ['id', 'name']);
  await permit('users',             'user',               byUserId,   ['id', 'email']);
  await permit('users',             'branch-coordinator', byUserId,   ['id', 'email']);
  await permit('user_branch_roles', 'user',               ownRoles,   ['user_id', 'branch_id', 'role']);
  await permit('user_branch_roles', 'branch-coordinator', byBranchId, ['user_id', 'branch_id', 'role']);

  console.log('✓ Permissions applied');
  console.log('\n=== Hasura setup complete ===');
}

main().catch((err) => {
  console.error('\nHasura setup failed:', err.message);
  process.exit(1);
});
