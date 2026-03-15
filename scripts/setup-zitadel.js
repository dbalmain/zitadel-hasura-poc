/**
 * Phase 1 setup. Runs before Hasura starts.
 *
 * What it does:
 *   1. Reads the admin PAT written by Zitadel on first run
 *   2. Registers 'zitadel' as a secondary instance domain (so Docker
 *      service-to-service calls with Host: zitadel:8080 are accepted)
 *   3. Creates a Zitadel project and PKCE OIDC application
 *   4. Registers the Zitadel Action and binds it to the Pre Access Token
 *      Creation trigger (flow 2, trigger 5)
 *   5. Creates a test user (alice@poc.local) in Zitadel
 *   6. Seeds the app DB with alice's user record and role assignments
 *   7. Writes frontend/config.json so the HTML frontend knows the client ID
 *
 * Phase 2 (Hasura metadata) is in setup-hasura.js and runs after Hasura starts.
 */

const fs = require('fs');
const http = require('http');
const path = require('path');
const { Pool } = require('pg');

const ZITADEL = process.env.ZITADEL_DOMAIN || 'http://zitadel:8080';
const MGMT = `${ZITADEL}/management/v1`;
const PAT_PATH = '/pat/admin.pat';
const FRONTEND_CONFIG = '/frontend/config.json';
const ACTION_SCRIPT_PATH = path.join(__dirname, '..', 'zitadel', 'action.js');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForZitadel() {
  console.log('Waiting for Zitadel HTTP endpoint...');
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`${ZITADEL}/debug/healthz`);
      if (res.ok) {
        console.log('✓ Zitadel is up');
        return;
      }
    } catch {}
    await wait(3000);
  }
  throw new Error('Zitadel did not become healthy after 3 minutes');
}

async function readPAT() {
  // Zitadel writes the PAT file during first-run init. Poll until it appears.
  for (let i = 0; i < 30; i++) {
    if (fs.existsSync(PAT_PATH)) {
      return fs.readFileSync(PAT_PATH, 'utf8').trim();
    }
    console.log('Waiting for admin PAT file...');
    await wait(2000);
  }
  throw new Error(`PAT file not found at ${PAT_PATH} after 60 seconds`);
}

// Node.js built-in fetch (undici) treats Host as a forbidden header and always
// overwrites it from the URL hostname. We use http.request directly so we can
// connect to 'zitadel:8080' (Docker DNS) while sending 'Host: localhost:8080'
// (the EXTERNALDOMAIN Zitadel uses to identify its instance).
function zitadelFetch(pat, method, urlPath, body) {
  const fullUrl = urlPath.startsWith('http') ? new URL(urlPath) : new URL(`${MGMT}${urlPath}`);
  const data = body ? JSON.stringify(body) : undefined;

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: fullUrl.hostname,
        port: fullUrl.port || 8080,
        path: fullUrl.pathname + fullUrl.search,
        method,
        headers: {
          Host: 'localhost:8080',
          Authorization: `Bearer ${pat}`,
          'Content-Type': 'application/json',
          ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
        },
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          if (res.statusCode >= 400) {
            reject(new Error(`${method} ${fullUrl.href} → ${res.statusCode}: ${raw}`));
          } else {
            resolve(JSON.parse(raw));
          }
        });
      }
    );
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function main() {
  console.log('=== IDP POC Setup ===\n');

  // 0. Wait for Zitadel HTTP
  await waitForZitadel();

  // 1. Read admin PAT
  const pat = await readPAT();
  console.log('✓ Admin PAT loaded');

  // 2. Get the default org ID (needed for user creation)
  const orgResp = await zitadelFetch(pat, 'GET', '/orgs/me');
  const orgId = orgResp.org.id;
  console.log(`✓ Default org: ${orgResp.org.name} (${orgId})`);

  // 3. Create project
  let projectId;
  try {
    const projectResp = await zitadelFetch(pat, 'POST', '/projects', {
      name: 'IDP POC',
    });
    projectId = projectResp.id;
    console.log(`✓ Created project: IDP POC (${projectId})`);
  } catch (err) {
    // If the project already exists, list and find it
    if (err.message.includes('409') || err.message.toLowerCase().includes('alreadyexists') || err.message.includes('already exists')) {
      const list = await zitadelFetch(pat, 'POST', '/projects/_search', {});
      const existing = list.result.find((p) => p.name === 'IDP POC');
      if (!existing) throw err;
      projectId = existing.id;
      console.log(`✓ Reusing existing project: IDP POC (${projectId})`);
    } else {
      throw err;
    }
  }

  // 4. Create OIDC application (PKCE, JWT access tokens)
  let clientId;
  try {
    const appResp = await zitadelFetch(pat, 'POST', `/projects/${projectId}/apps/oidc`, {
      name: 'POC Frontend',
      redirectUris: ['http://localhost:3001/callback'],
      responseTypes: ['OIDC_RESPONSE_TYPE_CODE'],
      grantTypes: [
        'OIDC_GRANT_TYPE_AUTHORIZATION_CODE',
        'OIDC_GRANT_TYPE_REFRESH_TOKEN',
      ],
      appType: 'OIDC_APP_TYPE_USER_AGENT',
      authMethodType: 'OIDC_AUTH_METHOD_TYPE_NONE', // PKCE — no client secret
      postLogoutRedirectUris: ['http://localhost:3001'],
      version: 'OIDC_VERSION_1_0',
      // JWT access tokens are required so Hasura can verify them directly.
      // Opaque tokens would require a token introspection endpoint.
      accessTokenType: 'OIDC_TOKEN_TYPE_JWT',
      accessTokenRoleAssertion: false,
      devMode: true, // Allows http:// redirect URIs
    });
    clientId = appResp.clientId;
    console.log(`✓ Created OIDC app: POC Frontend (client_id: ${clientId})`);
  } catch (err) {
    if (err.message.includes('409') || err.message.toLowerCase().includes('alreadyexists') || err.message.includes('already exists')) {
      // List apps to find the client ID
      const apps = await zitadelFetch(pat, 'POST', `/projects/${projectId}/apps/_search`, {});
      const existing = apps.result?.find((a) => a.name === 'POC Frontend');
      if (existing?.oidcConfig?.clientId) {
        clientId = existing.oidcConfig.clientId;
        console.log(`✓ Reusing existing OIDC app (client_id: ${clientId})`);
      } else {
        throw err;
      }
    } else {
      throw err;
    }
  }

  // 5. Register the Zitadel Action
  const actionScript = fs.readFileSync(ACTION_SCRIPT_PATH, 'utf8');
  let actionId;
  try {
    const actionResp = await zitadelFetch(pat, 'POST', '/actions', {
      name: 'addHasuraClaims',
      script: actionScript,
      timeout: '10s',
      allowedToFail: false,
    });
    actionId = actionResp.id;
    console.log(`✓ Created Action: addHasuraClaims (${actionId})`);
  } catch (err) {
    // 409 or message containing "AlreadyExists" / "already exists"
    const isConflict = err.message.includes('409') || err.message.toLowerCase().includes('alreadyexists') || err.message.includes('already exists');
    if (isConflict) {
      const list = await zitadelFetch(pat, 'POST', '/actions/_search', {});
      const existing = list.result?.find((a) => a.name === 'addHasuraClaims');
      if (existing) {
        actionId = existing.id;
        console.log(`✓ Reusing existing Action: addHasuraClaims (${actionId})`);
      } else {
        throw err;
      }
    } else {
      throw err;
    }
  }

  // 6. Bind the Action to the Pre Access Token Creation trigger
  //    Flow type 2 = FLOW_TYPE_COMPLEMENT_TOKEN
  //    Trigger type 5 = TRIGGER_TYPE_PRE_ACCESS_TOKEN_CREATION
  //    (Confirmed from GET /management/v1/flows/2 — NOT type 3 as some older docs say)
  //    SetTriggerActions is POST with {actionIds: [...]} — replaces all actions for the trigger.
  try {
    await zitadelFetch(pat, 'POST', '/flows/2/trigger/5', {
      actionIds: [actionId],
    });
  } catch (err) {
    // "No Changes" means it's already bound — treat as success
    if (!err.message.includes('No Changes') && !err.message.includes('COMMAND-Nfh52')) throw err;
  }
  console.log('✓ Action bound to Pre Access Token Creation trigger (type 5)');

  // 7. Create test user alice in Zitadel
  let aliceZitadelId;
  try {
    const userResp = await zitadelFetch(
      pat,
      'POST',
      `${ZITADEL}/v2/users/human`,
      {
        username: 'alice',
        organization: { orgId },
        profile: { givenName: 'Alice', familyName: 'Example' },
        email: {
          email: 'alice@poc.local',
          isVerified: true,
        },
        password: {
          password: 'Password1!',
          changeRequired: false,
        },
      }
    );
    aliceZitadelId = userResp.userId;
    console.log(`✓ Created Zitadel user: alice@poc.local (${aliceZitadelId})`);
  } catch (err) {
    if (err.message.includes('409') || err.message.toLowerCase().includes('alreadyexists') || err.message.includes('already exists') || err.message.includes('UniqueConstraintViolated')) {
      // Look up existing user
      const search = await zitadelFetch(pat, 'POST', `${ZITADEL}/v2/users`, {
        queries: [{ userNameQuery: { userName: 'alice', method: 'TEXT_QUERY_METHOD_EQUALS' } }],
      });
      aliceZitadelId = search.result?.[0]?.userId;
      if (!aliceZitadelId) throw err;
      console.log(`✓ Reusing existing Zitadel user: alice@poc.local (${aliceZitadelId})`);
    } else {
      throw err;
    }
  }

  // 8. Seed the app DB with alice's record and role assignments
  const pool = new Pool({ connectionString: process.env.APP_DB_URL });
  try {
    await pool.query(
      `INSERT INTO users (id, email) VALUES ($1, $2)
       ON CONFLICT (id) DO NOTHING`,
      [aliceZitadelId, 'alice@poc.local']
    );

    const roles = [
      { branchId: 'branch-1', role: 'BRANCH_COORDINATOR' },
      { branchId: 'branch-2', role: 'BRANCH_COORDINATOR' },
      { branchId: 'branch-1', role: 'USER' },
    ];
    for (const { branchId, role } of roles) {
      await pool.query(
        `INSERT INTO user_branch_roles (user_id, branch_id, role)
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
        [aliceZitadelId, branchId, role]
      );
    }
    console.log(`✓ Seeded app DB roles for alice`);
  } finally {
    await pool.end();
  }

  // 9. Write frontend config
  const config = {
    zitadelDomain: 'http://localhost:8080',       // reachable from browser
    roleValidatorUrl: 'http://localhost:3000',     // reachable from browser
    hasuraUrl: 'http://localhost:8090/v1/graphql', // reachable from browser
    clientId,
    // Scopes: offline_access gets a refresh token so we can re-mint tokens after role switch
    scope: 'openid profile email offline_access',
    redirectUri: 'http://localhost:3001/callback',
  };
  fs.writeFileSync(FRONTEND_CONFIG, JSON.stringify(config, null, 2));
  console.log(`✓ Wrote ${FRONTEND_CONFIG}`);

  console.log('\n=== Setup complete ===');
  console.log('');
  console.log('Services:');
  console.log('  Frontend:       http://localhost:3001');
  console.log('  Zitadel:        http://localhost:8080');
  console.log('  Hasura Console: http://localhost:8090/console  (admin secret: adminsecret)');
  console.log('  role-validator: http://localhost:3000');
  console.log('');
  console.log('Test credentials: alice@poc.local / Password1!');
  console.log('Admin console:    admin@poc.local / Password1!');
}

main().catch((err) => {
  console.error('\nSetup failed:', err.message);
  process.exit(1);
});
