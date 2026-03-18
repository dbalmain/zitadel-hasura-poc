/**
 * Zitadel setup — creates OIDC app, charlie + diana users, seeds app DB.
 * Runs after Zitadel and Postgres are healthy.
 *
 * Flow:
 *  1. Poll for PAT file written by Zitadel on first-run bootstrap
 *  2. Get org ID via management API
 *  3. Create OIDC project + app (PKCE, no client secret)
 *  4. Create charlie + diana as human users with @poc.northern.local emails
 *  5. Seed app DB with their Zitadel user IDs
 *  6. Write /zitadel-config/zitadel.json for the security proxy
 */

const { Client } = require('pg');
const fs = require('fs');
const path = require('path');

const ZITADEL_URL = process.env.ZITADEL_URL || 'http://zitadel:8080';
const APP_DB_URL = process.env.APP_DB_URL || 'postgres://postgres:postgres@postgres:5432/app';
const PAT_PATH = '/pat/admin.pat';
const CONFIG_OUT = '/zitadel-config/zitadel.json';

async function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForPat() {
  console.log('Waiting for Zitadel PAT file at', PAT_PATH, '...');
  for (let i = 0; i < 90; i++) {
    if (fs.existsSync(PAT_PATH)) {
      const content = fs.readFileSync(PAT_PATH, 'utf8').trim();
      if (content) {
        console.log('✓ PAT file found');
        return content;
      }
    }
    await wait(3000);
  }
  throw new Error('PAT file not found after 270 seconds');
}

async function zitadelApi(method, urlPath, body, pat) {
  const opts = {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Authorization': `Bearer ${pat}`,
    },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(`${ZITADEL_URL}${urlPath}`, opts);
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`Zitadel ${method} ${urlPath} => ${res.status}: ${text}`);
  }
  return text ? JSON.parse(text) : null;
}

async function getOrgId(pat) {
  const resp = await zitadelApi('GET', '/management/v1/orgs/me', undefined, pat);
  return resp.org.id;
}

async function createProject(pat, orgId) {
  try {
    const resp = await zitadelApi('POST', '/management/v1/projects', { name: 'POC-Northern' }, pat);
    return resp.id;
  } catch (err) {
    if (!err.message.includes('409')) throw err;
    // Already exists — find it
    const resp = await zitadelApi('POST', '/management/v1/projects/_search', { queries: [{ nameQuery: { name: 'POC-Northern', method: 'TEXT_QUERY_METHOD_EQUALS' } }] }, pat);
    return resp.result[0].id;
  }
}

async function createOidcApp(pat, projectId) {
  try {
    const resp = await zitadelApi('POST', `/management/v1/projects/${projectId}/apps/oidc`, {
      name: 'POC-Northern-App',
      redirectUris: ['http://localhost:3300/api/auth/callback'],
      responseTypes: ['OIDC_RESPONSE_TYPE_CODE'],
      grantTypes: ['OIDC_GRANT_TYPE_AUTHORIZATION_CODE'],
      appType: 'OIDC_APP_TYPE_WEB',
      authMethodType: 'OIDC_AUTH_METHOD_TYPE_NONE',  // PKCE — no client secret
      postLogoutRedirectUris: [],
      version: 'OIDC_VERSION_1_0',
      devMode: true,
      accessTokenType: 'OIDC_TOKEN_TYPE_BEARER',
      accessTokenRoleAssertion: false,
      idTokenRoleAssertion: false,
      idTokenUserinfoAssertion: false,
      clockSkew: '0s',
      additionalOrigins: ['http://localhost:3300'],
    }, pat);
    return resp.clientId;
  } catch (err) {
    if (!err.message.includes('409')) throw err;
    // Already exists — list apps and find it
    const resp = await zitadelApi('POST', `/management/v1/projects/${projectId}/apps/_search`, {}, pat);
    const app = resp.result.find(a => a.name === 'POC-Northern-App');
    return app.oidcConfig.clientId;
  }
}

async function createUser(pat, orgId, username, firstName, lastName, email) {
  try {
    const resp = await zitadelApi('POST', '/v2/users/human', {
      username: email,
      organization: { orgId },
      profile: { givenName: firstName, familyName: lastName, displayName: `${firstName} ${lastName}` },
      email: { email, isVerified: true },
      password: { password: 'TestPassword1!', changeRequired: false },
    }, pat);
    return resp.userId;
  } catch (err) {
    if (!err.message.includes('409')) throw err;
    // Already exists — find via management v1 search
    const resp = await zitadelApi('POST', '/management/v1/users/_search', { queries: [{ userNameQuery: { userName: email, method: 'TEXT_QUERY_METHOD_EQUALS' } }] }, pat);
    return resp.result[0].id;
  }
}

async function waitForZitadel(pat) {
  console.log('Waiting for Zitadel management API...');
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`${ZITADEL_URL}/management/v1/orgs/me`, {
        headers: { Authorization: `Bearer ${pat}`, Accept: 'application/json' },
      });
      if (res.ok || res.status === 403) {
        console.log('✓ Zitadel management API is up');
        return;
      }
    } catch {}
    await wait(3000);
  }
  throw new Error('Zitadel management API did not become ready after 180 seconds');
}

async function main() {
  console.log('=== Zitadel Setup ===\n');

  const pat = await waitForPat();
  await waitForZitadel(pat);

  console.log('Fetching org ID...');
  const orgId = await getOrgId(pat);
  console.log(`✓ Org ID: ${orgId}`);

  console.log('Creating project POC-Northern...');
  const projectId = await createProject(pat, orgId);
  console.log(`✓ Project ID: ${projectId}`);

  console.log('Creating OIDC app...');
  const clientId = await createOidcApp(pat, projectId);
  console.log(`✓ Client ID: ${clientId}`);

  console.log('Creating Zitadel users...');
  const charlieId = await createUser(pat, orgId, 'charlie', 'Charlie', 'Northern', 'charlie@poc.northern.local');
  console.log(`  charlie: ${charlieId}`);
  const dianaId = await createUser(pat, orgId, 'diana', 'Diana', 'Northern', 'diana@poc.northern.local');
  console.log(`  diana: ${dianaId}`);
  console.log('✓ Users created');

  // Seed app DB with Zitadel users
  console.log('\nSeeding app database (Zitadel users)...');
  const db = new Client({ connectionString: APP_DB_URL });
  await db.connect();

  await db.query(
    'INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING',
    [charlieId, 'charlie@poc.northern.local']
  );
  await db.query(
    'INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING',
    [dianaId, 'diana@poc.northern.local']
  );
  console.log('✓ Zitadel users inserted');

  // Role assignments for Zitadel users:
  //   charlie → branch-1 user
  //   diana   → branch-1 user
  const roleAssignments = [
    [charlieId, 'branch-1', 'user'],
    [dianaId,   'branch-1', 'user'],
  ];
  for (const [userId, branchId, role] of roleAssignments) {
    await db.query(
      'INSERT INTO user_branch_roles (user_id, branch_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
      [userId, branchId, role]
    );
  }
  console.log('✓ Role assignments inserted');

  await db.end();

  // Configure SMTP → Mailpit
  console.log('Configuring SMTP (Mailpit)...');
  // Check if a provider already exists (idempotency)
  const smtpList = await zitadelApi('POST', '/admin/v1/email/_search', {}, pat);
  let smtpId = smtpList.result?.[0]?.id;
  if (!smtpId) {
    const smtpResp = await zitadelApi('POST', '/admin/v1/email/smtp', {
      senderAddress: 'zitadel@poc.local',
      senderName: 'Zitadel',
      host: 'mailpit:1025',
      tls: false,
    }, pat);
    smtpId = smtpResp.id;
    console.log(`  Created provider: ${smtpId}`);
  } else {
    console.log(`  Existing provider: ${smtpId}`);
  }
  // Activate if not already active
  if (smtpList.result?.[0]?.state !== 'EMAIL_PROVIDER_ACTIVE') {
    await zitadelApi('POST', `/admin/v1/email/${smtpId}/_activate`, {}, pat);
    console.log('✓ SMTP configured and activated');
  } else {
    console.log('✓ SMTP already active');
  }

  // Write zitadel.json for security proxy
  const zitadelConfig = {
    client_id: clientId,
    public_url: 'http://localhost:8082',
    internal_url: 'http://zitadel-proxy:8081',
    domains: ['poc.northern.local'],
  };
  fs.writeFileSync(CONFIG_OUT, JSON.stringify(zitadelConfig, null, 2));
  console.log(`✓ Zitadel config written to ${CONFIG_OUT}`);

  console.log('\n=== Zitadel setup complete ===');
  console.log('\nZitadel users (password: TestPassword1!):');
  console.log('  charlie@poc.northern.local — branch-1 (user)');
  console.log('  diana@poc.northern.local   — branch-1 (user)');
  console.log('\nZitadel admin UI: http://localhost:8080');
  console.log(`  admin@poc.local / Password1!`);
}

main().catch((err) => {
  console.error('\nZitadel setup failed:', err.message);
  process.exit(1);
});
