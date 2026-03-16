const express = require('express');
const http = require('http');
const fs = require('fs');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

// CORS — frontend at :3001 calls this service at :3000
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Zitadel is accessed via the nginx proxy which rewrites Host → localhost:8080
const ZITADEL_PROXY_HOST = process.env.ZITADEL_PROXY_HOST || 'zitadel-proxy';
const ZITADEL_PROXY_PORT = parseInt(process.env.ZITADEL_PROXY_PORT || '8081', 10);
const PAT_PATH = process.env.PAT_PATH || '/pat/admin.pat';

// PAT is read lazily — it may not exist until Zitadel finishes first-run init
let _pat = null;
function getAdminPat() {
  if (_pat) return _pat;
  if (!fs.existsSync(PAT_PATH)) throw new Error('Admin PAT not yet available — is Zitadel still starting up?');
  _pat = fs.readFileSync(PAT_PATH, 'utf8').trim();
  return _pat;
}

// Low-level helper: HTTP request to zitadel-proxy (no redirect following)
function zitadelRequest(method, path, body, pat) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : undefined;
    const req = http.request(
      {
        hostname: ZITADEL_PROXY_HOST,
        port: ZITADEL_PROXY_PORT,
        path,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(pat ? { Authorization: `Bearer ${pat}` } : {}),
          ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
        },
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: raw }));
      }
    );
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// Called by Docker healthcheck
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// Called by the Zitadel Action on every token issuance.
app.get('/active-role/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { rows } = await pool.query(
      'SELECT role, branch_id FROM user_active_roles WHERE user_id = $1',
      [userId]
    );
    if (rows.length === 0) return res.json({ role: null, branchId: null });
    res.json({ role: rows[0].role, branchId: rows[0].branch_id });
  } catch (err) {
    console.error('active-role error:', err.message);
    res.status(500).json({ error: 'internal error' });
  }
});

// Called by the frontend when the user picks a role.
app.post('/switch-role', async (req, res) => {
  try {
    const { userId, role, branchId } = req.body;
    if (!userId || !role || !branchId) {
      return res.status(400).json({ error: 'userId, role, and branchId are required' });
    }
    const { rows } = await pool.query(
      'SELECT 1 FROM user_branch_roles WHERE user_id = $1 AND branch_id = $2 AND role = $3',
      [userId, branchId, role]
    );
    if (rows.length === 0) {
      return res.status(403).json({ error: 'Role not assigned to this user on this branch' });
    }
    await pool.query(
      `INSERT INTO user_active_roles (user_id, role, branch_id, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_id) DO UPDATE SET role = $2, branch_id = $3, updated_at = NOW()`,
      [userId, role, branchId]
    );
    res.json({ success: true, role, branchId });
  } catch (err) {
    console.error('switch-role error:', err.message);
    res.status(500).json({ error: 'internal error' });
  }
});

// Called by the frontend to populate the role-switcher UI.
app.get('/roles/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { rows } = await pool.query(
      `SELECT ubr.role, ubr.branch_id AS "branchId", b.name AS "branchName"
       FROM user_branch_roles ubr
       JOIN branches b ON b.id = ubr.branch_id
       WHERE ubr.user_id = $1
       ORDER BY b.name, ubr.role`,
      [userId]
    );
    res.json({ roles: rows });
  } catch (err) {
    console.error('roles error:', err.message);
    res.status(500).json({ error: 'internal error' });
  }
});

// Called by the frontend to perform an embedded login (no redirect to Zitadel UI).
//
// Flow (all Zitadel calls made server-side using the admin PAT):
//  1. Initiate OIDC auth request → extract authRequestId from redirect Location
//  2. Create a Zitadel session for the user (requires PAT to authorise the API call)
//  3. Finalise the auth request with the session → get callbackUrl containing the code
//  4. Return the code to the browser; browser exchanges it with its own PKCE verifier
//
// The PKCE verifier never leaves the browser, so the code exchange is still secure.
app.post('/api/login', async (req, res) => {
  const { username, password, codeChallenge, clientId, redirectUri, scope } = req.body;
  if (!username || !password || !codeChallenge || !clientId || !redirectUri) {
    return res.status(400).json({ error: 'username, password, codeChallenge, clientId, redirectUri are required' });
  }

  let pat;
  try {
    pat = getAdminPat();
  } catch (err) {
    return res.status(503).json({ error: err.message });
  }

  try {
    // Step 1 — initiate OIDC auth request; capture authRequestId from the redirect
    const authParams = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: scope || 'openid profile email offline_access',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });
    const authReq = await zitadelRequest('GET', `/oauth/v2/authorize?${authParams}`);
    const location = authReq.headers['location'];
    if (!location) throw new Error(`No redirect from Zitadel (status ${authReq.status})`);
    const locationUrl = location.startsWith('http') ? new URL(location) : new URL(location, 'http://localhost:8080');
    const authRequestId = locationUrl.searchParams.get('authRequest');
    if (!authRequestId) throw new Error(`No authRequest in Location: ${location}`);

    // Step 2 — create a Zitadel session for the user (PAT authorises this API call)
    const sessionResp = await zitadelRequest('POST', '/v2/sessions', {
      checks: {
        user: { loginName: username },
        password: { password },
      },
    }, pat);
    const sessionData = JSON.parse(sessionResp.body);
    if (sessionResp.status >= 400) throw new Error(sessionData.message || 'Session creation failed');
    const { sessionId, sessionToken } = sessionData;

    // Step 3 — finalise the auth request with the session
    const callbackResp = await zitadelRequest('POST', `/v2/oidc/auth_requests/${authRequestId}`, {
      session: { sessionId, sessionToken },
    }, pat);
    const callbackData = JSON.parse(callbackResp.body);
    if (callbackResp.status >= 400) throw new Error(callbackData.message || 'Auth request finalisation failed');
    const code = new URL(callbackData.callbackUrl).searchParams.get('code');
    if (!code) throw new Error('No code in callbackUrl');

    res.json({ code });
  } catch (err) {
    console.error('login error:', err.message);
    res.status(401).json({ error: err.message });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`role-validator listening on :${port}`));
