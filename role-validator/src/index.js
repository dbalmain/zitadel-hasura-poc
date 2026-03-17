const express = require('express');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

// CORS — frontend at :3301 calls this service at :3300
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const RAUTHY_URL    = process.env.RAUTHY_URL    || 'http://rauthy:8080';
const RAUTHY_API_KEY = process.env.RAUTHY_API_KEY;    // "bootstrap$<secret>"
const RAUTHY_CLIENT_ID = process.env.RAUTHY_CLIENT_ID || 'poc-app';
const RAUTHY_SCOPE  = 'openid email profile hasura';

// Low-level helper: Rauthy admin API call
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

// Called by Docker healthcheck
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

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

// Called by the frontend when the user picks a role.
// Validates the assignment in the app DB, updates the user's active role in Rauthy,
// then immediately refreshes the token and returns the new token pair — one round trip.
app.post('/switch-role', async (req, res) => {
  try {
    const { userId, role, branchId, refresh_token } = req.body;
    if (!userId || !role || !branchId || !refresh_token) {
      return res.status(400).json({ error: 'userId, role, branchId, and refresh_token are required' });
    }

    // Validate the role assignment in the app DB
    const { rows } = await pool.query(
      'SELECT 1 FROM user_branch_roles WHERE user_id = $1 AND branch_id = $2 AND role = $3',
      [userId, branchId, role]
    );
    if (rows.length === 0) {
      return res.status(403).json({ error: 'Role not assigned to this user on this branch' });
    }

    // Convert DB role (SNAKE_CASE) to Hasura role (kebab-case)
    const hasuraRole = role.toLowerCase().replace(/_/g, '-');

    // Update the user's active role in Rauthy
    const { status, body: data } = await rauthyAdmin('PUT', `/auth/v1/users/${userId}/attr`, {
      values: [
        { key: 'active_role',      value: hasuraRole },
        { key: 'active_branch_id', value: branchId },
      ],
    });
    if (status < 200 || status >= 300) {
      throw new Error(`Rauthy attribute update failed (${status}): ${JSON.stringify(data)}`);
    }

    // Immediately refresh to get a new token reflecting the updated role
    const tokenRes = await fetch(`${RAUTHY_URL}/auth/v1/oidc/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'refresh_token',
        client_id:     RAUTHY_CLIENT_ID,
        refresh_token,
        scope:         RAUTHY_SCOPE,
      }).toString(),
    });
    const tokenData = await tokenRes.json();
    if (!tokenRes.ok) {
      throw new Error(`Token refresh failed (${tokenRes.status}): ${JSON.stringify(tokenData)}`);
    }

    res.json({
      access_token:  tokenData.access_token,
      refresh_token: tokenData.refresh_token || refresh_token,
    });
  } catch (err) {
    console.error('switch-role error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Called by the frontend to perform an embedded login using ROPC.
// Returns {access_token, refresh_token} directly — no PKCE code exchange needed.
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }
  try {
    const body = new URLSearchParams({
      grant_type: 'password',
      client_id:  RAUTHY_CLIENT_ID,
      username,
      password,
      scope: RAUTHY_SCOPE,
    });
    const tokenRes = await fetch(`${RAUTHY_URL}/auth/v1/oidc/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    const data = await tokenRes.json();
    if (!tokenRes.ok) {
      return res.status(401).json({ error: data.error_description || data.error || 'Login failed' });
    }
    res.json({ access_token: data.access_token, refresh_token: data.refresh_token });
  } catch (err) {
    console.error('login error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Called by the frontend after a role switch (or to silently refresh the token).
// Returns a new {access_token, refresh_token}.
app.post('/api/refresh', async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) {
    return res.status(400).json({ error: 'refresh_token is required' });
  }
  try {
    const body = new URLSearchParams({
      grant_type:    'refresh_token',
      client_id:     RAUTHY_CLIENT_ID,
      refresh_token,
      scope:         RAUTHY_SCOPE,
    });
    const tokenRes = await fetch(`${RAUTHY_URL}/auth/v1/oidc/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    const data = await tokenRes.json();
    if (!tokenRes.ok) {
      return res.status(401).json({ error: data.error_description || data.error || 'Refresh failed' });
    }
    res.json({ access_token: data.access_token, refresh_token: data.refresh_token || refresh_token });
  } catch (err) {
    console.error('refresh error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`role-validator listening on :${port}`));
