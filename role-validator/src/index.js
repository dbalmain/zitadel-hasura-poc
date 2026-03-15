const express = require('express');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Called by Docker healthcheck and setup script
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// Called by the Zitadel Action on every token issuance.
// Returns the user's current active role (if any).
app.get('/active-role/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { rows } = await pool.query(
      'SELECT role, branch_id FROM user_active_roles WHERE user_id = $1',
      [userId]
    );
    if (rows.length === 0) {
      return res.json({ role: null, branchId: null });
    }
    res.json({ role: rows[0].role, branchId: rows[0].branch_id });
  } catch (err) {
    console.error('active-role error:', err.message);
    res.status(500).json({ error: 'internal error' });
  }
});

// Called by the frontend when the user picks a role.
// Validates the assignment exists in the DB before accepting it.
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

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`role-validator listening on :${port}`));
