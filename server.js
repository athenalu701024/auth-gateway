/**
 * Auth Gateway Server
 * Unified authentication service for IGS ad monitoring platform.
 *
 * Features:
 * - Email + password login (restricted to @igs.com.tw)
 * - JWT token issuance with httpOnly cookies
 * - Role-based access: admin (read+write), viewer (read-only)
 * - User management admin panel
 * - Cross-origin token validation endpoint for integrated apps
 */

import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const ALLOWED_DOMAIN = process.env.ALLOWED_EMAIL_DOMAIN || 'igs.com.tw';
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || '';
const TOKEN_EXPIRY = '7d';

// ─── Database ───
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('railway') ? { rejectUnauthorized: false } : false,
});

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        name VARCHAR(100) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'viewer',
        is_active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    `);

    // Create initial admin if not exists
    const adminEmail = process.env.ADMIN_EMAIL || `admin@${ALLOWED_DOMAIN}`;
    const adminPassword = process.env.ADMIN_PASSWORD || 'changeme123';
    const existing = await client.query('SELECT id FROM users WHERE email = $1', [adminEmail]);
    if (existing.rows.length === 0) {
      const hash = await bcrypt.hash(adminPassword, 12);
      await client.query(
        'INSERT INTO users (email, password_hash, name, role) VALUES ($1, $2, $3, $4)',
        [adminEmail, hash, 'Admin', 'admin']
      );
      console.log(`[Auth] Initial admin created: ${adminEmail}`);
    }
    console.log('[Auth] Database initialized');
  } finally {
    client.release();
  }
}

// ─── Middleware ───
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000,http://localhost:3001')
  .split(',').map(s => s.trim());

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(null, true); // Allow all in production for now — apps validate JWT
    }
  },
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(join(__dirname, 'public')));

// ─── Auth Helpers ───
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, name: user.name, role: user.role },
    JWT_SECRET,
    { expiresIn: TOKEN_EXPIRY }
  );
}

function setTokenCookie(res, token) {
  const cookieOpts = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  };
  if (COOKIE_DOMAIN) cookieOpts.domain = COOKIE_DOMAIN;
  res.cookie('auth_token', token, cookieOpts);
}

function getTokenFromRequest(req) {
  // 1. Cookie
  if (req.cookies?.auth_token) return req.cookies.auth_token;
  // 2. Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) return authHeader.slice(7);
  return null;
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// Auth middleware
function requireAuth(req, res, next) {
  const token = getTokenFromRequest(req);
  if (!token) return res.status(401).json({ error: '未登入' });
  const user = verifyToken(token);
  if (!user) return res.status(401).json({ error: 'Token 已過期，請重新登入' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: '權限不足，需要管理員權限' });
  }
  next();
}

// ─── Auth Routes ───

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: '請輸入帳號和密碼' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: '帳號或密碼錯誤' });
    if (!user.is_active) return res.status(403).json({ error: '帳號已被停用，請聯繫管理員' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: '帳號或密碼錯誤' });

    // Update last login
    await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

    const token = generateToken(user);
    setTokenCookie(res, token);

    res.json({
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
      token, // Also return token for apps that use Authorization header
    });
  } catch (err) {
    console.error('[Auth] Login error:', err);
    res.status(500).json({ error: '伺服器錯誤' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('auth_token');
  res.json({ success: true });
});

// Verify token (used by other apps to validate)
app.get('/api/auth/verify', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// Get current user
app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, name, role, is_active, created_at, last_login FROM users WHERE id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: '使用者不存在' });
    res.json({ user: result.rows[0] });
  } catch {
    res.status(500).json({ error: '伺服器錯誤' });
  }
});

// Change password
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: '請輸入目前密碼和新密碼' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: '新密碼至少 6 個字元' });
  }

  try {
    const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
    const valid = await bcrypt.compare(currentPassword, result.rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: '目前密碼不正確' });

    const hash = await bcrypt.hash(newPassword, 12);
    await pool.query('UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2', [hash, req.user.id]);
    res.json({ success: true, message: '密碼已更新' });
  } catch {
    res.status(500).json({ error: '伺服器錯誤' });
  }
});

// ─── Admin Routes ───

// List all users
app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, name, role, is_active, created_at, last_login FROM users ORDER BY created_at DESC'
    );
    res.json({ users: result.rows });
  } catch {
    res.status(500).json({ error: '伺服器錯誤' });
  }
});

// Create user
app.post('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const { email, name, password, role } = req.body;
  if (!email || !name || !password) {
    return res.status(400).json({ error: '請填寫所有欄位' });
  }

  // Validate email domain
  if (!email.toLowerCase().endsWith(`@${ALLOWED_DOMAIN}`)) {
    return res.status(400).json({ error: `只允許 @${ALLOWED_DOMAIN} 的信箱` });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: '密碼至少 6 個字元' });
  }

  const validRoles = ['admin', 'viewer'];
  if (role && !validRoles.includes(role)) {
    return res.status(400).json({ error: '無效的角色' });
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, name, role) VALUES ($1, $2, $3, $4) RETURNING id, email, name, role, is_active, created_at',
      [email.toLowerCase(), hash, name, role || 'viewer']
    );
    res.json({ user: result.rows[0], message: '使用者已建立' });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: '此 Email 已存在' });
    }
    console.error('[Admin] Create user error:', err);
    res.status(500).json({ error: '伺服器錯誤' });
  }
});

// Update user
app.put('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, role, is_active, password } = req.body;

  // Prevent admin from deactivating themselves
  if (parseInt(id) === req.user.id && is_active === false) {
    return res.status(400).json({ error: '無法停用自己的帳號' });
  }

  try {
    const updates = [];
    const values = [];
    let idx = 1;

    if (name !== undefined) { updates.push(`name = $${idx++}`); values.push(name); }
    if (role !== undefined) { updates.push(`role = $${idx++}`); values.push(role); }
    if (is_active !== undefined) { updates.push(`is_active = $${idx++}`); values.push(is_active); }
    if (password) {
      const hash = await bcrypt.hash(password, 12);
      updates.push(`password_hash = $${idx++}`);
      values.push(hash);
    }

    if (updates.length === 0) return res.status(400).json({ error: '沒有要更新的欄位' });

    updates.push(`updated_at = CURRENT_TIMESTAMP`);
    values.push(id);

    const result = await pool.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = $${idx} RETURNING id, email, name, role, is_active`,
      values
    );

    if (result.rows.length === 0) return res.status(404).json({ error: '使用者不存在' });
    res.json({ user: result.rows[0], message: '已更新' });
  } catch {
    res.status(500).json({ error: '伺服器錯誤' });
  }
});

// Delete user
app.delete('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  if (parseInt(id) === req.user.id) {
    return res.status(400).json({ error: '無法刪除自己的帳號' });
  }

  try {
    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING email', [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: '使用者不存在' });
    res.json({ success: true, message: `已刪除 ${result.rows[0].email}` });
  } catch {
    res.status(500).json({ error: '伺服器錯誤' });
  }
});

// ─── Health check ───
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'auth-gateway' });
});

// ─── SPA fallback ───
app.get('*', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});

// ─── Start ───
async function start() {
  try {
    await initDB();
    app.listen(PORT, () => {
      console.log(`[Auth Gateway] Running on http://localhost:${PORT}`);
      console.log(`[Auth Gateway] Allowed domain: @${ALLOWED_DOMAIN}`);
    });
  } catch (err) {
    console.error('[Auth Gateway] Failed to start:', err);
    process.exit(1);
  }
}

start();
