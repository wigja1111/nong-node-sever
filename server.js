
// server.js
// Node 24 (ESM) — Full API with image streaming, likes, user settings, avatar, comment edit/delete,
// post edit/delete (_method override), me-filter, and lightweight push notifications (DB + optional webhook).

import 'dotenv/config';
import express from 'express';
import mysql from 'mysql2/promise';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import sharp from 'sharp'; // 이미지 최적화
import { randomUUID, createHash } from 'crypto';

// -------------------- Config --------------------
const cfg = {
  httpPort: Number(process.env.PORT) || 3000,
  dbHost: process.env.DB_HOST || '',
  dbPort: Number(process.env.DB_PORT || 0),
  dbUser: process.env.DB_USER || '',
  dbPass: process.env.DB_PASSWORD || '',
  dbName: process.env.DB_NAME || '',
  bcryptRounds: Number(process.env.BCRYPT_SALT_ROUNDS || 12),
  corsOrigin: process.env.CORS_ORIGIN || '*',
  maxImageSizeMB: Number(process.env.MAX_IMAGE_MB || 10),
  maxImageFiles: Number(process.env.MAX_IMAGE_FILES || 10),
  jwtSecret: process.env.JWT_SECRET || 'dev-secret-change-it',
  pushWebhook: process.env.PUSH_WEBHOOK || '',   // optional: external push webhook
};

console.log('[BOOT CONFIG]', {
  DB_HOST: cfg.dbHost,
  DB_PORT: cfg.dbPort,
  DB_USER: cfg.dbUser,
  DB_NAME: cfg.dbName,
  PORT: cfg.httpPort,
  CORS_ORIGIN: cfg.corsOrigin,
  JWT_SECRET_SET: cfg.jwtSecret !== 'dev-secret-change-it',
  PUSH_WEBHOOK_SET: !!cfg.pushWebhook,
});

// -------------------- App --------------------
const app = express();
app.set('trust proxy', true);

app.use(
  helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  })
);
app.use(cors({ origin: cfg.corsOrigin, credentials: false }));
app.use(express.json({ limit: '2mb' }));

// Request id + basic logging
app.use((req, res, next) => {
  const rid = randomUUID();
  req.rid = rid;
  const t0 = Date.now();
  console.log(`[REQ] ${rid} ${req.method} ${req.url} ip=${req.ip}`);
  res.on('finish', () => {
    console.log(`[RES] ${rid} ${req.method} ${req.url} status=${res.statusCode} ms=${Date.now() - t0}`);
  });
  next();
});

// Upload (memory) — images stored in DB (LONGBLOB)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: cfg.maxImageSizeMB * 1024 * 1024, files: cfg.maxImageFiles },
  fileFilter: (_req, file, cb) => {
    if (!file.mimetype?.startsWith('image/')) return cb(new Error('Only image uploads are allowed'));
    cb(null, true);
  },
});

/** ===== 이미지 최적화 유틸 =====
 * 업로드된 이미지 버퍼가 1MB(1,048,576 bytes)를 초과하면
 * WebP 재인코딩(+필요 시 리사이즈)으로 1MB 이하로 줄입니다.
 */
const ONE_MB = 1024 * 1024;

/**
 * @param {Buffer} originalBuffer 원본 이미지 버퍼
 * @returns {Promise<{buffer:Buffer, mimetype:string|null}>} 최적화된 버퍼와 새 MIME (없으면 null)
 */
async function optimizeToUnder1MB(originalBuffer) {
  if (!originalBuffer || originalBuffer.length <= ONE_MB) {
    return { buffer: originalBuffer, mimetype: null };
  }
  let meta = {};
  try { meta = await sharp(originalBuffer).metadata(); } catch {}
  // 1차: 품질만 낮춰 시도 (90 -> 50)
  for (let q = 90; q >= 50; q -= 10) {
    const out = await sharp(originalBuffer).webp({ quality: q }).toBuffer();
    if (out.length <= ONE_MB) return { buffer: out, mimetype: 'image/webp' };
  }
  // 2차: 가로폭 85%씩 축소하며 품질(70 -> 40) 탐색
  let width = typeof meta.width === 'number' ? meta.width : 2048;
  while (width > 320) {
    width = Math.max(320, Math.round(width * 0.85));
    for (let q = 70; q >= 40; q -= 10) {
      const out = await sharp(originalBuffer)
        .resize({ width, withoutEnlargement: true })
        .webp({ quality: q })
        .toBuffer();
      if (out.length <= ONE_MB) return { buffer: out, mimetype: 'image/webp' };
    }
    if (width === 320) break;
  }
  // 3차: 최저 품질 fallback
  const fallback = await sharp(originalBuffer).webp({ quality: 40 }).toBuffer();
  return { buffer: fallback, mimetype: 'image/webp' };
}


// Helpers
const ok = (res, data = {}) => res.json({ ok: true, ...data });
const fail = (res, code = 400, message = 'Bad Request') => res.status(code).json({ ok: false, error: message });

// -------------------- DB Pool --------------------
let pool = null;
function ensurePool() {
  if (pool) return pool;
  if (!cfg.dbHost || !cfg.dbPort || !cfg.dbUser || !cfg.dbName) {
    throw new Error('DB env is missing: set DB_HOST/DB_PORT/DB_USER/DB_NAME (and DB_PASSWORD if needed)');
  }
  pool = mysql.createPool({
    host: cfg.dbHost,
    port: cfg.dbPort,
    user: cfg.dbUser,
    password: cfg.dbPass,
    database: cfg.dbName,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: 5000,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0,
    charset: 'utf8mb4',
  });
  return pool;
}

// -------------------- Diagnostics --------------------
app.get('/', (_req, res) => ok(res, { route: '/', node: process.version }));
app.get('/health', (_req, res) => ok(res, { status: 'ok' }));
app.get('/env-check', (_req, res) =>
  ok(res, {
    env: {
      DB_HOST: !!cfg.dbHost,
      DB_PORT: !!cfg.dbPort,
      DB_USER: !!cfg.dbUser,
      DB_PASSWORD: cfg.dbPass ? '(set)' : '(empty)',
      DB_NAME: !!cfg.dbName,
      JWT_SECRET: cfg.jwtSecret !== 'dev-secret-change-it',
      CORS_ORIGIN: cfg.corsOrigin,
      PUSH_WEBHOOK: !!cfg.pushWebhook,
    },
  })
);
app.get('/__routes', (_req, res) => {
  const routes = [];
  app._router?.stack?.forEach((m) => {
    if (m.route?.path) {
      const methods = Object.keys(m.route.methods).join(',').toUpperCase();
      routes.push(`${methods} ${m.route.path}`);
    } else if (m.name === 'router' && m.handle?.stack) {
      m.handle.stack.forEach((h) => {
        const p = h.route?.path;
        if (p) {
          const methods = Object.keys(h.route.methods).join(',').toUpperCase();
          routes.push(`${methods} ${p}`);
        }
      });
    }
  });
  ok(res, { routes });
});

app.get('/db-ping', async (_req, res) => {
  const t0 = Date.now();
  try {
    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      const [rows] = await conn.query('SELECT 1 AS ok');
      ok(res, { rows, ms: Date.now() - t0, target: { host: cfg.dbHost, port: cfg.dbPort, db: cfg.dbName } });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error('[DB-PING ERROR]', err?.code || err?.message || String(err));
    res.status(500).json({
      ok: false,
      code: err?.code || 'CONFIG/CONNECT_ERROR',
      message: String(err),
      ms: Date.now() - t0,
      target: { host: cfg.dbHost || '(empty)', port: cfg.dbPort || '(empty)', db: cfg.dbName || '(empty)' },
    });
  }
});

// -------------------- Auth --------------------
function authRequired(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return fail(res, 401, 'Unauthorized');
  try {
    const payload = jwt.verify(token, cfg.jwtSecret);
    req.user = payload;
    next();
  } catch {
    return fail(res, 401, 'Invalid token');
  }
}

function adminOrOwner(getOwnerId) {
  return async (req, res, next) => {
    if (!req.user) return fail(res, 401, 'Unauthorized');
    if (req.user.role === 'admin') return next();
    try {
      const ownerId = await getOwnerId(req, res);
      if (ownerId && Number(ownerId) === Number(req.user.id ?? req.user.uid)) return next();
      return fail(res, 403, 'Forbidden');
    } catch (e) {
      console.error('[ACL ERROR]', e);
      return fail(res, 500, 'Permission check failed');
    }
  };
}

const authLimiter = rateLimit({
  windowMs: 60_000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

// -------------------- Schema Init --------------------
async function initSchema() {
  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    await conn.query(
      `CREATE DATABASE IF NOT EXISTS \`${cfg.dbName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`
    );
    await conn.query(`USE \`${cfg.dbName}\``);

    await conn.query(
      `CREATE TABLE IF NOT EXISTS \`users\` (
        \`user_id\`       INT UNSIGNED NOT NULL AUTO_INCREMENT,
        \`user_name\`     VARCHAR(50)  NOT NULL,
        \`user_email\`    VARCHAR(120) NOT NULL,
        \`user_password\` VARCHAR(255) NOT NULL,
        \`user_role\`     ENUM('user','admin') NOT NULL DEFAULT 'user',
        \`created_at\`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (\`user_id\`),
        UNIQUE KEY \`uk_user_email\` (\`user_email\`)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
    );

    await conn.query(
      `CREATE TABLE IF NOT EXISTS \`categories\` (
        \`cat_id\`     INT UNSIGNED NOT NULL AUTO_INCREMENT,
        \`cat_name\`   VARCHAR(50) NOT NULL,
        \`created_at\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (\`cat_id\`),
        UNIQUE KEY \`uk_cat_name\` (\`cat_name\`)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
    );

    await conn.query(
      `CREATE TABLE IF NOT EXISTS \`posts\` (
        \`post_id\`       INT UNSIGNED NOT NULL AUTO_INCREMENT,
        \`post_user_id\`  INT UNSIGNED NULL,
        \`post_cat_id\`   INT UNSIGNED NULL,
        \`post_content\`  TEXT NOT NULL,
        \`post_priority\` INT NOT NULL DEFAULT 0,
        \`post_like\`     INT UNSIGNED NOT NULL DEFAULT 0,
        \`created_at\`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        \`updated_at\`    DATETIME NULL ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (\`post_id\`),
        KEY \`idx_posts_priority_created\` (\`post_priority\`, \`created_at\`),
        CONSTRAINT \`fk_posts_user\` FOREIGN KEY (\`post_user_id\`) REFERENCES \`users\`(\`user_id\`) ON DELETE SET NULL ON UPDATE CASCADE,
        CONSTRAINT \`fk_posts_cat\`  FOREIGN KEY (\`post_cat_id\`)  REFERENCES \`categories\`(\`cat_id\`) ON DELETE SET NULL ON UPDATE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
    );

    await conn.query(
      `CREATE TABLE IF NOT EXISTS \`post_images\` (
        \`img_id\`      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        \`img_post_id\` INT    UNSIGNED NOT NULL,
        \`img_mime\`    VARCHAR(80) NOT NULL,
        \`img_size\`    INT UNSIGNED NOT NULL,
        \`img_data\`    LONGBLOB NOT NULL,
        \`created_at\`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (\`img_id\`),
        KEY \`idx_post_images_post\` (\`img_post_id\`),
        CONSTRAINT \`fk_post_images_post\` FOREIGN KEY (\`img_post_id\`) REFERENCES \`posts\`(\`post_id\`) ON DELETE CASCADE ON UPDATE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
    );

    await conn.query(
      `CREATE TABLE IF NOT EXISTS \`comments\` (
        \`cmt_id\`                   INT UNSIGNED NOT NULL AUTO_INCREMENT,
        \`cmt_post_id\`              INT UNSIGNED NOT NULL,
        \`cmt_user_id\`              INT UNSIGNED NULL,
        \`cmt_parent_cmt_id\`        INT UNSIGNED NULL,
        \`cmt_thread_root_cmt_id\`   INT UNSIGNED NULL,
        \`cmt_depth\`                TINYINT UNSIGNED NOT NULL DEFAULT 0,
        \`cmt_content\`              TEXT NOT NULL,
        \`created_at\`               DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        \`updated_at\`               DATETIME NULL ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (\`cmt_id\`),
        KEY \`idx_comments_post\` (\`cmt_post_id\`),
        KEY \`idx_comments_thread\` (\`cmt_thread_root_cmt_id\`,\`cmt_depth\`,\`cmt_id\`),
        CONSTRAINT \`fk_comments_post\`   FOREIGN KEY (\`cmt_post_id\`)            REFERENCES \`posts\`(\`post_id\`) ON DELETE CASCADE ON UPDATE CASCADE,
        CONSTRAINT \`fk_comments_user\`   FOREIGN KEY (\`cmt_user_id\`)            REFERENCES \`users\`(\`user_id\`) ON DELETE SET NULL ON UPDATE CASCADE,
        CONSTRAINT \`fk_comments_parent\` FOREIGN KEY (\`cmt_parent_cmt_id\`)      REFERENCES \`comments\`(\`cmt_id\`) ON DELETE SET NULL ON UPDATE CASCADE,
        CONSTRAINT \`fk_comments_root\`   FOREIGN KEY (\`cmt_thread_root_cmt_id\`) REFERENCES \`comments\`(\`cmt_id\`) ON DELETE SET NULL ON UPDATE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
    );

    // User settings
    await conn.query(
      `CREATE TABLE IF NOT EXISTS \`user_settings\` (
        \`us_id\`          INT UNSIGNED NOT NULL AUTO_INCREMENT,
        \`us_user_id\`     INT UNSIGNED NOT NULL,
        \`us_nickname\`    VARCHAR(50) NULL,
        \`us_notify_email\` TINYINT(1) NOT NULL DEFAULT 0,
        \`us_notify_push\`  TINYINT(1) NOT NULL DEFAULT 0,
        \`created_at\`     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        \`updated_at\`     DATETIME NULL ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (\`us_id\`),
        UNIQUE KEY \`uk_user_settings_user\` (\`us_user_id\`),
        CONSTRAINT \`fk_user_settings_user\` FOREIGN KEY (\`us_user_id\`) REFERENCES \`users\`(\`user_id\`) ON DELETE CASCADE ON UPDATE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
    );

    // Per-user like table
    await conn.query(`CREATE TABLE IF NOT EXISTS post_likes (
      pl_post_id INT UNSIGNED NOT NULL,
      pl_user_id INT UNSIGNED NOT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (pl_post_id, pl_user_id),
      CONSTRAINT fk_pl_post FOREIGN KEY (pl_post_id) REFERENCES posts(post_id) ON DELETE CASCADE ON UPDATE CASCADE,
      CONSTRAINT fk_pl_user FOREIGN KEY (pl_user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

    // Avatar table
    await conn.query(`CREATE TABLE IF NOT EXISTS user_avatars (
      ua_user_id INT UNSIGNED NOT NULL PRIMARY KEY,
      ua_mime VARCHAR(80) NOT NULL,
      ua_size INT UNSIGNED NOT NULL,
      ua_data LONGBLOB NOT NULL,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_ua_user FOREIGN KEY (ua_user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

    // Push: device tokens + notifications log
    await conn.query(`CREATE TABLE IF NOT EXISTS device_tokens (
      dt_user_id INT UNSIGNED NOT NULL,
      dt_token VARCHAR(512) NOT NULL,
      dt_platform VARCHAR(20) NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (dt_user_id, dt_token),
      CONSTRAINT fk_dt_user FOREIGN KEY (dt_user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

    await conn.query(`CREATE TABLE IF NOT EXISTS notifications (
      noti_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      noti_user_id INT UNSIGNED NOT NULL,
      noti_type ENUM('comment','like') NOT NULL,
      noti_post_id INT UNSIGNED NOT NULL,
      noti_from_user_id INT UNSIGNED NULL,
      payload JSON NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (noti_id),
      KEY idx_noti_user (noti_user_id),
      CONSTRAINT fk_noti_user FOREIGN KEY (noti_user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  } finally {
    try { conn.release(); } catch {}
  }
}

app.post('/init', async (_req, res) => {
  try {
    await initSchema();
    res.json({ ok: true, message: 'Schema initialized' });
  } catch (e) {
    console.error('[INIT ERROR]', e?.code, e?.errno, e?.sqlMessage || String(e));
    res.status(500).json({ ok: false, code: e?.code, errno: e?.errno, message: e?.sqlMessage || String(e) });
  }
});

// -------------------- Auth: Signup / Login --------------------
app.post('/auth/signup', authLimiter, async (req, res) => {
  const { name, email, password, passwordConfirm } = req.body || {};
  if (!name || !email || !password || !passwordConfirm) return fail(res, 400, 'Missing fields');
  if (password !== passwordConfirm) return fail(res, 400, 'Password confirmation does not match');
  if (!/^[^@]+@[^@]+\.[^@]+$/.test(email)) return fail(res, 400, 'Invalid email');
  if (password.length < 8) return fail(res, 400, 'Password must be at least 8 chars');

  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const [dups] = await conn.execute('SELECT user_id FROM users WHERE user_email=?', [email]);
    if (dups.length) return fail(res, 409, 'Email already registered');

    const hash = await bcrypt.hash(password, cfg.bcryptRounds);
    const [r] = await conn.execute(
      'INSERT INTO users (user_name, user_email, user_password, user_role) VALUES (?, ?, ?, ?)',
      [name, email, hash, 'user']
    );
    ok(res, { user_id: r.insertId });
  } catch (e) {
    console.error('[SIGNUP]', e);
    fail(res, 500, 'Signup failed');
  } finally {
    conn.release();
  }
});

app.post('/auth/login', authLimiter, async (req, res) => {
  const t0 = Date.now();
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return fail(res, 400, 'email/password required');

    const p = ensurePool();
    const [rows] = await p.query(
      'SELECT user_id,user_name,user_email,user_password,user_role FROM users WHERE user_email=?',
      [email]
    );
    if (!rows || rows.length === 0) {
      console.warn('[LOGIN WARN] user not found', { email });
      return fail(res, 401, 'No such user');
    }

    const u = rows[0];
    const hash = String(u.user_password || '');
    if (!/^\$2[aby]\$/.test(hash) || hash.length < 55) {
      console.error('[LOGIN ERROR] invalid bcrypt hash format', { email, len: hash.length, preview: hash.slice(0, 12) });
      return fail(res, 422, 'Password hash invalid format');
    }

    const passOK = await bcrypt.compare(password, hash);
    if (!passOK) {
      console.warn('[LOGIN WARN] wrong password', { email });
      return fail(res, 401, 'Invalid password');
    }

    const token = jwt.sign({ id: u.user_id, role: u.user_role, name: u.user_name }, cfg.jwtSecret, { expiresIn: '7d' });
    console.log('[LOGIN OK]', email, `${Date.now() - t0}ms`);
    return ok(res, { token, user: { id: u.user_id, name: u.user_name, role: u.user_role } });
  } catch (e) {
    console.error('[LOGIN ERROR]', e?.code || e?.message || String(e));
    return res.status(500).json({ ok: false, error: 'LOGIN_INTERNAL' });
  }
});

// -------------------- Categories --------------------
app.post('/categories', authRequired, async (req, res) => {
  const { name } = req.body || {};
  if (!name) return fail(res, 400, 'cat name required');

  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const [r] = await conn.execute('INSERT INTO categories (cat_name) VALUES (?)', [name]);
    ok(res, { cat_id: r.insertId });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return fail(res, 409, 'duplicate category');
    console.error('[CAT CREATE]', e);
    fail(res, 500, 'failed');
  } finally {
    conn.release();
  }
});

app.get('/categories', async (_req, res) => {
  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const [rows] = await conn.query('SELECT cat_id, cat_name FROM categories ORDER BY cat_name ASC');
    ok(res, { rows });
  } finally {
    conn.release();
  }
});

// -------------------- Posts (+ images in DB) --------------------
app.post('/posts', authRequired, upload.array('images', cfg.maxImageFiles), async (req, res) => {
  const { cat_id, content, priority = 0 } = req.body || {};
  if (!content) return fail(res, 400, 'content required');

  const images = req.files || [];
  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    await conn.beginTransaction();
    const [r] = await conn.execute(
      'INSERT INTO posts (post_user_id, post_cat_id, post_content, post_priority) VALUES (?, ?, ?, ?)',
      [req.user.id ?? req.user.uid ?? null, cat_id ? Number(cat_id) : null, content, Number(priority) || 0]
    );
    const postId = r.insertId;

    if (images.length) {
      const q = 'INSERT INTO post_images (img_post_id, img_mime, img_size, img_data) VALUES (?, ?, ?, ?)';
      for (const f of images) {
        if (!f.mimetype?.startsWith('image/')) continue;
        const { buffer: optBuf, mimetype: newMime } = await optimizeToUnder1MB(f.buffer);
        const finalBuf = optBuf || f.buffer;
        const finalMime = newMime || f.mimetype;
        await conn.execute(q, [postId, finalMime, finalBuf.length, finalBuf]);
      }
    }
    await conn.commit();
    ok(res, { post_id: postId, images_uploaded: images.length });
  } catch (e) {
    await conn.rollback();
    console.error('[POST CREATE]', e);
    fail(res, 500, 'create failed');
  } finally {
    conn.release();
  }
});

// List posts (supports me=1 if authed)
app.get('/posts', async (req, res) => {
  const { cat_id, page = 1, size = 10, me } = req.query;
  const limit = Math.max(1, Math.min(Number(size) || 10, 50));
  const offset = (Math.max(1, Number(page) || 1) - 1) * limit;

  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  let authed = null;
  if (token) {
    try { authed = jwt.verify(token, cfg.jwtSecret); } catch {}
  }

  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const params = [];
    let where = ' WHERE 1=1 ';
    if (cat_id) { where += ' AND p.post_cat_id=? '; params.push(Number(cat_id)); }
    if (me && authed?.id) { where += ' AND p.post_user_id=? '; params.push(Number(authed.id)); }

    const sql = `
      SELECT p.post_id, p.post_content, p.post_priority, p.post_like, p.created_at, p.updated_at,
             u.user_id, u.user_name, c.cat_id, c.cat_name,
             IF(pl.pl_user_id IS NULL, 0, 1) AS liked
        FROM posts p
        LEFT JOIN users u ON u.user_id = p.post_user_id
        LEFT JOIN categories c ON c.cat_id = p.post_cat_id
        LEFT JOIN post_likes pl ON pl.pl_post_id=p.post_id AND pl.pl_user_id=${authed?.id ? Number(authed.id) : 0}
       ${where}
       ORDER BY p.post_priority DESC, p.created_at DESC
       LIMIT ? OFFSET ?`;
    params.push(limit, offset);
    const [rows] = await conn.execute(sql, params);
    ok(res, { rows, page: Number(page), size: limit });
  } catch (e) {
    console.error('[POST LIST]', e);
    fail(res, 500, 'list failed');
  } finally {
    conn.release();
  }
});

// Post detail (+ liked flag + images URLs)
app.get('/posts/:id', async (req, res) => {
  const id = Number(req.params.id);

  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  let authed = null;
  if (token) {
    try { authed = jwt.verify(token, cfg.jwtSecret); } catch {}
  }

  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const [[post]] = await conn.query(
      `SELECT p.*, u.user_name, c.cat_name,
              IF(pl.pl_user_id IS NULL, 0, 1) AS liked
         FROM posts p
         LEFT JOIN users u ON u.user_id=p.post_user_id
         LEFT JOIN categories c ON c.cat_id=p.post_cat_id
         LEFT JOIN post_likes pl ON pl.pl_post_id=p.post_id AND pl.pl_user_id=${authed?.id ? Number(authed.id) : 0}
        WHERE p.post_id=?`,
      [id]
    );
    if (!post) return fail(res, 404, 'not found');

    const [imgs] = await conn.query(
      'SELECT img_id, img_mime, img_size, created_at FROM post_images WHERE img_post_id=? ORDER BY img_id ASC',
      [id]
    );
    const base = `${req.protocol}://${req.get('host')}`;
    const images = imgs.map((i) => ({
      ...i,
      img_url: `${base}/posts/${id}/images/${i.img_id}`,
    }));
    ok(res, { post, images });
  } finally {
    conn.release();
  }
});

// --- Image streaming routes ---
app.get('/posts/:id/images/:imgId', async (req, res) => {
  const id = Number(req.params.id);
  const imgId = Number(req.params.imgId);
  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const [[img]] = await conn.query(
      'SELECT img_mime, img_size, img_data, created_at FROM post_images WHERE img_post_id=? AND img_id=?',
      [id, imgId]
    );
    if (!img) return fail(res, 404, 'image not found');

    const buf = img.img_data;
    const etag = createHash('sha1').update(buf).digest('hex');
    res.setHeader('Content-Type', img.img_mime);
    res.setHeader('Content-Length', String(img.img_size || buf.length));
    res.setHeader('Cache-Control', 'public, max-age=86400, immutable');
    res.setHeader('ETag', etag);
    res.setHeader('Last-Modified', new Date(img.created_at).toUTCString());
    if (req.headers['if-none-match'] === etag) return res.status(304).end();

    res.end(buf);
  } finally {
    conn.release();
  }
});

app.get('/images/:imgId', async (req, res) => {
  const imgId = Number(req.params.imgId);
  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const [[img]] = await conn.query(
      'SELECT img_mime, img_size, img_data, created_at FROM post_images WHERE img_id=?',
      [imgId]
    );
    if (!img) return fail(res, 404, 'image not found');

    const buf = img.img_data;
    const etag = createHash('sha1').update(buf).digest('hex');
    res.setHeader('Content-Type', img.img_mime);
    res.setHeader('Content-Length', String(img.img_size || buf.length));
    res.setHeader('Cache-Control', 'public, max-age=86400, immutable');
    res.setHeader('ETag', etag);
    res.setHeader('Last-Modified', new Date(img.created_at).toUTCString());
    if (req.headers['if-none-match'] === etag) return res.status(304).end();

    res.end(buf);
  } finally {
    conn.release();
  }
});

// ----- Post Update/Delete -----
app.put(
  '/posts/:id',
  authRequired,
  adminOrOwner(async (req) => {
    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      const [[row]] = await conn.query('SELECT post_user_id FROM posts WHERE post_id=?', [req.params.id]);
      return row?.post_user_id;
    } finally {
      conn.release();
    }
  }),
  async (req, res) => {
    const id = Number(req.params.id);
    const { cat_id, content, priority } = req.body || {};
    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      const [r] = await conn.execute(
        'UPDATE posts SET post_cat_id=?, post_content=?, post_priority=? WHERE post_id=?',
        [cat_id ?? null, content ?? null, (priority ?? 0), id]
      );
      ok(res, { affected: r.affectedRows });
    } catch (e) {
      console.error('[POST UPDATE]', e);
      fail(res, 500, 'update failed');
    } finally {
      conn.release();
    }
  }
);

// Method override by body: POST + _method=PUT
app.post('/posts/:id', authRequired, async (req, res, next) => {
  if ((req.body?._method || '').toString().toUpperCase() === 'PUT') return app._router.handle({ ...req, method: 'PUT' }, res, next);
  return fail(res, 400, 'Unsupported method');
});

app.delete(
  '/posts/:id',
  authRequired,
  adminOrOwner(async (req) => {
    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      const [[row]] = await conn.query('SELECT post_user_id FROM posts WHERE post_id=?', [req.params.id]);
      return row?.post_user_id;
    } finally {
      conn.release();
    }
  }),
  async (req, res) => {
    const id = Number(req.params.id);
    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      const [r] = await conn.execute('DELETE FROM posts WHERE post_id=?', [id]);
      ok(res, { deleted: r.affectedRows });
    } catch (e) {
      console.error('[POST DELETE]', e);
      fail(res, 500, 'delete failed');
    } finally {
      conn.release();
    }
  }
);

// Method override for delete: POST + _method=DELETE
app.post('/posts/:id/delete', authRequired, async (req, res, next) => {
  req.body = req.body || {};
  req.body._method = 'DELETE';
  return app._router.handle({ ...req, method: 'DELETE' }, res, next);
});

// -------------------- Comments --------------------
// List comments for a post
app.get('/posts/:id/comments', async (req, res) => {
  const postId = Number(req.params.id);
  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const [rows] = await conn.query(
      `SELECT c.cmt_id, c.cmt_post_id, c.cmt_user_id, c.cmt_parent_cmt_id,
              c.cmt_thread_root_cmt_id, c.cmt_depth, c.cmt_content, c.created_at, c.updated_at,
              u.user_name
         FROM comments c
    LEFT JOIN users u ON u.user_id=c.cmt_user_id
        WHERE c.cmt_post_id=?
        ORDER BY c.created_at ASC`,
      [postId]
    );
    ok(res, { rows });
  } catch (e) {
    console.error('[COMMENTS LIST]', e);
    fail(res, 500, 'List comments failed');
  } finally { conn.release(); }
});

// Create comment (root or reply) + create notifications
app.post('/posts/:id/comments', authRequired, async (req, res) => {
  const postId = Number(req.params.id);
  const userId = Number(req.user.id ?? req.user.uid);
  const content = (req.body?.content || '').toString().trim();
  const parentId = req.body?.parent_id ? Number(req.body.parent_id) : null;

  if (!postId || !Number.isFinite(postId)) {
    return fail(res, 400, 'invalid post id');
  }
  if (!userId || !Number.isFinite(userId)) {
    return fail(res, 401, 'invalid user');
  }
  if (!content) {
    return fail(res, 400, 'content required');
  }

  const p = ensurePool();
  const conn = await p.getConnection();

  try {
    await conn.beginTransaction();

    let depth = 0;
    let rootId = null;

    // 대댓글인 경우 부모 코멘트 정보 조회
    if (parentId) {
      const [[parent]] = await conn.query(
        'SELECT cmt_id, cmt_depth, cmt_thread_root_cmt_id FROM comments WHERE cmt_id=?',
        [parentId]
      );
      if (!parent) {
        await conn.rollback();
        return fail(res, 404, 'parent not found');
      }

      depth = Math.min(4, Number(parent.cmt_depth || 0) + 1);
      rootId = parent.cmt_thread_root_cmt_id ?? parent.cmt_id;
    }

    // 코멘트 저장
    const [r] = await conn.execute(
      `INSERT INTO comments (
          cmt_post_id,
          cmt_user_id,
          cmt_parent_cmt_id,
          cmt_thread_root_cmt_id,
          cmt_depth,
          cmt_content
        )
        VALUES (?, ?, ?, ?, ?, ?)`,
      [postId, userId, parentId ?? null, rootId, depth, content]
    );

    // 알림용: 게시글 작성자 조회
    const [[post]] = await conn.query(
      'SELECT post_user_id FROM posts WHERE post_id=?',
      [postId]
    );

    if (post && post.post_user_id && Number(post.post_user_id) !== userId) {
      const targetUser = Number(post.post_user_id);

      await conn.execute(
        `INSERT INTO notifications (
           noti_user_id,
           noti_type,
           noti_post_id,
           noti_from_user_id,
           payload
         )
         VALUES (?, 'comment', ?, ?, JSON_OBJECT('comment_id', ?, 'content', ?))`,
        [targetUser, postId, userId, r.insertId, content]
      );

      // (선택) 푸시 웹훅
      if (cfg.pushWebhook) {
        try {
          const resp = await fetch(cfg.pushWebhook, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              type: 'comment',
              post_id: postId,
              to_user_id: targetUser,
              from_user_id: userId,
              comment_id: r.insertId,
              content,
            }),
          });
          console.log('[PUSH WEBHOOK comment]', resp.status);
        } catch (e) {
          console.warn('[PUSH WEBHOOK FAIL]', e.message);
        }
      }
    }

    await conn.commit();
    return ok(res, { comment_id: r.insertId });
  } catch (e) {
    try { await conn.rollback(); } catch {}
    console.error('[COMMENT CREATE]', e);
    return fail(res, 500, 'create failed');
  } finally {
    conn.release();
  }
});


// Update comment
app.put('/comments/:id', authRequired, adminOrOwner(async (req) => {
  const p = ensurePool(); const conn = await p.getConnection();
  try {
    const [[row]] = await conn.query('SELECT cmt_user_id FROM comments WHERE cmt_id=?', [req.params.id]);
    return row?.cmt_user_id;
  } finally { conn.release(); }
}), async (req, res) => {
  const id = Number(req.params.id);
  const content = (req.body?.content || '').toString().trim();
  if (!content) return fail(res, 400, 'content required');
  const p = ensurePool(); const conn = await p.getConnection();
  try {
    const [r] = await conn.execute('UPDATE comments SET cmt_content=? WHERE cmt_id=?', [content, id]);
    ok(res, { affected: r.affectedRows });
  } catch (e) {
    console.error('[COMMENT UPDATE]', e);
    fail(res, 500, 'update failed');
  } finally { conn.release(); }
});

// Override: POST + _method=PUT
app.post('/comments/:id', authRequired, async (req, res, next) => {
  if ((req.body?._method || '').toString().toUpperCase() === 'PUT') return app._router.handle({ ...req, method: 'PUT' }, res, next);
  return fail(res, 400, 'Unsupported method');
});

// Delete comment
app.delete('/comments/:id', authRequired, adminOrOwner(async (req) => {
  const p = ensurePool(); const conn = await p.getConnection();
  try {
    const [[row]] = await conn.query('SELECT cmt_user_id FROM comments WHERE cmt_id=?', [req.params.id]);
    return row?.cmt_user_id;
  } finally { conn.release(); }
}), async (req, res) => {
  const id = Number(req.params.id);
  const p = ensurePool(); const conn = await p.getConnection();
  try {
    const [r] = await conn.execute('DELETE FROM comments WHERE cmt_id=?', [id]);
    ok(res, { deleted: r.affectedRows });
  } catch (e) {
    console.error('[COMMENT DELETE]', e);
    fail(res, 500, 'delete failed');
  } finally { conn.release(); }
});

// Override delete: POST + _method=DELETE
app.post('/comments/:id/delete', authRequired, async (req, res, next) => {
  req.body = req.body || {};
  req.body._method = 'DELETE';
  return app._router.handle({ ...req, method: 'DELETE' }, res, next);
});

// --- Like toggle per user + like notifications ---
app.post('/posts/:id/like', authRequired, async (req, res) => {
  const postId = Number(req.params.id);
  const userId = Number(req.user.id ?? req.user.uid);
  const p = ensurePool(); const conn = await p.getConnection();
  try {
    await conn.beginTransaction();
    const [[existing]] = await conn.query('SELECT 1 FROM post_likes WHERE pl_post_id=? AND pl_user_id=?', [postId, userId]);
    let liked;
    if (existing) {
      await conn.execute('DELETE FROM post_likes WHERE pl_post_id=? AND pl_user_id=?', [postId, userId]);
      await conn.execute('UPDATE posts SET post_like = GREATEST(0, post_like - 1) WHERE post_id=?', [postId]);
      liked = false;
    } else {
      await conn.execute('INSERT INTO post_likes (pl_post_id, pl_user_id) VALUES (?, ?)', [postId, userId]);
      await conn.execute('UPDATE posts SET post_like = post_like + 1 WHERE post_id=?', [postId]);
      liked = true;

      // Notify post author on new like
      const [[post]] = await conn.query('SELECT post_user_id FROM posts WHERE post_id=?', [postId]);
      const targetUser = post?.post_user_id;
      if (targetUser && Number(targetUser) !== userId) {
        await conn.execute(
          `INSERT INTO notifications (noti_user_id, noti_type, noti_post_id, noti_from_user_id, payload)
           VALUES (?, 'like', ?, ?, NULL)`,
          [targetUser, postId, userId]
        );
      }
    }
    const [[row]] = await conn.query('SELECT post_like FROM posts WHERE post_id=?', [postId]);
    await conn.commit();

    // Webhook (only when new like)
    if (cfg.pushWebhook && liked) {
      try {
        const resp = await fetch(cfg.pushWebhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ type: 'like', post_id: postId, from_user_id: userId }),
        });
        console.log('[PUSH WEBHOOK like]', resp.status);
      } catch(e) { console.warn('[PUSH WEBHOOK FAIL]', e.message); }
    }

    ok(res, { post_id: postId, liked, like: row.post_like });
  } catch (e) {
    try { await conn.rollback(); } catch {}
    console.error('[LIKE TOGGLE]', e);
    fail(res, 500, 'toggle failed');
  } finally { conn.release(); }
});

// -------------------- Avatar (Profile image) --------------------
// Upload or update my avatar
app.post('/me/avatar', authRequired, upload.single('file'), async (req, res) => {
  const f = req.file;
  if (!f) return fail(res, 400, 'file required');
  if (!f.mimetype?.startsWith('image/')) return fail(res, 400, 'image only');
  const uid = Number(req.user.id ?? req.user.uid);

  const p = ensurePool(); const conn = await p.getConnection();
  try {
    await conn.execute(
      `INSERT INTO user_avatars (ua_user_id, ua_mime, ua_size, ua_data)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE ua_mime=VALUES(ua_mime), ua_size=VALUES(ua_size), ua_data=VALUES(ua_data)`,
      [uid, (await (async()=>{const o=await optimizeToUnder1MB(f.buffer); f._optimized=o; return o.mimetype||f.mimetype;})()), (f._optimized?.buffer||f.buffer).length, (f._optimized?.buffer||f.buffer)]
    );
    ok(res, { updated: true });
  } catch (e) {
    console.error('[AVATAR UPSERT]', e);
    fail(res, 500, 'avatar failed');
  } finally { conn.release(); }
});

// Stream avatar
app.get('/users/:id/avatar', async (req, res) => {
  const uid = Number(req.params.id);
  const p = ensurePool(); const conn = await p.getConnection();
  try {
    const [[row]] = await conn.query('SELECT ua_mime, ua_size, ua_data, updated_at FROM user_avatars WHERE ua_user_id=?', [uid]);
    if (!row) return fail(res, 404, 'avatar not found');
    const buf = row.ua_data;
    const etag = createHash('sha1').update(buf).digest('hex');
    res.setHeader('Content-Type', row.ua_mime);
    res.setHeader('Content-Length', String(row.ua_size || buf.length));
    res.setHeader('Cache-Control', 'public, max-age=86400, immutable');
    res.setHeader('ETag', etag);
    res.setHeader('Last-Modified', new Date(row.updated_at).toUTCString());
    if (req.headers['if-none-match'] === etag) return res.status(304).end();
    res.end(buf);
  } finally { conn.release(); }
});

// -------------------- Push registration & fetch --------------------
app.post('/push/register', authRequired, async (req, res) => {
  const { token, platform } = req.body || {};
  if (!token) return fail(res, 400, 'token required');
  const uid = Number(req.user.id ?? req.user.uid);
  const p = ensurePool(); const conn = await p.getConnection();
  try {
    await conn.execute(
      `INSERT INTO device_tokens (dt_user_id, dt_token, dt_platform) VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE dt_platform=VALUES(dt_platform)`,
      [uid, token, platform || null]
    );
    ok(res, { registered: true });
  } catch (e) {
    console.error('[PUSH REGISTER]', e);
    fail(res, 500, 'register failed');
  } finally { conn.release(); }
});

app.get('/notifications', authRequired, async (req, res) => {
  const uid = Number(req.user.id ?? req.user.uid);
  const p = ensurePool(); const conn = await p.getConnection();
  try {
    const [rows] = await conn.query(
      `SELECT noti_id, noti_type, noti_post_id, noti_from_user_id, payload, created_at
         FROM notifications
        WHERE noti_user_id=?
        ORDER BY noti_id DESC
        LIMIT 100`,
      [uid]
    );
    ok(res, { rows });
  } catch (e) {
    console.error('[NOTI LIST]', e);
    fail(res, 500, 'failed');
  } finally { conn.release(); }
});

// -------------------- User Settings --------------------
app.get('/users/me/settings', authRequired, async (req, res) => {
  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const uid = req.user.id ?? req.user.uid;
    const [[s]] = await conn.query('SELECT us_nickname, us_notify_email, us_notify_push FROM user_settings WHERE us_user_id=?', [uid]);
    ok(res, { settings: s || null });
  } finally {
    conn.release();
  }
});

app.put('/users/me/settings', authRequired, async (req, res) => {
  const { nickname, notify_email, notify_push } = req.body || {};
  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const uid = req.user.id ?? req.user.uid;
    await conn.execute(
      `INSERT INTO user_settings (us_user_id, us_nickname, us_notify_email, us_notify_push)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE us_nickname=VALUES(us_nickname), us_notify_email=VALUES(us_notify_email), us_notify_push=VALUES(us_notify_push)`,
      [uid, nickname ?? null, notify_email ? 1 : 0, notify_push ? 1 : 0]
    );
    ok(res, { updated: true });
  } catch (e) {
    console.error('[USER SETTINGS]', e);
    fail(res, 500, 'failed');
  } finally {
    conn.release();
  }
});

// -------------------- 404 & Error Handlers --------------------
app.use((req, res, _next) => {
  console.warn('[404]', req.method, req.url);
  res.status(404).json({ ok: false, error: 'Not Found', path: req.url });
});

app.use((err, req, res, _next) => {
  console.error('[UNHANDLED ERROR]', req.rid, err);
  res.status(500).json({ ok: false, error: 'Internal Server Error' });
});

// -------------------- Start --------------------
app.listen(cfg.httpPort, () => {
  console.log(`[BOOT] listening on :${cfg.httpPort}`);
  console.log(`[READY] APIs: /health /env-check /__routes /db-ping /init /auth/* /categories /posts /comments /images /likes /users/me/settings /me/avatar /users/:id/avatar /push/* /notifications`);
});

process.on('unhandledRejection', (reason) => {
  console.error('[UNHANDLED REJECTION]', reason);
});
process.on('uncaughtException', (err) => {
  console.error('[UNCAUGHT EXCEPTION]', err);
});
