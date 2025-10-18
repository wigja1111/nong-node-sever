// server.js
// Node 24 (ESM) — 보안/디버깅 유틸 포함 전체본

import 'dotenv/config';
import express from 'express';
import mysql from 'mysql2/promise';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';           // ✅ 네이티브 bcrypt 대신 bcryptjs
import jwt from 'jsonwebtoken';
import multer from 'multer';
import { randomUUID } from 'crypto';

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
  jwtSecret: process.env.JWT_SECRET || 'dev-secret-change-it', // ✅ 추가/통일
};

// 민감정보 제외 설정 로그
console.log('[BOOT CONFIG]', {
  DB_HOST: cfg.dbHost,
  DB_PORT: cfg.dbPort,
  DB_USER: cfg.dbUser,
  DB_NAME: cfg.dbName,
  PORT: cfg.httpPort,
  CORS_ORIGIN: cfg.corsOrigin,
  JWT_SECRET_SET: cfg.jwtSecret !== 'dev-secret-change-it',
});

// -------------------- App --------------------
const app = express();
app.set('trust proxy', true);

// 보안/기본 미들웨어
app.use(helmet());
app.use(cors({ origin: cfg.corsOrigin, credentials: false }));
app.use(express.json({ limit: '1mb' }));

// 요청 ID + 간단 로깅
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

// 업로드(메모리) — 파일시스템 저장 없이 DB(LONGBLOB)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: cfg.maxImageSizeMB * 1024 * 1024, files: cfg.maxImageFiles },
});

// 응답 헬퍼
const ok = (res, data = {}) => res.json({ ok: true, ...data });
const fail = (res, code = 400, message = 'Bad Request') => res.status(code).json({ ok: false, error: message });

// -------------------- DB Pool (lazy) --------------------
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
    charset: 'utf8mb4', // ✅ 한국어/이모지 안전
    // ssl: { rejectUnauthorized: false }, // (필요 시)
  });
  return pool;
}

// -------------------- Diagnostics / Health --------------------
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

// -------------------- Auth Utils --------------------
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

// -------------------- Schema Init (on-demand) --------------------
async function initSchema() {
  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    // DB/테이블 생성 (권한 없으면 실패할 수 있음)
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
  } finally {
    conn.release();
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

    const p = ensurePool(); // ✅ 풀 보장
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
        await conn.execute(q, [postId, f.mimetype, f.size, f.buffer]);
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

app.get('/posts', async (req, res) => {
  const { cat_id, page = 1, size = 10 } = req.query;
  const limit = Math.max(1, Math.min(Number(size) || 10, 50));
  const offset = (Math.max(1, Number(page) || 1) - 1) * limit;

  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const params = [];
    let where = ' WHERE 1=1 ';
    if (cat_id) { where += ' AND post_cat_id=? '; params.push(Number(cat_id)); }
    const sql = `
      SELECT p.post_id, p.post_content, p.post_priority, p.created_at, p.updated_at,
             u.user_id, u.user_name, c.cat_id, c.cat_name
        FROM posts p
        LEFT JOIN users u ON u.user_id = p.post_user_id
        LEFT JOIN categories c ON c.cat_id = p.post_cat_id
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

app.get('/posts/:id', async (req, res) => {
  const id = Number(req.params.id);
  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const [[post]] = await conn.query(
      `SELECT p.*, u.user_name, c.cat_name
         FROM posts p
         LEFT JOIN users u ON u.user_id=p.post_user_id
         LEFT JOIN categories c ON c.cat_id=p.post_cat_id
        WHERE p.post_id=?`,
      [id]
    );
    if (!post) return fail(res, 404, 'not found');

    const [imgs] = await conn.query(
      'SELECT img_id, img_mime, img_size, created_at FROM post_images WHERE img_post_id=? ORDER BY img_id ASC',
      [id]
    );
    ok(res, { post, images: imgs });
  } finally {
    conn.release();
  }
});

app.get('/posts/:id/images/:imgId', async (req, res) => {
  const id = Number(req.params.id);
  const imgId = Number(req.params.imgId);
  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const [[img]] = await conn.query(
      'SELECT img_mime, img_data FROM post_images WHERE img_post_id=? AND img_id=?',
      [id, imgId]
    );
    if (!img) return fail(res, 404, 'image not found');
    res.setHeader('Content-Type', img.img_mime);
    res.setHeader('Cache-Control', 'public, max-age=86400');
    res.send(img.img_data);
  } finally {
    conn.release();
  }
});

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

// -------------------- Comments --------------------
app.post('/posts/:id/comments', authRequired, async (req, res) => {
  const postId = Number(req.params.id);
  const { content, parent_cmt_id } = req.body || {};
  if (!content) return fail(res, 400, 'content required');

  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    let depth = 0, rootId = null;
    if (parent_cmt_id) {
      const [[parent]] = await conn.query(
        'SELECT cmt_id, cmt_thread_root_cmt_id, cmt_depth FROM comments WHERE cmt_id=? AND cmt_post_id=?',
        [parent_cmt_id, postId]
      );
      if (!parent) return fail(res, 400, 'invalid parent');
      depth = (parent.cmt_depth || 0) + 1;
      rootId = parent.cmt_thread_root_cmt_id || parent.cmt_id;
      if (depth > 5) return fail(res, 400, 'max depth reached');
    }
    const [r] = await conn.execute(
      `INSERT INTO comments (cmt_post_id, cmt_user_id, cmt_parent_cmt_id, cmt_thread_root_cmt_id, cmt_depth, cmt_content)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [postId, req.user.id ?? req.user.uid ?? null, parent_cmt_id ?? null, rootId, depth, content]
    );
    ok(res, { cmt_id: r.insertId });
  } catch (e) {
    console.error('[COMMENT CREATE]', e);
    fail(res, 500, 'failed');
  } finally {
    conn.release();
  }
});

app.get('/posts/:id/comments', async (req, res) => {
  const postId = Number(req.params.id);
  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const [rows] = await conn.query(
      `SELECT c.cmt_id, c.cmt_parent_cmt_id, c.cmt_thread_root_cmt_id, c.cmt_depth,
              c.cmt_content, c.created_at, c.updated_at,
              u.user_id, u.user_name
         FROM comments c
         LEFT JOIN users u ON u.user_id=c.cmt_user_id
        WHERE c.cmt_post_id=?
        ORDER BY IFNULL(c.cmt_thread_root_cmt_id, c.cmt_id), c.cmt_depth, c.cmt_id`,
      [postId]
    );
    ok(res, { rows });
  } finally {
    conn.release();
  }
});

app.put(
  '/comments/:cmt_id',
  authRequired,
  adminOrOwner(async (req) => {
    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      const [[row]] = await conn.query('SELECT cmt_user_id FROM comments WHERE cmt_id=?', [req.params.cmt_id]);
      return row?.cmt_user_id;
    } finally {
      conn.release();
    }
  }),
  async (req, res) => {
    const id = Number(req.params.cmt_id);
    const { content } = req.body || {};
    if (!content) return fail(res, 400, 'content required');
    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      const [r] = await conn.execute('UPDATE comments SET cmt_content=? WHERE cmt_id=?', [content, id]);
      ok(res, { affected: r.affectedRows });
    } catch (e) {
      console.error('[COMMENT UPDATE]', e);
      fail(res, 500, 'failed');
    } finally {
      conn.release();
    }
  }
);

app.delete(
  '/comments/:cmt_id',
  authRequired,
  adminOrOwner(async (req) => {
    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      const [[row]] = await conn.query('SELECT cmt_user_id FROM comments WHERE cmt_id=?', [req.params.cmt_id]);
      return row?.cmt_user_id;
    } finally {
      conn.release();
    }
  }),
  async (req, res) => {
    const id = Number(req.params.cmt_id);
    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      const [r] = await conn.execute('DELETE FROM comments WHERE cmt_id=?', [id]);
      ok(res, { deleted: r.affectedRows });
    } catch (e) {
      console.error('[COMMENT DELETE]', e);
      fail(res, 500, 'failed');
    } finally {
      conn.release();
    }
  }
);

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
  console.log(`[READY] APIs: /health /env-check /__routes /db-ping /init /auth/* /categories /posts /comments`);
});

// -------------------- Process-level guards --------------------
process.on('unhandledRejection', (reason) => {
  console.error('[UNHANDLED REJECTION]', reason);
});
process.on('uncaughtException', (err) => {
  console.error('[UNCAUGHT EXCEPTION]', err);
});
