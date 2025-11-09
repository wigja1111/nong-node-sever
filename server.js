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
import { randomUUID, createHash } from 'crypto';

// -------------------- Config --------------------
const cfg = {
  httpPort: Number(process.env.PORT) || 3000,
  dbHost: process.env.DB_HOST || '',
  dbPort: Number(process.env.DB_PORT) || 0,
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
    console.log(
      `[RES] ${rid} ${req.method} ${req.url} status=${res.statusCode} ms=${Date.now() - t0}`
    );
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

// Helpers
const ok = (res, data = {}) => res.json({ ok: true, ...data });
const fail = (res, code = 400, message = 'Bad Request') =>
  res.status(code).json({ ok: false, error: String(message) });

// -------------------- DB Pool --------------------
let pool = null;
function ensurePool() {
  if (pool) return pool;
  if (!cfg.dbHost || !cfg.dbPort || !cfg.dbUser || !cfg.dbName) {
    throw new Error(
      'DB env is missing: set DB_HOST/DB_PORT/DB_USER/DB_NAME (and DB_PASSWORD if needed)'
    );
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
      ok(res, {
        rows,
        ms: Date.now() - t0,
        target: { host: cfg.dbHost, port: cfg.dbPort, db: cfg.dbName },
      });
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
      target: {
        host: cfg.dbHost || '(empty)',
        port: cfg.dbPort || '(empty)',
        db: cfg.dbName || '(empty)',
      },
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
      if (ownerId && Number(ownerId) === Number(req.user.id ?? req.user.uid)) {
        return next();
      }
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
        CONSTRAINT \`fk_posts_user\`
          FOREIGN KEY (\`post_user_id\`) REFERENCES \`users\`(\`user_id\`)
          ON DELETE SET NULL ON UPDATE CASCADE,
        CONSTRAINT \`fk_posts_cat\`
          FOREIGN KEY (\`post_cat_id\`) REFERENCES \`categories\`(\`cat_id\`)
          ON DELETE SET NULL ON UPDATE CASCADE
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
        CONSTRAINT \`fk_post_images_post\`
          FOREIGN KEY (\`img_post_id\`) REFERENCES \`posts\`(\`post_id\`)
          ON DELETE CASCADE ON UPDATE CASCADE
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
        KEY \`idx_comments_thread\`
          (\`cmt_thread_root_cmt_id\`,\`cmt_depth\`,\`cmt_id\`),
        CONSTRAINT \`fk_comments_post\`
          FOREIGN KEY (\`cmt_post_id\`) REFERENCES \`posts\`(\`post_id\`)
          ON DELETE CASCADE ON UPDATE CASCADE,
        CONSTRAINT \`fk_comments_user\`
          FOREIGN KEY (\`cmt_user_id\`) REFERENCES \`users\`(\`user_id\`)
          ON DELETE SET NULL ON UPDATE CASCADE,
        CONSTRAINT \`fk_comments_parent\`
          FOREIGN KEY (\`cmt_parent_cmt_id\`) REFERENCES \`comments\`(\`cmt_id\`)
          ON DELETE SET NULL ON UPDATE CASCADE,
        CONSTRAINT \`fk_comments_root\`
          FOREIGN KEY (\`cmt_thread_root_cmt_id\`) REFERENCES \`comments\`(\`cmt_id\`)
          ON DELETE SET NULL ON UPDATE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
    );

    await conn.query(
      `CREATE TABLE IF NOT EXISTS \`user_settings\` (
        \`us_id\`           INT UNSIGNED NOT NULL AUTO_INCREMENT,
        \`us_user_id\`      INT UNSIGNED NOT NULL,
        \`us_nickname\`     VARCHAR(50) NULL,
        \`us_notify_email\` TINYINT(1) NOT NULL DEFAULT 0,
        \`us_notify_push\`  TINYINT(1) NOT NULL DEFAULT 0,
        \`created_at\`      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        \`updated_at\`      DATETIME NULL ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (\`us_id\`),
        UNIQUE KEY \`uk_user_settings_user\` (\`us_user_id\`),
        CONSTRAINT \`fk_user_settings_user\`
          FOREIGN KEY (\`us_user_id\`) REFERENCES \`users\`(\`user_id\`)
          ON DELETE CASCADE ON UPDATE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
    );

    await conn.query(
      `CREATE TABLE IF NOT EXISTS post_likes (
        pl_post_id INT UNSIGNED NOT NULL,
        pl_user_id INT UNSIGNED NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (pl_post_id, pl_user_id),
        CONSTRAINT fk_pl_post FOREIGN KEY (pl_post_id)
          REFERENCES posts(post_id)
          ON DELETE CASCADE ON UPDATE CASCADE,
        CONSTRAINT fk_pl_user FOREIGN KEY (pl_user_id)
          REFERENCES users(user_id)
          ON DELETE CASCADE ON UPDATE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
    );

    await conn.query(
      `CREATE TABLE IF NOT EXISTS user_avatars (
        ua_user_id INT UNSIGNED NOT NULL PRIMARY KEY,
        ua_mime    VARCHAR(80) NOT NULL,
        ua_size    INT UNSIGNED NOT NULL,
        ua_data    LONGBLOB NOT NULL,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                     ON UPDATE CURRENT_TIMESTAMP,
        CONSTRAINT fk_ua_user FOREIGN KEY (ua_user_id)
          REFERENCES users(user_id)
          ON DELETE CASCADE ON UPDATE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
    );

    await conn.query(
      `CREATE TABLE IF NOT EXISTS device_tokens (
        dt_user_id  INT UNSIGNED NOT NULL,
        dt_token    VARCHAR(512) NOT NULL,
        dt_platform VARCHAR(20) NULL,
        created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (dt_user_id, dt_token),
        CONSTRAINT fk_dt_user FOREIGN KEY (dt_user_id)
          REFERENCES users(user_id)
          ON DELETE CASCADE ON UPDATE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
    );

    await conn.query(
      `CREATE TABLE IF NOT EXISTS notifications (
        noti_id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        noti_user_id     INT UNSIGNED NOT NULL,
        noti_type        ENUM('comment','like') NOT NULL,
        noti_post_id     INT UNSIGNED NOT NULL,
        noti_from_user_id INT UNSIGNED NULL,
        payload          JSON NULL,
        created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (noti_id),
        KEY idx_noti_user (noti_user_id),
        CONSTRAINT fk_noti_user FOREIGN KEY (noti_user_id)
          REFERENCES users(user_id)
          ON DELETE CASCADE ON UPDATE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
    );
  } finally {
    try {
      conn.release();
    } catch {}
  }
}

app.post('/init', async (_req, res) => {
  try {
    await initSchema();
    res.json({ ok: true, message: 'Schema initialized' });
  } catch (e) {
    console.error('[INIT ERROR]', e?.code, e?.errno, e?.sqlMessage || String(e));
    res.status(500).json({
      ok: false,
      code: e?.code,
      errno: e?.errno,
      message: e?.sqlMessage || String(e),
    });
  }
});

// -------------------- Auth: Signup / Login (existing 로직 유지) --------------------
app.post('/auth/signup', authLimiter, async (req, res) => {
  const { name, email, password, passwordConfirm } = req.body || {};
  if (!name || !email || !password || !passwordConfirm)
    return fail(res, 400, 'Missing fields');
  if (password !== passwordConfirm)
    return fail(res, 400, 'Password confirmation does not match');
  if (!/^[^@]+@[^@]+\.[^@]+$/.test(email))
    return fail(res, 400, 'Invalid email');
  if (password.length < 8)
    return fail(res, 400, 'Password must be at least 8 chars');

  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const [dups] = await conn.execute(
      'SELECT user_id FROM users WHERE user_email=?',
      [email]
    );
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
      console.error('[LOGIN ERROR] invalid bcrypt hash format', {
        email,
        len: hash.length,
        preview: hash.slice(0, 12),
      });
      return fail(res, 422, 'Password hash invalid format');
    }

    const passOK = await bcrypt.compare(password, hash);
    if (!passOK) {
      console.warn('[LOGIN WARN] wrong password', { email });
      return fail(res, 401, 'Invalid password');
    }

    const token = jwt.sign(
      { id: u.user_id, role: u.user_role, name: u.user_name },
      cfg.jwtSecret,
      { expiresIn: '7d' }
    );
    console.log('[LOGIN OK]', email, `${Date.now() - t0}ms`);
    return ok(res, {
      token,
      user: { id: u.user_id, name: u.user_name, role: u.user_role },
    });
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
    const [r] = await conn.execute(
      'INSERT INTO categories (cat_name) VALUES (?)',
      [name]
    );
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
    const [rows] = await conn.query(
      'SELECT cat_id, cat_name FROM categories ORDER BY cat_name ASC'
    );
    ok(res, { rows });
  } finally {
    conn.release();
  }
});

// -------------------- Posts (이미지 포함) --------------------
app.post(
  '/posts',
  authRequired,
  upload.array('images', cfg.maxImageFiles),
  async (req, res) => {
    const { cat_id, content, priority = 0 } = req.body || {};
    if (!content) return fail(res, 400, 'content required');

    const images = req.files || [];
    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      await conn.beginTransaction();
      const [r] = await conn.execute(
        'INSERT INTO posts (post_user_id, post_cat_id, post_content, post_priority) VALUES (?, ?, ?, ?)',
        [
          req.user.id ?? req.user.uid ?? null,
          cat_id ? Number(cat_id) : null,
          content,
          Number(priority) || 0,
        ]
      );
      const postId = r.insertId;

      if (images.length) {
        const q =
          'INSERT INTO post_images (img_post_id, img_mime, img_size, img_data) VALUES (?, ?, ?, ?)';
        for (const f of images) {
          if (!f.mimetype?.startsWith('image/')) continue;
          await conn.execute(q, [postId, f.mimetype, f.size, f.buffer]);
        }
      }
      await conn.commit();
      ok(res, { post_id: postId, images_uploaded: images.length });
    } catch (e) {
      try {
        await conn.rollback();
      } catch {}
      console.error('[POST CREATE]', e);
      fail(res, 500, 'create failed');
    } finally {
      conn.release();
    }
  }
);

// Post 리스트 (me 필터 포함)
// Post 리스트 (me 필터 + 이미지 URL 포함)
app.get('/posts', async (req, res) => {
  const { cat_id, page = 1, size = 10, me } = req.query;
  const limit = Math.max(1, Math.min(Number(size) || 10, 50));
  const offset = (Math.max(1, Number(page) || 1) - 1) * limit;

  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : null;

  let authed = null;
  if (token) {
    try {
      authed = jwt.verify(token, cfg.jwtSecret);
    } catch {
      // 토큰 에러는 무시하고 비로그인 상태로 취급
    }
  }

  const p = ensurePool();
  const conn = await p.getConnection();

  try {
    const params = [];
    let where = ' WHERE 1=1 ';

    if (cat_id) {
      where += ' AND p.post_cat_id=? ';
      params.push(Number(cat_id));
    }

    if (me && authed?.id) {
      where += ' AND p.post_user_id=? ';
      params.push(Number(authed.id));
    }

    const likeUserId = authed?.id ? Number(authed.id) : 0;

    const sql = `
      SELECT
        p.post_id,
        p.post_content,
        p.post_priority,
        p.post_like,
        p.created_at,
        p.updated_at,
        u.user_id,
        u.user_name,
        c.cat_id,
        c.cat_name,
        IF(pl.pl_user_id IS NULL, 0, 1) AS liked
      FROM posts p
      LEFT JOIN users u
        ON u.user_id = p.post_user_id
      LEFT JOIN categories c
        ON c.cat_id = p.post_cat_id
      LEFT JOIN post_likes pl
        ON pl.pl_post_id = p.post_id
       AND pl.pl_user_id = ?
      ${where}
      ORDER BY p.post_priority DESC, p.created_at DESC
      LIMIT ? OFFSET ?
    `;

    params.unshift(likeUserId); // pl.pl_user_id 바인딩
    params.push(limit, offset);

    const [rows] = await conn.execute(sql, params);

    // 🔹 여기서 각 post_id에 연결된 이미지 URL들을 붙여준다.
    const postIds = rows.map((r) => r.post_id);
    let imgsByPost = {};

    if (postIds.length > 0) {
      const [imgs] = await conn.query(
        'SELECT img_id, img_post_id FROM post_images WHERE img_post_id IN (?)',
        [postIds]
      );

      for (const img of imgs) {
        const pid = img.img_post_id;
        if (!imgsByPost[pid]) imgsByPost[pid] = [];
        // Flutter 쪽에서 바로 쓸 수 있는 상대 경로(URL)
        imgsByPost[pid].push(`/posts/${pid}/images/${img.img_id}`);
      }
    }

    const rowsWithImages = rows.map((r) => ({
      ...r,
      img_urls: imgsByPost[r.post_id] || [],
    }));

    ok(res, {
      rows: rowsWithImages,
      page: Number(page),
      size: limit,
    });
  } catch (e) {
    console.error('[POST LIST]', e);
    fail(res, 500, 'list failed');
  } finally {
    conn.release();
  }
});


// Post 상세
app.get('/posts/:id', async (req, res) => {
  const id = Number(req.params.id);

  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : null;
  let authed = null;
  if (token) {
    try {
      authed = jwt.verify(token, cfg.jwtSecret);
    } catch {
      /* ignore */
    }
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
         LEFT JOIN post_likes pl
           ON pl.pl_post_id=p.post_id
          AND pl.pl_user_id=${
            authed?.id ? Number(authed.id) : 0
          }
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

// 이미지 스트리밍
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
    res.setHeader(
      'Content-Length',
      String(img.img_size || buf.length)
    );
    res.setHeader(
      'Cache-Control',
      'public, max-age=86400, immutable'
    );
    res.setHeader('ETag', etag);
    res.setHeader(
      'Last-Modified',
      new Date(img.created_at).toUTCString()
    );
    if (req.headers['if-none-match'] === etag)
      return res.status(304).end();

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
    res.setHeader(
      'Content-Length',
      String(img.img_size || buf.length)
    );
    res.setHeader(
      'Cache-Control',
      'public, max-age=86400, immutable'
    );
    res.setHeader('ETag', etag);
    res.setHeader(
      'Last-Modified',
      new Date(img.created_at).toUTCString()
    );
    if (req.headers['if-none-match'] === etag)
      return res.status(304).end();

    res.end(buf);
  } finally {
    conn.release();
  }
});
// 기존 게시글에 이미지 추가 업로드
app.post(
  '/posts/:id/images',
  authRequired,
  adminOrOwner(async (req) => {
    // 이 이미지가 속할 게시글의 작성자(owner)를 찾는다.
    const postId = Number(req.params.id);
    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      const [[row]] = await conn.query(
        'SELECT post_user_id FROM posts WHERE post_id=?',
        [postId]
      );
      return row?.post_user_id;
    } finally {
      conn.release();
    }
  }),
  upload.array('images', cfg.maxImageFiles),
  async (req, res) => {
    const postId = Number(req.params.id);
    if (!postId || !Number.isFinite(postId)) {
      return fail(res, 400, 'invalid post id');
    }

    const files = req.files || [];
    if (!files.length) {
      return fail(res, 400, 'no images uploaded');
    }

    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      let count = 0;
      const sql =
        'INSERT INTO post_images (img_post_id, img_mime, img_size, img_data) VALUES (?, ?, ?, ?)';
      for (const f of files) {
        if (!f.mimetype?.startsWith('image/')) continue;
        await conn.execute(sql, [
          postId,
          f.mimetype,
          f.size,
          f.buffer,
        ]);
        count++;
      }
      ok(res, { uploaded: count });
    } catch (e) {
      console.error('[POST IMAGES UPLOAD]', e);
      fail(res, 500, 'upload failed');
    } finally {
      conn.release();
    }
  }
);
// 게시글 이미지 삭제
app.delete(
  '/posts/:id/images/:imgId',
  authRequired,
  adminOrOwner(async (req) => {
    const postId = Number(req.params.id);
    const imgId = Number(req.params.imgId);

    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      // 이미지가 속한 게시글의 작성자 확인
      const [[row]] = await conn.query(
        `SELECT p.post_user_id
           FROM post_images i
           JOIN posts p ON p.post_id = i.img_post_id
          WHERE i.img_id = ? AND i.img_post_id = ?`,
        [imgId, postId]
      );
      // adminOrOwner 에게 post_user_id 넘김
      return row?.post_user_id;
    } finally {
      conn.release();
    }
  }),
  async (req, res) => {
    const postId = Number(req.params.id);
    const imgId = Number(req.params.imgId);

    if (!postId || !Number.isFinite(postId) || !imgId || !Number.isFinite(imgId)) {
      return fail(res, 400, 'invalid ids');
    }

    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      const [r] = await conn.execute(
        'DELETE FROM post_images WHERE img_id = ? AND img_post_id = ?',
        [imgId, postId]
      );
      ok(res, { deleted: r.affectedRows });
    } catch (e) {
      console.error('[POST IMAGE DELETE]', e);
      fail(res, 500, 'delete failed');
    } finally {
      conn.release();
    }
  }
);





// Post 수정/삭제 (기존 로직 유지 - 생략 없이 그대로)

app.put(
  '/posts/:id',
  authRequired,
  adminOrOwner(async (req) => {
    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      const [[row]] = await conn.query(
        'SELECT post_user_id FROM posts WHERE post_id=?',
        [req.params.id]
      );
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
        [cat_id ?? null, content ?? null, priority ?? 0, id]
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

app.post('/posts/:id', authRequired, async (req, res, next) => {
  if (
    (req.body?._method || '')
      .toString()
      .toUpperCase() === 'PUT'
  ) {
    return app._router.handle(
      { ...req, method: 'PUT' },
      res,
      next
    );
  }
  return fail(res, 400, 'Unsupported method');
});

app.delete(
  '/posts/:id',
  authRequired,
  adminOrOwner(async (req) => {
    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      const [[row]] = await conn.query(
        'SELECT post_user_id FROM posts WHERE post_id=?',
        [req.params.id]
      );
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
      const [r] = await conn.execute(
        'DELETE FROM posts WHERE post_id=?',
        [id]
      );
      ok(res, { deleted: r.affectedRows });
    } catch (e) {
      console.error('[POST DELETE]', e);
      fail(res, 500, 'delete failed');
    } finally {
      conn.release();
    }
  }
);

app.post(
  '/posts/:id/delete',
  authRequired,
  async (req, res, next) => {
    req.body = req.body || {};
    req.body._method = 'DELETE';
    return app._router.handle(
      { ...req, method: 'DELETE' },
      res,
      next
    );
  }
);

// -------------------- Comments --------------------

// List comments
app.get('/posts/:id/comments', async (req, res) => {
  const postId = Number(req.params.id);
  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const [rows] = await conn.query(
      `SELECT c.cmt_id, c.cmt_post_id, c.cmt_user_id, c.cmt_parent_cmt_id,
              c.cmt_thread_root_cmt_id, c.cmt_depth, c.cmt_content,
              c.created_at, c.updated_at,
              u.user_name
         FROM comments c
         LEFT JOIN users u ON u.user_id=c.cmt_user_id
        WHERE c.cmt_post_id=?
        ORDER BY
  COALESCE(c.cmt_thread_root_cmt_id, c.cmt_id) ASC,
  c.cmt_depth ASC,
  c.created_at ASC`,
      [postId]
    );
    ok(res, { rows });
  } catch (e) {
    console.error('[COMMENTS LIST]', e);
    fail(res, 500, 'List comments failed');
  } finally {
    conn.release();
  }
});

// 🔴 Create comment (수정된 부분)
app.post('/posts/:id/comments', authRequired, async (req, res) => {
  const postId = Number(req.params.id);

  // content
  let content = '';
  if (req.body && Object.prototype.hasOwnProperty.call(req.body, 'content')) {
    content = String(req.body.content).trim();
  }

  // parent_id (optional)
  let parentId = null;
  if (
    req.body &&
    Object.prototype.hasOwnProperty.call(req.body, 'parent_id') &&
    req.body.parent_id !== null &&
    req.body.parent_id !== ''
  ) {
    const tmp = Number(req.body.parent_id);
    if (!Number.isNaN(tmp)) parentId = tmp;
  }

  if (!postId || !Number.isFinite(postId)) {
    return fail(res, 400, 'invalid post id');
  }
  if (!content) {
    return fail(res, 400, 'content required');
  }

  // userId 안전 추출
  const rawUserId =
    (req.user && (req.user.id ?? req.user.uid)) ?? null;
  const userId = Number(rawUserId);
  if (!userId || !Number.isFinite(userId)) {
    return fail(res, 401, 'invalid user');
  }

  const p = ensurePool();
  const conn = await p.getConnection();

  try {
    await conn.beginTransaction();

    let depth = 0;
    let rootId = null;

    if (parentId) {
      const [[parent]] = await conn.query(
        'SELECT cmt_id, cmt_depth, cmt_thread_root_cmt_id FROM comments WHERE cmt_id=?',
        [parentId]
      );
      if (!parent) {
        await conn.rollback();
        return fail(res, 404, 'parent not found');
      }

      depth =
        Math.min(
          4,
          Number(parent.cmt_depth || 0) + 1
        ) || 1;
      rootId =
        parent.cmt_thread_root_cmt_id || parent.cmt_id;
    }

    const [r] = await conn.execute(
      `INSERT INTO comments (
         cmt_post_id,
         cmt_user_id,
         cmt_parent_cmt_id,
         cmt_thread_root_cmt_id,
         cmt_depth,
         cmt_content,
         created_at
       )
       VALUES (?, ?, ?, ?, ?, ?, NOW())`,
      [
        postId,
        userId,
        parentId || null,
        rootId,
        depth,
        content,
      ]
    );
    const commentId = r.insertId;

    // 게시글 작성자 조회 (알림용)
    const [[post]] = await conn.query(
      'SELECT post_user_id FROM posts WHERE post_id=?',
      [postId]
    );

    if (
      post &&
      post.post_user_id &&
      Number(post.post_user_id) !== userId
    ) {
      const targetUser = Number(post.post_user_id);

      await conn.execute(
        `INSERT INTO notifications (
           noti_user_id,
           noti_type,
           noti_post_id,
           noti_from_user_id,
           payload
         )
         VALUES (
           ?,
           'comment',
           ?,
           ?,
           JSON_OBJECT('comment_id', ?, 'content', ?)
         )`,
        [
          targetUser,
          postId,
          userId,
          commentId,
          content,
        ]
      );

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
              comment_id: commentId,
              content,
            }),
          });
          console.log(
            '[PUSH WEBHOOK comment]',
            resp.status
          );
        } catch (e) {
          console.warn(
            '[PUSH WEBHOOK FAIL]',
            e.message
          );
        }
      }
    }

    await conn.commit();
    return ok(res, { comment_id: commentId });
  } catch (e) {
    try {
      await conn.rollback();
    } catch {}
    console.error('[COMMENT CREATE]', e);
    return fail(res, 500, 'create failed');
  } finally {
    conn.release();
  }
});

// Update / Delete comments (기존 코드 유지)
app.put(
  '/comments/:id',
  authRequired,
  adminOrOwner(async (req) => {
    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      const [[row]] = await conn.query(
        'SELECT cmt_user_id FROM comments WHERE cmt_id=?',
        [req.params.id]
      );
      return row?.cmt_user_id;
    } finally {
      conn.release();
    }
  }),
  async (req, res) => {
    const id = Number(req.params.id);
    const content = (req.body?.content || '').toString().trim();
    if (!content) return fail(res, 400, 'content required');
    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      const [r] = await conn.execute(
        'UPDATE comments SET cmt_content=? WHERE cmt_id=?',
        [content, id]
      );
      ok(res, { affected: r.affectedRows });
    } catch (e) {
      console.error('[COMMENT UPDATE]', e);
      fail(res, 500, 'update failed');
    } finally {
      conn.release();
    }
  }
);

app.post('/comments/:id', authRequired, async (req, res, next) => {
  if (
    (req.body?._method || '')
      .toString()
      .toUpperCase() === 'PUT'
  ) {
    return app._router.handle(
      { ...req, method: 'PUT' },
      res,
      next
    );
  }
  return fail(res, 400, 'Unsupported method');
});

app.delete(
  '/comments/:id',
  authRequired,
  adminOrOwner(async (req) => {
    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      const [[row]] = await conn.query(
        'SELECT cmt_user_id FROM comments WHERE cmt_id=?',
        [req.params.id]
      );
      return row?.cmt_user_id;
    } finally {
      conn.release();
    }
  }),
  async (req, res) => {
    const id = Number(req.params.id);
    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      const [r] = await conn.execute(
        'DELETE FROM comments WHERE cmt_id=?',
        [id]
      );
      ok(res, { deleted: r.affectedRows });
    } catch (e) {
      console.error('[COMMENT DELETE]', e);
      fail(res, 500, 'delete failed');
    } finally {
      conn.release();
    }
  }
);

app.post(
  '/comments/:id/delete',
  authRequired,
  async (req, res, next) => {
    req.body = req.body || {};
    req.body._method = 'DELETE';
    return app._router.handle(
      { ...req, method: 'DELETE' },
      res,
      next
    );
  }
);

// -------------------- Like toggle --------------------
app.post('/posts/:id/like', authRequired, async (req, res) => {
  const postId = Number(req.params.id);
  const userId = Number(req.user.id ?? req.user.uid);
  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    await conn.beginTransaction();
    const [[existing]] = await conn.query(
      'SELECT 1 FROM post_likes WHERE pl_post_id=? AND pl_user_id=?',
      [postId, userId]
    );
    let liked;
    if (existing) {
      await conn.execute(
        'DELETE FROM post_likes WHERE pl_post_id=? AND pl_user_id=?',
        [postId, userId]
      );
      await conn.execute(
        'UPDATE posts SET post_like = GREATEST(0, post_like - 1) WHERE post_id=?',
        [postId]
      );
      liked = false;
    } else {
      await conn.execute(
        'INSERT INTO post_likes (pl_post_id, pl_user_id) VALUES (?, ?)',
        [postId, userId]
      );
      await conn.execute(
        'UPDATE posts SET post_like = post_like + 1 WHERE post_id=?',
        [postId]
      );
      liked = true;

      const [[post]] = await conn.query(
        'SELECT post_user_id FROM posts WHERE post_id=?',
        [postId]
      );
      const targetUser = post?.post_user_id;
      if (targetUser && Number(targetUser) !== userId) {
        await conn.execute(
          `INSERT INTO notifications
           (noti_user_id, noti_type, noti_post_id, noti_from_user_id, payload)
           VALUES (?, 'like', ?, ?, NULL)`,
          [targetUser, postId, userId]
        );
      }
    }
    const [[row]] = await conn.query(
      'SELECT post_like FROM posts WHERE post_id=?',
      [postId]
    );
    await conn.commit();

    if (cfg.pushWebhook && liked) {
      try {
        const resp = await fetch(cfg.pushWebhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: 'like',
            post_id: postId,
            from_user_id: userId,
          }),
        });
        console.log('[PUSH WEBHOOK like]', resp.status);
      } catch (e) {
        console.warn('[PUSH WEBHOOK FAIL]', e.message);
      }
    }

    ok(res, { post_id: postId, liked, like: row.post_like });
  } catch (e) {
    try {
      await conn.rollback();
    } catch {}
    console.error('[LIKE TOGGLE]', e);
    fail(res, 500, 'toggle failed');
  } finally {
    conn.release();
  }
});

// -------------------- Avatar --------------------
app.post(
  '/me/avatar',
  authRequired,
  upload.single('file'),
  async (req, res) => {
    const f = req.file;
    if (!f) return fail(res, 400, 'file required');
    if (!f.mimetype?.startsWith('image/'))
      return fail(res, 400, 'image only');
    const uid = Number(req.user.id ?? req.user.uid);

    const p = ensurePool();
    const conn = await p.getConnection();
    try {
      await conn.execute(
        `INSERT INTO user_avatars (ua_user_id, ua_mime, ua_size, ua_data)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           ua_mime=VALUES(ua_mime),
           ua_size=VALUES(ua_size),
           ua_data=VALUES(ua_data)`,
        [uid, f.mimetype, f.size, f.buffer]
      );
      ok(res, { updated: true });
    } catch (e) {
      console.error('[AVATAR UPSERT]', e);
      fail(res, 500, 'avatar failed');
    } finally {
      conn.release();
    }
  }
);

app.get('/users/:id/avatar', async (req, res) => {
  const uid = Number(req.params.id);
  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const [[row]] = await conn.query(
      'SELECT ua_mime, ua_size, ua_data, updated_at FROM user_avatars WHERE ua_user_id=?',
      [uid]
    );
    if (!row) return fail(res, 404, 'avatar not found');
    const buf = row.ua_data;
    const etag = createHash('sha1').update(buf).digest('hex');
    res.setHeader('Content-Type', row.ua_mime);
    res.setHeader(
      'Content-Length',
      String(row.ua_size || buf.length)
    );
    res.setHeader(
      'Cache-Control',
      'public, max-age=86400, immutable'
    );
    res.setHeader('ETag', etag);
    res.setHeader(
      'Last-Modified',
      new Date(row.updated_at).toUTCString()
    );
    if (req.headers['if-none-match'] === etag)
      return res.status(304).end();
    res.end(buf);
  } finally {
    conn.release();
  }
});

// -------------------- Push / Notifications / User Settings (기존 유지) --------------------
app.post('/push/register', authRequired, async (req, res) => {
  const { token, platform } = req.body || {};
  if (!token) return fail(res, 400, 'token required');
  const uid = Number(req.user.id ?? req.user.uid);
  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    await conn.execute(
      `INSERT INTO device_tokens (dt_user_id, dt_token, dt_platform)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE dt_platform=VALUES(dt_platform)`,
      [uid, token, platform || null]
    );
    ok(res, { registered: true });
  } catch (e) {
    console.error('[PUSH REGISTER]', e);
    fail(res, 500, 'register failed');
  } finally {
    conn.release();
  }
});

app.get('/notifications', authRequired, async (req, res) => {
  const uid = Number(req.user.id ?? req.user.uid);
  const p = ensurePool();
  const conn = await p.getConnection();
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
  } finally {
    conn.release();
  }
});
// 현재 로그인한 유저 정보 조회
app.get('/users/me', authRequired, async (req, res) => {
  const uid = Number(req.user.id ?? req.user.uid);

  if (!uid) {
    return fail(res, 401, 'INVALID_TOKEN');
  }

  const p = ensurePool();
  const conn = await p.getConnection();

  try {
    const [[row]] = await conn.query(
      'SELECT user_id, user_name FROM users WHERE user_id = ?',
      [uid]
    );

    if (!row) {
      return fail(res, 404, 'USER_NOT_FOUND');
    }

    // ok() 헬퍼: { ok: true, ... } 형태로 응답
    return ok(res, {
      user: {
        id: row.user_id,
        name: row.user_name,
      },
    });
  } catch (e) {
    console.error('[USER ME][ERROR]', e);
    return fail(res, 500, 'failed');
  } finally {
    conn.release();
  }
});

app.get('/users/me/settings', authRequired, async (req, res) => {
  const uid = Number(req.user.id ?? req.user.uid);
  const p = ensurePool();
  const conn = await p.getConnection();
  try {
    const [[s]] = await conn.query(
      'SELECT us_nickname, us_notify_email, us_notify_push FROM user_settings WHERE us_user_id=?',
      [uid]
    );
    ok(res, { settings: s || null });
  } finally {
    conn.release();
  }
});

app.put('/users/me/settings', authRequired, async (req, res) => {
  const uid = Number(req.user.id ?? req.user.uid);
  const { nickname } = req.body || {};
  const p = ensurePool();
  const conn = await p.getConnection();

  try {
    console.log('[USER SETTINGS][PUT]', {
      uid,
      nickname,
    });

    const trimmed =
      typeof nickname === 'string' ? nickname.trim() : null;

    // 닉네임 안 들어왔으면 에러
    if (!trimmed) {
      return fail(res, 400, 'nickname is required');
    }

    // 1) 중복 체크: users.user_name에 같은 값이 다른 유저에 있는지
    const [dups] = await conn.query(
      'SELECT user_id FROM users WHERE user_name = ? AND user_id <> ? LIMIT 1',
      [trimmed, uid]
    );

    if (dups.length) {
      console.warn('[NICKNAME DUP]', {
        uid,
        nickname: trimmed,
        conflictUserId: dups[0].user_id,
      });

      return res.status(409).json({
        ok: false,
        code: 'NICKNAME_TAKEN',
        message: '이미 사용 중인 닉네임입니다.',
      });
    }

    // 2) 실제 업데이트: users.user_name
    const [result] = await conn.execute(
      'UPDATE users SET user_name = ? WHERE user_id = ?',
      [trimmed, uid]
    );

    // 해당 유저가 없을 때
    if (!result.affectedRows) {
      console.warn('[NICKNAME UPDATE][NO USER]', { uid, nickname: trimmed });
      return fail(res, 400, 'invalid user id');
    }

    console.log('[NICKNAME UPDATED]', {
      uid,
      nickname: trimmed,
    });

    return ok(res, { updated: true, nickname: trimmed });
  } catch (e) {
  console.error('[USER SETTINGS][ERROR]', e?.code, e?.errno, e?.sqlMessage || e?.message);

  // 상황별로 어떤 문제인지 바로 알 수 있게
  if (e.code === 'ER_NO_SUCH_TABLE') {
    return fail(res, 500, 'user_settings table missing');
  }
  if (e.code === 'ER_BAD_FIELD_ERROR') {
    return fail(res, 500, 'invalid column in user_settings query');
  }
  if (e.code === 'ER_NO_REFERENCED_ROW_2') {
    // FK: users에 없는 uid로 insert하려고 할 때
    return fail(res, 400, 'invalid user id for settings');
  }

  return fail(res, 500, 'failed');
} finally {
  conn.release();
}

});


// 내 이름(user_name) 변경
app.put('/users/me/name', authRequired, async (req, res) => {
  const rid = req.rid || 'no-rid';
  const { name } = req.body || {};

  // 1) 기본 검증
  if (name === undefined || name === null) {
    console.warn('[USER NAME][VALIDATION] missing', { rid, body: req.body });
    return res.status(400).json({
      ok: false,
      code: 'MISSING_NAME',
      message: '새 이름을 입력하세요.',
    });
  }

  if (typeof name !== 'string') {
    console.warn('[USER NAME][VALIDATION] not_string', { rid, typeof: typeof name });
    return res.status(400).json({
      ok: false,
      code: 'INVALID_TYPE',
      message: '이름 형식이 올바르지 않습니다.',
    });
  }

  const trimmed = name.trim();

  if (!trimmed) {
    console.warn('[USER NAME][VALIDATION] empty_after_trim', { rid, name });
    return res.status(400).json({
      ok: false,
      code: 'EMPTY_NAME',
      message: '공백만으로는 이름을 설정할 수 없습니다.',
    });
  }

  if (trimmed.length < 2 || trimmed.length > 30) {
    console.warn('[USER NAME][VALIDATION] length', { rid, len: trimmed.length });
    return res.status(400).json({
      ok: false,
      code: 'INVALID_LENGTH',
      message: '이름은 2~30자 사이여야 합니다.',
    });
  }

  // 한글/영문/숫자/공백/._- 허용 (필요시 패턴 조정)
  const re = /^[가-힣a-zA-Z0-9 _.\-]{2,30}$/;
  if (!re.test(trimmed)) {
    console.warn('[USER NAME][VALIDATION] pattern', { rid, trimmed });
    return res.status(400).json({
      ok: false,
      code: 'INVALID_CHAR',
      message: '허용되지 않는 문자가 포함되어 있습니다.',
    });
  }

  const p = ensurePool();
  const conn = await p.getConnection();

  try {
    // 2) 토큰에서 user_id 추출
    const uid = req.user?.id ?? req.user?.uid;
    if (!uid) {
      console.error('[USER NAME][AUTH] no_uid_in_token', { rid, user: req.user });
      return res.status(401).json({
        ok: false,
        code: 'INVALID_TOKEN',
        message: '인증 정보가 올바르지 않습니다. 다시 로그인하세요.',
      });
    }

    // 3) 사용자 존재 여부 확인
    const [[user]] = await conn.query(
      'SELECT user_id, user_name FROM users WHERE user_id=?',
      [uid]
    );

    if (!user) {
      console.warn('[USER NAME][NOT_FOUND]', { rid, uid });
      return res.status(404).json({
        ok: false,
        code: 'USER_NOT_FOUND',
        message: '사용자 정보를 찾을 수 없습니다.',
      });
    }

    // 4) 동일 이름인 경우
    if (user.user_name === trimmed) {
      console.log('[USER NAME][NO_CHANGE]', {
        rid,
        uid,
        name: trimmed,
      });
      return res.json({
        ok: true,
        code: 'NO_CHANGE',
        message: '현재 사용 중인 이름과 동일합니다.',
        user: {
          id: user.user_id,
          name: user.user_name,
        },
      });
    }

    // 5) 실제 업데이트
    const [result] = await conn.execute(
      'UPDATE users SET user_name=? WHERE user_id=?',
      [trimmed, uid]
    );

    if (!result || result.affectedRows === 0) {
      console.error('[USER NAME][UPDATE_FAIL] no_rows_affected', {
        rid,
        uid,
        next: trimmed,
      });
      return res.status(500).json({
        ok: false,
        code: 'UPDATE_FAILED',
        message: '이름 변경에 실패했습니다. 다시 시도해주세요.',
      });
    }

    console.log('[USER NAME][UPDATED]', {
      rid,
      uid,
      prev: user.user_name,
      next: trimmed,
    });

    // 클라이언트에서 바로 화면에 메시지/정보 표시 가능
    return res.json({
      ok: true,
      code: 'UPDATED',
      message: '이름이 변경되었습니다.',
      user: {
        id: user.user_id,
        name: trimmed,
      },
    });
  } catch (err) {
    console.error('[USER NAME][ERROR]', { rid, error: err?.message });
    return res.status(500).json({
      ok: false,
      code: 'SERVER_ERROR',
      message: '서버 오류로 이름 변경에 실패했습니다.',
    });
  } finally {
    conn.release();
  }
});

// -------------------- 404 & Error --------------------
app.use((req, res) => {
  console.warn('[404]', req.method, req.url);
  res
    .status(404)
    .json({ ok: false, error: 'Not Found', path: req.url });
});

app.use((err, req, res, _next) => {
  console.error('[UNHANDLED ERROR]', req.rid, err);
  if (res.headersSent) return;
  res
    .status(500)
    .json({ ok: false, error: 'Internal Server Error' });
});

// -------------------- Start --------------------
app.listen(cfg.httpPort, () => {
  console.log(`[BOOT] listening on :${cfg.httpPort}`);
});

// 안전망
process.on('unhandledRejection', (reason) => {
  console.error('[UNHANDLED REJECTION]', reason);
});
process.on('uncaughtException', (err) => {
  console.error('[UNCAUGHT EXCEPTION]', err);
});