const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { initDatabase, getDb, saveDatabase } = require('./config/database');
const { uploadPost, uploadNews, uploadBookCover, uploadBookFile, uploadMerch } = require('./config/upload');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'cyberpunk_drive_secret_key_2026';

// ===== УРОВНИ ДОСТУПА =====
const ROLE_LEVELS = {
  'guest': 0,
  'user': 1,
  'subscriber': 2,
  'operator': 3,
  'admin': 4
};

function requireMinRole(minRole) {
  return (req, res, next) => {
    let currentRole = 'guest';
    let user = null;

    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        currentRole = decoded.role || 'guest';
        user = decoded;
      } catch (err) {}
    }

    req.userRole = currentRole;
    req.user = user;

    if (ROLE_LEVELS[currentRole] >= ROLE_LEVELS[minRole]) {
      next();
    } else {
      if (req.path.startsWith('/api/')) {
        return res.status(403).json({ success: false, error: `Недостаточно прав. Требуется: ${minRole}` });
      }
      return res.redirect('/access?error=access_denied&required=' + minRole);
    }
  };
}

// ===== ХЕЛПЕРЫ ДЛЯ ДИНАМИЧЕСКИХ СТРАНИЦ =====
function escapeHtmlStr(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function ensurePageExists(db, slug, defaultTitle) {
  const find = db.prepare('SELECT id, content_json FROM pages WHERE slug = ?');
  find.bind([slug]);
  let page = null;
  if (find.step()) page = find.getAsObject();
  find.free();

  if (page) return page;

  const ins = db.prepare('INSERT INTO pages (slug, title, content_type) VALUES (?, ?, ?)');
  ins.run([slug, defaultTitle || slug, 'static']);
  ins.free();

  const find2 = db.prepare('SELECT id, content_json FROM pages WHERE slug = ?');
  find2.bind([slug]);
  let p2 = null;
  if (find2.step()) p2 = find2.getAsObject();
  find2.free();
  return p2;
}

function renderPageWithConfig(slug, filename, defaultTitle) {
  try {
    const db = getDb();
    let html = fs.readFileSync(path.join(__dirname, filename), 'utf8');

    ensurePageExists(db, slug, defaultTitle || slug);

    const stmt = db.prepare('SELECT slug, title, content_json FROM pages');
    const allPages = [];
    while (stmt.step()) allPages.push(stmt.getAsObject());
    stmt.free();

    const configs = {};
    allPages.forEach(p => {
      let cfg = {};
      if (p.content_json) {
        try { cfg = JSON.parse(p.content_json); } catch (e) {}
      }
      configs[p.slug] = {
        slug: p.slug,
        title: p.title,
        menu_label: cfg.menu_label || '',
        font_family: cfg.font_family || '',
        custom_head: cfg.custom_head || '',
        hero_image: cfg.hero_image || ''
      };
    });

    const thisConfig = configs[slug] || {};

    allPages.forEach(p => {
      const cfg = configs[p.slug];
      if (cfg.menu_label) {
        const re = new RegExp('(data-mode="' + p.slug + '"[^>]*>)\\s*[^<]+', 'g');
        html = html.replace(re, '$1' + escapeHtmlStr(cfg.menu_label));
      }
    });

    if (thisConfig.title) {
      html = html.replace(/<title>[^<]*<\/title>/, '<title>' + escapeHtmlStr(thisConfig.title) + '</title>');
    }

    const injections = [];
    if (thisConfig.font_family) {
      injections.push('<style>:root { --font-mono: ' + thisConfig.font_family + ' !important; } body, .menu-item, button, input, textarea, select { font-family: ' + thisConfig.font_family + ' !important; }</style>');
    }
    if (thisConfig.hero_image) {
      injections.push(
        '<style>' +
        '.hero-section { margin-top: 190px !important; }' +
        '.hero-bg { top: 0 !important; left: -10% !important; right: -10% !important; bottom: -10% !important; width: 120% !important; height: auto !important; background-image: url("' + thisConfig.hero_image + '") !important; background-size: cover !important; background-position: center !important; background-repeat: no-repeat !important; }' +
        '.hero-bg::before { background: linear-gradient(180deg, rgba(5,6,10,0.55) 0%, rgba(5,6,10,0.75) 100%) !important; }' +
        '</style>'
      );
    }
    if (thisConfig.custom_head) {
      injections.push('<!-- PAGE CUSTOM HEAD -->\n' + thisConfig.custom_head);
    }

    if (injections.length) {
      html = html.replace('</head>', injections.join('\n') + '\n</head>');
    }

    html = html.replace(/<body([^>]*)>/i, '<body data-page-slug="' + slug + '"$1>');

    if (!html.includes('/js/subnav.js')) {
      html = html.replace('</body>', '<script src="/js/subnav.js" defer></script>\n</body>');
    }

    return html;
  } catch (err) {
    console.error('[renderPageWithConfig]', err);
    try {
      return fs.readFileSync(path.join(__dirname, filename), 'utf8');
    } catch (e) {
      return '<html><body>Ошибка загрузки страницы</body></html>';
    }
  }
}

// ===== MIDDLEWARE =====
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ===== ПРОВЕРКА СТОП-СЛОВ =====
function checkStopWords(db, text) {
  if (!text) return [];
  const plain = String(text).toLowerCase().replace(/<[^>]*>/g, ' ');
  if (!plain.trim()) return [];

  const stmt = db.prepare('SELECT word FROM stop_words');
  const found = [];
  while (stmt.step()) {
    const w = String(stmt.getAsObject().word || '').toLowerCase().trim();
    if (!w) continue;
    const escaped = w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp('(^|[^a-zа-яё0-9_])' + escaped + '($|[^a-zа-яё0-9_])', 'i');
    if (re.test(plain)) found.push(w);
  }
  stmt.free();
  return found;
}

// ===== АВТОРИЗАЦИЯ АДМИНА =====
function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, error: 'Токен не предоставлен' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Только для администраторов' });
    }
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: 'Недействительный токен' });
  }
}

// ===== АВТОРИЗАЦИЯ ПОЛЬЗОВАТЕЛЯ =====
function requireUserAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, error: 'Требуется авторизация' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const db = getDb();
    const stmt = db.prepare('SELECT id, username, email, role, avatar, bio, is_blocked FROM users WHERE id = ?');
    stmt.bind([decoded.id]);
    let user = null;
    if (stmt.step()) user = stmt.getAsObject();
    stmt.free();

    if (!user) return res.status(401).json({ success: false, error: 'Пользователь не найден' });
    if (user.is_blocked) return res.status(403).json({ success: false, error: 'Аккаунт заблокирован' });

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, error: 'Недействительный токен' });
  }
}

// ===== ЗАГРУЗКА АВАТАРОВ =====
const avatarsDir = path.join(__dirname, 'public', 'uploads', 'avatars');
if (!fs.existsSync(avatarsDir)) fs.mkdirSync(avatarsDir, { recursive: true });

const avatarStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, avatarsDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname).toLowerCase());
  }
});

const avatarUpload = multer({
  storage: avatarStorage,
  limits: { fileSize: 3 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /^image\/(jpeg|jpg|png|webp|gif)$/.test(file.mimetype);
    cb(ok ? null : new Error('Разрешены только изображения'), ok);
  }
});

// ===== ЗАГРУЗКА HERO-КАРТИНОК ДЛЯ СТРАНИЦ =====
const heroesDir = path.join(__dirname, 'public', 'uploads', 'heroes');
if (!fs.existsSync(heroesDir)) fs.mkdirSync(heroesDir, { recursive: true });

const heroStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, heroesDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname).toLowerCase());
  }
});

const heroUpload = multer({
  storage: heroStorage,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /^image\/(jpeg|jpg|png|webp|gif)$/.test(file.mimetype);
    cb(ok ? null : new Error('Разрешены только изображения'), ok);
  }
});

// ===== API: АВТОРИЗАЦИЯ АДМИНА =====
app.post('/api/admin/login', (req, res) => {
  try {
    const db = getDb();
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, error: 'Заполните все поля' });

    const stmt = db.prepare('SELECT * FROM users WHERE username = ? AND role = ?');
    stmt.bind([username, 'admin']);
    let user = null;
    if (stmt.step()) user = stmt.getAsObject();
    stmt.free();

    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ success: false, error: 'Неверный логин или пароль' });
    }

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/admin/me', requireAuth, (req, res) => res.json({ success: true, user: req.user }));
app.post('/api/admin/logout', (req, res) => res.json({ success: true }));

// ===== API: ТЕКУЩИЙ ПОЛЬЗОВАТЕЛЬ =====
app.get('/api/me', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.json({ success: true, user: { role: 'guest', username: 'Гость' } });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const db = getDb();
    const stmt = db.prepare('SELECT id, username, email, role, avatar, bio, is_blocked FROM users WHERE id = ?');
    stmt.bind([decoded.id]);
    let u = null;
    if (stmt.step()) u = stmt.getAsObject();
    stmt.free();
    if (!u) return res.json({ success: true, user: { role: 'guest', username: 'Гость' } });
    res.json({ success: true, user: u });
  } catch (err) {
    res.json({ success: true, user: { role: 'guest', username: 'Гость' } });
  }
});

// ===== API: РЕГИСТРАЦИЯ =====
app.post('/api/register', (req, res) => {
  try {
    const db = getDb();

    const allowRow = db.prepare("SELECT value FROM settings WHERE key = 'allow_registration'");
    let allow = true;
    if (allowRow.step()) allow = String(allowRow.getAsObject().value) !== '0';
    allowRow.free();
    if (!allow) return res.status(403).json({ success: false, error: 'Регистрация временно отключена' });

    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ success: false, error: 'Заполните все поля' });
    }
    if (username.length < 3 || username.length > 20) {
      return res.status(400).json({ success: false, error: 'Позывной должен быть от 3 до 20 символов' });
    }
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      return res.status(400).json({ success: false, error: 'Только латиница, цифры и _' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, error: 'Некорректный email' });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, error: 'Пароль минимум 6 символов' });
    }

    const checkUser = db.prepare('SELECT id FROM users WHERE username = ?');
    checkUser.bind([username]);
    if (checkUser.step()) {
      checkUser.free();
      return res.status(400).json({ success: false, error: 'Позывной уже занят' });
    }
    checkUser.free();

    const checkEmail = db.prepare('SELECT id FROM users WHERE email = ?');
    checkEmail.bind([email]);
    if (checkEmail.step()) {
      checkEmail.free();
      return res.status(400).json({ success: false, error: 'Email уже используется' });
    }
    checkEmail.free();

    const passwordHash = bcrypt.hashSync(password, 10);
    const stmt = db.prepare('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)');
    stmt.run([username, email, passwordHash, 'user']);
    stmt.free();

    const idStmt = db.prepare('SELECT last_insert_rowid() as id');
    const newId = idStmt.step() ? idStmt.getAsObject().id : null;
    idStmt.free();

    const token = jwt.sign({ id: newId, username, role: 'user' }, JWT_SECRET, { expiresIn: '30d' });
    saveDatabase();

    res.json({
      success: true,
      message: 'Регистрация успешна',
      token,
      user: { id: newId, username, role: 'user' }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ===== API: ВХОД =====
app.post('/api/login', (req, res) => {
  try {
    const db = getDb();
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, error: 'Заполните все поля' });

    const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
    stmt.bind([username]);
    let user = null;
    if (stmt.step()) user = stmt.getAsObject();
    stmt.free();

    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ success: false, error: 'Неверный позывной или пароль' });
    }

    if (user.is_blocked) {
      return res.status(403).json({ success: false, error: 'Аккаунт заблокирован. Обратитесь к администрации.' });
    }

    const upd = db.prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?");
    upd.run([user.id]);
    upd.free();
    saveDatabase();

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================
// ===== API ЛИЧНОГО КАБИНЕТА ПОЛЬЗОВАТЕЛЯ ===================
// ============================================================

app.get('/api/user/profile', requireUserAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare('SELECT id, username, email, role, avatar, bio, created_at, last_login_at FROM users WHERE id = ?');
    stmt.bind([req.user.id]);
    let u = null;
    if (stmt.step()) u = stmt.getAsObject();
    stmt.free();
    res.json({ success: true, data: u });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/user/profile', requireUserAuth, (req, res) => {
  try {
    const db = getDb();
    const { username, email, bio } = req.body;

    if (!username || username.length < 3 || username.length > 20) {
      return res.status(400).json({ success: false, error: 'Позывной: 3–20 символов' });
    }
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      return res.status(400).json({ success: false, error: 'Только латиница, цифры и _' });
    }
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, error: 'Некорректный email' });
    }

    const checkUser = db.prepare('SELECT id FROM users WHERE username = ? AND id != ?');
    checkUser.bind([username, req.user.id]);
    if (checkUser.step()) {
      checkUser.free();
      return res.status(400).json({ success: false, error: 'Позывной занят' });
    }
    checkUser.free();

    if (email) {
      const checkEmail = db.prepare('SELECT id FROM users WHERE email = ? AND id != ?');
      checkEmail.bind([email, req.user.id]);
      if (checkEmail.step()) {
        checkEmail.free();
        return res.status(400).json({ success: false, error: 'Email уже используется' });
      }
      checkEmail.free();
    }

    const stmt = db.prepare('UPDATE users SET username = ?, email = ?, bio = ? WHERE id = ?');
    stmt.run([username, email || '', String(bio || '').slice(0, 500), req.user.id]);
    stmt.free();
    saveDatabase();

    const newToken = jwt.sign(
      { id: req.user.id, username, role: req.user.role },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      success: true,
      message: 'Профиль обновлён',
      token: newToken,
      user: { id: req.user.id, username, role: req.user.role }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/user/profile/password', requireUserAuth, (req, res) => {
  try {
    const db = getDb();
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({ success: false, error: 'Заполните оба поля' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ success: false, error: 'Пароль минимум 6 символов' });
    }
    if (oldPassword === newPassword) {
      return res.status(400).json({ success: false, error: 'Новый пароль совпадает со старым' });
    }

    const stmt = db.prepare('SELECT password_hash FROM users WHERE id = ?');
    stmt.bind([req.user.id]);
    let u = null;
    if (stmt.step()) u = stmt.getAsObject();
    stmt.free();

    if (!u || !bcrypt.compareSync(oldPassword, u.password_hash)) {
      return res.status(401).json({ success: false, error: 'Старый пароль неверен' });
    }

    const hash = bcrypt.hashSync(newPassword, 10);
    const upd = db.prepare('UPDATE users SET password_hash = ? WHERE id = ?');
    upd.run([hash, req.user.id]);
    upd.free();
    saveDatabase();

    res.json({ success: true, message: 'Пароль изменён' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/user/profile/avatar', requireUserAuth, avatarUpload.single('avatar'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'Файл не загружен' });

    const db = getDb();
    const newPath = '/uploads/avatars/' + req.file.filename;

    const sel = db.prepare('SELECT avatar FROM users WHERE id = ?');
    sel.bind([req.user.id]);
    let cur = null;
    if (sel.step()) cur = sel.getAsObject();
    sel.free();

    if (cur && cur.avatar && cur.avatar.startsWith('/uploads/avatars/')) {
      const oldPath = path.join(__dirname, 'public', cur.avatar);
      if (fs.existsSync(oldPath)) {
        try { fs.unlinkSync(oldPath); } catch (e) {}
      }
    }

    const stmt = db.prepare('UPDATE users SET avatar = ? WHERE id = ?');
    stmt.run([newPath, req.user.id]);
    stmt.free();
    saveDatabase();

    res.json({ success: true, avatar: newPath });
  } catch (err) {
    if (req.file) fs.unlink(req.file.path, () => {});
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/user/profile/avatar', requireUserAuth, (req, res) => {
  try {
    const db = getDb();
    const sel = db.prepare('SELECT avatar FROM users WHERE id = ?');
    sel.bind([req.user.id]);
    let cur = null;
    if (sel.step()) cur = sel.getAsObject();
    sel.free();

    if (cur && cur.avatar && cur.avatar.startsWith('/uploads/avatars/')) {
      const oldPath = path.join(__dirname, 'public', cur.avatar);
      if (fs.existsSync(oldPath)) {
        try { fs.unlinkSync(oldPath); } catch (e) {}
      }
    }

    const stmt = db.prepare('UPDATE users SET avatar = NULL WHERE id = ?');
    stmt.run([req.user.id]);
    stmt.free();
    saveDatabase();

    res.json({ success: true, message: 'Аватар удалён' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/user/orders', requireUserAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare(`
      SELECT * FROM orders
      WHERE user_id = ? OR customer_email = ?
      ORDER BY created_at DESC
    `);
    stmt.bind([req.user.id, req.user.email]);
    const orders = [];
    while (stmt.step()) orders.push(stmt.getAsObject());
    stmt.free();

    for (const o of orders) {
      const items = db.prepare(`
        SELECT oi.*, m.name as merch_name, m.image_path as merch_image, m.price
        FROM order_items oi
        LEFT JOIN merch_items m ON oi.merch_id = m.id
        WHERE oi.order_id = ?
      `);
      items.bind([o.id]);
      o.items = [];
      while (items.step()) o.items.push(items.getAsObject());
      items.free();
    }

    res.json({ success: true, data: orders });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/user/comments', requireUserAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare(`
      SELECT c.*, p.title as post_title
      FROM post_comments c
      LEFT JOIN posts p ON c.post_id = p.id
      WHERE c.user_id = ?
      ORDER BY c.created_at DESC
      LIMIT 100
    `);
    stmt.bind([req.user.id]);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    res.json({ success: true, data: rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/user/stats', requireUserAuth, (req, res) => {
  try {
    const db = getDb();
    const count = (sql, params) => {
      const s = db.prepare(sql);
      s.bind(params);
      let c = 0;
      if (s.step()) c = s.getAsObject().count || 0;
      s.free();
      return c;
    };
    res.json({
      success: true,
      data: {
        orders: count('SELECT COUNT(*) as count FROM orders WHERE user_id = ? OR customer_email = ?', [req.user.id, req.user.email]),
        comments: count('SELECT COUNT(*) as count FROM post_comments WHERE user_id = ?', [req.user.id]),
        posts: count('SELECT COUNT(*) as count FROM posts WHERE author_id = ?', [req.user.id])
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================
// ===== ПУБЛИЧНЫЙ ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ ======================
// ============================================================

app.get('/api/user/public/:username', (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare(`
      SELECT id, username, role, avatar, bio, created_at
      FROM users
      WHERE username = ? AND is_blocked = 0
    `);
    stmt.bind([req.params.username]);
    let u = null;
    if (stmt.step()) u = stmt.getAsObject();
    stmt.free();

    if (!u) return res.status(404).json({ success: false, error: 'Пользователь не найден' });

    const count = (sql, params) => {
      const s = db.prepare(sql);
      s.bind(params);
      let c = 0;
      if (s.step()) c = s.getAsObject().count || 0;
      s.free();
      return c;
    };

    u.stats = {
      comments: count('SELECT COUNT(*) as count FROM post_comments WHERE user_id = ?', [u.id]),
      posts: count('SELECT COUNT(*) as count FROM posts WHERE author_id = ? AND status = ?', [u.id, 'published'])
    };

    res.json({ success: true, data: u });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================
// ===== АДМИН: ДЕТАЛИ ПОЛЬЗОВАТЕЛЯ ==========================
// ============================================================

app.get('/api/admin/users/:id/full', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const userId = parseInt(req.params.id);

    const stmt = db.prepare('SELECT id, username, email, role, is_subscriber, avatar, bio, is_blocked, created_at, last_login_at FROM users WHERE id = ?');
    stmt.bind([userId]);
    let u = null;
    if (stmt.step()) u = stmt.getAsObject();
    stmt.free();

    if (!u) return res.status(404).json({ success: false, error: 'Пользователь не найден' });

    const count = (sql, params) => {
      const s = db.prepare(sql);
      s.bind(params);
      let c = 0;
      if (s.step()) c = s.getAsObject().count || 0;
      s.free();
      return c;
    };

    u.stats = {
      orders: count('SELECT COUNT(*) as count FROM orders WHERE user_id = ? OR customer_email = ?', [userId, u.email]),
      comments: count('SELECT COUNT(*) as count FROM post_comments WHERE user_id = ?', [userId]),
      posts: count('SELECT COUNT(*) as count FROM posts WHERE author_id = ?', [userId])
    };

    res.json({ success: true, data: u });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.patch('/api/admin/users/:id/block', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const userId = parseInt(req.params.id);
    const { is_blocked } = req.body;

    if (userId === 1) {
      return res.status(403).json({ success: false, error: 'Нельзя заблокировать главного администратора' });
    }

    const stmt = db.prepare('UPDATE users SET is_blocked = ? WHERE id = ?');
    stmt.run([is_blocked ? 1 : 0, userId]);
    stmt.free();
    saveDatabase();

    res.json({ success: true, message: is_blocked ? 'Пользователь заблокирован' : 'Пользователь разблокирован' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/admin/users/:id/reset-password', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const userId = parseInt(req.params.id);

    if (userId === 1 && req.user.id !== 1) {
      return res.status(403).json({ success: false, error: 'Нельзя сбросить пароль главного администратора' });
    }

    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%';
    let newPassword = '';
    for (let i = 0; i < 12; i++) {
      newPassword += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    const hash = bcrypt.hashSync(newPassword, 10);
    const stmt = db.prepare('UPDATE users SET password_hash = ? WHERE id = ?');
    stmt.run([hash, userId]);
    stmt.free();
    saveDatabase();

    res.json({ success: true, message: 'Пароль сброшен', new_password: newPassword });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================
// ===== API: ПУБЛИЧНЫЕ ДАННЫЕ ================================
// ============================================================

app.get('/api/news', (req, res) => {
  try {
    const db = getDb();
    const { category, priority, limit = 50 } = req.query;
    let query = 'SELECT * FROM news WHERE 1=1';
    const params = [];
    if (category && category !== 'all') { query += ' AND category = ?'; params.push(category); }
    if (priority && priority !== 'all') { query += ' AND priority = ?'; params.push(priority); }
    query += ' ORDER BY created_at DESC LIMIT ?';
    params.push(parseInt(limit));

    const stmt = db.prepare(query);
    stmt.bind(params);
    const news = [];
    while (stmt.step()) news.push(stmt.getAsObject());
    stmt.free();
    res.json({ success: true, data: news });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/books', (req, res) => {
  try {
    const db = getDb();
    const { genre, limit = 50 } = req.query;
    let query = 'SELECT * FROM books WHERE status = ?';
    const params = ['approved'];
    if (genre && genre !== 'all') { query += ' AND genre = ?'; params.push(genre); }
    query += ' ORDER BY created_at DESC LIMIT ?';
    params.push(parseInt(limit));

    const stmt = db.prepare(query);
    stmt.bind(params);
    const books = [];
    while (stmt.step()) books.push(stmt.getAsObject());
    stmt.free();
    res.json({ success: true, data: books });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/books/:id', (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare('SELECT * FROM books WHERE id = ?');
    stmt.bind([parseInt(req.params.id)]);
    let book = null;
    if (stmt.step()) book = stmt.getAsObject();
    stmt.free();
    if (!book) return res.status(404).json({ success: false, error: 'Книга не найдена' });
    res.json({ success: true, data: book });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/resources', (req, res) => {
  try {
    const db = getDb();
    const { type, limit = 50 } = req.query;
    let query = 'SELECT * FROM resources WHERE is_active = 1';
    const params = [];
    if (type && type !== 'all') { query += ' AND type = ?'; params.push(type); }
    query += ' ORDER BY created_at DESC LIMIT ?';
    params.push(parseInt(limit));

    const stmt = db.prepare(query);
    stmt.bind(params);
    const resources = [];
    while (stmt.step()) resources.push(stmt.getAsObject());
    stmt.free();
    res.json({ success: true, data: resources });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/resources/:id/click', (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare('UPDATE resources SET clicks_count = clicks_count + 1 WHERE id = ?');
    stmt.run([req.params.id]);
    stmt.free();
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/gallery', (req, res) => {
  try {
    const db = getDb();
    const { type, album, limit = 50 } = req.query;
    let query = 'SELECT * FROM gallery_items WHERE 1=1';
    const params = [];
    if (type && type !== 'all') { query += ' AND type = ?'; params.push(type); }
    if (album) { query += ' AND album_id = ?'; params.push(album); }
    query += ' ORDER BY created_at DESC LIMIT ?';
    params.push(parseInt(limit));

    const stmt = db.prepare(query);
    stmt.bind(params);
    const items = [];
    while (stmt.step()) items.push(stmt.getAsObject());
    stmt.free();

    const albumsStmt = db.prepare('SELECT * FROM gallery_albums');
    const albums = [];
    while (albumsStmt.step()) albums.push(albumsStmt.getAsObject());
    albumsStmt.free();

    res.json({ success: true, data: { items, albums } });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ============================================================
// ===== API: ПОСТЫ ===========================================
// ============================================================

app.post('/api/posts', requireMinRole('subscriber'), uploadPost.single('image'), (req, res) => {
  try {
    const db = getDb();
    const { title, content, category, tags } = req.body;
    if (!title || !content || !category) {
      return res.status(400).json({ success: false, error: 'Заполните обязательные поля' });
    }

    const isStaff = ['operator', 'admin'].includes(req.userRole);
    const status = isStaff ? 'published' : 'pending';
    const imagePath = req.file ? '/uploads/posts/' + req.file.filename : '';

    const stmt = db.prepare(`
      INSERT INTO posts (author_id, title, content, category, tags, image_path, status)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run([req.user.id, String(title).trim(), String(content).trim(), String(category).trim(), String(tags || ''), imagePath, status]);
    stmt.free();

    const idStmt = db.prepare('SELECT last_insert_rowid() as id');
    const newId = idStmt.step() ? idStmt.getAsObject().id : null;
    idStmt.free();
    saveDatabase();

    res.json({
      success: true,
      message: isStaff ? 'Пост опубликован' : 'Пост отправлен на модерацию',
      id: newId,
      status
    });
  } catch (err) {
    if (req.file) { try { fs.unlinkSync(req.file.path); } catch (e) {} }
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/posts', requireMinRole('subscriber'), (req, res) => {
  try {
    const db = getDb();
    const { category, limit = 20 } = req.query;
    let query = `SELECT p.*, u.username as author_name, u.avatar as author_avatar FROM posts p LEFT JOIN users u ON p.author_id = u.id WHERE p.status = 'published'`;
    const params = [];
    if (category && category !== 'all') { query += ' AND p.category = ?'; params.push(category); }
    query += ' ORDER BY p.created_at DESC LIMIT ?';
    params.push(parseInt(limit));

    const stmt = db.prepare(query);
    stmt.bind(params);
    const posts = [];
    while (stmt.step()) posts.push(stmt.getAsObject());
    stmt.free();
    res.json({ success: true, data: posts });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/posts/:id/comments', requireMinRole('subscriber'), (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare(`
      SELECT c.*, u.username as author_name, u.avatar as author_avatar
      FROM post_comments c
      LEFT JOIN users u ON c.user_id = u.id
      WHERE c.post_id = ? AND c.status = 'approved'
      ORDER BY c.created_at ASC
    `);
    stmt.bind([parseInt(req.params.id)]);
    const comments = [];
    while (stmt.step()) comments.push(stmt.getAsObject());
    stmt.free();
    res.json({ success: true, data: comments });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/posts/:id/comments', requireMinRole('subscriber'), (req, res) => {
  try {
    const db = getDb();
    const { content } = req.body;
    if (!content || !String(content).trim()) {
      return res.status(400).json({ success: false, error: 'Комментарий не может быть пустым' });
    }

    let fullAutoMod = false;
    const settingRow = db.prepare("SELECT value FROM settings WHERE key = 'auto_moderation'");
    if (settingRow.step()) {
      fullAutoMod = String(settingRow.getAsObject().value) === '1';
    }
    settingRow.free();

    const matched = checkStopWords(db, content);

    let status;
    let reason = '';

    if (fullAutoMod) {
      status = 'pending';
      reason = 'Полная авто-модерация';
    } else if (matched.length > 0) {
      status = 'pending';
      reason = 'Найдены стоп-слова: ' + matched.join(', ');
    } else {
      status = 'approved';
    }

    const stmt = db.prepare('INSERT INTO post_comments (post_id, user_id, content, status) VALUES (?, ?, ?, ?)');
    stmt.run([parseInt(req.params.id), req.user.id, String(content).trim(), status]);
    stmt.free();
    saveDatabase();

    res.json({
      success: true,
      message: status === 'pending' ? 'Комментарий отправлен на модерацию' : 'Комментарий добавлен',
      status,
      matched_words: matched,
      reason
    });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ===== API: STATS АДМИНА =====
app.get('/api/stats', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const getCount = (query, params = []) => {
      const stmt = db.prepare(query);
      stmt.bind(params);
      let count = 0;
      if (stmt.step()) count = stmt.getAsObject().count || 0;
      stmt.free();
      return count;
    };
    res.json({ success: true, data: {
      users: getCount('SELECT COUNT(*) as count FROM users'),
      users_blocked: getCount('SELECT COUNT(*) as count FROM users WHERE is_blocked = 1'),
      posts_published: getCount("SELECT COUNT(*) as count FROM posts WHERE status = 'published'"),
      posts_pending: getCount("SELECT COUNT(*) as count FROM posts WHERE status = 'pending'"),
      comments_pending: getCount("SELECT COUNT(*) as count FROM post_comments WHERE status = 'pending'"),
      books: getCount("SELECT COUNT(*) as count FROM books WHERE status = 'approved'"),
      news: getCount('SELECT COUNT(*) as count FROM news'),
      gallery: getCount('SELECT COUNT(*) as count FROM gallery_items'),
      resources: getCount('SELECT COUNT(*) as count FROM resources WHERE is_active = 1'),
      orders_pending: getCount("SELECT COUNT(*) as count FROM orders WHERE status = 'pending'")
    }});
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ===== API АДМИНА: ПОЛЬЗОВАТЕЛИ =====
app.get('/api/admin/users', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare(`
      SELECT id, username, email, role, is_subscriber, avatar, is_blocked, created_at, last_login_at
      FROM users
      ORDER BY created_at DESC
    `);
    const users = [];
    while (stmt.step()) users.push(stmt.getAsObject());
    stmt.free();
    res.json({ success: true, data: users });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/admin/users/:id/role', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const userId = parseInt(req.params.id);
    const { role } = req.body;

    if (!['user', 'subscriber', 'operator', 'admin'].includes(role)) {
      return res.status(400).json({ success: false, error: 'Недопустимая роль' });
    }

    const stmt = db.prepare('UPDATE users SET role = ? WHERE id = ?');
    stmt.run([role, userId]);
    stmt.free();

    saveDatabase();
    res.json({ success: true, message: 'Роль обновлена' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/admin/users/:id', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const userId = parseInt(req.params.id);

    if (userId === 1) {
      return res.status(403).json({ success: false, error: 'Нельзя удалить главного администратора' });
    }

    const stmt = db.prepare('DELETE FROM users WHERE id = ?');
    stmt.run([userId]);
    stmt.free();

    saveDatabase();
    res.json({ success: true, message: 'Пользователь удалён' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================
// ===== API АДМИНА: КОММЕНТАРИИ ==============================
// ============================================================

app.get('/api/admin/comments', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { status, search, post_id, limit = 300 } = req.query;

    let query = `
      SELECT c.id, c.post_id, c.user_id, c.content, c.status, c.created_at, c.updated_at,
             u.username AS author_name, u.avatar AS author_avatar,
             p.title AS post_title
      FROM post_comments c
      LEFT JOIN users u ON c.user_id = u.id
      LEFT JOIN posts p ON c.post_id = p.id
      WHERE 1=1
    `;
    const params = [];

    if (status && status !== 'all') {
      query += ' AND c.status = ?';
      params.push(status);
    }
    if (post_id) {
      query += ' AND c.post_id = ?';
      params.push(parseInt(post_id));
    }
    if (search && String(search).trim()) {
      const s = '%' + String(search).trim() + '%';
      query += ' AND (c.content LIKE ? OR u.username LIKE ?)';
      params.push(s, s);
    }
    query += ' ORDER BY c.created_at DESC LIMIT ?';
    params.push(parseInt(limit));

    const stmt = db.prepare(query);
    stmt.bind(params);
    const comments = [];
    while (stmt.step()) comments.push(stmt.getAsObject());
    stmt.free();

    res.json({ success: true, data: comments });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/admin/comments/stats', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const count = (sql) => {
      const s = db.prepare(sql);
      let c = 0;
      if (s.step()) c = s.getAsObject().count || 0;
      s.free();
      return c;
    };
    res.json({
      success: true,
      data: {
        total: count('SELECT COUNT(*) AS count FROM post_comments'),
        approved: count("SELECT COUNT(*) AS count FROM post_comments WHERE status = 'approved'"),
        pending: count("SELECT COUNT(*) AS count FROM post_comments WHERE status = 'pending'"),
        hidden: count("SELECT COUNT(*) AS count FROM post_comments WHERE status = 'hidden'")
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.patch('/api/admin/comments/:id/status', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const commentId = parseInt(req.params.id);
    const { status } = req.body;

    if (!['approved', 'pending', 'hidden'].includes(status)) {
      return res.status(400).json({ success: false, error: 'Недопустимый статус' });
    }

    const check = db.prepare('SELECT id FROM post_comments WHERE id = ?');
    check.bind([commentId]);
    const exists = check.step();
    check.free();
    if (!exists) return res.status(404).json({ success: false, error: 'Комментарий не найден' });

    const stmt = db.prepare("UPDATE post_comments SET status = ?, updated_at = datetime('now') WHERE id = ?");
    stmt.run([status, commentId]);
    stmt.free();
    saveDatabase();

    res.json({ success: true, message: 'Статус обновлён' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/admin/comments/:id', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const commentId = parseInt(req.params.id);

    const check = db.prepare('SELECT id FROM post_comments WHERE id = ?');
    check.bind([commentId]);
    const exists = check.step();
    check.free();
    if (!exists) return res.status(404).json({ success: false, error: 'Комментарий не найден' });

    db.prepare('DELETE FROM post_comments WHERE parent_id = ?').run([commentId]);
    db.prepare('DELETE FROM post_comments WHERE id = ?').run([commentId]);
    saveDatabase();

    res.json({ success: true, message: 'Комментарий удалён' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================
// ===== API АДМИНА: СТОП-СЛОВА ===============================
// ============================================================

app.get('/api/admin/stop-words', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare('SELECT id, word, created_at FROM stop_words ORDER BY word ASC');
    const words = [];
    while (stmt.step()) words.push(stmt.getAsObject());
    stmt.free();
    res.json({ success: true, data: words });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/stop-words', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { word } = req.body;
    if (!word || !String(word).trim()) {
      return res.status(400).json({ success: false, error: 'Укажите слово' });
    }
    const w = String(word).trim().toLowerCase();
    if (w.length < 2) {
      return res.status(400).json({ success: false, error: 'Минимум 2 символа' });
    }
    if (w.length > 40) {
      return res.status(400).json({ success: false, error: 'Максимум 40 символов' });
    }

    const check = db.prepare('SELECT id FROM stop_words WHERE LOWER(word) = ?');
    check.bind([w]);
    const exists = check.step();
    check.free();
    if (exists) return res.status(400).json({ success: false, error: 'Такое слово уже есть' });

    const stmt = db.prepare('INSERT INTO stop_words (word) VALUES (?)');
    stmt.run([w]);
    stmt.free();
    const idStmt = db.prepare('SELECT last_insert_rowid() as id');
    const newId = idStmt.step() ? idStmt.getAsObject().id : null;
    idStmt.free();
    saveDatabase();

    res.json({ success: true, message: 'Слово добавлено', id: newId, word: w });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/stop-words/bulk', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { words } = req.body;
    if (!Array.isArray(words) || !words.length) {
      return res.status(400).json({ success: false, error: 'Передайте массив слов' });
    }

    const stmt = db.prepare('INSERT OR IGNORE INTO stop_words (word) VALUES (?)');
    let added = 0;
    for (const w of words) {
      const word = String(w).trim().toLowerCase();
      if (word.length < 2 || word.length > 40) continue;
      try { stmt.run([word]); added++; } catch (e) {}
    }
    stmt.free();
    saveDatabase();

    res.json({ success: true, message: 'Добавлено слов: ' + added, added });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/admin/stop-words/:id', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare('DELETE FROM stop_words WHERE id = ?');
    stmt.run([parseInt(req.params.id)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Слово удалено' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ============================================================
// ===== API АДМИНА: БЭКАП БД =================================
// ============================================================

app.get('/api/admin/settings/export', requireAuth, (req, res) => {
  try {
    const dbPath = path.join(__dirname, 'database', 'cyberpunk.db');
    if (!fs.existsSync(dbPath)) {
      return res.status(404).json({ success: false, error: 'Файл БД не найден' });
    }
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    res.download(dbPath, 'cyberpunk_backup_' + stamp + '.db');
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

const backupTmpDir = path.join(__dirname, 'database', 'tmp');
if (!fs.existsSync(backupTmpDir)) fs.mkdirSync(backupTmpDir, { recursive: true });
const backupUpload = multer({ dest: backupTmpDir, limits: { fileSize: 50 * 1024 * 1024 } });

app.post('/api/admin/settings/import', requireAuth, backupUpload.single('backup'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'Файл не загружен' });

    const ext = (req.file.originalname || '').toLowerCase().split('.').pop();
    if (ext !== 'db') {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ success: false, error: 'Ожидается файл .db' });
    }

    const dbPath = path.join(__dirname, 'database', 'cyberpunk.db');
    const newPath = dbPath + '.new';

    fs.copyFileSync(req.file.path, newPath);
    fs.unlinkSync(req.file.path);

    res.json({
      success: true,
      message: 'Файл БД загружен. Перезапустите сервер, чтобы применить изменения.'
    });
  } catch (err) {
    if (req.file) { try { fs.unlinkSync(req.file.path); } catch (e) {} }
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================
// ===== API АДМИНА: НАСТРОЙКИ СТРАНИЦ =======================
// ============================================================

const BASE_PAGES = [
  { slug: 'index',    defaultTitle: 'CYBERPUNK // NEURO-GRID',        defaultMenu: 'Главная' },
  { slug: 'hub',      defaultTitle: 'CYBERPUNK // ЦЕНТРАЛЬНЫЙ ХАБ',   defaultMenu: 'Центральный_хаб' },
  { slug: 'stream',   defaultTitle: 'CYBERPUNK // ПОТОК ДАННЫХ',      defaultMenu: 'Поток_данных' },
  { slug: 'manifest', defaultTitle: 'CYBERPUNK // МАНИФЕСТ',          defaultMenu: 'Манифест' },
  { slug: 'logs',     defaultTitle: 'CYBERPUNK // АРХИВ ЛОГОВ',       defaultMenu: 'Логи' },
  { slug: 'matrix',   defaultTitle: 'CYBERPUNK // МАТРИЦА ОБРАЗОВ',   defaultMenu: 'Матрица_образов' },
  { slug: 'access',   defaultTitle: 'CYBERPUNK // ДОСТУП',            defaultMenu: 'Доступ' },
  { slug: 'ripper',   defaultTitle: 'CYBERPUNK // РИППЕРДОК',         defaultMenu: 'Риппердок' },
  { slug: 'cog',      defaultTitle: 'CYBERPUNK // КОГНИТИВНЫЙ ФИД',   defaultMenu: 'Когнитивный_фид' },
  { slug: 'implant',  defaultTitle: 'CYBERPUNK // ИМПЛАНТАТЫ',        defaultMenu: 'Имплантаты' }
];

app.get('/api/admin/pages', requireAuth, (req, res) => {
  try {
    const db = getDb();

    BASE_PAGES.forEach(p => ensurePageExists(db, p.slug, p.defaultTitle));
    saveDatabase();

    const result = BASE_PAGES.map(bp => {
      const stmt = db.prepare('SELECT id, title, content_json FROM pages WHERE slug = ?');
      stmt.bind([bp.slug]);
      let page = null;
      if (stmt.step()) page = stmt.getAsObject();
      stmt.free();

      let cfg = {};
      if (page && page.content_json) {
        try { cfg = JSON.parse(page.content_json); } catch (e) {}
      }

      return {
        id: page ? page.id : null,
        slug: bp.slug,
        title: page ? page.title : bp.defaultTitle,
        menu_label: cfg.menu_label || bp.defaultMenu,
        font_family: cfg.font_family || '',
        custom_head: cfg.custom_head || '',
        hero_image: cfg.hero_image || ''
      };
    });

    res.json({ success: true, data: result });
  } catch (err) {
    console.error('[admin/pages]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Загрузка hero-картинки
app.post('/api/admin/pages/:slug/hero', requireAuth, heroUpload.single('hero'), (req, res) => {
  try {
    const db = getDb();
    const slug = String(req.params.slug || '').trim();
    const bp = BASE_PAGES.find(p => p.slug === slug);
    if (!bp) {
      if (req.file) fs.unlink(req.file.path, () => {});
      return res.status(404).json({ success: false, error: 'Страница не найдена' });
    }

    if (!req.file) return res.status(400).json({ success: false, error: 'Файл не загружен' });

    ensurePageExists(db, slug, bp.defaultTitle);

    const find = db.prepare('SELECT id, content_json FROM pages WHERE slug = ?');
    find.bind([slug]);
    let page = null;
    if (find.step()) page = find.getAsObject();
    find.free();
    if (!page) {
      if (req.file) fs.unlink(req.file.path, () => {});
      return res.status(404).json({ success: false, error: 'Страница не найдена' });
    }

    let cfg = {};
    if (page.content_json) {
      try { cfg = JSON.parse(page.content_json); } catch (e) {}
    }

    if (cfg.hero_image && cfg.hero_image.startsWith('/uploads/heroes/')) {
      const oldPath = path.join(__dirname, 'public', cfg.hero_image);
      if (fs.existsSync(oldPath)) { try { fs.unlinkSync(oldPath); } catch (e) {} }
    }

    const heroUrl = '/uploads/heroes/' + req.file.filename;
    cfg.hero_image = heroUrl;

    const upd = db.prepare('UPDATE pages SET content_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
    upd.run([JSON.stringify(cfg), page.id]);
    upd.free();
    saveDatabase();

    res.json({ success: true, hero_image: heroUrl });
  } catch (err) {
    if (req.file) fs.unlink(req.file.path, () => {});
    console.error('[pages/hero]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Удаление hero-картинки
app.delete('/api/admin/pages/:slug/hero', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const slug = String(req.params.slug || '').trim();
    const bp = BASE_PAGES.find(p => p.slug === slug);
    if (!bp) return res.status(404).json({ success: false, error: 'Страница не найдена' });

    const find = db.prepare('SELECT id, content_json FROM pages WHERE slug = ?');
    find.bind([slug]);
    let page = null;
    if (find.step()) page = find.getAsObject();
    find.free();
    if (!page) return res.status(404).json({ success: false, error: 'Страница не найдена' });

    let cfg = {};
    if (page.content_json) {
      try { cfg = JSON.parse(page.content_json); } catch (e) {}
    }

    if (cfg.hero_image && cfg.hero_image.startsWith('/uploads/heroes/')) {
      const oldPath = path.join(__dirname, 'public', cfg.hero_image);
      if (fs.existsSync(oldPath)) { try { fs.unlinkSync(oldPath); } catch (e) {} }
    }

    cfg.hero_image = '';

    const upd = db.prepare('UPDATE pages SET content_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
    upd.run([JSON.stringify(cfg), page.id]);
    upd.free();
    saveDatabase();

    res.json({ success: true, message: 'Картинка удалена' });
  } catch (err) {
    console.error('[pages/hero delete]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/admin/pages/:slug', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const slug = String(req.params.slug || '').trim();
    const { title, menu_label, font_family, custom_head, hero_image } = req.body;

    const bp = BASE_PAGES.find(p => p.slug === slug);
    if (!bp) return res.status(404).json({ success: false, error: 'Страница не найдена' });

    ensurePageExists(db, slug, bp.defaultTitle);

    const find = db.prepare('SELECT id, content_json FROM pages WHERE slug = ?');
    find.bind([slug]);
    let page = null;
    if (find.step()) page = find.getAsObject();
    find.free();

    if (!page) return res.status(404).json({ success: false, error: 'Страница не найдена' });

    let cfg = {};
    if (page.content_json) {
      try { cfg = JSON.parse(page.content_json); } catch (e) {}
    }

    cfg.menu_label = String(menu_label || '').slice(0, 60);
    cfg.font_family = String(font_family || '').slice(0, 200);
    cfg.custom_head = String(custom_head || '').slice(0, 50000);
    if (hero_image !== undefined) cfg.hero_image = String(hero_image || '').slice(0, 500);
    else if (cfg.hero_image === undefined) cfg.hero_image = '';

    const cleanTitle = String(title || bp.defaultTitle).slice(0, 200);

    const upd = db.prepare('UPDATE pages SET title = ?, content_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
    upd.run([cleanTitle, JSON.stringify(cfg), page.id]);
    upd.free();
    saveDatabase();

    res.json({ success: true, message: 'Страница обновлена' });
  } catch (err) {
    console.error('[admin/pages] update', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================
// ===== API: ДОПОЛНИТЕЛЬНЫЕ СТРАНИЦЫ =========================
// ============================================================

const PARENT_PAGES = [
  { slug: 'hub',      label: 'Центральный_хаб' },
  { slug: 'stream',   label: 'Поток_данных' },
  { slug: 'logs',     label: 'Логи' },
  { slug: 'matrix',   label: 'Матрица_образов' },
  { slug: 'ripper',   label: 'Риппердок' },
  { slug: 'cog',      label: 'Когнитивный_фид' },
  { slug: 'implant',  label: 'Имплантаты' },
  { slug: 'manifest', label: 'Манифест' }
];

function parseCustomContentJson(raw) {
  try { return JSON.parse(raw || '{}'); } catch (e) { return {}; }
}

function getCustomPages(db) {
  const stmt = db.prepare("SELECT * FROM pages WHERE content_type = 'custom' ORDER BY id ASC");
  const items = [];
  while (stmt.step()) {
    const row = stmt.getAsObject();
    const cfg = parseCustomContentJson(row.content_json);
    items.push({
      id: row.id,
      slug: row.slug,
      title: row.title || '',
      menu_label: cfg.menu_label || row.title || row.slug,
      parent_slug: cfg.parent_slug || '',
      category: cfg.category || '',
      html_content: cfg.html_content || '',
      custom_head: cfg.custom_head || '',
      mode: cfg.mode || 'body',
      is_active: row.is_active ? 1 : 0,
      sort_order: cfg.sort_order || 0
    });
  }
  stmt.free();
  return items;
}

app.get('/api/pages/submenu/:parentSlug', (req, res) => {
  try {
    const db = getDb();
    const parentSlug = String(req.params.parentSlug || '').trim();
    const all = getCustomPages(db).filter(p => p.parent_slug === parentSlug && p.is_active);
    all.sort((a, b) => (a.sort_order - b.sort_order) || a.slug.localeCompare(b.slug));
    res.json({ success: true, data: all.map(p => ({
      slug: p.slug,
      title: p.title,
      menu_label: p.menu_label,
      category: p.category
    }))});
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

function renderCustomShell(page) {
  const db = getDb();
  const stmt = db.prepare("SELECT slug, title, content_json FROM pages WHERE content_type != 'custom' OR content_type IS NULL");
  const basePages = [];
  while (stmt.step()) basePages.push(stmt.getAsObject());
  stmt.free();

  const labels = {
    'hub': 'Центральный_хаб', 'stream': 'Поток_данных', 'manifest': 'Манифест',
    'logs': 'Логи', 'matrix': 'Матрица_образов', 'access': 'Доступ',
    'ripper': 'Риппердок', 'cog': 'Когнитивный_фид', 'implant': 'Имплантаты'
  };
  basePages.forEach(p => {
    if (p.content_json) {
      try {
        const cfg = JSON.parse(p.content_json);
        if (cfg.menu_label) labels[p.slug] = cfg.menu_label;
      } catch (e) {}
    }
  });

  const order = ['hub', 'stream', 'manifest', 'logs', 'matrix', 'access', 'ripper', 'cog', 'implant'];
  const menuHtml = order.map(s => {
    if (!labels[s]) return '';
    const active = s === page.parent_slug ? ' active' : '';
    return '<a href="/' + s + '" class="menu-item' + active + '">' + escapeHtmlStr(labels[s]) + '<span class="bracket">]</span></a>';
  }).join('');

  const headExtra = page.custom_head ? '\n' + page.custom_head : '';

  return `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtmlStr(page.title || page.slug)}</title>
<style>
  :root { --cyan: #00ffff; --magenta: #ff00ff; --green: #00ff00; --yellow: #ffcc00; --bg-dark: #05060a; --font-mono: 'Courier New', Courier, monospace; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg-dark); color: var(--cyan); font-family: var(--font-mono); overflow-x: hidden; cursor: crosshair; }
  body::after { content: ''; position: fixed; inset: 0; background: repeating-linear-gradient(0deg, rgba(0,0,0,0) 0px, rgba(0,0,0,0) 2px, rgba(0,0,0,0.08) 3px, rgba(0,0,0,0) 4px); pointer-events: none; z-index: 999; }
  .menu { position: fixed; top: 0; left: 50%; transform: translateX(-50%); display: flex; flex-wrap: wrap; justify-content: center; gap: 15px 25px; z-index: 100; padding: 15px 25px; background: rgba(5, 6, 10, 0.9); backdrop-filter: blur(10px); border-bottom: 1px solid rgba(0, 255, 255, 0.2); max-width: 95vw; }
  .menu-item { position: relative; padding: 6px 12px 6px 22px; font-size: 11px; letter-spacing: 1.5px; color: var(--cyan); text-transform: uppercase; cursor: pointer; transition: color 0.2s; white-space: nowrap; text-decoration: none; }
  .menu-item:hover { color: var(--magenta); text-shadow: 0 0 8px var(--magenta); }
  .menu-item.active { color: var(--yellow); text-shadow: 0 0 10px var(--yellow); }
  .menu-item .bracket { color: var(--magenta); opacity: 0; transition: opacity 0.2s; margin-left: 14px; }
  .menu-item:hover .bracket, .menu-item.active .bracket { opacity: 1; }
  .page-wrap { max-width: 1200px; margin: 0 auto; padding: 130px 20px 80px; }
  .custom-content { font-size: 14px; line-height: 1.8; color: rgba(255,255,255,0.85); }
  .custom-content h1, .custom-content h2, .custom-content h3 { color: #fff; letter-spacing: 3px; text-transform: uppercase; margin: 20px 0 15px; text-shadow: 0 0 10px rgba(0,255,255,0.5); }
  .custom-content h1::before, .custom-content h2::before { content: '> '; color: var(--cyan); }
  .custom-content a { color: var(--cyan); }
  .custom-content img { max-width: 100%; height: auto; border: 1px solid rgba(0,255,255,0.2); }
  .custom-content code { background: rgba(0,255,255,0.1); padding: 2px 6px; }
  .custom-content p { margin: 0 0 12px; }
  .custom-content ul, .custom-content ol { margin: 8px 0 12px 24px; }
  .custom-content blockquote { border-left: 3px solid var(--magenta); padding-left: 14px; margin: 12px 0; color: var(--yellow); font-style: italic; }
  .system-ticker { position: fixed; bottom: 0; left: 0; width: 100%; height: 28px; background: rgba(0, 5, 10, 0.95); border-top: 1px solid var(--cyan); display: flex; align-items: center; overflow: hidden; z-index: 90; font-size: 11px; letter-spacing: 2px; color: var(--cyan); }
  .ticker-track { display: flex; white-space: nowrap; animation: scrollTicker 25s linear infinite; }
  .ticker-track span { padding-right: 60px; display: flex; align-items: center; gap: 15px; }
  .ticker-track .separator { color: var(--magenta); font-weight: bold; }
  @keyframes scrollTicker { 0% { transform: translateX(0); } 100% { transform: translateX(-50%); } }
  ${headExtra}
</style>
</head>
<body data-page-slug="${escapeHtmlStr(page.parent_slug || '')}">
<nav class="menu">${menuHtml}</nav>
<div class="page-wrap">
  <div class="custom-content">${page.html_content || ''}</div>
</div>
<div class="system-ticker">
  <div class="ticker-track">
    <span>SYS.ONLINE <span class="separator">//</span> USER: GUEST <span class="separator">//</span> ENCRYPTION: AES-256 <span class="separator">//</span> SECURE_CHANNEL: ENABLED <span class="separator">//</span></span>
    <span>SYS.ONLINE <span class="separator">//</span> USER: GUEST <span class="separator">//</span> ENCRYPTION: AES-256 <span class="separator">//</span> SECURE_CHANNEL: ENABLED <span class="separator">//</span></span>
  </div>
</div>
<script src="/js/subnav.js" defer></script>
<script src="/js/user-nav.js"></script>
</body>
</html>`;
}

app.get('/page/:slug', (req, res) => {
  try {
    const db = getDb();
    const slug = String(req.params.slug || '').trim();
    const stmt = db.prepare("SELECT * FROM pages WHERE slug = ? AND content_type = 'custom'");
    stmt.bind([slug]);
    let row = null;
    if (stmt.step()) row = stmt.getAsObject();
    stmt.free();

    if (!row) {
      return res.status(404).type('html').send('<h1 style="font-family:monospace;color:#00ffff;text-align:center;padding:60px;">404 // СТРАНИЦА НЕ НАЙДЕНА</h1>');
    }
    if (!row.is_active) {
      return res.status(404).type('html').send('<h1 style="font-family:monospace;color:#ff0040;text-align:center;padding:60px;">403 // СТРАНИЦА СКРЫТА</h1>');
    }

    const cfg = parseCustomContentJson(row.content_json);

    if (cfg.mode === 'full' && cfg.html_content) {
      let html = String(cfg.html_content);

      if (html.indexOf('data-page-slug=') === -1) {
        html = html.replace(/<body([^>]*)>/i, function (m, attrs) {
          return '<body data-page-slug="' + (cfg.parent_slug || '') + '"' + attrs + '>';
        });
      }

      if (html.indexOf('/js/user-nav.js') === -1 && html.indexOf('</body>') !== -1) {
        html = html.replace(/<\/body>/i, '<script src="/js/user-nav.js"></script>\n</body>');
      }
      if (html.indexOf('/js/subnav.js') === -1 && html.indexOf('</body>') !== -1) {
        html = html.replace(/<\/body>/i, '<script src="/js/subnav.js" defer></script>\n</body>');
      }

      return res.type('html').send(html);
    }

    const page = {
      slug: row.slug,
      title: row.title || row.slug,
      parent_slug: cfg.parent_slug || '',
      html_content: cfg.html_content || '',
      custom_head: cfg.custom_head || ''
    };
    res.type('html').send(renderCustomShell(page));
  } catch (err) {
    console.error('[page/:slug]', err);
    res.status(500).type('html').send('Ошибка загрузки страницы');
  }
});

app.get('/api/admin/pages/custom', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const items = getCustomPages(db);
    res.json({ success: true, data: items });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/pages/custom', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { slug, title, menu_label, parent_slug, category, html_content, custom_head, mode, is_active, sort_order } = req.body;

    const cleanSlug = String(slug || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
    if (cleanSlug.length < 2 || cleanSlug.length > 50) {
      return res.status(400).json({ success: false, error: 'Slug: 2-50 символов, латиница/цифры/_-' });
    }
    if (!title || !String(title).trim()) {
      return res.status(400).json({ success: false, error: 'Укажите название' });
    }
    if (!parent_slug || !PARENT_PAGES.find(p => p.slug === parent_slug)) {
      return res.status(400).json({ success: false, error: 'Выберите родительскую страницу' });
    }

    const check = db.prepare('SELECT id FROM pages WHERE slug = ?');
    check.bind([cleanSlug]);
    if (check.step()) {
      check.free();
      return res.status(400).json({ success: false, error: 'Такой slug уже существует' });
    }
    check.free();

    const cfg = {
      menu_label: String(menu_label || '').slice(0, 60) || String(title).slice(0, 60),
      parent_slug: String(parent_slug),
      category: String(category || '').slice(0, 60),
      html_content: String(html_content || '').slice(0, 200000),
      custom_head: String(custom_head || '').slice(0, 50000),
      mode: (mode === 'full' ? 'full' : 'body'),
      sort_order: parseInt(sort_order || 0, 10) || 0
    };

    const stmt = db.prepare("INSERT INTO pages (slug, title, content_type, content_json, is_active) VALUES (?, ?, 'custom', ?, ?)");
    stmt.run([cleanSlug, String(title).slice(0, 200), JSON.stringify(cfg), is_active ? 1 : 1]);
    stmt.free();
    saveDatabase();

    res.json({ success: true, message: 'Страница создана', slug: cleanSlug });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/admin/pages/custom/:slug', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const slug = String(req.params.slug || '').trim();
    const { title, menu_label, parent_slug, category, html_content, custom_head, mode, is_active, sort_order } = req.body;

    if (!title || !String(title).trim()) {
      return res.status(400).json({ success: false, error: 'Укажите название' });
    }
    if (!parent_slug || !PARENT_PAGES.find(p => p.slug === parent_slug)) {
      return res.status(400).json({ success: false, error: 'Выберите родительскую страницу' });
    }

    const check = db.prepare("SELECT id FROM pages WHERE slug = ? AND content_type = 'custom'");
    check.bind([slug]);
    if (!check.step()) {
      check.free();
      return res.status(404).json({ success: false, error: 'Страница не найдена' });
    }
    check.free();

    const cfg = {
      menu_label: String(menu_label || '').slice(0, 60) || String(title).slice(0, 60),
      parent_slug: String(parent_slug),
      category: String(category || '').slice(0, 60),
      html_content: String(html_content || '').slice(0, 200000),
      custom_head: String(custom_head || '').slice(0, 50000),
      mode: (mode === 'full' ? 'full' : 'body'),
      sort_order: parseInt(sort_order || 0, 10) || 0
    };

    const stmt = db.prepare("UPDATE pages SET title = ?, content_json = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE slug = ? AND content_type = 'custom'");
    stmt.run([String(title).slice(0, 200), JSON.stringify(cfg), is_active ? 1 : 0, slug]);
    stmt.free();
    saveDatabase();

    res.json({ success: true, message: 'Страница обновлена' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/admin/pages/custom/:slug', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const slug = String(req.params.slug || '').trim();
    const stmt = db.prepare("DELETE FROM pages WHERE slug = ? AND content_type = 'custom'");
    stmt.run([slug]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Страница удалена' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ============================================================
// ===== AI-АССИСТЕНТ (DeepSeek) ==============================
// ============================================================

const AI_IGNORE_DIRS = ['node_modules', 'database', '.git', 'uploads', '.vscode', 'tmp', 'public/uploads'];
const AI_MAX_FILE = 200 * 1024;
const AI_MAX_RESULTS = 30;

function aiSafePath(relPath) {
  const cleaned = String(relPath || '').replace(/\\/g, '/').replace(/^\/+/, '');
  if (cleaned.includes('..')) return null;
  const full = path.join(__dirname, cleaned);
  if (!full.startsWith(__dirname)) return null;
  return full;
}

function aiShouldSkip(name) {
  if (AI_IGNORE_DIRS.includes(name)) return true;
  if (name.endsWith('.db') || name.endsWith('.db.new')) return true;
  if (name === '.env') return true;
  return false;
}

function aiListFiles(dir) {
  const full = aiSafePath(dir || '.');
  if (!full || !fs.existsSync(full)) return { error: 'not found' };
  const stat = fs.statSync(full);
  if (!stat.isDirectory()) return { error: 'not a directory' };
  const items = fs.readdirSync(full);
  const result = [];
  for (const name of items) {
    if (aiShouldSkip(name)) continue;
    const childPath = path.join(full, name);
    try {
      const st = fs.statSync(childPath);
      const rel = path.relative(__dirname, childPath).replace(/\\/g, '/');
      result.push({
        name: name,
        path: rel,
        type: st.isDirectory() ? 'dir' : 'file',
        size: st.isDirectory() ? 0 : st.size
      });
    } catch (e) {}
  }
  return { items: result };
}

function aiReadFile(relPath) {
  const full = aiSafePath(relPath);
  if (!full || !fs.existsSync(full)) return { error: 'not found' };
  const stat = fs.statSync(full);
  if (stat.isDirectory()) return { error: 'is directory' };
  if (stat.size > AI_MAX_FILE) return { error: 'file too large (>' + Math.round(AI_MAX_FILE/1024) + 'KB)' };
  const content = fs.readFileSync(full, 'utf8');
  return { path: relPath, content: content, size: stat.size };
}

function aiSearchCode(query, dir) {
  if (!query || query.length < 2) return { error: 'query too short' };
  const root = aiSafePath(dir || '.');
  if (!root) return { error: 'bad dir' };
  const results = [];

  function walk(current) {
    if (results.length >= AI_MAX_RESULTS) return;
    let items;
    try { items = fs.readdirSync(current); } catch (e) { return; }
    for (const name of items) {
      if (results.length >= AI_MAX_RESULTS) return;
      if (aiShouldSkip(name)) continue;
      const childPath = path.join(current, name);
      let st;
      try { st = fs.statSync(childPath); } catch (e) { continue; }
      if (st.isDirectory()) {
        walk(childPath);
      } else {
        if (st.size > AI_MAX_FILE) continue;
        const ext = path.extname(name).toLowerCase();
        if (!['.js', '.json', '.html', '.css', '.md', '.txt'].includes(ext)) continue;
        try {
          const text = fs.readFileSync(childPath, 'utf8');
          const lines = text.split('\n');
          for (let i = 0; i < lines.length; i++) {
            if (results.length >= AI_MAX_RESULTS) break;
            if (lines[i].toLowerCase().includes(query.toLowerCase())) {
              const rel = path.relative(__dirname, childPath).replace(/\\/g, '/');
              results.push({ path: rel, line: i + 1, text: lines[i].trim().slice(0, 200) });
            }
          }
        } catch (e) {}
      }
    }
  }
  walk(root);
  return { results: results };
}

const AI_TOOLS = [
  {
    type: 'function',
    function: {
      name: 'list_files',
      description: 'Показать содержимое директории проекта. Используй "." для корня.',
      parameters: {
        type: 'object',
        properties: { directory: { type: 'string', description: 'Относительный путь к директории' } }
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'read_file',
      description: 'Прочитать содержимое файла по относительному пути.',
      parameters: {
        type: 'object',
        properties: { path: { type: 'string', description: 'Например "server.js"' } },
        required: ['path']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'search_code',
      description: 'Найти строку/паттерн в файлах проекта.',
      parameters: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Что искать' },
          directory: { type: 'string', description: 'Где искать. По умолчанию "."' }
        },
        required: ['query']
      }
    }
  }
];

async function aiCallDeepSeek(apiKey, model, messages) {
  const body = {
    model: model || 'deepseek-chat',
    messages: messages,
    temperature: 0.3,
    tools: AI_TOOLS
  };

  const r = await fetch('https://api.deepseek.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + apiKey
    },
    body: JSON.stringify(body)
  });

  if (!r.ok) {
    const errText = await r.text();
    throw new Error('DeepSeek API ' + r.status + ': ' + errText.slice(0, 400));
  }
  return await r.json();
}

app.post('/api/admin/ai/chat', requireAuth, async (req, res) => {
  try {
    const db = getDb();
    const { messages } = req.body;
    if (!Array.isArray(messages) || !messages.length) {
      return res.status(400).json({ success: false, error: 'Пустая история' });
    }

    const settings = {};
    const st = db.prepare('SELECT key, value FROM settings');
    while (st.step()) { const r = st.getAsObject(); settings[r.key] = r.value; }
    st.free();

    const apiKey = settings.deepseek_api_key || process.env.DEEPSEEK_API_KEY || '';
    const model = settings.deepseek_model || 'deepseek-chat';

    if (!apiKey) {
      return res.status(400).json({ success: false, error: 'Не указан DeepSeek API-ключ. Настройки → AI.' });
    }

    const sysPrompt = {
      role: 'system',
      content: [
        'Ты — AI-ассистент, встроенный в админку проекта CYBERPUNK_DRIVE.',
        'Стек: Node.js + Express, база — sql.js (файл database/cyberpunk.db), фронт — чистый HTML/CSS/JS.',
        'Основные файлы: server.js, config/database.js, config/upload.js, admin/*.html, public/js/*.js, *.html в корне.',
        '',
        'Доступные инструменты:',
        '- list_files(directory) — показать файлы в директории.',
        '- read_file(path) — прочитать файл.',
        '- search_code(query, directory) — найти строку в коде.',
        '',
        'Правила:',
        '1. Не проси пользователя вставить код — вызывай инструменты и читай сам.',
        '2. Когда предлагаешь код — давай файл целиком, готовый к вставке.',
        '3. Отвечай по-русски, кратко.',
        '4. После изменений в server.js напоминай: нужно перезапустить сервер.',
        '5. Не выдумывай функции и файлы — проверяй через инструменты.'
      ].join('\n')
    };

    const convo = [sysPrompt].concat(messages);
    const toolTrace = [];
    const MAX_STEPS = 6;

    for (let step = 0; step < MAX_STEPS; step++) {
      const apiRes = await aiCallDeepSeek(apiKey, model, convo);
      const choice = apiRes.choices && apiRes.choices[0];
      if (!choice) throw new Error('Пустой ответ от DeepSeek');

      const msg = choice.message;
      convo.push(msg);

      if (msg.tool_calls && msg.tool_calls.length) {
        for (const call of msg.tool_calls) {
          let args = {};
          try { args = JSON.parse(call.function.arguments || '{}'); } catch (e) {}

          let result = { error: 'unknown tool' };
          if (call.function.name === 'list_files') result = aiListFiles(args.directory || '.');
          else if (call.function.name === 'read_file') result = aiReadFile(args.path || '');
          else if (call.function.name === 'search_code') result = aiSearchCode(args.query || '', args.directory || '.');

          let summary = 'ок';
          if (result.error) summary = 'ошибка: ' + result.error;
          else if (result.items) summary = 'найдено элементов: ' + result.items.length;
          else if (result.results) summary = 'совпадений: ' + result.results.length;
          else if (result.content) summary = 'прочитано ' + result.size + ' байт';

          toolTrace.push({ tool: call.function.name, args: args, summary: summary });

          convo.push({
            role: 'tool',
            tool_call_id: call.id,
            content: JSON.stringify(result).slice(0, 50000)
          });
        }
        continue;
      }

      return res.json({
        success: true,
        reply: msg.content || '',
        tool_trace: toolTrace,
        model: apiRes.model || model,
        usage: apiRes.usage || null
      });
    }

    res.json({
      success: true,
      reply: 'Не удалось завершить за ' + MAX_STEPS + ' шагов. Уточните вопрос.',
      tool_trace: toolTrace
    });
  } catch (err) {
    console.error('[ai/chat]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================
// ===== API АДМИНА: ГЛОБАЛЬНЫЙ ПОИСК ========================
// ============================================================

app.get('/api/admin/search', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const q = String(req.query.q || '').trim();
    if (q.length < 2) {
      return res.json({ success: true, data: { results: [], query: q } });
    }

    const like = '%' + q + '%';
    const limit = 5;

    const query = (sql, params) => {
      const stmt = db.prepare(sql);
      stmt.bind(params);
      const rows = [];
      while (stmt.step()) rows.push(stmt.getAsObject());
      stmt.free();
      return rows;
    };

    const results = [];

    query(`SELECT id, username, email FROM users WHERE username LIKE ? OR email LIKE ? ORDER BY created_at DESC LIMIT ?`, [like, like, limit])
      .forEach(r => results.push({ type: 'user', icon: '◈', title: r.username, subtitle: r.email || '', url: '/admin/users', id: r.id }));

    query(`SELECT id, title, status FROM posts WHERE title LIKE ? OR content LIKE ? ORDER BY created_at DESC LIMIT ?`, [like, like, limit])
      .forEach(r => results.push({ type: 'post', icon: '◊', title: r.title, subtitle: 'Статус: ' + r.status, url: '/admin/posts', id: r.id }));

    query(`SELECT id, content FROM post_comments WHERE content LIKE ? ORDER BY created_at DESC LIMIT ?`, [like, limit])
      .forEach(r => {
        const plain = String(r.content || '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
        results.push({ type: 'comment', icon: '◉', title: plain.slice(0, 80) + (plain.length > 80 ? '…' : ''), subtitle: 'Комментарий', url: '/admin/comments', id: r.id });
      });

    query(`SELECT id, title FROM news WHERE title LIKE ? OR content LIKE ? ORDER BY created_at DESC LIMIT ?`, [like, like, limit])
      .forEach(r => results.push({ type: 'news', icon: '◆', title: r.title, subtitle: 'Новость', url: '/admin/news', id: r.id }));

    query(`SELECT id, title, author_name FROM books WHERE title LIKE ? OR author_name LIKE ? ORDER BY created_at DESC LIMIT ?`, [like, like, limit])
      .forEach(r => results.push({ type: 'book', icon: '▣', title: r.title, subtitle: r.author_name || '', url: '/admin/books', id: r.id }));

    query(`SELECT id, name, price FROM merch_items WHERE name LIKE ? OR description LIKE ? ORDER BY created_at DESC LIMIT ?`, [like, like, limit])
      .forEach(r => results.push({ type: 'merch', icon: '◐', title: r.name, subtitle: r.price + ' ₽', url: '/admin/merch', id: r.id }));

    query(`SELECT id, customer_name, customer_email, total_amount, status FROM orders WHERE customer_name LIKE ? OR customer_email LIKE ? ORDER BY created_at DESC LIMIT ?`, [like, like, limit])
      .forEach(r => results.push({ type: 'order', icon: '◇', title: '#' + r.id + ' — ' + r.customer_name, subtitle: r.customer_email + ' • ' + r.total_amount + ' ₽ • ' + r.status, url: '/admin/orders', id: r.id }));

    res.json({ success: true, data: { results, query: q } });
  } catch (err) {
    console.error('[admin/search]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================
// ===== API АДМИНА: ПОСТЫ ====================================
// ============================================================

app.get('/api/admin/posts', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { status, category } = req.query;
    let query = `SELECT p.*, u.username as author_name FROM posts p LEFT JOIN users u ON p.author_id = u.id WHERE 1=1`;
    const params = [];
    if (status && status !== 'all') { query += ' AND p.status = ?'; params.push(status); }
    if (category && category !== 'all') { query += ' AND p.category = ?'; params.push(category); }
    query += ' ORDER BY p.created_at DESC';

    const stmt = db.prepare(query);
    stmt.bind(params);
    const posts = [];
    while (stmt.step()) posts.push(stmt.getAsObject());
    stmt.free();
    res.json({ success: true, data: posts });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/admin/posts/:id', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare(`SELECT p.*, u.username as author_name FROM posts p LEFT JOIN users u ON p.author_id = u.id WHERE p.id = ?`);
    stmt.bind([parseInt(req.params.id)]);
    let post = null;
    if (stmt.step()) post = stmt.getAsObject();
    stmt.free();
    if (!post) return res.status(404).json({ success: false, error: 'Пост не найден' });
    res.json({ success: true, data: post });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/posts', requireMinRole('operator'), (req, res) => {
  try {
    const db = getDb();
    const { title, content, category, tags, is_subscriber_only, status = 'published' } = req.body;
    if (!title || !content || !category) return res.status(400).json({ success: false, error: 'Заполните обязательные поля' });
    const stmt = db.prepare(`INSERT INTO posts (author_id, title, content, category, tags, is_subscriber_only, status) VALUES (?, ?, ?, ?, ?, ?, ?)`);
    stmt.run([req.user.id, title, content, category, tags || '', is_subscriber_only ? 1 : 0, status]);
    stmt.free();
    const idStmt = db.prepare('SELECT last_insert_rowid() as id');
    let newId = idStmt.step() ? idStmt.getAsObject().id : null;
    idStmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Пост создан', id: newId });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/admin/posts/:id', requireMinRole('operator'), (req, res) => {
  try {
    const db = getDb();
    const { title, content, category, tags, is_subscriber_only } = req.body;
    const stmt = db.prepare(`UPDATE posts SET title = ?, content = ?, category = ?, tags = ?, is_subscriber_only = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`);
    stmt.run([title, content, category, tags || '', is_subscriber_only ? 1 : 0, parseInt(req.params.id)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Пост обновлён' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.patch('/api/admin/posts/:id/status', requireMinRole('operator'), (req, res) => {
  try {
    const db = getDb();
    const { status } = req.body;
    if (!['published', 'pending', 'archived'].includes(status)) return res.status(400).json({ success: false, error: 'Недопустимый статус' });
    const stmt = db.prepare(`UPDATE posts SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`);
    stmt.run([status, parseInt(req.params.id)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Статус изменён' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/admin/posts/:id', requireMinRole('operator'), (req, res) => {
  try {
    const db = getDb();
    db.prepare('DELETE FROM posts WHERE id = ?').run([parseInt(req.params.id)]);
    saveDatabase();
    res.json({ success: true, message: 'Пост удалён' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/posts/:id/image', requireMinRole('operator'), uploadPost.single('image'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'Файл не загружен' });
    const db = getDb();
    const stmt = db.prepare('UPDATE posts SET image_path = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
    stmt.run(['/uploads/posts/' + req.file.filename, parseInt(req.params.id)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, image_path: '/uploads/posts/' + req.file.filename });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ===== API АДМИНА: НОВОСТИ =====
app.get('/api/admin/news', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare('SELECT * FROM news ORDER BY created_at DESC');
    const news = [];
    while (stmt.step()) news.push(stmt.getAsObject());
    stmt.free();
    res.json({ success: true, data: news });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/news', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { title, content, source, priority = 'info', category = 'general' } = req.body;
    if (!title || !content) return res.status(400).json({ success: false, error: 'Заполните обязательные поля' });
    const stmt = db.prepare(`INSERT INTO news (title, content, source, priority, category) VALUES (?, ?, ?, ?, ?)`);
    stmt.run([title, content, source || '', priority, category]);
    stmt.free();
    const idStmt = db.prepare('SELECT last_insert_rowid() as id');
    let newId = idStmt.step() ? idStmt.getAsObject().id : null;
    idStmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Новость создана', id: newId });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/admin/news/:id', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { title, content, source, priority, category } = req.body;
    const stmt = db.prepare(`UPDATE news SET title = ?, content = ?, source = ?, priority = ?, category = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`);
    stmt.run([title, content, source || '', priority, category, parseInt(req.params.id)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Новость обновлена' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/admin/news/:id', requireAuth, (req, res) => {
  try {
    const db = getDb();
    db.prepare('DELETE FROM news WHERE id = ?').run([parseInt(req.params.id)]);
    saveDatabase();
    res.json({ success: true, message: 'Новость удалена' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/news/:id/image', requireAuth, uploadNews.single('image'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'Файл не загружен' });
    const db = getDb();
    const stmt = db.prepare('UPDATE news SET image_path = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
    stmt.run(['/uploads/news/' + req.file.filename, parseInt(req.params.id)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, image_path: '/uploads/news/' + req.file.filename });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ===== API АДМИНА: КНИГИ =====
app.get('/api/admin/books', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare('SELECT * FROM books ORDER BY created_at DESC');
    const books = [];
    while (stmt.step()) books.push(stmt.getAsObject());
    stmt.free();
    res.json({ success: true, data: books });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/admin/books/:id', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare('SELECT * FROM books WHERE id = ?');
    stmt.bind([parseInt(req.params.id)]);
    let book = null;
    if (stmt.step()) book = stmt.getAsObject();
    stmt.free();
    if (!book) return res.status(404).json({ success: false, error: 'Книга не найдена' });
    res.json({ success: true, data: book });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/books', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { title, author_name, genre, description, status = 'draft' } = req.body;
    if (!title || !author_name) return res.status(400).json({ success: false, error: 'Заполните название и автора' });
    const stmt = db.prepare(`INSERT INTO books (title, author_name, genre, description, status, file_path, cover_path, file_type, file_size) VALUES (?, ?, ?, ?, ?, '', '', '', 0)`);
    stmt.run([title, author_name, genre || 'cyberpunk', description || '', status]);
    stmt.free();
    const idStmt = db.prepare('SELECT last_insert_rowid() as id');
    let newId = idStmt.step() ? idStmt.getAsObject().id : null;
    idStmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Книга создана', id: newId });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/admin/books/:id', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { title, author_name, genre, description, status } = req.body;
    const stmt = db.prepare(`UPDATE books SET title = ?, author_name = ?, genre = ?, description = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`);
    stmt.run([title, author_name, genre, description || '', status, parseInt(req.params.id)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Книга обновлена' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/admin/books/:id', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const bookId = parseInt(req.params.id);
    const stmt = db.prepare('SELECT file_path, cover_path FROM books WHERE id = ?');
    stmt.bind([bookId]);
    let book = null;
    if (stmt.step()) book = stmt.getAsObject();
    stmt.free();
    if (book) {
      if (book.file_path) { const p = path.join(__dirname, 'public', book.file_path); if (fs.existsSync(p)) fs.unlinkSync(p); }
      if (book.cover_path) { const p = path.join(__dirname, 'public', book.cover_path); if (fs.existsSync(p)) fs.unlinkSync(p); }
    }
    db.prepare('DELETE FROM books WHERE id = ?').run([bookId]);
    saveDatabase();
    res.json({ success: true, message: 'Книга удалена' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/books/:id/file', requireAuth, uploadBookFile.single('file'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'Файл не загружен' });
    const db = getDb();
    const filePath = '/uploads/books/files/' + req.file.filename;
    const stmt = db.prepare('UPDATE books SET file_path = ?, file_type = ?, file_size = ? WHERE id = ?');
    stmt.run([filePath, req.file.originalname.split('.').pop().toLowerCase(), req.file.size, parseInt(req.params.id)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, file_path: filePath });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/books/:id/cover', requireAuth, uploadBookCover.single('cover'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'Файл не загружен' });
    const db = getDb();
    const coverPath = '/uploads/books/covers/' + req.file.filename;
    const stmt = db.prepare('UPDATE books SET cover_path = ? WHERE id = ?');
    stmt.run([coverPath, parseInt(req.params.id)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, cover_path: coverPath });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/admin/books/:id/cover', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const bookId = parseInt(req.params.id);
    const stmt = db.prepare('SELECT cover_path FROM books WHERE id = ?');
    stmt.bind([bookId]);
    let book = null;
    if (stmt.step()) book = stmt.getAsObject();
    stmt.free();
    if (book && book.cover_path) {
      const fullPath = path.join(__dirname, 'public', book.cover_path);
      if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
    }
    db.prepare('UPDATE books SET cover_path = \'\' WHERE id = ?').run([bookId]);
    saveDatabase();
    res.json({ success: true, message: 'Обложка удалена' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/admin/books/:id/file', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const bookId = parseInt(req.params.id);
    const stmt = db.prepare('SELECT file_path FROM books WHERE id = ?');
    stmt.bind([bookId]);
    let book = null;
    if (stmt.step()) book = stmt.getAsObject();
    stmt.free();
    if (book && book.file_path) {
      const fullPath = path.join(__dirname, 'public', book.file_path);
      if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
    }
    db.prepare('UPDATE books SET file_path = \'\', file_type = \'\', file_size = 0 WHERE id = ?').run([bookId]);
    saveDatabase();
    res.json({ success: true, message: 'Файл удалён' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ===== ГАЛЕРЕЯ =====
function translitSlug(str) {
  const map = { 'а':'a','б':'b','в':'v','г':'g','д':'d','е':'e','ё':'e','ж':'zh','з':'z','и':'i','й':'y','к':'k','л':'l','м':'m','н':'n','о':'o','п':'p','р':'r','с':'s','т':'t','у':'u','ф':'f','х':'h','ц':'c','ч':'ch','ш':'sh','щ':'sch','ъ':'','ы':'y','ь':'','э':'e','ю':'yu','я':'ya' };
  return String(str || '').toLowerCase().split('').map(ch => map[ch] !== undefined ? map[ch] : ch).join('').replace(/[^a-z0-9_]+/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '');
}
function normalizeItemType(type) {
  if (type === 'photo' || type === 'image') return 'photo';
  if (type === 'video') return 'video';
  return null;
}
function parseAlbumId(raw) {
  if (raw == null || raw === 'default' || raw === 'all' || raw === '') return null;
  const n = parseInt(raw, 10);
  if (Number.isNaN(n) || n <= 0) return null;
  return n;
}

app.get('/api/admin/gallery-albums', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare('SELECT * FROM gallery_albums ORDER BY created_at DESC');
    const albums = [];
    while (stmt.step()) albums.push(stmt.getAsObject());
    stmt.free();
    res.json({ success: true, data: albums });
  } catch (err) { res.status(500).json({ success: false, error: 'Ошибка сервера' }); }
});

app.post('/api/admin/gallery-albums', requireAuth, (req, res) => {
  try {
    const { name, description } = req.body;
    if (!name || !String(name).trim()) return res.status(400).json({ success: false, error: 'Название обязательно' });
    const db = getDb();
    const baseSlug = translitSlug(name) || 'album';
    let slug = baseSlug, counter = 1;
    while (true) {
      const check = db.prepare('SELECT id FROM gallery_albums WHERE slug = ?');
      check.bind([slug]);
      const exists = check.step();
      check.free();
      if (!exists) break;
      slug = baseSlug + '-' + (++counter);
      if (counter > 1000) { slug = baseSlug + '-' + Date.now(); break; }
    }
    const stmt = db.prepare(`INSERT INTO gallery_albums (name, slug, description, created_at) VALUES (?, ?, ?, datetime('now'))`);
    stmt.run([String(name).trim(), slug, String(description || '').trim()]);
    stmt.free();
    const idStmt = db.prepare('SELECT last_insert_rowid() as id');
    const newId = idStmt.step() ? idStmt.getAsObject().id : null;
    idStmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Альбом создан', id: newId, slug });
  } catch (err) { res.status(500).json({ success: false, error: 'Ошибка сервера' }); }
});

app.delete('/api/admin/gallery-albums/:id', requireAuth, (req, res) => {
  try {
    const albumId = parseInt(req.params.id, 10);
    if (Number.isNaN(albumId)) return res.status(400).json({ success: false, error: 'Неверный ID' });
    const db = getDb();
    const check = db.prepare('SELECT id, name FROM gallery_albums WHERE id = ?');
    check.bind([albumId]);
    let album = null;
    if (check.step()) album = check.getAsObject();
    check.free();
    if (!album) return res.status(404).json({ success: false, error: 'Альбом не найден' });
    db.prepare('UPDATE gallery_items SET album_id = NULL WHERE album_id = ?').run([albumId]);
    db.prepare('DELETE FROM gallery_albums WHERE id = ?').run([albumId]);
    saveDatabase();
    res.json({ success: true, message: 'Альбом «' + album.name + '» удалён' });
  } catch (err) { res.status(500).json({ success: false, error: 'Ошибка сервера' }); }
});

app.get('/api/admin/gallery-items', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { type, album } = req.query;
    let query = 'SELECT * FROM gallery_items WHERE 1=1';
    const params = [];
    if (type && type !== 'all') { query += ' AND type = ?'; params.push(type); }
    if (album && album !== 'all') {
      if (album === 'default') { query += ' AND (album_id IS NULL OR album_id = 0)'; }
      else {
        const aid = parseInt(album, 10);
        if (!Number.isNaN(aid) && aid > 0) { query += ' AND album_id = ?'; params.push(aid); }
      }
    }
    query += ' ORDER BY created_at DESC';
    const stmt = db.prepare(query);
    stmt.bind(params);
    const items = [];
    while (stmt.step()) items.push(stmt.getAsObject());
    stmt.free();
    res.json({ success: true, data: items });
  } catch (err) { res.status(500).json({ success: false, error: 'Ошибка сервера' }); }
});

app.get('/api/admin/gallery-items/:id', requireAuth, (req, res) => {
  try {
    const itemId = parseInt(req.params.id, 10);
    if (Number.isNaN(itemId)) return res.status(400).json({ success: false, error: 'Неверный ID' });
    const db = getDb();
    const stmt = db.prepare('SELECT * FROM gallery_items WHERE id = ?');
    stmt.bind([itemId]);
    let item = null;
    if (stmt.step()) item = stmt.getAsObject();
    stmt.free();
    if (!item) return res.status(404).json({ success: false, error: 'Не найдено' });
    res.json({ success: true, data: item });
  } catch (err) { res.status(500).json({ success: false, error: 'Ошибка сервера' }); }
});

app.post('/api/admin/gallery-items', requireAuth, (req, res) => {
  try {
    const { title, type, album_id, description } = req.body;
    if (!title || !String(title).trim()) return res.status(400).json({ success: false, error: 'Название обязательно' });
    const normType = normalizeItemType(type);
    if (!normType) return res.status(400).json({ success: false, error: 'Тип должен быть photo или video' });
    const albumId = parseAlbumId(album_id);
    const db = getDb();
    const stmt = db.prepare(`INSERT INTO gallery_items (title, type, album_id, description, file_path, created_at, updated_at) VALUES (?, ?, ?, ?, '', datetime('now'), datetime('now'))`);
    stmt.run([String(title).trim(), normType, albumId, String(description || '')]);
    stmt.free();
    const idStmt = db.prepare('SELECT last_insert_rowid() as id');
    const newId = idStmt.step() ? idStmt.getAsObject().id : null;
    idStmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Элемент создан', id: newId });
  } catch (err) { res.status(500).json({ success: false, error: 'Ошибка сервера' }); }
});

app.put('/api/admin/gallery-items/:id', requireAuth, (req, res) => {
  try {
    const itemId = parseInt(req.params.id, 10);
    if (Number.isNaN(itemId)) return res.status(400).json({ success: false, error: 'Неверный ID' });
    const { title, type, album_id, description } = req.body;
    if (!title || !String(title).trim()) return res.status(400).json({ success: false, error: 'Название обязательно' });
    const normType = normalizeItemType(type);
    if (!normType) return res.status(400).json({ success: false, error: 'Тип должен быть photo или video' });
    const albumId = parseAlbumId(album_id);
    const db = getDb();
    const stmt = db.prepare(`UPDATE gallery_items SET title = ?, type = ?, album_id = ?, description = ?, updated_at = datetime('now') WHERE id = ?`);
    stmt.run([String(title).trim(), normType, albumId, String(description || ''), itemId]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Элемент обновлён' });
  } catch (err) { res.status(500).json({ success: false, error: 'Ошибка сервера' }); }
});

app.delete('/api/admin/gallery-items/:id', requireAuth, (req, res) => {
  try {
    const itemId = parseInt(req.params.id, 10);
    if (Number.isNaN(itemId)) return res.status(400).json({ success: false, error: 'Неверный ID' });
    const db = getDb();
    const sel = db.prepare('SELECT file_path FROM gallery_items WHERE id = ?');
    sel.bind([itemId]);
    let item = null;
    if (sel.step()) item = sel.getAsObject();
    sel.free();
    if (!item) return res.status(404).json({ success: false, error: 'Не найдено' });
    db.prepare('DELETE FROM gallery_items WHERE id = ?').run([itemId]);
    saveDatabase();
    if (item.file_path && item.file_path.startsWith('/uploads/gallery/')) {
      const rel = item.file_path.replace(/^\/uploads\//, '');
      const fullPath = path.join(__dirname, 'public', 'uploads', rel);
      fs.unlink(fullPath, () => {});
    }
    res.json({ success: true, message: 'Элемент удалён' });
  } catch (err) { res.status(500).json({ success: false, error: 'Ошибка сервера' }); }
});

const galleryUploadsRoot = path.join(__dirname, 'public', 'uploads', 'gallery');
const galleryImagesDir = path.join(galleryUploadsRoot, 'images');
const galleryVideosDir = path.join(galleryUploadsRoot, 'videos');
if (!fs.existsSync(galleryImagesDir)) fs.mkdirSync(galleryImagesDir, { recursive: true });
if (!fs.existsSync(galleryVideosDir)) fs.mkdirSync(galleryVideosDir, { recursive: true });

const galleryStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const isVideo = (file.mimetype || '').startsWith('video/');
    cb(null, isVideo ? galleryVideosDir : galleryImagesDir);
  },
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname).toLowerCase());
  }
});
const galleryUpload = multer({
  storage: galleryStorage,
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = (file.mimetype || '').split('/').pop().toLowerCase();
    const ok = /^(jpeg|jpg|png|webp|gif|mp4|webm)$/.test(ext);
    cb(ok ? null : new Error('Разрешены только изображения и видео'), ok);
  }
});

app.post('/api/admin/gallery-items/:id/file', requireAuth, galleryUpload.single('file'), (req, res) => {
  try {
    const itemId = parseInt(req.params.id, 10);
    if (Number.isNaN(itemId)) { if (req.file) fs.unlink(req.file.path, () => {}); return res.status(400).json({ success: false, error: 'Неверный ID' }); }
    if (!req.file) return res.status(400).json({ success: false, error: 'Файл не загружен' });
    const isVideo = (req.file.mimetype || '').startsWith('video/');
    const filePath = isVideo ? '/uploads/gallery/videos/' + req.file.filename : '/uploads/gallery/images/' + req.file.filename;
    const db = getDb();
    const check = db.prepare('SELECT id, file_path FROM gallery_items WHERE id = ?');
    check.bind([itemId]);
    let existing = null;
    if (check.step()) existing = check.getAsObject();
    check.free();
    if (!existing) { fs.unlink(req.file.path, () => {}); return res.status(404).json({ success: false, error: 'Элемент не найден' }); }
    if (existing.file_path && existing.file_path.startsWith('/uploads/gallery/') && existing.file_path !== filePath) {
      const rel = existing.file_path.replace(/^\/uploads\//, '');
      const old = path.join(__dirname, 'public', 'uploads', rel);
      fs.unlink(old, () => {});
    }
    const stmt = db.prepare(`UPDATE gallery_items SET file_path = ?, file_size = ?, updated_at = datetime('now') WHERE id = ?`);
    stmt.run([filePath, req.file.size, itemId]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, file_path: filePath });
  } catch (err) { if (req.file) fs.unlink(req.file.path, () => {}); res.status(500).json({ success: false, error: 'Ошибка сервера' }); }
});

// ===== РЕСУРСЫ =====
app.get('/api/admin/resources', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { type } = req.query;
    let query = 'SELECT * FROM resources WHERE 1=1';
    const params = [];
    if (type && type !== 'all') { query += ' AND type = ?'; params.push(type); }
    query += ' ORDER BY created_at DESC';
    const stmt = db.prepare(query);
    stmt.bind(params);
    const resources = [];
    while (stmt.step()) resources.push(stmt.getAsObject());
    stmt.free();
    res.json({ success: true, data: resources });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/resources', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { name, type, url, icon, category, description, tags, is_active } = req.body;
    if (!name || !type || !url) return res.status(400).json({ success: false, error: 'Заполните название, тип и URL' });
    const stmt = db.prepare(`INSERT INTO resources (name, type, description, url, icon, category, tags, is_active, image_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '')`);
    stmt.run([name, type, description || '', url, icon || '◈', category || '', tags || '', is_active ? 1 : 0]);
    stmt.free();
    const idStmt = db.prepare('SELECT last_insert_rowid() as id');
    let newId = idStmt.step() ? idStmt.getAsObject().id : null;
    idStmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Ресурс создан', id: newId });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/admin/resources/:id', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { name, type, url, icon, category, description, tags, is_active } = req.body;
    const stmt = db.prepare(`UPDATE resources SET name = ?, type = ?, description = ?, url = ?, icon = ?, category = ?, tags = ?, is_active = ? WHERE id = ?`);
    stmt.run([name, type, description || '', url, icon || '◈', category || '', tags || '', is_active ? 1 : 0, parseInt(req.params.id)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Ресурс обновлён' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/admin/resources/:id', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const resourceId = parseInt(req.params.id);
    const sel = db.prepare('SELECT image_path FROM resources WHERE id = ?');
    sel.bind([resourceId]);
    let existing = null;
    if (sel.step()) existing = sel.getAsObject();
    sel.free();
    if (existing && existing.image_path) {
      const fullPath = path.join(__dirname, 'public', existing.image_path);
      if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
    }
    db.prepare('DELETE FROM resources WHERE id = ?').run([resourceId]);
    saveDatabase();
    res.json({ success: true, message: 'Ресурс удалён' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ===== МЕРЧ =====
app.get('/api/admin/merch', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare('SELECT * FROM merch_items ORDER BY created_at DESC');
    const items = [];
    while (stmt.step()) items.push(stmt.getAsObject());
    stmt.free();
    res.json({ success: true, data: items });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/merch', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { name, type, price, description, sizes, stock, category, is_active } = req.body;
    if (!name || !type || !price) return res.status(400).json({ success: false, error: 'Заполните название, тип и цену' });
    const active = (is_active === undefined || is_active === null) ? 1 : (is_active ? 1 : 0);
    const stmt = db.prepare(`INSERT INTO merch_items (name, type, price, description, sizes, stock, category, is_active, image_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '')`);
    stmt.run([name, type, parseInt(price), description || '', sizes || '', parseInt(stock || 0), category || '', active]);
    stmt.free();
    const idStmt = db.prepare('SELECT last_insert_rowid() as id');
    let newId = idStmt.step() ? idStmt.getAsObject().id : null;
    idStmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Товар создан', id: newId });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/admin/merch/:id', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { name, type, price, description, sizes, stock, category, is_active } = req.body;
    if (!name || !type || !price) return res.status(400).json({ success: false, error: 'Заполните название, тип и цену' });
    const stmt = db.prepare(`UPDATE merch_items SET name = ?, type = ?, price = ?, description = ?, sizes = ?, stock = ?, category = ?, is_active = ? WHERE id = ?`);
    stmt.run([name, type, parseInt(price), description || '', sizes || '', parseInt(stock || 0), category || '', is_active ? 1 : 0, parseInt(req.params.id)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Товар обновлён' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.patch('/api/admin/merch/:id/active', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { is_active } = req.body;
    const stmt = db.prepare('UPDATE merch_items SET is_active = ? WHERE id = ?');
    stmt.run([is_active ? 1 : 0, parseInt(req.params.id)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Статус обновлён' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/admin/merch/:id', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const merchId = parseInt(req.params.id);
    const stmt = db.prepare('SELECT image_path FROM merch_items WHERE id = ?');
    stmt.bind([merchId]);
    let item = null;
    if (stmt.step()) item = stmt.getAsObject();
    stmt.free();
    if (item && item.image_path) {
      const fullPath = path.join(__dirname, 'public', item.image_path);
      if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
    }
    db.prepare('DELETE FROM merch_items WHERE id = ?').run([merchId]);
    saveDatabase();
    res.json({ success: true, message: 'Товар удалён' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/merch/:id/image', requireAuth, uploadMerch.single('image'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'Файл не загружен' });
    const db = getDb();
    const stmt = db.prepare('UPDATE merch_items SET image_path = ? WHERE id = ?');
    stmt.run(['/uploads/merch/' + req.file.filename, parseInt(req.params.id)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, image_path: '/uploads/merch/' + req.file.filename });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ===== ЗАКАЗЫ =====
app.get('/api/admin/orders', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { status } = req.query;
    let query = 'SELECT * FROM orders WHERE 1=1';
    const params = [];
    if (status && status !== 'all') { query += ' AND status = ?'; params.push(status); }
    query += ' ORDER BY created_at DESC';
    const stmt = db.prepare(query);
    stmt.bind(params);
    const orders = [];
    while (stmt.step()) orders.push(stmt.getAsObject());
    stmt.free();
    res.json({ success: true, data: orders });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/admin/orders/:id', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const orderId = parseInt(req.params.id);
    const orderStmt = db.prepare('SELECT * FROM orders WHERE id = ?');
    orderStmt.bind([orderId]);
    let order = null;
    if (orderStmt.step()) order = orderStmt.getAsObject();
    orderStmt.free();
    if (!order) return res.status(404).json({ success: false, error: 'Заказ не найден' });
    const itemsStmt = db.prepare(`SELECT oi.*, m.name as merch_name, m.image_path as merch_image, m.price as price FROM order_items oi LEFT JOIN merch_items m ON oi.merch_id = m.id WHERE oi.order_id = ?`);
    itemsStmt.bind([orderId]);
    const items = [];
    while (itemsStmt.step()) items.push(itemsStmt.getAsObject());
    itemsStmt.free();
    res.json({ success: true, data: { order, items } });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.patch('/api/admin/orders/:id/status', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { status } = req.body;
    if (!['pending', 'processing', 'shipped', 'delivered', 'cancelled'].includes(status)) return res.status(400).json({ success: false, error: 'Недопустимый статус' });
    const stmt = db.prepare('UPDATE orders SET status = ? WHERE id = ?');
    stmt.run([status, parseInt(req.params.id)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Статус обновлён' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ===== НАСТРОЙКИ / HUB / MANIFEST =====
app.get('/api/admin/settings', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare('SELECT * FROM settings');
    const settings = {};
    while (stmt.step()) {
      const row = stmt.getAsObject();
      settings[row.key] = row.value;
    }
    stmt.free();
    res.json({ success: true, data: settings });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/settings', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const settings = req.body;
    const stmt = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
    for (const [key, value] of Object.entries(settings)) {
      stmt.run([key, String(value)]);
    }
    stmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Настройки сохранены' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/hub', (req, res) => {
  try {
    const db = getDb();
    const settingsStmt = db.prepare('SELECT * FROM settings');
    const settings = {};
    while (settingsStmt.step()) {
      const row = settingsStmt.getAsObject();
      settings[row.key] = row.value;
    }
    settingsStmt.free();
    const defaultConfig = {
      news: [
        { date: '2026.09.05 // 14:32', title: 'Обновление нейросети v.4.2', excerpt: '...', link: '/stream' }
      ],
      timeline: [
        { time: '2026.09.05 // 14:32', title: 'Запуск нейросети v.4.2', description: '...' }
      ],
      modules: [
        { icon: '◈', title: 'МАТРИЦА ОБРАЗОВ', description: 'Галерея визуальных данных', link: '/matrix' }
      ]
    };
    let config = defaultConfig;
    if (settings.hub_config) {
      try { config = { ...defaultConfig, ...JSON.parse(settings.hub_config) }; } catch (e) {}
    }
    res.json({ success: true, data: config });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/hub-config', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
    stmt.run(['hub_config', JSON.stringify(req.body)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Конфигурация хаба сохранена' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/manifest', (req, res) => {
  try {
    const db = getDb();
    const settingsStmt = db.prepare('SELECT * FROM settings');
    const settings = {};
    while (settingsStmt.step()) {
      const row = settingsStmt.getAsObject();
      settings[row.key] = row.value;
    }
    settingsStmt.free();
    const defaultManifest = { about: [], principles: [], techIntro: '', techStack: [], timeline: [] };
    let config = defaultManifest;
    if (settings.manifest_config) {
      try { config = { ...defaultManifest, ...JSON.parse(settings.manifest_config) }; } catch (e) {}
    }
    res.json({ success: true, data: config });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/manifest-config', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
    stmt.run(['manifest_config', JSON.stringify(req.body)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Конфигурация манифеста сохранена' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/admin/hub-settings', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'hub-settings.html')));
app.get('/admin/manifest-settings', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'manifest-settings.html')));

// ===== РЕСУРСЫ (картинки) / МЕРЧ публичный / ЗАКАЗ =====
const resourcesImagesDir = path.join(__dirname, 'public', 'uploads', 'resources');
if (!fs.existsSync(resourcesImagesDir)) fs.mkdirSync(resourcesImagesDir, { recursive: true });

const resourceImageStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, resourcesImagesDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname).toLowerCase());
  }
});
const resourceImageUpload = multer({
  storage: resourceImageStorage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /^image\/(jpeg|jpg|png|webp|gif)$/.test(file.mimetype);
    cb(ok ? null : new Error('Разрешены только изображения'), ok);
  }
});

app.post('/api/admin/resources/:id/image', requireAuth, resourceImageUpload.single('image'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'Файл не загружен' });
    const db = getDb();
    const resourceId = parseInt(req.params.id);
    const sel = db.prepare('SELECT image_path FROM resources WHERE id = ?');
    sel.bind([resourceId]);
    let existing = null;
    if (sel.step()) existing = sel.getAsObject();
    sel.free();
    if (!existing) { fs.unlink(req.file.path, () => {}); return res.status(404).json({ success: false, error: 'Ресурс не найден' }); }
    if (existing.image_path && existing.image_path.startsWith('/uploads/resources/')) {
      const oldPath = path.join(__dirname, 'public', existing.image_path);
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }
    const imagePath = '/uploads/resources/' + req.file.filename;
    const stmt = db.prepare('UPDATE resources SET image_path = ? WHERE id = ?');
    stmt.run([imagePath, resourceId]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, image_path: imagePath });
  } catch (err) { if (req.file) fs.unlink(req.file.path, () => {}); res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/admin/resources/:id/image', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const resourceId = parseInt(req.params.id);
    const sel = db.prepare('SELECT image_path FROM resources WHERE id = ?');
    sel.bind([resourceId]);
    let existing = null;
    if (sel.step()) existing = sel.getAsObject();
    sel.free();
    if (existing && existing.image_path) {
      const fullPath = path.join(__dirname, 'public', existing.image_path);
      if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
    }
    db.prepare('UPDATE resources SET image_path = \'\' WHERE id = ?').run([resourceId]);
    saveDatabase();
    res.json({ success: true, message: 'Картинка удалена' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/merch', (req, res) => {
  try {
    const db = getDb();
    const { category } = req.query;
    let query = 'SELECT * FROM merch_items WHERE is_active = 1';
    const params = [];
    if (category && category !== 'all') { query += ' AND (category = ? OR type = ?)'; params.push(category, category); }
    query += ' ORDER BY created_at DESC';
    const stmt = db.prepare(query);
    stmt.bind(params);
    const items = [];
    while (stmt.step()) items.push(stmt.getAsObject());
    stmt.free();
    res.json({ success: true, data: items });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/orders', (req, res) => {
  try {
    const db = getDb();
    const { name, email, phone, quantity, size, merch_id } = req.body;

    if (!name || !String(name).trim()) return res.status(400).json({ success: false, error: 'Укажите имя' });
    if (!email || !String(email).trim()) return res.status(400).json({ success: false, error: 'Укажите e-mail' });
    if (!phone || !String(phone).trim()) return res.status(400).json({ success: false, error: 'Укажите телефон' });
    if (!merch_id) return res.status(400).json({ success: false, error: 'Не указан товар' });

    const qty = parseInt(quantity);
    if (!qty || qty < 1) return res.status(400).json({ success: false, error: 'Неверное количество' });

    const merchStmt = db.prepare('SELECT * FROM merch_items WHERE id = ? AND is_active = 1');
    merchStmt.bind([parseInt(merch_id)]);
    let merch = null;
    if (merchStmt.step()) merch = merchStmt.getAsObject();
    merchStmt.free();

    if (!merch) return res.status(404).json({ success: false, error: 'Товар не найден' });
    if (qty > Number(merch.stock)) return res.status(400).json({ success: false, error: 'На складе только ' + merch.stock + ' шт.' });

    const total = Number(merch.price) * qty;

    let userId = null;
    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        userId = decoded.id;
      } catch (e) {}
    }

    const orderStmt = db.prepare(
      `INSERT INTO orders (customer_email, customer_name, shipping_address, phone, total_amount, status, user_id)
       VALUES (?, ?, ?, ?, ?, 'pending', ?)`
    );
    orderStmt.run([String(email).trim(), String(name).trim(), '', String(phone).trim(), total, userId]);
    orderStmt.free();

    const idStmt = db.prepare('SELECT last_insert_rowid() as id');
    const orderId = idStmt.step() ? idStmt.getAsObject().id : null;
    idStmt.free();

    const itemStmt = db.prepare(`INSERT INTO order_items (order_id, merch_id, quantity, size) VALUES (?, ?, ?, ?)`);
    itemStmt.run([orderId, parseInt(merch_id), qty, String(size || '')]);
    itemStmt.free();

    const stockStmt = db.prepare('UPDATE merch_items SET stock = stock - ? WHERE id = ?');
    stockStmt.run([qty, parseInt(merch_id)]);
    stockStmt.free();

    saveDatabase();

    res.json({ success: true, message: 'Заказ оформлен', order_id: orderId });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ===== УРОВНИ ДОСТУПА =====
app.get('/api/access-levels', (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare('SELECT * FROM access_levels WHERE is_active = 1 ORDER BY id ASC');
    const levels = [];
    while (stmt.step()) {
      const row = stmt.getAsObject();
      try { row.features = JSON.parse(row.features || '[]'); } catch(e) { row.features = []; }
      levels.push(row);
    }
    stmt.free();
    res.json({ success: true, data: levels });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.get('/api/admin/access-levels', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare('SELECT * FROM access_levels ORDER BY id ASC');
    const levels = [];
    while (stmt.step()) {
      const row = stmt.getAsObject();
      try { row.features = JSON.parse(row.features || '[]'); } catch(e) { row.features = []; }
      levels.push(row);
    }
    stmt.free();
    res.json({ success: true, data: levels });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.post('/api/admin/access-levels', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { name, code, icon, features, is_active } = req.body;
    if (!name || !code || !icon) return res.status(400).json({ success: false, error: 'Заполните обязательные поля' });
    const featuresArray = Array.isArray(features) ? features : (features ? features.split(',').map(f => f.trim()) : []);
    const active = is_active !== undefined ? (is_active ? 1 : 0) : 1;
    const stmt = db.prepare('INSERT INTO access_levels (name, code, icon, features, is_active) VALUES (?, ?, ?, ?, ?)');
    stmt.run([name, code, icon, JSON.stringify(featuresArray), active]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Уровень доступа создан' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/admin/access-levels/:id', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { name, code, icon, features, is_active } = req.body;
    const featuresArray = Array.isArray(features) ? features : (features ? features.split(',').map(f => f.trim()) : []);
    const active = is_active !== undefined ? (is_active ? 1 : 0) : 1;
    const stmt = db.prepare('UPDATE access_levels SET name = ?, code = ?, icon = ?, features = ?, is_active = ? WHERE id = ?');
    stmt.run([name, code, icon, JSON.stringify(featuresArray), active, parseInt(req.params.id)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Уровень доступа обновлён' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/admin/access-levels/:id', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare('DELETE FROM access_levels WHERE id = ?');
    stmt.run([parseInt(req.params.id)]);
    stmt.free();
    saveDatabase();
    res.json({ success: true, message: 'Уровень доступа удалён' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ===== ПРОФИЛЬ АДМИНА =====
app.get('/api/admin/profile', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const stmt = db.prepare('SELECT id, username, email, role, created_at FROM users WHERE id = ?');
    stmt.bind([req.user.id]);
    let user = null;
    if (stmt.step()) user = stmt.getAsObject();
    stmt.free();
    if (!user) return res.status(404).json({ success: false, error: 'Пользователь не найден' });
    res.json({ success: true, data: user });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/admin/profile', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { username, email } = req.body;
    if (!username || username.length < 3 || username.length > 20) return res.status(400).json({ success: false, error: 'Позывной: 3-20 символов' });
    if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ success: false, error: 'Только латиница, цифры и _' });
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ success: false, error: 'Некорректный email' });

    const check = db.prepare('SELECT id FROM users WHERE username = ? AND id != ?');
    check.bind([username, req.user.id]);
    const busy = check.step();
    check.free();
    if (busy) return res.status(400).json({ success: false, error: 'Позывной занят' });

    const stmt = db.prepare('UPDATE users SET username = ?, email = ? WHERE id = ?');
    stmt.run([username, email || '', req.user.id]);
    stmt.free();
    saveDatabase();

    const token = jwt.sign({ id: req.user.id, username, role: req.user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, message: 'Профиль обновлён', token, user: { id: req.user.id, username, role: req.user.role } });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.put('/api/admin/profile/password', requireAuth, (req, res) => {
  try {
    const db = getDb();
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return res.status(400).json({ success: false, error: 'Заполните оба поля' });
    if (newPassword.length < 6) return res.status(400).json({ success: false, error: 'Минимум 6 символов' });
    if (oldPassword === newPassword) return res.status(400).json({ success: false, error: 'Новый совпадает со старым' });

    const stmt = db.prepare('SELECT password_hash FROM users WHERE id = ?');
    stmt.bind([req.user.id]);
    let user = null;
    if (stmt.step()) user = stmt.getAsObject();
    stmt.free();
    if (!user || !bcrypt.compareSync(oldPassword, user.password_hash)) {
      return res.status(401).json({ success: false, error: 'Старый пароль неверен' });
    }
    const hash = bcrypt.hashSync(newPassword, 10);
    const upd = db.prepare('UPDATE users SET password_hash = ? WHERE id = ?');
    upd.run([hash, req.user.id]);
    upd.free();
    saveDatabase();
    res.json({ success: true, message: 'Пароль изменён' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ============================================================
// ===== РОУТИНГ HTML =========================================
// ============================================================

const publicPages = {
  '/':         { file: 'index.html',    slug: 'index',    title: 'CYBERPUNK // NEURO-GRID' },
  '/hub':      { file: 'hub.html',      slug: 'hub',      title: 'CYBERPUNK // ЦЕНТРАЛЬНЫЙ ХАБ' },
  '/stream':   { file: 'stream.html',   slug: 'stream',   title: 'CYBERPUNK // ПОТОК ДАННЫХ' },
  '/manifest': { file: 'manifest.html', slug: 'manifest', title: 'CYBERPUNK // МАНИФЕСТ' },
  '/logs':     { file: 'logs.html',     slug: 'logs',     title: 'CYBERPUNK // АРХИВ ЛОГОВ' },
  '/matrix':   { file: 'matrix.html',   slug: 'matrix',   title: 'CYBERPUNK // МАТРИЦА ОБРАЗОВ' },
  '/access':   { file: 'access.html',   slug: 'access',   title: 'CYBERPUNK // ДОСТУП' },
  '/ripper':   { file: 'ripper.html',   slug: 'ripper',   title: 'CYBERPUNK // РИППЕРДОК' },
  '/implant':  { file: 'implant.html',  slug: 'implant',  title: 'CYBERPUNK // ИМПЛАНТАТЫ' },
  '/read':     { file: 'read.html',     slug: 'read',     title: 'CYBERPUNK // ЧТЕНИЕ' },
};

Object.entries(publicPages).forEach(([route, info]) => {
  app.get(route, (req, res) => {
    res.type('html').send(renderPageWithConfig(info.slug, info.file, info.title));
  });
});

app.get('/cog', (req, res) => {
  res.type('html').send(renderPageWithConfig('cog', 'cog.html', 'CYBERPUNK // КОГНИТИВНЫЙ ФИД'));
});

app.get('/profile',  (req, res) => res.sendFile(path.join(__dirname, 'profile.html')));
app.get('/user/:username', (req, res) => res.sendFile(path.join(__dirname, 'u.html')));

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'login.html')));
app.get('/admin/login', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'login.html')));
app.get('/admin/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'dashboard.html')));
app.get('/admin/posts', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'posts.html')));
app.get('/admin/news', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'news.html')));
app.get('/admin/books', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'books.html')));
app.get('/admin/gallery', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'gallery.html')));
app.get('/admin/resources', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'resources.html')));
app.get('/admin/merch', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'merch.html')));
app.get('/admin/orders', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'orders.html')));
app.get('/admin/users', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'users.html')));
app.get('/admin/comments', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'comments.html')));
app.get('/admin/stop-words', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'stop-words.html')));
app.get('/admin/ai-chat', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'ai-chat.html')));
app.get('/admin/settings', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'settings.html')));
app.get('/admin/profile', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'profile.html')));
app.get('/admin/access', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'access.html')));

// ===== ЗАПУСК =====
async function startServer() {
  try {
    const dbPath = path.join(__dirname, 'database', 'cyberpunk.db');
    const newDbPath = dbPath + '.new';
    if (fs.existsSync(newDbPath)) {
      console.log('  [БД] Обнаружен загруженный файл .new. Заменяю основную БД...');
      try {
        fs.copyFileSync(newDbPath, dbPath);
        fs.unlinkSync(newDbPath);
        console.log('  [БД] Файл БД заменён успешно.');
      } catch (e) {
        console.error('  [БД] Ошибка замены файла:', e);
      }
    }

    await initDatabase();

    try {
      const db = getDb();
      db.exec(`CREATE TABLE IF NOT EXISTS access_levels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        code TEXT NOT NULL,
        icon TEXT NOT NULL,
        features TEXT,
        is_active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`);

      const countStmt = db.prepare('SELECT COUNT(*) as count FROM access_levels');
      let count = 0;
      if (countStmt.step()) count = countStmt.getAsObject().count;
      countStmt.free();

      if (count === 0) {
        const defaults = [
          { name: 'ГОСТЬ', code: 'GUEST_00', icon: '◌', features: 'Просмотр публичных данных,Чтение манифеста' },
          { name: 'ПОЛЬЗОВАТЕЛЬ', code: 'USER_01', icon: '◈', features: 'Все права гостя,Архив логов (базовый),Комментарии в фиде' },
          { name: 'ПОДПИСЧИК', code: 'SUB_02', icon: '◉', features: 'Все права пользователя,Полный архив логов,Матрица образов (HD),Приоритетный аплинк' },
          { name: 'ОПЕРАТОР', code: 'OPS_03', icon: '◆', features: 'Все права подписчика,Создание постов через API,Расширенный доступ к фиду,Приоритетная обработка запросов' }
        ];
        const insertStmt = db.prepare('INSERT INTO access_levels (name, code, icon, features) VALUES (?, ?, ?, ?)');
        defaults.forEach(d => {
          insertStmt.run([d.name, d.code, d.icon, JSON.stringify(d.features.split(','))]);
        });
        insertStmt.free();
        saveDatabase();
        console.log('[БД] Таблица access_levels инициализирована.');
      }
    } catch (err) {
      console.error('[БД] Ошибка access_levels:', err);
    }

    app.listen(PORT, () => {
      console.log('╔══════════════════════════════════════════════╗');
      console.log('║     CYBERPUNK_DRIVE v1.0 // SYSTEM ONLINE    ║');
      console.log('══════════════════════════════════════════════');
      console.log(`║  СЕРВЕР: http://localhost:${PORT}`);
      console.log(`║  АДМИН:  http://localhost:${PORT}/admin`);
      console.log('╚══════════════════════════════════════════════╝');
    });
  } catch (err) {
    console.error('  Ошибка инициализации БД:', err);
    process.exit(1);
  }
}

startServer();