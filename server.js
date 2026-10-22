require('dotenv').config();

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const UPLOAD_DIR = path.join(ROOT, 'uploads');
const DATA_DIR = path.join(ROOT, 'data');

fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new sqlite3.Database(path.join(DATA_DIR, 'groupdrive.db'));
db.configure('busyTimeout', 5000);
db.run('PRAGMA foreign_keys = ON');

const run = (sql, params = []) => new Promise((resolve, reject) => {
  db.run(sql, params, function (err) {
    if (err) reject(err);
    else resolve({ id: this.lastID, changes: this.changes });
  });
});

const get = (sql, params = []) => new Promise((resolve, reject) => {
  db.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
});

const all = (sql, params = []) => new Promise((resolve, reject) => {
  db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows));
});

const randomToken = (n = 32) => crypto.randomBytes(n).toString('hex');
const timezone = process.env.APP_TIMEZONE || 'Europe/Moscow';

function formatDate(value) {
  if (!value) return value;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;

  return new Intl.DateTimeFormat('ru-RU', {
    timeZone: timezone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  }).format(d);
}

function publicFile(row) {
  if (!row) return row;
  return { ...row, created_at_display: formatDate(row.created_at) };
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[c]));
}

function asyncRoute(fn) {
  return (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));

app.use(session({
  name: 'groupdrive.sid',
  secret: process.env.SESSION_SECRET || 'CHANGE_THIS_SESSION_SECRET_BEFORE_DEPLOYMENT',
  resave: false,
  saveUninitialized: false,
  store: new SQLiteStore({
    db: 'sessions.sqlite',
    dir: DATA_DIR
  }),
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 12 * 60 * 60 * 1000
  }
}));

// ===================== ЗАГРУЗКА ФАЙЛОВ =====================

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    cb(
      null,
      `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${path.extname(file.originalname).slice(0, 15)}`
    );
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: Number(process.env.MAX_FILE_MB || 500) * 1024 * 1024,
    files: 1
  },
  fileFilter: (_req, file, cb) => {
    const blocked = /\.(exe|bat|cmd|com|msi|ps1|sh|php|js|html?)$/i
      .test(file.originalname);

    cb(
      blocked ? new Error('Этот тип файла запрещён для загрузки') : null,
      !blocked
    );
  }
});

// ===================== ПРАВА ДОСТУПА =====================

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: 'Войди в аккаунт, чтобы продолжить.'
    });
  }
  next();
}

async function currentUser(req) {
  if (!req.session.userId) return null;

  return get(`
    SELECT id,name,email,role,confirmed,approved,
           group_id,must_change_password,created_at
    FROM users WHERE id=?
  `, [req.session.userId]);
}

function requireStaff(req, res, next) {
  currentUser(req).then(user => {
    if (!user || !['teacher', 'admin'].includes(user.role)) {
      return res.status(403).json({
        error: 'Доступ только для преподавателя или администратора.'
      });
    }

    req.user = user;
    next();
  }).catch(next);
}

function requireAdmin(req, res, next) {
  currentUser(req).then(user => {
    if (!user || user.role !== 'admin') {
      return res.status(403).json({
        error: 'Это действие доступно только администратору.'
      });
    }

    req.user = user;
    next();
  }).catch(next);
}

async function teacherCanSeeStudent(teacher, studentId) {
  if (teacher.role === 'admin') return true;
  if (teacher.role !== 'teacher') return false;

  const student = await get(`
    SELECT id,group_id FROM users
    WHERE id=? AND role='student' AND approved=1
  `, [studentId]);

  if (!student || !student.group_id) return false;

  return !!(await get(`
    SELECT 1 FROM teacher_groups
    WHERE teacher_id=? AND group_id=?
  `, [teacher.id, student.group_id]));
}

async function canAccessFile(user, file) {
  if (!user || !file) return false;
  if (Number(file.owner_id) === Number(user.id)) return true;
  if (user.role === 'admin') return true;

  if (user.role === 'teacher') {
    return teacherCanSeeStudent(user, file.owner_id);
  }

  return false;
}

// ===================== БАЗА ДАННЫХ =====================

async function initDb() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'student',
      confirmed INTEGER NOT NULL DEFAULT 1,
      confirm_token TEXT,
      confirm_expires INTEGER,
      reset_token TEXT,
      reset_expires INTEGER,
      group_id INTEGER,
      approved INTEGER NOT NULL DEFAULT 0,
      must_change_password INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS study_groups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS teacher_groups (
      teacher_id INTEGER NOT NULL,
      group_id INTEGER NOT NULL,
      PRIMARY KEY(teacher_id,group_id),
      FOREIGN KEY(teacher_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(group_id) REFERENCES study_groups(id) ON DELETE CASCADE
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS folders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      owner_id INTEGER NOT NULL,
      parent_id INTEGER,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(owner_id) REFERENCES users(id),
      FOREIGN KEY(parent_id) REFERENCES folders(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id INTEGER NOT NULL,
      folder_id INTEGER,
      original_name TEXT NOT NULL,
      stored_name TEXT NOT NULL,
      mime_type TEXT,
      size INTEGER NOT NULL DEFAULT 0,
      can_download INTEGER NOT NULL DEFAULT 1,
      is_public INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(owner_id) REFERENCES users(id),
      FOREIGN KEY(folder_id) REFERENCES folders(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS assignments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      due_at TEXT,
      created_by INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS shares (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      file_id INTEGER NOT NULL,
      token TEXT NOT NULL UNIQUE,
      created_by INTEGER NOT NULL,
      allow_download INTEGER NOT NULL DEFAULT 0,
      expires_at INTEGER,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS file_reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      file_id INTEGER NOT NULL UNIQUE,
      teacher_id INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      comment TEXT NOT NULL DEFAULT '',
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(file_id) REFERENCES files(id),
      FOREIGN KEY(teacher_id) REFERENCES users(id)
    )
  `);

  // Добавляем поля в старую базу, не удаляя студентов и файлы.
  const userCols = await all('PRAGMA table_info(users)');
  const hasUser = name => userCols.some(c => c.name === name);

  if (!hasUser('group_id')) {
    await run('ALTER TABLE users ADD COLUMN group_id INTEGER');
  }

  if (!hasUser('approved')) {
    await run('ALTER TABLE users ADD COLUMN approved INTEGER NOT NULL DEFAULT 1');
    await run(`
      UPDATE users SET approved=0
      WHERE confirmed=0 AND role='student'
    `);
  }

  if (!hasUser('must_change_password')) {
    await run(`
      ALTER TABLE users ADD COLUMN must_change_password
      INTEGER NOT NULL DEFAULT 0
    `);
  }

  const fileCols = await all('PRAGMA table_info(files)');

  if (!fileCols.some(c => c.name === 'can_download')) {
    await run(`
      ALTER TABLE files ADD COLUMN can_download
      INTEGER NOT NULL DEFAULT 1
    `);
  }

  if (!fileCols.some(c => c.name === 'is_public')) {
    await run(`
      ALTER TABLE files ADD COLUMN is_public
      INTEGER NOT NULL DEFAULT 0
    `);
  }

  // Администраторы и преподаватели не должны зависеть от подтверждения почты.
  await run(`
    UPDATE users SET approved=1
    WHERE role IN ('admin','teacher')
  `);

  // Старые неподтверждённые регистрации переходят на одобрение администратором.
  await run(`
    UPDATE users SET approved=0
    WHERE confirmed=0 AND role='student'
  `);

  // Начальный администратор берётся из .env.
  // Пароль хранится только в виде хеша.
  const adminEmail = String(process.env.SEED_ADMIN_EMAIL || '')
    .trim().toLowerCase();
  const adminPassword = String(process.env.SEED_ADMIN_PASSWORD || '');

  if (adminEmail && adminPassword) {
    const existing = await get(
      'SELECT id FROM users WHERE email=?',
      [adminEmail]
    );

    const hash = await bcrypt.hash(adminPassword, 12);

    if (existing) {
      await run(`
        UPDATE users
        SET password_hash=?,
            role='admin',
            approved=1,
            confirmed=1,
            group_id=NULL
        WHERE id=?
      `, [hash, existing.id]);

      console.log('Пароль администратора обновлён:', adminEmail);
    } else {
      await run(`
        INSERT INTO users(name,email,password_hash,role,confirmed,approved)
        VALUES(?,?,?,'admin',1,1)
      `, [
        process.env.SEED_ADMIN_NAME || 'Администратор',
        adminEmail,
        hash
      ]);

      console.log('Создан администратор:', adminEmail);
    }
  }
}

// ===================== РЕГИСТРАЦИЯ БЕЗ ПОЧТЫ =====================

// Все самостоятельные регистрации становятся заявками.
// До одобрения администратором войти в личный кабинет нельзя.
app.post('/api/register', asyncRoute(async (req, res) => {
  const name = String(req.body.name || '').trim().replace(/\s+/g, ' ');
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (name.length < 2 || name.length > 100) {
    return res.status(400).json({ error: 'Укажи имя и фамилию.' });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({
      error: 'Проверь адрес электронной почты.'
    });
  }

  if (password.length < 8 || password.length > 200) {
    return res.status(400).json({
      error: 'Пароль должен содержать от 8 до 200 символов.'
    });
  }

  if (await get('SELECT id FROM users WHERE email=?', [email])) {
    return res.status(409).json({
      error: 'Аккаунт с этой почтой уже существует. Если потерян доступ, обратись к администратору.'
    });
  }

  const hash = await bcrypt.hash(password, 12);

  await run(`
    INSERT INTO users(name,email,password_hash,role,confirmed,approved)
    VALUES(?,?,?,'student',1,0)
  `, [name, email, hash]);

  res.status(201).json({
    message: 'Заявка создана! Дождись, когда администратор подтвердит аккаунт и назначит группу. Письмо не требуется.'
  });
}));

// ===================== ВХОД =====================

app.post('/api/login', asyncRoute(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const requestedRole = String(req.body.role || 'student');

  const user = await get(
    'SELECT * FROM users WHERE email=?',
    [email]
  );

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({
      error: 'Неверная почта или пароль.'
    });
  }

  if (user.approved !== 1) {
    if (user.approved === -1) {
      return res.status(403).json({
        error: 'Заявка отклонена. Обратись к администратору.'
      });
    }

    return res.status(403).json({
      error: 'Аккаунт ещё не подтверждён администратором. Попробуй позже.'
    });
  }

  // Администратор может войти через существующую вкладку «Студент».
  if (
    requestedRole !== user.role &&
    !(user.role === 'admin' && requestedRole === 'student')
  ) {
    return res.status(403).json({
      error: user.role === 'admin'
        ? 'Войди через вкладку «Студент», после входа открой /admin.html.'
        : user.role === 'teacher'
          ? 'Выбери вход «Преподаватель».'
          : 'Выбери вход «Студент».'
    });
  }

  req.session.regenerate(err => {
    if (err) {
      return res.status(500).json({
        error: 'Не удалось создать сессию.'
      });
    }

    req.session.userId = user.id;

    req.session.save(saveErr => {
      if (saveErr) {
        console.error('Не удалось сохранить сессию:', saveErr);
        return res.status(500).json({
          error: 'Не удалось сохранить сессию. Попробуй войти ещё раз.'
        });
      }

      res.json({
        ok: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          group_id: user.group_id,
          must_change_password: !!user.must_change_password
        }
      });
    });
  });
}));

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('groupdrive.sid');
    res.json({ ok: true });
  });
});

app.get('/api/me', requireAuth, asyncRoute(async (req, res) => {
  const user = await currentUser(req);

  if (!user || user.approved !== 1) {
    return res.status(401).json({
      error: 'Аккаунт не активирован.'
    });
  }

  res.json({
    ...user,
    created_at_display: formatDate(user.created_at)
  });
}));

// Почтовое восстановление отключено.
// Пользователь обращается к администратору за временным паролем.
app.post('/api/forgot', (_req, res) => {
  res.json({
    message: 'Восстановление через почту отключено. Обратись к администратору: он сбросит пароль и выдаст временный.'
  });
});

app.post('/api/reset', (_req, res) => {
  res.status(410).json({
    error: 'Сброс по электронной почте отключён. Обратись к администратору.'
  });
});

// Пользователь может самостоятельно изменить пароль после входа.
app.post('/api/change-password', requireAuth, asyncRoute(async (req, res) => {
  const oldPassword = String(req.body.old_password || '');
  const newPassword = String(req.body.new_password || '');

  if (newPassword.length < 8 || newPassword.length > 200) {
    return res.status(400).json({
      error: 'Новый пароль должен содержать минимум 8 символов.'
    });
  }

  const user = await get(
    'SELECT id,password_hash FROM users WHERE id=?',
    [req.session.userId]
  );

  if (!user || !(await bcrypt.compare(oldPassword, user.password_hash))) {
    return res.status(403).json({
      error: 'Текущий пароль введён неверно.'
    });
  }

  await run(
    'UPDATE users SET password_hash=?,must_change_password=0 WHERE id=?',
    [await bcrypt.hash(newPassword, 12), user.id]
  );

  res.json({ ok: true, message: 'Пароль обновлён.' });
}));

// ===================== УПРАВЛЕНИЕ ГРУППАМИ =====================

app.get('/api/admin/groups', requireAuth, requireAdmin, asyncRoute(async (_req, res) => {
  const groups = await all(`
    SELECT g.id,g.name,g.created_at,
      (SELECT COUNT(*) FROM users u
       WHERE u.group_id=g.id AND u.role='student' AND u.approved=1)
       AS student_count
    FROM study_groups g
    ORDER BY g.name COLLATE NOCASE
  `);

  for (const group of groups) {
    group.teachers = await all(`
      SELECT u.id,u.name,u.email
      FROM teacher_groups tg
      JOIN users u ON u.id=tg.teacher_id
      WHERE tg.group_id=? AND u.role='teacher'
      ORDER BY u.name COLLATE NOCASE
    `, [group.id]);
  }

  res.json(groups);
}));

app.post('/api/admin/groups', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const name = String(req.body.name || '').trim();

  if (name.length < 1 || name.length > 80) {
    return res.status(400).json({
      error: 'Название группы должно содержать от 1 до 80 символов.'
    });
  }

  try {
    const result = await run(
      'INSERT INTO study_groups(name) VALUES(?)',
      [name]
    );

    res.status(201).json({
      id: result.id,
      name,
      student_count: 0,
      teachers: []
    });
  } catch (e) {
    if (/UNIQUE/i.test(e.message)) {
      return res.status(409).json({
        error: 'Такая группа уже существует.'
      });
    }
    throw e;
  }
}));

app.patch('/api/admin/groups/:id', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const name = String(req.body.name || '').trim();

  if (!name || name.length > 80) {
    return res.status(400).json({ error: 'Неверное название группы.' });
  }

  try {
    const result = await run(
      'UPDATE study_groups SET name=? WHERE id=?',
      [name, Number(req.params.id)]
    );

    if (!result.changes) {
      return res.status(404).json({ error: 'Группа не найдена.' });
    }

    res.json({ ok: true, name });
  } catch (e) {
    if (/UNIQUE/i.test(e.message)) {
      return res.status(409).json({
        error: 'Такая группа уже существует.'
      });
    }
    throw e;
  }
}));

app.delete('/api/admin/groups/:id', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);

  await run('UPDATE users SET group_id=NULL WHERE group_id=?', [id]);
  await run('DELETE FROM teacher_groups WHERE group_id=?', [id]);

  const result = await run('DELETE FROM study_groups WHERE id=?', [id]);

  if (!result.changes) {
    return res.status(404).json({ error: 'Группа не найдена.' });
  }

  res.json({ ok: true });
}));

// Назначение преподавателей выбранной группе.
app.put('/api/admin/groups/:id/teachers', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);

  if (!(await get('SELECT id FROM study_groups WHERE id=?', [groupId]))) {
    return res.status(404).json({ error: 'Группа не найдена.' });
  }

  const ids = Array.isArray(req.body.teacher_ids)
    ? [...new Set(req.body.teacher_ids.map(Number).filter(Number.isInteger))]
    : [];

  for (const id of ids) {
    const teacher = await get(`
      SELECT id FROM users
      WHERE id=? AND role='teacher' AND approved=1
    `, [id]);

    if (!teacher) {
      return res.status(400).json({
        error: `Аккаунт преподавателя ${id} не найден.`
      });
    }
  }

  await run('DELETE FROM teacher_groups WHERE group_id=?', [groupId]);

  for (const id of ids) {
    await run(
      'INSERT INTO teacher_groups(teacher_id,group_id) VALUES(?,?)',
      [id, groupId]
    );
  }

  res.json({ ok: true, teacher_ids: ids });
}));

// ===================== СПИСОК АККАУНТОВ =====================

app.get('/api/admin/users', requireAuth, requireAdmin, asyncRoute(async (_req, res) => {
  const users = await all(`
    SELECT u.id,u.name,u.email,u.role,u.approved,u.group_id,
           g.name AS group_name,u.created_at,
      (SELECT COUNT(*) FROM files f WHERE f.owner_id=u.id) AS files_count
    FROM users u
    LEFT JOIN study_groups g ON g.id=u.group_id
    WHERE u.role IN ('student','teacher')
    ORDER BY
      CASE WHEN u.approved=0 THEN 0 ELSE 1 END,
      CASE u.role WHEN 'student' THEN 0 ELSE 1 END,
      u.name COLLATE NOCASE
  `);

  res.json(users);
}));

app.get('/api/admin/pending', requireAuth, requireAdmin, asyncRoute(async (_req, res) => {
  res.json(await all(`
    SELECT id,name,email,created_at
    FROM users
    WHERE role='student' AND approved=0
    ORDER BY created_at
  `));
}));

// Одобрить студента и назначить ему группу.
app.post('/api/admin/users/:id/approve', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const groupId =
    req.body.group_id === null ||
    req.body.group_id === '' ||
    req.body.group_id === undefined
      ? null
      : Number(req.body.group_id);

  const student = await get(`
    SELECT id FROM users
    WHERE id=? AND role='student' AND approved=0
  `, [id]);

  if (!student) {
    return res.status(404).json({
      error: 'Заявка студента не найдена.'
    });
  }

  if (groupId !== null &&
      !(await get('SELECT id FROM study_groups WHERE id=?', [groupId]))) {
    return res.status(400).json({
      error: 'Выбранная группа не существует.'
    });
  }

  await run(`
    UPDATE users
    SET approved=1,confirmed=1,group_id=?
    WHERE id=?
  `, [groupId, id]);

  res.json({
    ok: true,
    message: 'Студент подтверждён и добавлен в группу.'
  });
}));

app.post('/api/admin/users/:id/group', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const groupId =
    req.body.group_id === null || req.body.group_id === ''
      ? null
      : Number(req.body.group_id);

  const student = await get(`
    SELECT id FROM users
    WHERE id=? AND role='student' AND approved=1
  `, [id]);

  if (!student) {
    return res.status(404).json({ error: 'Студент не найден.' });
  }

  if (groupId !== null &&
      !(await get('SELECT id FROM study_groups WHERE id=?', [groupId]))) {
    return res.status(400).json({ error: 'Группа не найдена.' });
  }

  await run('UPDATE users SET group_id=? WHERE id=?', [groupId, id]);
  res.json({ ok: true });
}));

app.post('/api/admin/users/:id/reject', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const result = await run(`
    UPDATE users SET approved=-1
    WHERE id=? AND role='student' AND approved=0
  `, [Number(req.params.id)]);

  if (!result.changes) {
    return res.status(404).json({
      error: 'Ожидающая заявка не найдена.'
    });
  }

  res.json({ ok: true, message: 'Заявка отклонена.' });
}));

app.delete('/api/admin/users/:id', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);

  const user = await get(`
    SELECT id FROM users
    WHERE id=? AND role='student' AND approved IN (0,-1)
  `, [id]);

  if (!user) {
    return res.status(404).json({
      error: 'Можно удалить только ожидающую или отклонённую заявку.'
    });
  }

  await run('DELETE FROM users WHERE id=?', [id]);
  res.json({ ok: true });
}));

// Только администратор создаёт учётные записи преподавателей.
app.post('/api/admin/teachers', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const name = String(req.body.name || '').trim().replace(/\s+/g, ' ');
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (name.length < 2 || name.length > 100) {
    return res.status(400).json({
      error: 'Укажи имя и фамилию преподавателя.'
    });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({
      error: 'Неверный адрес электронной почты.'
    });
  }

  if (password.length < 12) {
    return res.status(400).json({
      error: 'Временный пароль должен содержать минимум 12 символов.'
    });
  }

  if (await get('SELECT id FROM users WHERE email=?', [email])) {
    return res.status(409).json({
      error: 'Пользователь с этой почтой уже существует.'
    });
  }

  const hash = await bcrypt.hash(password, 12);

  const result = await run(`
    INSERT INTO users
      (name,email,password_hash,role,confirmed,approved,must_change_password)
    VALUES(?,?,?,'teacher',1,1,1)
  `, [name, email, hash]);

  res.status(201).json({
    id: result.id,
    name,
    email,
    role: 'teacher',
    message: 'Преподаватель создан. Передай ему временный пароль безопасным способом.'
  });
}));

app.get('/api/admin/teachers', requireAuth, requireAdmin, asyncRoute(async (_req, res) => {
  res.json(await all(`
    SELECT id,name,email,created_at
    FROM users
    WHERE role='teacher' AND approved=1
    ORDER BY name COLLATE NOCASE
  `));
}));

app.delete('/api/admin/teachers/:id', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);

  const result = await run(`
    UPDATE users SET role='student',group_id=NULL,approved=1
    WHERE id=? AND role='teacher'
  `, [id]);

  await run('DELETE FROM teacher_groups WHERE teacher_id=?', [id]);

  if (!result.changes) {
    return res.status(404).json({ error: 'Преподаватель не найден.' });
  }

  res.json({ ok: true });
}));

// Проверяем пароль самого администратора перед сбросом.
// Новый пароль показывается один раз и в базе сохраняется только его хеш.
app.post('/api/admin/users/:id/reset-password', requireAuth, requireAdmin, asyncRoute(async (req, res) => {
  const adminPassword = String(req.body.admin_password || '');

  const admin = await get(
    'SELECT password_hash FROM users WHERE id=?',
    [req.session.userId]
  );

  if (!admin || !(await bcrypt.compare(adminPassword, admin.password_hash))) {
    return res.status(403).json({
      error: 'Пароль администратора введён неверно.'
    });
  }

  const target = await get(`
    SELECT id,name,email,role FROM users
    WHERE id=? AND role IN ('student','teacher')
  `, [Number(req.params.id)]);

  if (!target) {
    return res.status(404).json({ error: 'Пользователь не найден.' });
  }

  const temporaryPassword =
    crypto.randomBytes(9).toString('base64url') + 'aA7!';

  const hash = await bcrypt.hash(temporaryPassword, 12);

  await run(`
    UPDATE users
    SET password_hash=?,must_change_password=1,
        reset_token=NULL,reset_expires=NULL
    WHERE id=?
  `, [hash, target.id]);

  res.json({
    ok: true,
    user: {
      id: target.id,
      name: target.name,
      email: target.email
    },
    temporary_password: temporaryPassword,
    message: 'Скопируй временный пароль сейчас: повторно показать его нельзя.'
  });
}));

// ===================== ЛИЧНЫЕ ПАПКИ СТУДЕНТОВ =====================

app.get('/api/folders', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  const parent = req.query.parent ? Number(req.query.parent) : null;

  const rows = parent
    ? await all(`
        SELECT * FROM folders
        WHERE owner_id=? AND parent_id=?
        ORDER BY name COLLATE NOCASE
      `, [me.id, parent])
    : await all(`
        SELECT * FROM folders
        WHERE owner_id=? AND parent_id IS NULL
        ORDER BY name COLLATE NOCASE
      `, [me.id]);

  res.json(rows.map(publicFile));
}));

app.post('/api/folders', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  const name = String(req.body.name || '').trim();
  const parentId = req.body.parent_id ? Number(req.body.parent_id) : null;

  if (me.approved !== 1) {
    return res.status(403).json({ error: 'Аккаунт ещё не подтверждён.' });
  }

  if (!name || name.length > 120) {
    return res.status(400).json({
      error: 'Название папки должно содержать от 1 до 120 символов.'
    });
  }

  if (parentId) {
    const parent = await get(
      'SELECT id,owner_id FROM folders WHERE id=?',
      [parentId]
    );

    if (!parent || Number(parent.owner_id) !== Number(me.id)) {
      return res.status(403).json({
        error: 'Можно создавать папки только внутри собственных папок.'
      });
    }
  }

  const result = await run(`
    INSERT INTO folders(name,owner_id,parent_id,created_at)
    VALUES(?,?,?,?)
  `, [name, me.id, parentId, new Date().toISOString()]);

  res.status(201).json({
    id: result.id,
    name,
    owner_id: me.id,
    parent_id: parentId
  });
}));

app.delete('/api/folders/:id', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  const id = Number(req.params.id);

  const folder = await get('SELECT * FROM folders WHERE id=?', [id]);

  if (!folder) {
    return res.status(404).json({ error: 'Папка не найдена.' });
  }

  if (Number(folder.owner_id) !== Number(me.id) && me.role !== 'admin') {
    return res.status(403).json({ error: 'Нет доступа.' });
  }

  const child = await get(
    'SELECT id FROM folders WHERE parent_id=? LIMIT 1',
    [id]
  );

  const file = await get(
    'SELECT id FROM files WHERE folder_id=? LIMIT 1',
    [id]
  );

  if (child || file) {
    return res.status(409).json({
      error: 'Сначала удали файлы и вложенные папки.'
    });
  }

  await run('DELETE FROM folders WHERE id=?', [id]);
  res.json({ ok: true });
}));

// ===================== ФАЙЛЫ =====================

app.get('/api/files', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  const folder = req.query.folder ? Number(req.query.folder) : null;

  const rows = folder
    ? await all(`
        SELECT id,owner_id,folder_id,original_name,mime_type,size,
               can_download,is_public,created_at
        FROM files
        WHERE owner_id=? AND folder_id=?
        ORDER BY created_at DESC
      `, [me.id, folder])
    : await all(`
        SELECT id,owner_id,folder_id,original_name,mime_type,size,
               can_download,is_public,created_at
        FROM files
        WHERE owner_id=? AND folder_id IS NULL
        ORDER BY created_at DESC
      `, [me.id]);

  res.json(rows.map(publicFile));
}));

app.post('/api/upload', requireAuth, upload.single('file'), asyncRoute(async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Выбери файл для загрузки.' });
  }

  const me = await currentUser(req);
  const folderId = req.body.folder_id ? Number(req.body.folder_id) : null;

  if (me.approved !== 1) {
    fs.unlink(req.file.path, () => {});
    return res.status(403).json({ error: 'Аккаунт ещё не подтверждён.' });
  }

  if (folderId) {
    const folder = await get(
      'SELECT id,owner_id FROM folders WHERE id=?',
      [folderId]
    );

    if (!folder || Number(folder.owner_id) !== Number(me.id)) {
      fs.unlink(req.file.path, () => {});
      return res.status(403).json({ error: 'Нет доступа к папке.' });
    }
  }

  const originalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8');
  const uploadedAt = new Date().toISOString();

  const result = await run(`
    INSERT INTO files
      (owner_id,folder_id,original_name,stored_name,mime_type,size,can_download,created_at)
    VALUES(?,?,?,?,?,?,1,?)
  `, [
    me.id,
    folderId,
    originalName,
    req.file.filename,
    req.file.mimetype,
    req.file.size,
    uploadedAt
  ]);

  res.status(201).json({
    id: result.id,
    original_name: originalName,
    size: req.file.size,
    created_at: uploadedAt,
    created_at_display: formatDate(uploadedAt)
  });
}));

async function getFileAccess(user, fileId) {
  const file = await get(`
    SELECT f.*,u.name AS owner_name,u.email AS owner_email,
           u.role AS owner_role,u.group_id AS owner_group_id
    FROM files f
    JOIN users u ON u.id=f.owner_id
    WHERE f.id=?
  `, [fileId]);

  if (!file) return { error: 404 };
  if (!(await canAccessFile(user, file))) return { error: 403 };

  return { file };
}

app.get('/api/files/:id/download', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  const result = await getFileAccess(me, Number(req.params.id));

  if (result.error) {
    return res.status(result.error).json({
      error: result.error === 404
        ? 'Файл не найден.'
        : 'Нет доступа к этому файлу.'
    });
  }

  const file = result.file;

  if (req.query.inline !== '1' && !file.can_download && me.role !== 'admin') {
    return res.status(403).json({
      error: 'Скачивание запрещено преподавателем.'
    });
  }

  const fp = path.join(UPLOAD_DIR, path.basename(file.stored_name));

  if (!fs.existsSync(fp)) {
    return res.status(404).json({
      error: 'Файл отсутствует на сервере.'
    });
  }

  res.setHeader('Content-Type', file.mime_type || 'application/octet-stream');

  if (req.query.inline === '1') {
    res.setHeader(
      'Content-Disposition',
      `inline; filename*=UTF-8''${encodeURIComponent(file.original_name)}`
    );
    return res.sendFile(fp);
  }

  res.download(fp, file.original_name);
}));

// Преподаватель управляет скачиванием только для закреплённых групп.
// Если скачивание запрещено, отключаем и скачивание по ранее созданным ссылкам.
app.patch('/api/files/:id/permissions', requireAuth, requireStaff, asyncRoute(async (req, res) => {
  const me = req.user;
  const id = Number(req.params.id);
  const allow = req.body.can_download === true || req.body.can_download === 1;

  const file = await get(
    'SELECT id,owner_id FROM files WHERE id=?',
    [id]
  );

  if (!file) {
    return res.status(404).json({ error: 'Файл не найден.' });
  }

  if (me.role !== 'admin' &&
      !(await teacherCanSeeStudent(me, file.owner_id))) {
    return res.status(403).json({
      error: 'Этот студент не относится к вашим группам.'
    });
  }

  await run(
    'UPDATE files SET can_download=? WHERE id=?',
    [allow ? 1 : 0, id]
  );

  if (!allow) {
    await run('UPDATE shares SET allow_download=0 WHERE file_id=?', [id]);
  }

  res.json({ ok: true, can_download: allow });
}));

app.delete('/api/files/:id', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  const id = Number(req.params.id);
  const file = await get('SELECT * FROM files WHERE id=?', [id]);

  if (!file) {
    return res.status(404).json({ error: 'Файл не найден.' });
  }

  if (Number(file.owner_id) !== Number(me.id) && me.role !== 'admin') {
    return res.status(403).json({
      error: 'Удалять можно только свои файлы.'
    });
  }

  await run('DELETE FROM shares WHERE file_id=?', [id]);
  await run('DELETE FROM file_reviews WHERE file_id=?', [id]);
  await run('DELETE FROM files WHERE id=?', [id]);

  fs.unlink(path.join(UPLOAD_DIR, path.basename(file.stored_name)), () => {});
  res.json({ ok: true });
}));

// ===================== ССЫЛКИ НА ФАЙЛЫ =====================

app.post('/api/share/:fileId', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);
  const fileId = Number(req.params.fileId);

  const file = await get(
    'SELECT id,owner_id,can_download FROM files WHERE id=?',
    [fileId]
  );

  if (!file) {
    return res.status(404).json({ error: 'Файл не найден.' });
  }

  if (Number(file.owner_id) !== Number(me.id)) {
    return res.status(403).json({
      error: 'Можно создавать ссылки только на свои файлы.'
    });
  }

  const allow =
    (req.body.allow_download === true || req.body.allow_download === 1) &&
    file.can_download === 1 ? 1 : 0;

  const days = Math.max(
    0,
    Math.min(Number(req.body.expires_days || 0), 365)
  );

  const expiresAt = days ? Date.now() + days * 86400000 : null;
  const shareToken = randomToken();

  await run(`
    INSERT INTO shares(file_id,token,created_by,allow_download,expires_at)
    VALUES(?,?,?,?,?)
  `, [fileId, shareToken, me.id, allow, expiresAt]);

  res.json({
    url: `${req.protocol}://${req.get('host')}/share/${shareToken}`,
    allow_download: !!allow,
    expires_at: expiresAt
  });
}));

app.get('/share/:token', asyncRoute(async (req, res) => {
  const share = await get(`
    SELECT s.*,f.original_name,f.mime_type,f.can_download
    FROM shares s
    JOIN files f ON f.id=s.file_id
    WHERE s.token=?
  `, [req.params.token]);

  if (!share || (share.expires_at && share.expires_at < Date.now())) {
    return res.status(404).send('Ссылка не найдена или истекла.');
  }

  const ext = path.extname(share.original_name).toLowerCase();
  const contentUrl = `/share/${encodeURIComponent(req.params.token)}/content`;
  const canDownload = share.allow_download === 1 && share.can_download === 1;

  let preview = '<p>Предпросмотр этого формата не поддерживается.</p>';

  if (['.png','.jpg','.jpeg','.gif','.webp'].includes(ext)) {
    preview = `<img style="max-width:95%;max-height:80vh" src="${contentUrl}" alt="${escapeHtml(share.original_name)}">`;
  }

  if (ext === '.pdf') {
    preview = `<iframe style="width:95%;height:80vh;border:0" src="${contentUrl}"></iframe>`;
  }

  if (['.mp4','.webm','.ogg'].includes(ext)) {
    preview = `<video controls playsinline style="max-width:95%;max-height:80vh" src="${contentUrl}"></video>`;
  }

  res.type('html').send(`
    <!doctype html>
    <html lang="ru">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width">
    <title>${escapeHtml(share.original_name)}</title>
    <body style="margin:0;background:#0b1224;color:#eef3ff;font:16px Arial;padding:24px">
      <h2>${escapeHtml(share.original_name)}</h2>
      ${preview}
      <p>
        ${canDownload
          ? `<a style="color:#83e6f4" href="/share/${encodeURIComponent(req.params.token)}/download">Скачать файл</a>`
          : 'Скачивание запрещено владельцем или преподавателем.'}
      </p>
    </body>
    </html>
  `);
}));

app.get('/share/:token/content', asyncRoute(async (req, res) => {
  const share = await get(`
    SELECT s.expires_at,f.*
    FROM shares s JOIN files f ON f.id=s.file_id
    WHERE s.token=?
  `, [req.params.token]);

  if (!share || (share.expires_at && share.expires_at < Date.now())) {
    return res.status(404).end();
  }

  const fp = path.join(UPLOAD_DIR, path.basename(share.stored_name));
  if (!fs.existsSync(fp)) return res.status(404).end();

  res.setHeader('Content-Type', share.mime_type || 'application/octet-stream');
  res.setHeader(
    'Content-Disposition',
    `inline; filename*=UTF-8''${encodeURIComponent(share.original_name)}`
  );

  res.sendFile(fp);
}));

app.get('/share/:token/download', asyncRoute(async (req, res) => {
  const share = await get(`
    SELECT s.allow_download,s.expires_at,f.*
    FROM shares s JOIN files f ON f.id=s.file_id
    WHERE s.token=?
  `, [req.params.token]);

  if (
    !share ||
    share.allow_download !== 1 ||
    share.can_download !== 1 ||
    (share.expires_at && share.expires_at < Date.now())
  ) {
    return res.status(403).send('Скачивание запрещено или ссылка истекла.');
  }

  const fp = path.join(UPLOAD_DIR, path.basename(share.stored_name));
  if (!fs.existsSync(fp)) return res.status(404).send('Файл не найден.');

  res.download(fp, share.original_name);
}));

// ===================== СПИСОК СТУДЕНТОВ =====================

app.get('/api/students', requireAuth, requireStaff, asyncRoute(async (req, res) => {
  const me = req.user;
  let rows;

  if (me.role === 'admin') {
    rows = await all(`
      SELECT u.id,u.name,u.email,u.group_id,g.name AS group_name,u.created_at,
        (SELECT COUNT(*) FROM files f WHERE f.owner_id=u.id) AS files_count
      FROM users u
      LEFT JOIN study_groups g ON g.id=u.group_id
      WHERE u.role='student' AND u.approved=1
      ORDER BY g.name,u.name COLLATE NOCASE
    `);
  } else {
    rows = await all(`
      SELECT u.id,u.name,u.email,u.group_id,g.name AS group_name,u.created_at,
        (SELECT COUNT(*) FROM files f WHERE f.owner_id=u.id) AS files_count
      FROM users u
      JOIN teacher_groups tg ON tg.group_id=u.group_id
      LEFT JOIN study_groups g ON g.id=u.group_id
      WHERE u.role='student' AND u.approved=1 AND tg.teacher_id=?
      ORDER BY g.name,u.name COLLATE NOCASE
    `, [me.id]);
  }

  res.json(rows.map(publicFile));
}));

// Вся структура работ конкретного студента:
// папки, вложенные папки, файлы и сведения о проверках.
app.get('/api/students/:id/workspace', requireAuth, requireStaff, asyncRoute(async (req, res) => {
  const me = req.user;
  const studentId = Number(req.params.id);

  if (!(await teacherCanSeeStudent(me, studentId))) {
    return res.status(403).json({
      error: 'Студент не относится к вашим группам.'
    });
  }

  const student = await get(`
    SELECT u.id,u.name,u.email,u.group_id,g.name AS group_name
    FROM users u
    LEFT JOIN study_groups g ON g.id=u.group_id
    WHERE u.id=? AND u.role='student' AND u.approved=1
  `, [studentId]);

  if (!student) {
    return res.status(404).json({ error: 'Студент не найден.' });
  }

  const folders = await all(`
    SELECT id,name,owner_id,parent_id,created_at
    FROM folders
    WHERE owner_id=?
    ORDER BY name COLLATE NOCASE
  `, [studentId]);

  const files = await all(`
    SELECT f.id,f.owner_id,f.folder_id,f.original_name,
           f.mime_type,f.size,f.can_download,f.created_at,
           r.status,r.comment,r.updated_at AS reviewed_at,t.name AS reviewed_by
    FROM files f
    LEFT JOIN file_reviews r ON r.file_id=f.id
    LEFT JOIN users t ON t.id=r.teacher_id
    WHERE f.owner_id=?
    ORDER BY f.created_at DESC
  `, [studentId]);

  res.json({
    student,
    folders: folders.map(publicFile),
    files: files.map(publicFile)
  });
}));

// ===================== ПРОВЕРКА РАБОТ =====================

app.get('/api/reviews', requireAuth, asyncRoute(async (req, res) => {
  const me = await currentUser(req);

  if (['teacher','admin'].includes(me.role)) {
    const studentId = req.query.student_id
      ? Number(req.query.student_id)
      : null;

    if (studentId && !(await teacherCanSeeStudent(me, studentId))) {
      return res.status(403).json({
        error: 'Студент не относится к вашим группам.'
      });
    }

    let filter = "WHERE u.role='student' AND u.approved=1";
    const params = [];

    if (studentId) {
      filter += ' AND u.id=?';
      params.push(studentId);
    }

    if (me.role === 'teacher') {
      filter += `
        AND EXISTS (
          SELECT 1 FROM teacher_groups tg
          WHERE tg.group_id=u.group_id AND tg.teacher_id=?
        )
      `;
      params.push(me.id);
    }

    const rows = await all(`
      SELECT f.id AS file_id,f.owner_id,f.folder_id,f.original_name,
        f.size,f.created_at,f.can_download,d.name AS folder_name,
        u.id AS student_id,u.name AS student_name,u.email AS student_email,
        u.group_id,r.status,r.comment,r.updated_at AS reviewed_at,
        t.name AS reviewed_by
      FROM files f
      JOIN users u ON u.id=f.owner_id
      LEFT JOIN folders d ON d.id=f.folder_id
      LEFT JOIN file_reviews r ON r.file_id=f.id
      LEFT JOIN users t ON t.id=r.teacher_id
      ${filter}
      ORDER BY f.created_at DESC
    `, params);

    return res.json(rows.map(publicFile));
  }

  if (me.approved !== 1) {
    return res.status(403).json({ error: 'Аккаунт не активирован.' });
  }

  const rows = await all(`
    SELECT f.id AS file_id,f.owner_id,f.folder_id,f.original_name,
      f.size,f.created_at,f.can_download,d.name AS folder_name,
      r.status,r.comment,r.updated_at AS reviewed_at,t.name AS reviewed_by
    FROM files f
    LEFT JOIN folders d ON d.id=f.folder_id
    LEFT JOIN file_reviews r ON r.file_id=f.id
    LEFT JOIN users t ON t.id=r.teacher_id
    WHERE f.owner_id=?
    ORDER BY f.created_at DESC
  `, [me.id]);

  res.json(rows.map(publicFile));
}));

app.patch('/api/files/:id/review', requireAuth, requireStaff, asyncRoute(async (req, res) => {
  const me = req.user;
  const fileId = Number(req.params.id);
  const status = String(req.body.status || 'pending');
  const comment = String(req.body.comment || '').trim().slice(0, 5000);

  if (!['pending','accepted','revision'].includes(status)) {
    return res.status(400).json({
      error: 'Неизвестный статус проверки.'
    });
  }

  const file = await get(`
    SELECT f.id,f.owner_id
    FROM files f
    JOIN users u ON u.id=f.owner_id
    WHERE f.id=? AND u.role='student' AND u.approved=1
  `, [fileId]);

  if (!file) {
    return res.status(404).json({
      error: 'Работа студента не найдена.'
    });
  }

  if (!(await teacherCanSeeStudent(me, file.owner_id))) {
    return res.status(403).json({
      error: 'Студент не относится к вашим группам.'
    });
  }

  await run(`
    INSERT INTO file_reviews
      (file_id,teacher_id,status,comment,updated_at)
    VALUES(?,?,?,?,?)
    ON CONFLICT(file_id) DO UPDATE SET
      teacher_id=excluded.teacher_id,
      status=excluded.status,
      comment=excluded.comment,
      updated_at=excluded.updated_at
  `, [
    fileId,
    me.id,
    status,
    comment,
    new Date().toISOString()
  ]);

  res.json({ ok: true, status, comment });
}));

// ===================== ЗАДАНИЯ =====================

app.get('/api/assignments', requireAuth, asyncRoute(async (_req, res) => {
  res.json(await all(`
    SELECT a.*,u.name AS teacher_name
    FROM assignments a
    JOIN users u ON u.id=a.created_by
    ORDER BY a.created_at DESC
  `));
}));

app.post('/api/assignments', requireAuth, requireStaff, asyncRoute(async (req, res) => {
  const title = String(req.body.title || '').trim();
  const description = String(req.body.description || '').trim();

  if (!title) {
    return res.status(400).json({ error: 'Укажи название задания.' });
  }

  const result = await run(`
    INSERT INTO assignments(title,description,due_at,created_by)
    VALUES(?,?,?,?)
  `, [
    title,
    description,
    req.body.due_at || null,
    req.user.id
  ]);

  res.status(201).json({
    id: result.id,
    title,
    description,
    due_at: req.body.due_at || null
  });
}));

app.delete('/api/assignments/:id', requireAuth, requireStaff, asyncRoute(async (req, res) => {
  await run(
    'DELETE FROM assignments WHERE id=?',
    [Number(req.params.id)]
  );
  res.json({ ok: true });
}));

// ===================== СТРАНИЦЫ И ОШИБКИ =====================

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, app: 'GroupDrive' });
});

app.use(express.static(PUBLIC_DIR));

app.get('/', (_req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'login.html'));
});

app.use((err, _req, res, _next) => {
  console.error('GroupDrive error:', err);

  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      error: err.code === 'LIMIT_FILE_SIZE'
        ? `Файл слишком большой. Лимит: ${process.env.MAX_FILE_MB || 500} МБ.`
        : 'Ошибка загрузки файла.'
    });
  }

  res.status(500).json({
    error: process.env.NODE_ENV === 'production'
      ? 'Внутренняя ошибка сервера.'
      : (err.message || 'Внутренняя ошибка сервера.')
  });
});

initDb()
  .then(() => app.listen(PORT, () => {
    console.log(`GroupDrive запущен на порту ${PORT}`);
    console.log(`Часовой пояс отображения времени: ${timezone}`);
    console.log('Регистрация без писем. Новые аккаунты ожидают подтверждения администратора.');
  }))
  .catch(err => {
    console.error('Не удалось инициализировать базу данных:', err);
    process.exit(1);
  });