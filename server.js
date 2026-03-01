/**
 * Freedom Chat — Node.js Server + PostgreSQL
 */

const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const path       = require('path');
const crypto     = require('crypto');
const { Pool }   = require('pg');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  maxHttpBufferSize: 10 * 1024 * 1024,
  cors: { origin: '*' },
});

const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

const db = {
  query: (text, params) => pool.query(text, params),
};

async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      username      TEXT PRIMARY KEY,
      display_name  TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      bio           TEXT    DEFAULT '',
      avatar        TEXT    DEFAULT NULL,
      banner        TEXT    DEFAULT NULL,
      last_seen     BIGINT  DEFAULT NULL,
      privacy       JSONB   DEFAULT '{"lastSeen":"everyone","avatar":"everyone"}',
      created_at    BIGINT  DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
    );

    -- Добавляем колонку banner если её нет (для существующих БД)
    DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='banner') THEN
        ALTER TABLE users ADD COLUMN banner TEXT DEFAULT NULL;
      END IF;
    END $$;

    CREATE TABLE IF NOT EXISTS sessions (
      token      TEXT PRIMARY KEY,
      username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
      created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
    );

    CREATE TABLE IF NOT EXISTS messages (
      id         TEXT    PRIMARY KEY,
      from_user  TEXT    NOT NULL REFERENCES users(username) ON DELETE CASCADE,
      to_user    TEXT    NOT NULL REFERENCES users(username) ON DELETE CASCADE,
      content    TEXT    NOT NULL,
      type       TEXT    DEFAULT 'text',
      reply_to   TEXT    DEFAULT NULL,
      duration   TEXT    DEFAULT NULL,
      read       BOOLEAN DEFAULT FALSE,
      deleted    BOOLEAN DEFAULT FALSE,
      timestamp  BIGINT  NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_messages_chat
      ON messages (LEAST(from_user, to_user), GREATEST(from_user, to_user), timestamp);
  `);
  console.log('✅ БД инициализирована');
}

function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw + 'freedom_salt').digest('hex');
}

function makeSession() {
  return crypto.randomBytes(24).toString('hex');
}

function makeId() {
  return crypto.randomBytes(8).toString('hex');
}

// Онлайн-пользователи: username → Set<socketId>  (поддержка нескольких вкладок)
const onlineUsers = new Map();

function addOnline(username, socketId) {
  if (!onlineUsers.has(username)) onlineUsers.set(username, new Set());
  onlineUsers.get(username).add(socketId);
}

function removeOnline(username, socketId) {
  const set = onlineUsers.get(username);
  if (!set) return;
  set.delete(socketId);
  if (set.size === 0) onlineUsers.delete(username);
}

function isOnline(username) {
  return onlineUsers.has(username) && onlineUsers.get(username).size > 0;
}

function userPublic(u) {
  return {
    username:    u.username,
    displayName: u.display_name,
    bio:         u.bio      || '',
    avatar:      u.avatar   || null,
    banner:      u.banner   || null,
    online:      isOnline(u.username),
    lastSeen:    u.last_seen || null,
    privacy:     u.privacy  || { lastSeen: 'everyone', avatar: 'everyone' },
  };
}

function sendTo(username, event, data) {
  const sockets = onlineUsers.get(username);
  if (!sockets) return;
  sockets.forEach(socketId => {
    const sock = io.sockets.sockets.get(socketId);
    if (sock) sock.emit(event, data);
  });
}

async function getContacts(username) {
  const { rows } = await db.query(`
    SELECT
      u.*,
      (
        SELECT row_to_json(m) FROM (
          SELECT id, from_user AS "from", to_user AS "to",
                 content, type, timestamp, read
          FROM messages
          WHERE deleted = FALSE
            AND ((from_user = $1 AND to_user = u.username)
              OR (from_user = u.username AND to_user = $1))
          ORDER BY timestamp DESC LIMIT 1
        ) m
      ) AS "lastMessage",
      (
        SELECT COUNT(*)::INT FROM messages
        WHERE to_user = $1 AND from_user = u.username
          AND read = FALSE AND deleted = FALSE
      ) AS unread
    FROM users u
    WHERE u.username != $1
    ORDER BY (
      SELECT timestamp FROM messages
      WHERE deleted = FALSE
        AND ((from_user = $1 AND to_user = u.username)
          OR (from_user = u.username AND to_user = $1))
      ORDER BY timestamp DESC LIMIT 1
    ) DESC NULLS LAST
  `, [username]);

  return rows.map(r => ({
    ...userPublic(r),
    lastMessage: r.lastMessage || null,
    unread:      r.unread || 0,
  }));
}

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/users', async (req, res) => {
  try {
    const { rows } = await db.query('SELECT * FROM users ORDER BY created_at ASC');
    res.json(rows.map(r => userPublic(r)));
  } catch (e) {
    res.json([]);
  }
});

// ── Socket.IO ──────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  let me = null;

  // ── Восстановление сессии ──────────────────────────────────────────────
  socket.on('restore_session', async (tokenOrCreds, cb) => {
    try {
      let user = null;

      // ФИКС: поддержка как токена (строка), так и старого формата {username,password}
      if (typeof tokenOrCreds === 'string' && tokenOrCreds.length > 8) {
        // Правильный путь — поиск по токену
        const { rows } = await db.query(
          `SELECT u.* FROM sessions s
           JOIN users u ON u.username = s.username
           WHERE s.token = $1`,
          [tokenOrCreds]
        );
        user = rows[0] || null;
      } else if (tokenOrCreds && typeof tokenOrCreds === 'object' && tokenOrCreds.username) {
        // Устаревший формат — авторизуемся по логину/паролю
        const { rows } = await db.query('SELECT * FROM users WHERE username = $1', [tokenOrCreds.username]);
        if (rows[0] && tokenOrCreds.password && rows[0].password_hash === hashPassword(tokenOrCreds.password)) {
          user = rows[0];
          // Создаём нормальный токен для этого сокета
          const newToken = makeSession();
          await db.query('INSERT INTO sessions (token, username) VALUES ($1, $2) ON CONFLICT DO NOTHING', [newToken, user.username]);
          // Шлём клиенту новый токен чтобы он его сохранил
          socket.emit('upgrade_token', newToken);
        }
      }

      if (!user) return cb({ ok: false });

      me = user;
      addOnline(me.username, socket.id);
      io.emit('user_online', { username: me.username });

      cb({
        ok:       true,
        user:     userPublic(me),
        contacts: await getContacts(me.username),
      });
    } catch (e) {
      console.error('restore_session:', e.message);
      cb({ ok: false });
    }
  });

  // ── Регистрация ────────────────────────────────────────────────────────
  socket.on('register', async ({ username, password, displayName }, cb) => {
    try {
      if (!username || !password) return cb({ ok: false, error: 'Заполните поля' });
      if (username.length < 3)    return cb({ ok: false, error: 'Минимум 3 символа' });

      const exists = await db.query('SELECT 1 FROM users WHERE username = $1', [username]);
      if (exists.rows.length)     return cb({ ok: false, error: 'Имя занято' });

      await db.query(
        'INSERT INTO users (username, display_name, password_hash) VALUES ($1, $2, $3)',
        [username, displayName || username, hashPassword(password)]
      );

      const token = makeSession();
      await db.query('INSERT INTO sessions (token, username) VALUES ($1, $2)', [token, username]);

      const { rows } = await db.query('SELECT * FROM users WHERE username = $1', [username]);
      me = rows[0];
      addOnline(me.username, socket.id);
      io.emit('new_user', userPublic(me));

      cb({ ok: true, user: userPublic(me), token, contacts: await getContacts(me.username) });
    } catch (e) {
      console.error('register:', e.message);
      cb({ ok: false, error: 'Ошибка сервера' });
    }
  });

  // ── Вход ──────────────────────────────────────────────────────────────
  socket.on('login', async ({ username, password }, cb) => {
    try {
      const { rows } = await db.query('SELECT * FROM users WHERE username = $1', [username]);
      const user = rows[0];
      if (!user || user.password_hash !== hashPassword(password)) {
        return cb({ ok: false, error: 'Неверное имя или пароль' });
      }

      const token = makeSession();
      await db.query('INSERT INTO sessions (token, username) VALUES ($1, $2)', [token, username]);

      me = user;
      addOnline(me.username, socket.id);
      io.emit('user_online', { username: me.username });

      cb({
        ok:       true,
        user:     userPublic(me),
        token,
        contacts: await getContacts(me.username),
      });
    } catch (e) {
      console.error('login:', e.message);
      cb({ ok: false, error: 'Ошибка сервера' });
    }
  });

  // ── Выход ──────────────────────────────────────────────────────────────
  socket.on('logout', async () => {
    if (!me) return;
    try {
      await db.query('DELETE FROM sessions WHERE username = $1', [me.username]);
      const ts = Date.now();
      await db.query('UPDATE users SET last_seen = $1 WHERE username = $2', [ts, me.username]);
      removeOnline(me.username, socket.id);
      if (!isOnline(me.username)) {
        io.emit('user_offline', { username: me.username, lastSeen: ts });
      }
    } catch (e) {}
    me = null;
  });

  // ── Контакты ───────────────────────────────────────────────────────────
  socket.on('get_contacts', async (cb) => {
    if (!me) return cb?.([]);
    try {
      cb?.(await getContacts(me.username));
    } catch (e) {
      cb?.([]);
    }
  });

  // ── Сообщения ──────────────────────────────────────────────────────────
  socket.on('get_messages', async ({ with: partner }, cb) => {
    if (!me) return cb([]);
    try {
      const { rows } = await db.query(`
        SELECT id, from_user AS "from", to_user AS "to",
               content, type, reply_to AS "replyTo",
               duration, read, timestamp
        FROM messages
        WHERE deleted = FALSE
          AND ((from_user = $1 AND to_user = $2)
            OR (from_user = $2 AND to_user = $1))
        ORDER BY timestamp ASC
      `, [me.username, partner]);
      cb(rows);
    } catch (e) {
      console.error('get_messages:', e.message);
      cb([]);
    }
  });

  // ── Отправить сообщение ────────────────────────────────────────────────
  socket.on('send_message', async ({ to, content, type = 'text', replyTo, duration }, cb) => {
    if (!me || !to || !content) return cb?.({ ok: false });
    try {
      const msg = {
        id:        makeId(),
        from:      me.username,
        to,
        content,
        type,
        replyTo:   replyTo  || null,
        duration:  duration || null,
        timestamp: Date.now(),
        read:      false,
      };

      await db.query(`
        INSERT INTO messages
          (id, from_user, to_user, content, type, reply_to, duration, timestamp)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `, [msg.id, msg.from, msg.to, msg.content, msg.type, msg.replyTo, msg.duration, msg.timestamp]);

      // ФИКС: отправляем получателю через socket
      sendTo(to, 'new_message', msg);
      cb?.({ ok: true, message: msg });
    } catch (e) {
      console.error('send_message:', e.message);
      cb?.({ ok: false });
    }
  });

  // ── Прочитать ──────────────────────────────────────────────────────────
  socket.on('mark_read', async ({ chatWith }) => {
    if (!me) return;
    try {
      await db.query(`
        UPDATE messages SET read = TRUE
        WHERE to_user = $1 AND from_user = $2 AND read = FALSE AND deleted = FALSE
      `, [me.username, chatWith]);
      sendTo(chatWith, 'messages_read', { by: me.username });
    } catch (e) {}
  });

  // ── Печатает ───────────────────────────────────────────────────────────
  socket.on('typing', ({ to, isTyping }) => {
    if (!me) return;
    sendTo(to, 'user_typing', { from: me.username, isTyping });
  });

  // ── Удалить сообщение ──────────────────────────────────────────────────
  socket.on('delete_message', async ({ msgId, chatWith }, cb) => {
    if (!me) return cb?.({ ok: false });
    try {
      const { rowCount } = await db.query(
        'UPDATE messages SET deleted = TRUE WHERE id = $1 AND from_user = $2',
        [msgId, me.username]
      );
      if (!rowCount) return cb?.({ ok: false });
      sendTo(chatWith, 'message_deleted', { msgId });
      cb?.({ ok: true });
    } catch (e) {
      cb?.({ ok: false });
    }
  });

  // ── Обновить профиль ───────────────────────────────────────────────────
  socket.on('update_profile', async ({ displayName, bio, avatar, banner, privacy }, cb) => {
    if (!me) return cb?.({ ok: false });
    try {
      if (displayName !== undefined) {
        await db.query('UPDATE users SET display_name = $1 WHERE username = $2', [displayName, me.username]);
        me.display_name = displayName;
      }
      if (bio !== undefined) {
        await db.query('UPDATE users SET bio = $1 WHERE username = $2', [bio, me.username]);
        me.bio = bio;
      }
      if (avatar !== undefined) {
        await db.query('UPDATE users SET avatar = $1 WHERE username = $2', [avatar, me.username]);
        me.avatar = avatar;
      }
      if (banner !== undefined) {
        await db.query('UPDATE users SET banner = $1 WHERE username = $2', [banner, me.username]);
        me.banner = banner;
      }
      if (privacy !== undefined) {
        const merged = { ...(me.privacy || {}), ...privacy };
        await db.query('UPDATE users SET privacy = $1 WHERE username = $2', [JSON.stringify(merged), me.username]);
        me.privacy = merged;
      }
      io.emit('user_updated', userPublic(me));
      cb?.({ ok: true, user: userPublic(me) });
    } catch (e) {
      cb?.({ ok: false });
    }
  });

  // ── Сменить пароль ─────────────────────────────────────────────────────
  socket.on('change_password', async ({ oldPassword, newPassword }, cb) => {
    if (!me) return cb?.({ ok: false });
    try {
      const { rows } = await db.query('SELECT password_hash FROM users WHERE username = $1', [me.username]);
      if (rows[0].password_hash !== hashPassword(oldPassword)) {
        return cb?.({ ok: false, error: 'Неверный текущий пароль' });
      }
      await db.query('UPDATE users SET password_hash = $1 WHERE username = $2', [hashPassword(newPassword), me.username]);
      cb?.({ ok: true });
    } catch (e) {
      cb?.({ ok: false });
    }
  });

  // ── WebRTC ─────────────────────────────────────────────────────────────
  socket.on('call_user', ({ to, offer, callType }) => {
    if (!me) return;
    if (!isOnline(to)) { socket.emit('call_busy'); return; }
    sendTo(to, 'incoming_call', { from: me.username, offer, callType });
  });

  socket.on('call_answer', ({ to, answer }) => {
    if (!me) return;
    sendTo(to, 'call_answered', { from: me.username, answer });
  });

  socket.on('ice_candidate', ({ to, candidate }) => {
    if (!me) return;
    sendTo(to, 'ice_candidate', { from: me.username, candidate });
  });

  socket.on('call_end', ({ to }) => {
    if (!me) return;
    sendTo(to, 'call_ended', { from: me.username });
  });

  socket.on('call_reject', ({ to }) => {
    if (!me) return;
    sendTo(to, 'call_rejected', { from: me.username });
  });

  // ── Отключение ─────────────────────────────────────────────────────────
  socket.on('disconnect', async () => {
    if (!me) return;
    try {
      removeOnline(me.username, socket.id);
      if (!isOnline(me.username)) {
        const ts = Date.now();
        await db.query('UPDATE users SET last_seen = $1 WHERE username = $2', [ts, me.username]);
        io.emit('user_offline', { username: me.username, lastSeen: ts });
      }
    } catch (e) {}
  });
});

// ── Запуск ─────────────────────────────────────────────────────────────────
async function start() {
  try {
    await pool.connect();
    console.log('✅ Подключение к PostgreSQL успешно');
    await initDB();
    server.listen(PORT, () => {
      console.log(`
  ╔══════════════════════════════════════╗
  ║        Freedom Chat — запущен        ║
  ║  http://localhost:${PORT}               ║
  ╚══════════════════════════════════════╝
      `);
    });
  } catch (e) {
    console.error('❌ Ошибка подключения к БД:', e.message);
    process.exit(1);
  }
}

start();
