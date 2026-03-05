/**
 * Freedom Chat — Node.js + Firebase Firestore
 */

const express      = require('express');
const http         = require('http');
const { Server }   = require('socket.io');
const path         = require('path');
const crypto       = require('crypto');
const admin        = require('firebase-admin');

// ── Firebase init ──────────────────────────────────────────────────────────
admin.initializeApp({
  credential: admin.credential.cert({
    type: "service_account",
    project_id: "freedom-chat-737d8",
    private_key_id: "121487ee15292a6b8ce298f1974e6c4b48c1439b",
    private_key: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC+0owovPAOlom1\n5XPG2+ykPCgHgoT0RGJwwxBi4FihxaHGbDM4UG3PFsmjO8K0YV8uPHx5vy6w3x2u\nHQ8zAvjAdWBSY6BDxDyEwPlsKh+9qyDS/U743GzwqKcGSduMzqdIVxUSZhc/EZyB\nFEO01btzTlkX+yqnY72Ss0MQP2rpFuvUja49b/KXIAZAldlnfgj8uRaOMhUXyghO\nFQGI/pA+UhzJxXC8BFbkJ5Qpld3lkXCSewoh2pUp/aErmCkDx4IhrUTm7GehnAKg\n4MBfe9tsRYkyJW38+E2D9FLhLz35lfAM7q3CevQjZf+9MEFA+48OHNyjKvgT2CKd\nxUqR6EnLAgMBAAECggEADjt16LPu06e2rbJnaDWO+NDjy2uYrv9KuE5UMou5EJfE\n8R+w0kptZjy03U/fvcRlbPVl806nFNoPRKU2NP/Lvc8DWCHGGkfQm7Yo5EBgDa1t\nzU7HTRhjp69shbOMhHwFTgfwsmaa5UFTAu2X/yzRxk/ZpUg+bi2qPf7Qya1xM+E4\nqYYYubd3p2xuOBIwc7HQ9fR5mOOYv6w0JTJ5PeRf1UuwI/1LtT4QhrusY88HqkIh\nxlCPDPwcr3pXCf0WArTlwSiEaKN4gm0ie2b36PIhoOUaSgG9tqbp9AV7D8YcHuM/\nhrXMZfeQuP6dzmN88sXzflICzpWIDSgzO/HDxmppgQKBgQDyXJKn3iNb7HwQl51e\nLPKa5N3fOayd6qF7wSidQx7wbIKwGkzEpyeFCRdKdtzobwgb8gLDH+TdroUmE+V9\nUStvcsYGn8bv01DS7TlUaLDuYxNakKdpkhbhOf6aRev3mwmvuXfirKukVNkDgo8I\nOMcrJMS0VSTElcDBi3i4hrsMyQKBgQDJj4I9ROSbwKH890yrhdfcTF0gAUpNho/W\nozOzcSdj0TT0CNl5QFgeR1xhMD0tHt/Za/l2e0zHNzohM/kPbVMlOGvFIXGpxnTT\n6ncQoTZ4Zkb289I/eU19UEY23WavRdxcS6S4CJ0aJbv5c/aFYOCvGupTApbSkO63\nlZlCbVBv8wKBgD6wo164nvzQFudT0Gjjx305ZgqvqG7QmiSguhizm/UknElhBCp5\n8kb/Kv8f79RPpBFWcFB4l4Kf+eD3lIztygZx8bcU7ShryKRGqGWlDt8a0Y7DjApK\nt5Bap/jPzVGm0MKbft8rOtqu99NomgbOaPZH9HmQ7InNEqb9pKRWdVvBAoGBAIWM\nZ4/u+MXWIb55oLw5J2hY1I8jK7coRF/DrLrla2Lwt/RFdMqo/nm5cJUYoEAoJ8to\nhlahpaKNjh93zzsQhbmwo39vBF+oFbpfrNpA5tVpdvWjYZga6GPyb0Nk+OeDE1m3\n6QDi/CzZ+a1zz1BaeySqYb30hjgoPXM4VN61jUlPAoGAeiggGcMtSVE9rUwPtWsJ\nKT6Dfy9exr1RYXUpnXl6H3Y1aDj0Qvvtkd/KLAXTa6R2zhMKA+sEEpOiGMQpOi1w\nUqDZ3jDeN5yltGt+5Q1wf23uII/XmXPeMlsw45k7SuxggZaOlnRFd4dslqcx8A9u\nNn8O5qqhQ9+V6KJcTHTowFc=\n-----END PRIVATE KEY-----\n",
    client_email: "firebase-adminsdk-fbsvc@freedom-chat-737d8.iam.gserviceaccount.com",
    client_id: "117329059940151937510",
    auth_uri: "https://accounts.google.com/o/oauth2/auth",
    token_uri: "https://oauth2.googleapis.com/token",
    auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
    client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40freedom-chat-737d8.iam.gserviceaccount.com",
    universe_domain: "googleapis.com"
  }),
});

const db = admin.firestore();
db.settings({ ignoreUndefinedProperties: true });

const usersCol    = db.collection('users');
const sessionsCol = db.collection('sessions');
const msgsCol     = db.collection('messages');
const e2eKeysCol  = db.collection('e2e_keys');   // Публичные E2E-ключи пользователей

// ── Express + Socket.IO ────────────────────────────────────────────────────
const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  maxHttpBufferSize: 1 * 1024 * 1024,
  cors: { origin: '*' },
});

const PORT = process.env.PORT || 3000;

// ── Helpers ────────────────────────────────────────────────────────────────
function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw + 'freedom_salt').digest('hex');
}
function makeId()    { return crypto.randomBytes(8).toString('hex'); }
function makeToken() { return crypto.randomBytes(24).toString('hex'); }
function chatId(a, b) { return [a, b].sort().join('__'); }

// ── Online users ───────────────────────────────────────────────────────────
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
function sendTo(username, event, data) {
  const sockets = onlineUsers.get(username);
  if (!sockets) return;
  sockets.forEach(sid => {
    const sock = io.sockets.sockets.get(sid);
    if (sock) sock.emit(event, data);
  });
}

function userPublic(u) {
  return {
    username:    u.username,
    displayName: u.displayName || u.username,
    bio:         u.bio      || '',
    avatar:      u.avatar   || null,
    banner:      u.banner   || null,
    online:      isOnline(u.username),
    lastSeen:    u.lastSeen || null,
    privacy:     u.privacy  || { lastSeen: 'everyone', avatar: 'everyone' },
    e2eEnabled:  u.e2eEnabled || false,   // Поддерживает ли E2E шифрование
  };
}

async function getContacts(username) {
  const snap = await usersCol.orderBy('createdAt', 'asc').get();
  const users = snap.docs.map(d => d.data()).filter(u => u.username !== username);

  const results = await Promise.all(users.map(async u => {
    const cid = chatId(username, u.username);

    const [lastSnap, unreadSnap] = await Promise.all([
      msgsCol.where('chatId','==',cid).where('deleted','==',false)
             .orderBy('timestamp','desc').limit(1).get(),
      msgsCol.where('chatId','==',cid).where('to','==',username)
             .where('from','==',u.username).where('read','==',false)
             .where('deleted','==',false).get()
    ]);

    const lastMsg = lastSnap.empty ? null : lastSnap.docs[0].data();
    return {
      ...userPublic(u),
      lastMessage: lastMsg ? { ...lastMsg, timestamp: Number(lastMsg.timestamp) } : null,
      unread: unreadSnap.size,
    };
  }));

  results.sort((a, b) => {
    const ta = a.lastMessage ? a.lastMessage.timestamp : 0;
    const tb = b.lastMessage ? b.lastMessage.timestamp : 0;
    return tb - ta;
  });

  return results;
}

// ── REST ───────────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/api/users', async (req, res) => {
  try {
    const snap = await usersCol.orderBy('createdAt', 'asc').get();
    res.json(snap.docs.map(d => userPublic(d.data())));
  } catch (e) { res.json([]); }
});

// ── Socket.IO ──────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  let me = null;

  // ── Восстановление сессии ────────────────────────────────────────────
  socket.on('restore_session', async (tokenOrCreds, cb) => {
    try {
      let userData = null;

      if (typeof tokenOrCreds === 'string' && tokenOrCreds.length > 8) {
        const sesSnap = await sessionsCol.doc(tokenOrCreds).get();
        if (sesSnap.exists) {
          const uSnap = await usersCol.doc(sesSnap.data().username).get();
          if (uSnap.exists) userData = uSnap.data();
        }
      } else if (tokenOrCreds?.username) {
        const uSnap = await usersCol.doc(tokenOrCreds.username).get();
        if (uSnap.exists) {
          const u = uSnap.data();
          if (tokenOrCreds.password && u.passwordHash === hashPassword(tokenOrCreds.password)) {
            userData = u;
            const newToken = makeToken();
            await sessionsCol.doc(newToken).set({ username: u.username, createdAt: Date.now() });
            socket.emit('upgrade_token', newToken);
          }
        }
      }

      if (!userData) return cb({ ok: false });
      me = userData;
      addOnline(me.username, socket.id);
      io.emit('user_online', { username: me.username });
      cb({ ok: true, user: userPublic(me), contacts: await getContacts(me.username) });
    } catch (e) {
      console.error('restore_session:', e.message);
      cb({ ok: false });
    }
  });

  // ── Регистрация ──────────────────────────────────────────────────────
  socket.on('register', async ({ username, password, displayName }, cb) => {
    try {
      if (!username || !password) return cb({ ok: false, error: 'Заполните поля' });
      if (username.length < 3)    return cb({ ok: false, error: 'Минимум 3 символа' });

      const exists = await usersCol.doc(username).get();
      if (exists.exists) return cb({ ok: false, error: 'Имя занято' });

      const user = {
        username, displayName: displayName || username,
        passwordHash: hashPassword(password),
        bio: '', avatar: null, banner: null, lastSeen: null,
        privacy: { lastSeen: 'everyone', avatar: 'everyone' },
        createdAt: Date.now(),
      };
      await usersCol.doc(username).set(user);
      const token = makeToken();
      await sessionsCol.doc(token).set({ username, createdAt: Date.now() });

      me = user;
      addOnline(me.username, socket.id);
      io.emit('user_online', { username: me.username });
      cb({ ok: true, user: userPublic(me), token, contacts: [] });
    } catch (e) {
      console.error('register:', e.message);
      cb({ ok: false, error: 'Ошибка сервера' });
    }
  });

  // ── Логин ────────────────────────────────────────────────────────────
  socket.on('login', async ({ username, password, token: loginToken }, cb) => {
    try {
      let userData = null;

      if (loginToken) {
        const sesSnap = await sessionsCol.doc(loginToken).get();
        if (sesSnap.exists) {
          const uSnap = await usersCol.doc(sesSnap.data().username).get();
          if (uSnap.exists) userData = uSnap.data();
        }
      }
      if (!userData && username && password) {
        const uSnap = await usersCol.doc(username).get();
        if (!uSnap.exists) return cb({ ok: false, error: 'Пользователь не найден' });
        const u = uSnap.data();
        if (u.passwordHash !== hashPassword(password)) return cb({ ok: false, error: 'Неверный пароль' });
        userData = u;
      }
      if (!userData) return cb({ ok: false, error: 'Неверные данные' });

      const token = makeToken();
      await sessionsCol.doc(token).set({ username: userData.username, createdAt: Date.now() });

      me = userData;
      addOnline(me.username, socket.id);
      io.emit('user_online', { username: me.username });
      cb({ ok: true, user: userPublic(me), token, contacts: await getContacts(me.username) });
    } catch (e) {
      console.error('login:', e.message);
      cb({ ok: false, error: 'Ошибка сервера' });
    }
  });

  // ── Выход ────────────────────────────────────────────────────────────
  socket.on('logout', async () => {
    if (!me) return;
    try {
      const snap = await sessionsCol.where('username', '==', me.username).get();
      const batch = db.batch();
      snap.docs.forEach(d => batch.delete(d.ref));
      await batch.commit();
      const ts = Date.now();
      await usersCol.doc(me.username).update({ lastSeen: ts });
      removeOnline(me.username, socket.id);
      if (!isOnline(me.username)) io.emit('user_offline', { username: me.username, lastSeen: ts });
    } catch (e) {}
    me = null;
  });

  // ── Контакты ─────────────────────────────────────────────────────────
  socket.on('get_contacts', async (cb) => {
    if (!me) return cb?.([]);
    try { cb?.(await getContacts(me.username)); } catch (e) { cb?.([]); }
  });

  // ── Превью чатов ─────────────────────────────────────────────────────
  socket.on('get_previews', async (_, cb) => {
    if (!me) return cb?.({});
    try {
      const snap = await msgsCol
        .where('participants', 'array-contains', me.username)
        .where('deleted', '==', false)
        .orderBy('timestamp', 'desc')
        .get();

      const seen = new Set(), result = {};
      snap.docs.forEach(d => {
        const msg = d.data();
        const partner = msg.from === me.username ? msg.to : msg.from;
        if (!seen.has(partner)) {
          seen.add(partner);
          result[partner] = { ...msg, timestamp: Number(msg.timestamp) };
        }
      });
      cb?.(result);
    } catch (e) {
      console.error('get_previews:', e.message);
      cb?.({});
    }
  });

  // ── Сообщения ─────────────────────────────────────────────────────────
  socket.on('get_messages', async ({ with: partner }, cb) => {
    if (!me) return cb([]);
    try {
      const cid = chatId(me.username, partner);
      const snap = await msgsCol
        .where('chatId', '==', cid)
        .where('deleted', '==', false)
        .orderBy('timestamp', 'asc')
        .get();
      cb(snap.docs.map(d => ({ ...d.data(), timestamp: Number(d.data().timestamp) })));
    } catch (e) {
      console.error('get_messages:', e.message);
      cb([]);
    }
  });

  // ── Отправить сообщение ───────────────────────────────────────────────
  // Поддерживает обычные и E2E-зашифрованные сообщения (e2e: true).
  // Сервер не видит содержимое зашифрованных сообщений — только передаёт
  // зашифрованный blob и x3dhInit (для первого сообщения в сессии).
  socket.on('send_message', async ({ to, content, text, image, type, replyTo, duration,
                                     e2e, encrypted, x3dhInit }, cb) => {
    if (!me || !to) return cb?.({ ok: false });

    // E2E-сообщение: содержимое зашифровано клиентом
    if (e2e && encrypted) {
      try {
        const msg = {
          id:           makeId(),
          from:         me.username,
          to,
          chatId:       chatId(me.username, to),
          participants: [me.username, to],
          // Зашифрованный payload — сервер не расшифровывает
          content:      '[e2e]',           // Заглушка для превью (не читаемо)
          type:         type || 'text',
          replyTo:      replyTo || null,
          duration:     duration || null,
          timestamp:    Date.now(),
          read:         false,
          deleted:      false,
          // E2E-поля (передаются получателю как есть)
          e2e:          true,
          encrypted:    encrypted,         // { header, iv, ciphertext }
          x3dhInit:     x3dhInit || null,  // Только в первом сообщении сессии
        };
        await msgsCol.doc(msg.id).set(msg);
        const out = { ...msg, timestamp: Number(msg.timestamp) };
        sendTo(to, 'new_message', out);
        cb?.({ ok: true, message: out });
      } catch (e) {
        console.error('send_message(e2e):', e.message);
        cb?.({ ok: false });
      }
      return;
    }

    // Обычное (нешифрованное) сообщение
    const msgContent = content || text || image || null;
    const msgType    = type || (image ? 'image' : 'text');
    if (!msgContent) return cb?.({ ok: false });
    try {
      const msg = {
        id: makeId(), from: me.username, to,
        chatId: chatId(me.username, to),
        participants: [me.username, to],
        content: msgContent, type: msgType,
        replyTo: replyTo || null, duration: duration || null,
        timestamp: Date.now(), read: false, deleted: false,
        e2e: false,
      };
      await msgsCol.doc(msg.id).set(msg);
      const out = { ...msg, timestamp: Number(msg.timestamp) };
      sendTo(to, 'new_message', out);
      cb?.({ ok: true, message: out });
    } catch (e) {
      console.error('send_message:', e.message);
      cb?.({ ok: false });
    }
  });

  // ── Прочитать ─────────────────────────────────────────────────────────
  socket.on('mark_read', async ({ chatWith }) => {
    if (!me) return;
    try {
      const cid = chatId(me.username, chatWith);
      const snap = await msgsCol
        .where('chatId','==',cid).where('to','==',me.username)
        .where('read','==',false).where('deleted','==',false).get();
      const batch = db.batch();
      snap.docs.forEach(d => batch.update(d.ref, { read: true }));
      await batch.commit();
      sendTo(chatWith, 'messages_read', { by: me.username });
    } catch (e) {}
  });

  // ── Печатает ──────────────────────────────────────────────────────────
  socket.on('typing', ({ to, isTyping }) => {
    if (me) sendTo(to, 'user_typing', { from: me.username, isTyping });
  });

  // ── Удалить сообщение ─────────────────────────────────────────────────
  socket.on('delete_message', async ({ msgId, chatWith }, cb) => {
    if (!me) return cb?.({ ok: false });
    try {
      const doc = await msgsCol.doc(msgId).get();
      if (!doc.exists || doc.data().from !== me.username) return cb?.({ ok: false });
      await msgsCol.doc(msgId).update({ deleted: true });
      sendTo(chatWith, 'message_deleted', { msgId });
      cb?.({ ok: true });
    } catch (e) { cb?.({ ok: false }); }
  });

  // ── Обновить профиль ──────────────────────────────────────────────────
  socket.on('update_profile', async ({ displayName, bio, avatar, banner, privacy }, cb) => {
    if (!me) return cb?.({ ok: false });
    try {
      const upd = {};
      if (displayName !== undefined) { upd.displayName = displayName; me.displayName = displayName; }
      if (bio         !== undefined) { upd.bio         = bio;         me.bio         = bio; }
      if (avatar      !== undefined) { upd.avatar      = avatar;      me.avatar      = avatar; }
      if (banner      !== undefined) { upd.banner      = banner;      me.banner      = banner; }
      if (privacy     !== undefined) {
        upd.privacy = { ...(me.privacy || {}), ...privacy };
        me.privacy  = upd.privacy;
      }
      await usersCol.doc(me.username).update(upd);
      io.emit('user_updated', userPublic(me));
      cb?.({ ok: true, user: userPublic(me) });
    } catch (e) { cb?.({ ok: false }); }
  });

  // ── Сменить пароль ────────────────────────────────────────────────────
  socket.on('change_password', async ({ oldPassword, newPassword }, cb) => {
    if (!me) return cb?.({ ok: false });
    try {
      const snap = await usersCol.doc(me.username).get();
      if (snap.data().passwordHash !== hashPassword(oldPassword))
        return cb?.({ ok: false, error: 'Неверный текущий пароль' });
      await usersCol.doc(me.username).update({ passwordHash: hashPassword(newPassword) });
      cb?.({ ok: true });
    } catch (e) { cb?.({ ok: false }); }
  });

  // ── E2E: Регистрация публичных ключей ────────────────────────────────
  // Клиент отправляет свой публичный bundle после генерации ключей.
  // Сервер хранит только публичные части — приватные ключи никогда не покидают клиент.
  //
  // bundle = {
  //   IK:     string (base64) — Identity Key (долгосрочный)
  //   SPK:    string (base64) — Signed PreKey (меняется раз в неделю)
  //   SPKSig: string (base64) — Подпись SPK через IK
  //   OPKs:   string[]        — One-Time PreKeys (одноразовые, пачка)
  // }
  socket.on('register_e2e_keys', async (bundle, cb) => {
    if (!me) return cb?.({ ok: false });
    try {
      const { IK, SPK, SPKSig, OPKs } = bundle;
      if (!IK || !SPK || !SPKSig || !Array.isArray(OPKs))
        return cb?.({ ok: false, error: 'Неверный формат bundle' });

      const existing = await e2eKeysCol.doc(me.username).get();

      // Если уже есть запись — сохраняем существующие OPK и добавляем новые
      const existingOPKs = existing.exists ? (existing.data().OPKs || []) : [];
      const mergedOPKs = [...existingOPKs, ...OPKs];

      await e2eKeysCol.doc(me.username).set({
        IK, SPK, SPKSig,
        OPKs:      mergedOPKs,
        updatedAt: Date.now(),
      });

      // Помечаем пользователя как поддерживающего E2E
      await usersCol.doc(me.username).update({ e2eEnabled: true });
      me.e2eEnabled = true;

      console.log(`[E2E] ${me.username}: зарегистрировал ключи (OPK: ${mergedOPKs.length})`);
      cb?.({ ok: true, opkCount: mergedOPKs.length });
    } catch (e) {
      console.error('register_e2e_keys:', e.message);
      cb?.({ ok: false });
    }
  });

  // ── E2E: Получить публичный bundle пользователя ───────────────────────
  // Инициатор запрашивает bundle получателя перед первым сообщением.
  // Сервер атомарно отдаёт И удаляет один OPK (одноразовый ключ).
  // Если OPK закончились — уведомляет получателя о пополнении.
  socket.on('get_e2e_keys', async ({ username: target }, cb) => {
    if (!me) return cb?.({ ok: false });
    try {
      const snap = await e2eKeysCol.doc(target).get();
      if (!snap.exists) return cb?.({ ok: false, error: 'E2E не поддерживается' });

      const data = snap.data();
      const { IK, SPK, SPKSig, OPKs } = data;

      // Атомарно берём один OPK и удаляем его из пула
      let usedOPK = null;
      let remainingOPKs = OPKs || [];

      if (remainingOPKs.length > 0) {
        usedOPK = remainingOPKs[0];
        remainingOPKs = remainingOPKs.slice(1);
        await e2eKeysCol.doc(target).update({ OPKs: remainingOPKs });

        // Уведомляем получателя если OPK на исходе
        if (remainingOPKs.length < 5) {
          sendTo(target, 'e2e_low_opk', { remaining: remainingOPKs.length });
          console.log(`[E2E] ${target}: мало OPK осталось (${remainingOPKs.length})`);
        }
      } else {
        // OPK нет — сессия без одноразового ключа (менее безопасно, но работает)
        console.warn(`[E2E] ${target}: OPK пул пуст, сессия без OPK`);
      }

      cb?.({
        ok: true,
        bundle: {
          IK,
          SPK,
          SPKSig,
          OPKs: usedOPK ? [usedOPK] : [],  // Отдаём ровно один OPK
        },
      });
    } catch (e) {
      console.error('get_e2e_keys:', e.message);
      cb?.({ ok: false });
    }
  });

  // ── E2E: Пополнение OPK ───────────────────────────────────────────────
  // Клиент отправляет новую порцию одноразовых ключей когда их стало мало.
  socket.on('replenish_opks', async (newOPKs, cb) => {
    if (!me || !Array.isArray(newOPKs)) return cb?.({ ok: false });
    try {
      const snap = await e2eKeysCol.doc(me.username).get();
      if (!snap.exists) return cb?.({ ok: false, error: 'Сначала зарегистрируйте ключи' });

      const current = snap.data().OPKs || [];
      const merged  = [...current, ...newOPKs];
      await e2eKeysCol.doc(me.username).update({ OPKs: merged });

      console.log(`[E2E] ${me.username}: пополнил OPK (${current.length} → ${merged.length})`);
      cb?.({ ok: true, opkCount: merged.length });
    } catch (e) {
      console.error('replenish_opks:', e.message);
      cb?.({ ok: false });
    }
  });

  // ── E2E: Обновление SPK (раз в неделю) ───────────────────────────────
  // Подписанный prekey нужно обновлять периодически для forward secrecy.
  socket.on('update_spk', async ({ SPK, SPKSig }, cb) => {
    if (!me || !SPK || !SPKSig) return cb?.({ ok: false });
    try {
      await e2eKeysCol.doc(me.username).update({ SPK, SPKSig, updatedAt: Date.now() });
      console.log(`[E2E] ${me.username}: обновил SPK`);
      cb?.({ ok: true });
    } catch (e) {
      console.error('update_spk:', e.message);
      cb?.({ ok: false });
    }
  });

  // ── E2E: Проверить статус E2E для пользователя ────────────────────────
  // Клиент может узнать поддерживает ли собеседник E2E перед отправкой.
  socket.on('check_e2e', async ({ username: target }, cb) => {
    if (!me) return cb?.({ ok: false });
    try {
      const snap = await e2eKeysCol.doc(target).get();
      cb?.({ ok: true, e2eEnabled: snap.exists, opkAvailable: snap.exists && (snap.data().OPKs || []).length > 0 });
    } catch (e) {
      cb?.({ ok: false, e2eEnabled: false });
    }
  });

  // ── WebRTC ────────────────────────────────────────────────────────────
  socket.on('call_user',     ({ to, offer, callType }) => {
    if (!me) return;
    if (!isOnline(to)) { socket.emit('call_busy'); return; }
    sendTo(to, 'incoming_call', { from: me.username, offer, callType });
  });
  socket.on('call_answer',   ({ to, answer })    => { if (me) sendTo(to, 'call_answered',  { from: me.username, answer }); });
  socket.on('ice_candidate', ({ to, candidate }) => { if (me) sendTo(to, 'ice_candidate',  { from: me.username, candidate }); });
  socket.on('call_end',      ({ to })            => { if (me) sendTo(to, 'call_ended',     { from: me.username }); });
  socket.on('call_reject',   ({ to })            => { if (me) sendTo(to, 'call_rejected',  { from: me.username }); });

  // ── Редактирование сообщения ─────────────────────────────────────────
  socket.on('edit_message', async ({ msgId, content, chatWith }, cb) => {
    if (!me || !msgId || !content) return cb?.({ ok: false });
    try {
      const snap = await msgsCol.doc(msgId).get();
      if (!snap.exists) return cb?.({ ok: false, error: 'Сообщение не найдено' });
      const msg = snap.data();
      if (msg.from !== me.username) return cb?.({ ok: false, error: 'Нет прав' });
      await msgsCol.doc(msgId).update({ content, edited: true, editedAt: Date.now() });
      // Уведомляем собеседника
      sendTo(chatWith, 'message_edited', { msgId, content, editedAt: Date.now() });
      cb?.({ ok: true });
    } catch (e) {
      console.error('edit_message:', e.message);
      cb?.({ ok: false });
    }
  });

  // ── Реакции на сообщение ─────────────────────────────────────────────
  socket.on('react_message', async ({ msgId, chatWith, emoji, action }) => {
    if (!me || !msgId || !emoji) return;
    try {
      const snap = await msgsCol.doc(msgId).get();
      if (!snap.exists) return;
      const msg = snap.data();
      const reactions = msg.reactions || {};
      if (!reactions[emoji]) reactions[emoji] = [];
      if (action === 'add') {
        if (!reactions[emoji].includes(me.username)) reactions[emoji].push(me.username);
      } else {
        reactions[emoji] = reactions[emoji].filter(u => u !== me.username);
        if (reactions[emoji].length === 0) delete reactions[emoji];
      }
      await msgsCol.doc(msgId).update({ reactions });
      // Уведомляем собеседника
      sendTo(chatWith, 'message_reaction', { msgId, emoji, action, from: me.username, chatWith: me.username });
    } catch (e) {
      console.error('react_message:', e.message);
    }
  });

  // ── Отключение ────────────────────────────────────────────────────────
  socket.on('disconnect', async () => {
    if (!me) return;
    try {
      removeOnline(me.username, socket.id);
      if (!isOnline(me.username)) {
        const ts = Date.now();
        await usersCol.doc(me.username).update({ lastSeen: ts });
        io.emit('user_offline', { username: me.username, lastSeen: ts });
      }
    } catch (e) {}
  });
});

// ── Запуск ─────────────────────────────────────────────────────────────────
async function start() {
  try {
    await db.collection('_health').doc('ping').set({ ts: Date.now() });
    console.log('✅ Firebase Firestore подключён');
    server.listen(PORT, () => {
      console.log(`
  ╔══════════════════════════════════════╗
  ║     Freedom Chat — Firebase mode     ║
  ║  http://localhost:${PORT}               ║
  ╚══════════════════════════════════════╝
      `);
    });
  } catch (e) {
    console.error('❌ Ошибка Firebase:', e.message);
    process.exit(1);
  }
}

start();
