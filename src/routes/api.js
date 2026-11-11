'use strict';

/**
 * Beatles-WS REST API.
 *
 * Menyediakan autentikasi JWT berbasis role (USER / ADMIN / BOS), manajemen
 * database nomor tujuan, template pesan, pengiriman pesan, broadcast massal
 * dengan jeda anti-ban, deteksi status nomor, serta endpoint WhatsApp
 * (QR / pairing code) yang terhubung ke gateway Baileys.
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const multer = require('multer');

const {
  connectWhatsApp,
  createNewWhatsAppSession,
  startSession,
  requestPairingCode,
  sendMessage,
  checkNumber,
  getWhatsAppStatus,
  listWhatsAppSessions,
  findReusableCodeSession,
  disconnectWhatsApp,
  logoutWhatsApp,
} = require('./whatsapp/client');

const {
  readStore,
  saveStore,
  publicUser,
  normalizeNumber,
} = require('../store');

const {
  VALID_NUMBER,
  asyncHandler,
  isValidPhone,
  clampString,
  sanitizeFilename,
  isAllowedUpload,
  isContactFile,
  hasUnsafeKeys,
  setNoStore,
} = require('../utils/helpers');

const { parseContactFile } = require('../utils/contacts');

const {
  LANGUAGES,
  isSupportedLang,
  translateText,
} = require('../utils/translate');

const router = express.Router();

// Tolak body JSON yang mencoba mencemari prototype (__proto__/constructor/
// prototype) sebelum menyentuh handler mana pun.
router.use((req, res, next) => {
  if (req.body && typeof req.body === 'object' && hasUnsafeKeys(req.body)) {
    return res.status(400).json({ ok: false, error: 'Payload tidak valid.' });
  }
  return next();
});

// File unggahan disimpan di folder yang sama dengan yang disajikan server
// pada rute /uploads, agar berkas yang diunggah benar-benar dapat diakses.
const uploadDir = path.join(__dirname, '..', '..', 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadDir),
    filename: (_req, file, cb) => {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
      // Nama asli dibersihkan agar tidak bisa keluar dari folder uploads
      // (path traversal) maupun menyisipkan ekstensi berbahaya.
      cb(null, `${uniqueSuffix}-${sanitizeFilename(file.originalname)}`);
    },
  }),
  limits: { fileSize: 10 * 1024 * 1024, files: 1 }, // 10MB, satu berkas
  fileFilter: (_req, file, cb) => {
    if (!isAllowedUpload(file.originalname)) {
      const error = new Error(
        'Tipe berkas tidak diizinkan. Gunakan .txt, .csv, .xlsx, .json, gambar (png/jpg), atau video .mp4.'
      );
      error.code = 'UNSUPPORTED_FILE_TYPE';
      return cb(error);
    }
    return cb(null, true);
  },
});

const jwtSecret = process.env.JWT_SECRET;

// ---------- Persistence ----------
// (dipindah ke src/store.js dan diimpor di atas)

// ---------- Authentication & permissions ----------

function auth(req, res, next) {
  if (!jwtSecret || jwtSecret.length < 32) {
    return res.status(503).json({
      ok: false,
      error: 'JWT_SECRET belum disetel. Isi .env dengan secret acak minimal 32 karakter.',
    });
  }

  const header = req.headers.authorization || '';
  const match = header.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    return res.status(401).json({ ok: false, error: 'Token autentikasi diperlukan.' });
  }

  try {
    // Algoritma dipin ke HS256 agar token dengan alg lain (mis. "none") ditolak.
    const payload = jwt.verify(match[1], jwtSecret, {
      issuer: 'beatles-ws',
      algorithms: ['HS256'],
    });

    // Token yang masih berlaku tidak cukup: pastikan akunnya masih ada dan
    // aktif. Tanpa ini, user yang dihapus/dinonaktifkan tetap bisa memakai
    // token lamanya sampai kedaluwarsa (8 jam).
    const store = readStore();
    const user = store.users.find((u) => u.username === payload.username);

    if (!user || user.active === false) {
      return res.status(401).json({ ok: false, error: 'Akun tidak ditemukan atau dinonaktifkan.' });
    }

    // Pakai data user terbaru dari store agar perubahan role/status langsung
    // berlaku, bukan nilai yang tertanam di token lama.
    req.user = publicUser(user);
    setNoStore(res);
    return next();
  } catch {
    return res.status(401).json({ ok: false, error: 'Token tidak valid atau sesi berakhir.' });
  }
}

function allow(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ ok: false, error: 'Akses ditolak untuk role ini.' });
    }
    return next();
  };
}

function handleError(res, error, fallback, status = 500) {
  console.error(`${fallback}:`, error.message);

  let code = status;

  if (error.code === 'NOT_CONNECTED') code = 409;
  else if (error.code === 'UNSUPPORTED_FILE_TYPE') code = 415;
  else if (error.code === 'LIMIT_FILE_SIZE') code = 413;

  return res.status(code).json({ ok: false, error: error.message || fallback });
}

/*
 * Menentukan sesi WhatsApp yang dipakai untuk mengirim. Bila pemanggil tidak
 * menyebut sesi (atau sesi yang diminta tidak ada), pakai sesi pertama yang
 * berstatus "connected". Ini memungkinkan halaman USER ikut memakai gateway
 * yang sudah ditautkan oleh ADMIN tanpa perlu tahu detail sesi.
 */
function resolveActiveSession(requested) {
  const sessions = listWhatsAppSessions();
  const wanted = String(requested || '').trim();

  if (wanted && sessions.some((s) => s.sessionId === wanted)) {
    return wanted;
  }

  const connected = sessions.find((s) => s.status === 'connected');
  return connected ? connected.sessionId : (wanted || 'device-01');
}

// ---------- Health ----------

router.get('/health', (_req, res) => {
  res.json({
    ok: true,
    app: 'BEATLES-WS API',
    mode: 'production',
    timestamp: new Date().toISOString(),
  });
});

// ---------- Login & Register ----------

router.post('/auth/login', (req, res) => {
  if (!jwtSecret || jwtSecret.length < 32) {
    return res.status(503).json({
      ok: false,
      error: 'Backend belum dikonfigurasi. Isi JWT_SECRET minimal 32 karakter.',
    });
  }

  const username = String(req.body?.username || '').trim().toLowerCase().slice(0, 64);
  const password = String(req.body?.password || '').slice(0, 200);

  const store = readStore();
  const user = store.users.find((item) => item.username === username);

  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ ok: false, error: 'Username atau password salah.' });
  }

  if (user.active === false) {
    return res.status(403).json({ ok: false, error: 'Akun dinonaktifkan. Hubungi admin.' });
  }

  const token = jwt.sign(publicUser(user), jwtSecret, {
    expiresIn: '8h',
    issuer: 'beatles-ws',
    algorithm: 'HS256',
  });

  setNoStore(res);

  return res.json({
    ok: true,
    token,
    user: publicUser(user),
    expiresIn: 28800,
  });
});

router.post('/auth/register', (req, res) => {
  const name = clampString(req.body?.name, 80);
  const username = String(req.body?.username || '').trim().toLowerCase();
  const password = String(req.body?.password || '');

  if (!username || !password) {
    return res.status(400).json({ ok: false, error: 'Username dan password wajib diisi.' });
  }

  if (!/^[a-z0-9_.-]{3,32}$/.test(username)) {
    return res.status(400).json({
      ok: false,
      error: 'Username 3-32 karakter, hanya huruf kecil, angka, titik, garis bawah, atau strip.',
    });
  }

  if (password.length < 6 || password.length > 200) {
    return res.status(400).json({ ok: false, error: 'Password 6-200 karakter.' });
  }

  const store = readStore();

  if (store.users.some((u) => u.username === username)) {
    return res.status(400).json({ ok: false, error: 'Username sudah digunakan.' });
  }

  store.users.push({
    username,
    passwordHash: bcrypt.hashSync(password, 10),
    role: 'USER',
    name: name || username,
    active: true,
    quota: 0,
    telegram: '',
    referral: '',
    pinHash: null,
  });

  saveStore(store);

  return res.status(201).json({ ok: true, message: 'Registrasi berhasil. Silakan masuk.' });
});

router.get('/auth/me', auth, (req, res) => {
  res.json({ ok: true, user: req.user });
});

// ---------- Dashboard ----------

router.get('/dashboard', auth, (req, res) => {
  const store = readStore();

  const withdrawals = store.withdrawals.filter(
    (item) => req.user.role !== 'USER' || item.username === req.user.username
  );

  const messages = (store.messages || []).filter(
    (item) => req.user.role !== 'USER' || item.username === req.user.username
  );

  res.json({
    ok: true,
    user: req.user,
    tariff: store.tariff,
    databasesCount: (store.databases || []).length,
    contactsCount: (store.contacts || []).length,
    templatesCount: (store.templates || []).length,
    withdrawalCount: withdrawals.length,
    pendingWithdrawals: withdrawals.filter((item) => item.status === 'PENDING').length,
    messagesSent: messages.filter((item) => item.status === 'sent').length,
    messagesFailed: messages.filter((item) => item.status && item.status !== 'sent').length,
  });
});

// ---------- Admin: Database & Template Management ----------

router.get('/admin/databases', auth, allow('ADMIN', 'BOS'), (_req, res) => {
  const store = readStore();
  res.json({ ok: true, databases: store.databases || [] });
});

router.post('/admin/databases', auth, allow('ADMIN'), upload.single('file'), asyncHandler(async (req, res) => {
  const name = clampString(req.body?.name || 'Kategori Baru', 80) || 'Kategori Baru';
  const tariffPerMsg = Number(req.body?.tariffPerMsg || 150);
  const mediaType = clampString(req.body?.mediaType || 'text', 20) || 'text';

  // Template pesan Stok DB: "Nama | Teks | URL | Foto". Masing-masing bagian
  // opsional kecuali teks. Foto boleh berupa URL atau path hasil unggahan.
  const templateContent = clampString(req.body?.templateContent, 4000);
  const templateName = clampString(req.body?.templateName, 80);
  const mediaUrl = clampString(req.body?.mediaUrl, 2048);
  const photoUrl = clampString(req.body?.photoUrl, 2048);

  let totalNumbers = 0;
  let filePath = null;
  let stats = { invalid: 0, duplicates: 0 };
  const extracted = [];

  if (req.file) {
    filePath = req.file.path;
    const parsed = await parseContactFile(filePath, req.file.originalname);
    extracted.push(...parsed.valid);
    totalNumbers = parsed.total;
    stats = { invalid: parsed.invalid, duplicates: parsed.duplicates };
  }

  const store = readStore();
  if (!store.databases) store.databases = [];

  const newDb = {
    id: `db_${Date.now()}`,
    name,
    totalNumbers,
    filePath,
    originalFile: req.file ? req.file.originalname : null,
    tariffPerMsg: Number.isFinite(tariffPerMsg) ? tariffPerMsg : 150,
    mediaType,
    templateName,
    templateContent,
    mediaUrl,
    photoUrl,
    createdAt: new Date().toISOString(),
  };

  store.databases.unshift(newDb);

  // Nomor yang diekstrak sekaligus dimasukkan ke database kontak.
  if (!store.contacts) store.contacts = [];

  const existing = new Set(store.contacts.map((c) => c.phone));

  for (const number of extracted) {
    const phone = normalizeNumber(number);
    if (existing.has(phone)) continue;
    existing.add(phone);
    store.contacts.push({
      id: `ct_${crypto.randomUUID()}`,
      phone,
      name: '',
      tag: name,
      source: 'database-upload',
      status: 'unknown',
      createdAt: new Date().toISOString(),
    });
  }

  saveStore(store);

  return res.status(201).json({
    ok: true,
    database: newDb,
    stats,
    message: `Terdeteksi ${totalNumbers} nomor valid (${stats.duplicates} duplikat, ${stats.invalid} tidak valid dibuang).`,
  });
}));

router.delete('/admin/databases/:id', auth, allow('ADMIN'), (req, res) => {
  const store = readStore();
  if (!store.databases) store.databases = [];

  const index = store.databases.findIndex((d) => d.id === req.params.id);

  if (index === -1) {
    return res.status(404).json({ ok: false, error: 'Database tidak ditemukan.' });
  }

  const removed = store.databases.splice(index, 1)[0];

  if (removed.filePath && fs.existsSync(removed.filePath)) {
    try {
      fs.unlinkSync(removed.filePath);
    } catch {
      // File mungkin sudah hilang.
    }
  }

  saveStore(store);
  return res.json({ ok: true, message: 'Database berhasil dihapus.' });
});

// ---------- Tariff ----------

router.get('/settings/tariff', auth, (_req, res) => {
  res.json({ ok: true, tariff: readStore().tariff });
});

router.put('/settings/tariff', auth, allow('ADMIN', 'BOS'), (req, res) => {
  const tariff = Number(req.body?.tariff);

  if (!Number.isInteger(tariff) || tariff < 0 || tariff > 1000000) {
    return res.status(400).json({
      ok: false,
      error: 'Tarif harus bilangan bulat 0 sampai 1.000.000.',
    });
  }

  const store = readStore();
  store.tariff = tariff;
  saveStore(store);

  return res.json({ ok: true, tariff });
});

// ---------- Templates ----------

router.get('/templates', auth, (req, res) => {
  const store = readStore();

  const templates = (store.templates || []).filter(
    (item) => req.user.role !== 'USER' || item.active
  );

  res.json({ ok: true, templates });
});

router.post('/templates', auth, allow('ADMIN', 'BOS'), upload.single('media'), (req, res) => {
  const name = clampString(req.body?.name, 80);
  const content = clampString(req.body?.content, 4000);
  const url = clampString(req.body?.url || req.body?.link, 2048);
  // Media bisa berupa file unggahan (foto/video) atau URL eksternal.
  const mediaUrl = req.file
    ? `/uploads/${req.file.filename}`
    : clampString(req.body?.mediaUrl || req.body?.photoUrl, 2048);
  const mediaType = clampString(req.body?.mediaType || 'image', 20).toLowerCase();
  const databaseId = clampString(req.body?.databaseId, 80);

  if (!name || !content) {
    return res.status(400).json({ ok: false, error: 'Nama dan isi template wajib diisi.' });
  }

  const store = readStore();
  if (!store.templates) store.templates = [];

  const item = {
    id: `tpl_${Date.now()}`,
    name,
    content,
    url: url || '',
    mediaUrl: mediaUrl || '',
    mediaType: ['image', 'video'].includes(mediaType) ? mediaType : 'image',
    databaseId: databaseId || null,
    owner: req.user.username,
    active: true,
    createdAt: new Date().toISOString(),
  };

  store.templates.unshift(item);
  saveStore(store);

  return res.status(201).json({ ok: true, template: item });
});

router.patch('/templates/:id', auth, allow('ADMIN', 'BOS'), (req, res) => {
  const store = readStore();
  const item = (store.templates || []).find((t) => t.id === req.params.id);

  if (!item) {
    return res.status(404).json({ ok: false, error: 'Template tidak ditemukan.' });
  }

  if (req.body?.name !== undefined) {
    const name = clampString(req.body.name, 80);
    if (!name) {
      return res.status(400).json({ ok: false, error: 'Nama template tidak boleh kosong.' });
    }
    item.name = name;
  }

  if (req.body?.content !== undefined) {
    const content = clampString(req.body.content, 4000);
    if (!content) {
      return res.status(400).json({ ok: false, error: 'Isi template tidak boleh kosong.' });
    }
    item.content = content;
  }

  if (req.body?.mediaUrl !== undefined || req.body?.photoUrl !== undefined) {
    item.mediaUrl = clampString(req.body.mediaUrl || req.body.photoUrl, 2048);
  }

  if (req.body?.url !== undefined || req.body?.link !== undefined) {
    item.url = clampString(req.body.url || req.body.link, 2048);
  }

  if (req.body?.databaseId !== undefined) {
    item.databaseId = clampString(req.body.databaseId, 80) || null;
  }

  if (req.body?.mediaType !== undefined) {
    const mediaType = clampString(req.body.mediaType, 20).toLowerCase();
    item.mediaType = ['image', 'video'].includes(mediaType) ? mediaType : 'image';
  }

  if (req.body?.active !== undefined) {
    item.active = Boolean(req.body.active);
  }

  item.updatedAt = new Date().toISOString();
  saveStore(store);

  return res.json({ ok: true, template: item });
});

router.delete('/templates/:id', auth, allow('ADMIN', 'BOS'), (req, res) => {
  const store = readStore();
  const list = store.templates || [];
  const index = list.findIndex((t) => t.id === req.params.id);

  if (index === -1) {
    return res.status(404).json({ ok: false, error: 'Template tidak ditemukan.' });
  }

  list.splice(index, 1);
  saveStore(store);

  return res.json({ ok: true, message: 'Template berhasil dihapus.' });
});

// ---------- Contacts (database nomor tujuan) ----------

function sanitizeContact(body) {
  const phone = normalizeNumber(body?.phone);

  if (!isValidPhone(phone)) {
    return { error: 'Nomor tidak valid. Gunakan 8-15 digit angka.' };
  }

  return {
    phone,
    name: clampString(body?.name, 80),
    tag: clampString(body?.tag, 40),
  };
}

router.get('/contacts', auth, (req, res) => {
  const store = readStore();

  let contacts = store.contacts || [];

  const search = String(req.query.search || '').trim().toLowerCase();
  const tag = String(req.query.tag || '').trim().toLowerCase();

  if (search) {
    contacts = contacts.filter(
      (c) =>
        c.phone.includes(search) ||
        (c.name || '').toLowerCase().includes(search) ||
        (c.tag || '').toLowerCase().includes(search)
    );
  }

  if (tag) {
    contacts = contacts.filter((c) => (c.tag || '').toLowerCase() === tag);
  }

  const tags = Array.from(
    new Set((store.contacts || []).map((c) => c.tag).filter(Boolean))
  );

  res.json({ ok: true, contacts, total: contacts.length, tags });
});

router.post('/contacts', auth, allow('ADMIN', 'BOS'), (req, res) => {
  const data = sanitizeContact(req.body);

  if (data.error) {
    return res.status(400).json({ ok: false, error: data.error });
  }

  const store = readStore();
  if (!store.contacts) store.contacts = [];

  if (store.contacts.some((c) => c.phone === data.phone)) {
    return res.status(400).json({ ok: false, error: 'Nomor sudah ada di database kontak.' });
  }

  const contact = {
    id: `ct_${crypto.randomUUID()}`,
    ...data,
    source: 'manual',
    status: 'unknown',
    createdAt: new Date().toISOString(),
  };

  store.contacts.unshift(contact);
  saveStore(store);

  return res.status(201).json({ ok: true, contact });
});

router.patch('/contacts/:id', auth, allow('ADMIN', 'BOS'), (req, res) => {
  const store = readStore();
  const contact = (store.contacts || []).find((c) => c.id === req.params.id);

  if (!contact) {
    return res.status(404).json({ ok: false, error: 'Kontak tidak ditemukan.' });
  }

  if (req.body?.phone !== undefined) {
    const phone = normalizeNumber(req.body.phone);

    if (!VALID_NUMBER.test(phone)) {
      return res.status(400).json({ ok: false, error: 'Nomor tidak valid.' });
    }

    if (store.contacts.some((c) => c.phone === phone && c.id !== contact.id)) {
      return res.status(400).json({ ok: false, error: 'Nomor sudah dipakai kontak lain.' });
    }

    contact.phone = phone;
  }

  if (req.body?.name !== undefined) {
    contact.name = String(req.body.name).trim().slice(0, 80);
  }

  if (req.body?.tag !== undefined) {
    contact.tag = String(req.body.tag).trim().slice(0, 40);
  }

  contact.updatedAt = new Date().toISOString();
  saveStore(store);

  return res.json({ ok: true, contact });
});

router.delete('/contacts/:id', auth, allow('ADMIN', 'BOS'), (req, res) => {
  const store = readStore();
  const list = store.contacts || [];
  const index = list.findIndex((c) => c.id === req.params.id);

  if (index === -1) {
    return res.status(404).json({ ok: false, error: 'Kontak tidak ditemukan.' });
  }

  list.splice(index, 1);
  saveStore(store);

  return res.json({ ok: true, message: 'Kontak berhasil dihapus.' });
});

router.post('/contacts/import', auth, allow('ADMIN', 'BOS'), (req, res) => {
  const raw = String(req.body?.numbers || '').trim();

  if (!raw) {
    return res.status(400).json({ ok: false, error: 'Tidak ada nomor untuk diimpor.' });
  }

  const tag = String(req.body?.tag || '').trim().slice(0, 40);
  const tokens = raw.split(/[\r\n,;]+/).map((n) => n.trim()).filter(Boolean);

  const store = readStore();
  if (!store.contacts) store.contacts = [];

  const existing = new Set(store.contacts.map((c) => c.phone));

  let added = 0;
  let skipped = 0;
  let invalid = 0;

  for (const token of tokens) {
    const phone = normalizeNumber(token);

    if (!VALID_NUMBER.test(phone)) {
      invalid += 1;
      continue;
    }

    if (existing.has(phone)) {
      skipped += 1;
      continue;
    }

    existing.add(phone);
    store.contacts.push({
      id: `ct_${crypto.randomUUID()}`,
      phone,
      name: '',
      tag,
      source: 'import',
      status: 'unknown',
      createdAt: new Date().toISOString(),
    });
    added += 1;
  }

  saveStore(store);

  return res.json({ ok: true, added, skipped, invalid, total: store.contacts.length });
});

// ---------- Number status / shadowban detection ----------

router.post('/contacts/check', auth, allow('ADMIN', 'BOS', 'USER'), async (req, res) => {
  try {
    const sessionId = resolveActiveSession(req.body?.sessionId);

    const requested = Array.isArray(req.body?.phones)
      ? req.body.phones
      : String(req.body?.phones || req.body?.phone || '')
          .split(/[\r\n,;]+/)
          .filter(Boolean);

    if (!requested.length) {
      return res.status(400).json({ ok: false, error: 'Tidak ada nomor untuk diperiksa.' });
    }

    const store = readStore();
    const results = [];

    for (const raw of requested.slice(0, 50)) {
      const phone = normalizeNumber(raw);
      const result = await checkNumber(sessionId, phone);
      results.push(result);

      const contact = (store.contacts || []).find((c) => c.phone === phone);
      if (contact) {
        contact.status = result.status;
        contact.statusCheckedAt = new Date().toISOString();
      }
    }

    saveStore(store);

    return res.json({ ok: true, results });
  } catch (error) {
    return handleError(res, error, 'Gagal memeriksa status nomor.', 409);
  }
});

// ---------- Messaging ----------

/**
 * Mengambil opsi media (foto/URL) dari body permintaan pengiriman. Mendukung
 * `mediaUrl`/`photoUrl` + `mediaType`, sehingga template "Teks | URL | Foto"
 * pada Stok DB bisa dikirim sebagai gambar dengan caption.
 */
function mediaOptionsFrom(body) {
  const mediaUrl = clampString(body?.mediaUrl || body?.photoUrl || body?.image, 2048);
  if (!mediaUrl) return null;

  const rawType = clampString(body?.mediaType || 'image', 20).toLowerCase();
  const type = ['image', 'video'].includes(rawType) ? rawType : 'image';

  return { mediaUrl, mediaType: type };
}

function logMessage(store, entry) {
  if (!store.messages) store.messages = [];
  store.messages.unshift(entry);

  // Batasi riwayat agar file store tidak tumbuh tanpa batas.
  if (store.messages.length > 1000) {
    store.messages.length = 1000;
  }
}

router.get('/messages', auth, (req, res) => {
  const store = readStore();

  const messages = (store.messages || []).filter(
    (item) => req.user.role !== 'USER' || item.username === req.user.username
  );

  res.json({ ok: true, messages: messages.slice(0, 200) });
});

// Anti-Blast: ADMIN & BOS dilarang mengirim/blast langsung (hanya USER).
router.post('/send-message', auth, allow('USER'), async (req, res) => {
  const sessionId = resolveActiveSession(req.body?.sessionId);
  const phone = normalizeNumber(req.body?.phone || req.body?.to);
  const text = clampString(req.body?.message ?? req.body?.text ?? '', 8000);
  const media = mediaOptionsFrom(req.body);

  if (!isValidPhone(phone)) {
    return res.status(400).json({ ok: false, error: 'Nomor tujuan tidak valid.' });
  }

  if (!text && !media) {
    return res.status(400).json({ ok: false, error: 'Isi pesan tidak boleh kosong.' });
  }

  try {
    const result = await sendMessage(sessionId, phone, text, media || {});

    const store = readStore();
    logMessage(store, {
      id: `msg_${crypto.randomUUID()}`,
      username: req.user.username,
      sessionId,
      phone,
      text,
      mediaUrl: media ? media.mediaUrl : null,
      status: result.status,
      detail: result.detail,
      messageId: result.messageId || null,
      createdAt: new Date().toISOString(),
    });
    saveStore(store);

    return res.json({ ok: result.success, ...result });
  } catch (error) {
    return handleError(res, error, 'Gagal mengirim pesan.', 409);
  }
});

// ---------- Broadcast (massal) dengan jeda anti-ban ----------

const broadcastJobs = new Map();

const DELAY_PRESETS = { safe: 30000, standard: 5000, brutal: 1000 };

function runBroadcast(job) {
  (async () => {
    const store = readStore();
    const numbers = job.phones;

    for (let i = 0; i < numbers.length; i += 1) {
      if (job.cancelled) {
        job.status = 'cancelled';
        break;
      }

      const phone = numbers[i];
      job.current = i + 1;

      try {
        const result = await sendMessage(job.sessionId, phone, job.message, job.media || {});
        job.sent += result.success ? 1 : 0;

        if (!result.success) {
          job.failed += 1;
          job.lastError = result.detail || result.reason;
        }

        const fresh = readStore();
        logMessage(fresh, {
          id: `msg_${crypto.randomUUID()}`,
          username: job.username,
          sessionId: job.sessionId,
          phone,
          text: job.message,
          mediaUrl: job.media ? job.media.mediaUrl : null,
          status: result.status,
          detail: result.detail,
          broadcastId: job.id,
          createdAt: new Date().toISOString(),
        });
        saveStore(fresh);
      } catch (error) {
        job.failed += 1;
        job.lastError = error.message;
      }

      if (i < numbers.length - 1 && !job.cancelled) {
        await new Promise((resolve) => setTimeout(resolve, job.delayMs));
      }
    }

    if (!job.cancelled) {
      job.status = 'completed';
    }

    job.finishedAt = new Date().toISOString();

    const fresh = readStore();
    const stored = (fresh.broadcasts || []).find((b) => b.id === job.id);

    if (stored) {
      stored.status = job.status;
      stored.sent = job.sent;
      stored.failed = job.failed;
      stored.current = job.current;
      stored.finishedAt = job.finishedAt;
      saveStore(fresh);
    }

    setTimeout(() => broadcastJobs.delete(job.id), 10 * 60 * 1000);
  })().catch((error) => {
    job.status = 'failed';
    job.lastError = error.message;
  });
}

// Anti-Blast: ADMIN & BOS dilarang mengirim/blast langsung (hanya USER).
router.post('/broadcast', auth, allow('USER'), (req, res) => {
  const sessionId = resolveActiveSession(req.body?.sessionId);
  const text = clampString(req.body?.message ?? req.body?.text ?? '', 8000);
  const speed = String(req.body?.speed || 'safe').toLowerCase();
  const media = mediaOptionsFrom(req.body);

  if (!text && !media) {
    return res.status(400).json({ ok: false, error: 'Isi pesan tidak boleh kosong.' });
  }

  const delayMs = Number.isFinite(Number(req.body?.delayMs))
    ? Math.min(Math.max(Number(req.body.delayMs), 500), 120000)
    : DELAY_PRESETS[speed] || DELAY_PRESETS.safe;

  let phones = [];

  if (Array.isArray(req.body?.phones)) {
    phones = req.body.phones.map(normalizeNumber).filter((n) => VALID_NUMBER.test(n));
  }

  if (!phones.length && Array.isArray(req.body?.contactIds)) {
    const store = readStore();
    const wanted = new Set(req.body.contactIds);
    phones = (store.contacts || [])
      .filter((c) => wanted.has(c.id))
      .map((c) => c.phone);
  }

  // Kirim ke seluruh kontak hanya bila diminta eksplisit (source/tag "all"
  // atau tanpa penanda target sama sekali). Daftar nomor yang kosong tidak
  // boleh diam-diam berubah menjadi blast ke semua kontak.
  const explicitEmptyList =
    Array.isArray(req.body?.phones) || Array.isArray(req.body?.contactIds);

  if (!phones.length && !explicitEmptyList) {
    const store = readStore();
    const tag = String(req.body?.tag || '').trim().toLowerCase();
    phones = (store.contacts || [])
      .filter((c) => (tag ? (c.tag || '').toLowerCase() === tag : true))
      .map((c) => c.phone);
  }

  phones = Array.from(new Set(phones));

  if (!phones.length) {
    return res.status(400).json({ ok: false, error: 'Tidak ada nomor tujuan yang valid.' });
  }

  const job = {
    id: `bc_${crypto.randomUUID()}`,
    username: req.user.username,
    sessionId,
    message: text,
    media,
    phones,
    delayMs,
    total: phones.length,
    current: 0,
    sent: 0,
    failed: 0,
    status: 'running',
    lastError: null,
    cancelled: false,
    createdAt: new Date().toISOString(),
  };

  broadcastJobs.set(job.id, job);

  const store = readStore();
  if (!store.broadcasts) store.broadcasts = [];
  store.broadcasts.unshift({
    id: job.id,
    username: job.username,
    sessionId,
    total: job.total,
    delayMs,
    status: 'running',
    sent: 0,
    failed: 0,
    createdAt: job.createdAt,
  });
  saveStore(store);

  runBroadcast(job);

  return res.status(202).json({
    ok: true,
    broadcastId: job.id,
    total: job.total,
    delayMs,
    message: 'Broadcast dimulai. Pantau progres melalui endpoint status.',
  });
});

router.get('/broadcast/:id', auth, (req, res) => {
  const job = broadcastJobs.get(req.params.id);

  if (!job) {
    const store = readStore();
    const stored = (store.broadcasts || []).find((b) => b.id === req.params.id);

    if (!stored) {
      return res.status(404).json({ ok: false, error: 'Broadcast tidak ditemukan.' });
    }

    // Job hilang dari memori (mis. server di-restart saat blast berjalan):
    // tandai "interrupted" agar klien berhenti memantau selamanya.
    if (stored.status === 'running') {
      stored.status = 'interrupted';
      stored.finishedAt = new Date().toISOString();
      saveStore(store);
    }

    // USER hanya boleh melihat broadcast miliknya sendiri.
    if (req.user.role === 'USER' && stored.username !== req.user.username) {
      return res.status(403).json({ ok: false, error: 'Akses ditolak untuk broadcast ini.' });
    }

    return res.json({ ok: true, broadcast: stored });
  }

  // USER hanya boleh memantau broadcast miliknya sendiri.
  if (req.user.role === 'USER' && job.username !== req.user.username) {
    return res.status(403).json({ ok: false, error: 'Akses ditolak untuk broadcast ini.' });
  }

  return res.json({
    ok: true,
    broadcast: {
      id: job.id,
      status: job.status,
      total: job.total,
      current: job.current,
      sent: job.sent,
      failed: job.failed,
      delayMs: job.delayMs,
      lastError: job.lastError,
      createdAt: job.createdAt,
      finishedAt: job.finishedAt || null,
    },
  });
});

router.post('/broadcast/:id/cancel', auth, allow('ADMIN', 'BOS', 'USER'), (req, res) => {
  const job = broadcastJobs.get(req.params.id);

  if (!job) {
    return res.status(404).json({ ok: false, error: 'Broadcast tidak aktif.' });
  }

  // USER hanya boleh membatalkan broadcast miliknya sendiri.
  if (req.user.role === 'USER' && job.username !== req.user.username) {
    return res.status(403).json({ ok: false, error: 'Akses ditolak untuk broadcast ini.' });
  }

  job.cancelled = true;

  return res.json({ ok: true, message: 'Permintaan pembatalan dikirim.' });
});

// ---------- BOS: Sistem Darurat ----------
// Menghentikan semua broadcast yang sedang berjalan. Khusus BOS (dan ADMIN).
router.post('/boss/emergency-stop', auth, allow('BOS', 'ADMIN'), (_req, res) => {
  let stopped = 0;

  for (const job of broadcastJobs.values()) {
    if (!job.finishedAt && !job.cancelled) {
      job.cancelled = true;
      stopped += 1;
    }
  }

  return res.json({
    ok: true,
    stopped,
    message: stopped
      ? `${stopped} broadcast dihentikan.`
      : 'Tidak ada broadcast yang sedang berjalan.',
  });
});

// ---------- Withdrawals ----------

router.get('/withdrawals', auth, (req, res) => {
  const store = readStore();

  const withdrawals = store.withdrawals.filter(
    (item) => req.user.role !== 'USER' || item.username === req.user.username
  );

  res.json({ ok: true, withdrawals });
});

router.post('/withdrawals', auth, allow('USER'), (req, res) => {
  const amount = Number(req.body?.amount);
  const method = String(req.body?.method || '').trim().slice(0, 40);
  const destination = String(req.body?.destination || '').trim().slice(0, 160);

  if (
    !Number.isInteger(amount) ||
    amount < 1000 ||
    amount > 100000000 ||
    !method ||
    !destination
  ) {
    return res.status(400).json({
      ok: false,
      error: 'Nominal minimal Rp1.000 dan metode/tujuan wajib diisi.',
    });
  }

  const store = readStore();

  const item = {
    id: `wd_${Date.now()}`,
    username: req.user.username,
    amount,
    method,
    destination,
    status: 'PENDING',
    createdAt: new Date().toISOString(),
  };

  store.withdrawals.unshift(item);
  saveStore(store);

  return res.status(201).json({
    ok: true,
    withdrawal: item,
    note: 'Permintaan dicatat sebagai demo. Tidak ada uang yang dipindahkan.',
  });
});

router.patch('/withdrawals/:id/status', auth, allow('ADMIN'), (req, res) => {
  const status = String(req.body?.status || '').toUpperCase();

  if (!['PENDING', 'APPROVED', 'REJECTED', 'PAID'].includes(status)) {
    return res.status(400).json({ ok: false, error: 'Status tidak valid.' });
  }

  const store = readStore();
  const item = store.withdrawals.find((entry) => entry.id === req.params.id);

  if (!item) {
    return res.status(404).json({ ok: false, error: 'Permintaan tidak ditemukan.' });
  }

  item.status = status;
  item.updatedAt = new Date().toISOString();
  saveStore(store);

  return res.json({ ok: true, withdrawal: item });
});

// ---------- Users ----------

router.get('/users', auth, allow('ADMIN'), (_req, res) => {
  const store = readStore();
  res.json({ ok: true, users: store.users.map(publicUser) });
});

// ADMIN mengelola data user: kuota blast, status aktif, nama, telegram, role.
router.patch('/users/:username', auth, allow('ADMIN'), (req, res) => {
  const store = readStore();
  const user = store.users.find((u) => u.username === req.params.username);

  if (!user) {
    return res.status(404).json({ ok: false, error: 'User tidak ditemukan.' });
  }

  if (req.body?.name !== undefined) {
    const name = clampString(req.body.name, 80);
    if (name) user.name = name;
  }

  if (req.body?.quota !== undefined) {
    const quota = Number(req.body.quota);
    if (!Number.isFinite(quota) || quota < 0) {
      return res.status(400).json({ ok: false, error: 'Kuota harus angka >= 0.' });
    }
    user.quota = Math.floor(quota);
  }

  if (req.body?.active !== undefined) {
    user.active = Boolean(req.body.active);
  }

  if (req.body?.telegram !== undefined) {
    user.telegram = clampString(req.body.telegram, 64);
  }

  if (req.body?.referral !== undefined) {
    user.referral = clampString(req.body.referral, 64);
  }

  if (req.body?.role !== undefined) {
    const role = String(req.body.role).toUpperCase();
    if (['USER', 'ADMIN', 'BOS'].includes(role)) user.role = role;
  }

  user.updatedAt = new Date().toISOString();
  saveStore(store);

  return res.json({ ok: true, user: publicUser(user) });
});

// USER mengatur PIN penarikan (disimpan sebagai hash bcrypt).
router.post('/users/me/pin', auth, allow('USER'), (req, res) => {
  const pin = String(req.body?.pin || '').trim();

  if (!/^\d{4,8}$/.test(pin)) {
    return res.status(400).json({ ok: false, error: 'PIN harus 4-8 digit angka.' });
  }

  const store = readStore();
  const user = store.users.find((u) => u.username === req.user.username);

  if (!user) {
    return res.status(404).json({ ok: false, error: 'User tidak ditemukan.' });
  }

  user.pinHash = bcrypt.hashSync(pin, 10);
  saveStore(store);

  return res.json({ ok: true, message: 'PIN penarikan berhasil disimpan.' });
});

// ---------- Admin: Monitoring Server ----------

router.get('/admin/monitoring', auth, allow('ADMIN'), (_req, res) => {
  const store = readStore();
  const sessions = listWhatsAppSessions();
  const messages = store.messages || [];

  const mem = process.memoryUsage();

  return res.json({
    ok: true,
    uptimeSeconds: Math.round(process.uptime()),
    memoryMb: Math.round(mem.rss / 1024 / 1024),
    nodeVersion: process.version,
    platform: process.platform,
    sessions,
    connectedSessions: sessions.filter((s) => s.status === 'connected').length,
    usersCount: store.users.length,
    contactsCount: (store.contacts || []).length,
    templatesCount: (store.templates || []).length,
    databasesCount: (store.databases || []).length,
    messagesTotal: messages.length,
    messagesSent: messages.filter((m) => m.status === 'sent').length,
    messagesFailed: messages.filter((m) => m.status && m.status !== 'sent').length,
    pendingWithdrawals: (store.withdrawals || []).filter((w) => w.status === 'PENDING').length,
    tariff: store.tariff,
  });
});

// ---------- BOS: Executive Analytics ----------

router.get('/boss/analytics', auth, allow('BOS', 'ADMIN'), (_req, res) => {
  const store = readStore();
  const messages = store.messages || [];
  const withdrawals = store.withdrawals || [];

  const sent = messages.filter((m) => m.status === 'sent').length;
  const failed = messages.filter((m) => m.status && m.status !== 'sent').length;
  const revenue = sent * store.tariff;

  return res.json({
    ok: true,
    tariff: store.tariff,
    messagesTotal: messages.length,
    messagesSent: sent,
    messagesFailed: failed,
    estimatedRevenue: revenue,
    contactsCount: (store.contacts || []).length,
    templatesCount: (store.templates || []).length,
    usersCount: store.users.length,
    withdrawalsTotal: withdrawals.length,
    withdrawalsPending: withdrawals.filter((w) => w.status === 'PENDING').length,
    withdrawalsApproved: withdrawals.filter((w) => w.status === 'APPROVED' || w.status === 'PAID').length,
    cashflow: [
      { label: 'Pendapatan (estimasi)', amount: revenue, type: 'in' },
      { label: 'Withdraw disetujui', amount: withdrawals.filter((w) => w.status === 'APPROVED' || w.status === 'PAID').reduce((sum, w) => sum + Number(w.amount || 0), 0), type: 'out' },
    ],
  });
});

// ---------- BOS: Audit Log Admin ----------

router.get('/boss/audit', auth, allow('BOS', 'ADMIN'), (_req, res) => {
  const store = readStore();

  const events = [];

  for (const item of store.messages || []) {
    events.push({
      at: item.createdAt,
      actor: item.username || '-',
      action: 'send_message',
      detail: `${item.phone} → ${item.status}`,
    });
  }

  for (const item of store.withdrawals || []) {
    events.push({
      at: item.createdAt,
      actor: item.username || '-',
      action: 'withdrawal',
      detail: `Rp ${item.amount} (${item.status})`,
    });
  }

  events.sort((a, b) => String(b.at).localeCompare(String(a.at)));

  return res.json({ ok: true, events: events.slice(0, 100) });
});

// ---------- Statistics (BOS & ADMIN) ----------

const MONTH_LABELS = ['Jan', 'Feb', 'Mar', 'Apr', 'Mei', 'Jun', 'Jul', 'Agu', 'Sep', 'Okt', 'Nov', 'Des'];

// Menentukan kode negara dari awalan nomor (best-effort untuk statistik).
function countryOf(phone) {
  const digits = normalizeNumber(phone);
  const prefixes = [
    ['62', 'Indonesia (+62)'],
    ['60', 'Malaysia (+60)'],
    ['65', 'Singapore (+65)'],
    ['66', 'Thailand (+66)'],
    ['84', 'Vietnam (+84)'],
    ['63', 'Filipina (+63)'],
    ['91', 'India (+91)'],
    ['1', 'Amerika/Kanada (+1)'],
    ['44', 'Inggris (+44)'],
  ];
  for (const [prefix, label] of prefixes) {
    if (digits.startsWith(prefix)) return label;
  }
  return 'Lainnya';
}

router.get('/statistics', auth, allow('BOS', 'ADMIN'), (_req, res) => {
  const store = readStore();
  const messages = store.messages || [];

  const monthlyDelivery = {};
  for (const label of MONTH_LABELS) monthlyDelivery[label] = 0;

  const countryStats = {};
  let sent = 0;
  let failed = 0;

  for (const msg of messages) {
    const date = new Date(msg.createdAt || Date.now());
    const label = MONTH_LABELS[date.getMonth()] || 'Jan';
    monthlyDelivery[label] += 1;

    const country = countryOf(msg.phone);
    countryStats[country] = (countryStats[country] || 0) + 1;

    if (msg.status === 'sent') sent += 1;
    else if (msg.status) failed += 1;
  }

  return res.json({
    ok: true,
    totalSent: sent,
    totalFailed: failed,
    totalMessages: messages.length,
    monthlyDelivery,
    countryStats,
    usersCount: store.users.length,
    databasesCount: (store.databases || []).length,
    templatesCount: (store.templates || []).length,
  });
});

// ---------- Multi Server (ADMIN) ----------

router.get('/servers', auth, allow('ADMIN', 'BOS'), (_req, res) => {
  const store = readStore();
  res.json({ ok: true, servers: store.servers || [] });
});

router.post('/servers', auth, allow('ADMIN'), (req, res) => {
  const name = clampString(req.body?.name, 80);
  const host = clampString(req.body?.host, 80);
  const region = clampString(req.body?.region, 40);
  const role = clampString(req.body?.role || 'worker', 20);

  if (!name || !host) {
    return res.status(400).json({ ok: false, error: 'Nama dan host server wajib diisi.' });
  }

  const store = readStore();
  if (!store.servers) store.servers = [];

  const item = {
    id: `srv_${Date.now()}`,
    name,
    host,
    region,
    role: ['primary', 'backup', 'worker'].includes(role) ? role : 'worker',
    status: 'online',
    load: 0,
    createdAt: new Date().toISOString(),
  };

  store.servers.push(item);
  saveStore(store);

  return res.status(201).json({ ok: true, server: item });
});

router.patch('/servers/:id', auth, allow('ADMIN'), (req, res) => {
  const store = readStore();
  const server = (store.servers || []).find((s) => s.id === req.params.id);

  if (!server) {
    return res.status(404).json({ ok: false, error: 'Server tidak ditemukan.' });
  }

  if (req.body?.name !== undefined) server.name = clampString(req.body.name, 80) || server.name;
  if (req.body?.host !== undefined) server.host = clampString(req.body.host, 80) || server.host;
  if (req.body?.region !== undefined) server.region = clampString(req.body.region, 40);
  if (req.body?.status !== undefined) {
    const status = String(req.body.status).toLowerCase();
    if (['online', 'offline', 'maintenance'].includes(status)) server.status = status;
  }
  if (req.body?.load !== undefined && Number.isFinite(Number(req.body.load))) {
    server.load = Math.max(0, Math.min(100, Number(req.body.load)));
  }

  saveStore(store);
  return res.json({ ok: true, server });
});

router.delete('/servers/:id', auth, allow('ADMIN'), (req, res) => {
  const store = readStore();
  const list = store.servers || [];
  const index = list.findIndex((s) => s.id === req.params.id);

  if (index === -1) {
    return res.status(404).json({ ok: false, error: 'Server tidak ditemukan.' });
  }

  list.splice(index, 1);
  saveStore(store);
  return res.json({ ok: true, message: 'Server berhasil dihapus.' });
});

// ---------- Announcements (ADMIN broadcast; semua role membaca) ----------

router.get('/announcements', auth, (_req, res) => {
  const store = readStore();
  res.json({ ok: true, announcements: store.announcements || [] });
});

router.post('/announcements', auth, allow('ADMIN'), (req, res) => {
  const text = clampString(req.body?.message || req.body?.text, 2000);

  if (!text) {
    return res.status(400).json({ ok: false, error: 'Isi pengumuman wajib diisi.' });
  }

  const store = readStore();
  if (!store.announcements) store.announcements = [];

  const item = {
    id: `ann_${Date.now()}`,
    message: text,
    author: req.user.username,
    createdAt: new Date().toISOString(),
  };

  store.announcements.unshift(item);
  saveStore(store);

  return res.status(201).json({ ok: true, announcement: item });
});

router.delete('/announcements/:id', auth, allow('ADMIN'), (req, res) => {
  const store = readStore();
  const list = store.announcements || [];
  const index = list.findIndex((a) => a.id === req.params.id);

  if (index === -1) {
    return res.status(404).json({ ok: false, error: 'Pengumuman tidak ditemukan.' });
  }

  list.splice(index, 1);
  saveStore(store);
  return res.json({ ok: true, message: 'Pengumuman dihapus.' });
});

// ---------- Settings (ADMIN tulis; BOS baca) ----------

router.get('/settings', auth, allow('ADMIN', 'BOS'), (_req, res) => {
  const store = readStore();
  res.json({ ok: true, settings: store.settings });
});

router.put('/settings', auth, allow('ADMIN'), (req, res) => {
  const store = readStore();
  if (!store.settings) store.settings = {};

  if (req.body?.maintenance !== undefined) store.settings.maintenance = Boolean(req.body.maintenance);
  if (req.body?.blockIndo !== undefined) store.settings.blockIndo = Boolean(req.body.blockIndo);
  if (req.body?.blockShadowban !== undefined) store.settings.blockShadowban = Boolean(req.body.blockShadowban);
  if (req.body?.referralEnabled !== undefined) store.settings.referralEnabled = Boolean(req.body.referralEnabled);
  if (req.body?.maxPairing !== undefined) {
    const max = Number(req.body.maxPairing);
    if (Number.isFinite(max) && max >= 1 && max <= 20) store.settings.maxPairing = Math.floor(max);
  }

  saveStore(store);
  return res.json({ ok: true, settings: store.settings });
});

// ---------- WhatsApp: QR connection ----------

router.post('/whatsapp/connect', auth, allow('ADMIN', 'BOS'), async (req, res) => {
  try {
    const requestedSessionId = String(req.body?.sessionId || '').trim();

    const createNew =
      req.body?.newSession === true ||
      req.body?.mode === 'new' ||
      !requestedSessionId;

    let result;

    if (createNew) {
      result = await createNewWhatsAppSession('qr');
    } else {
      const current = getWhatsAppStatus(requestedSessionId);

      if (current.connected) {
        result = await createNewWhatsAppSession('qr');
      } else {
        result = await connectWhatsApp(requestedSessionId);
      }
    }

    return res.json({
      ok: true,
      ...result,
      sessionId: result.sessionId,
      message:
        'Permintaan koneksi diproses. Gunakan sessionId ini untuk memeriksa status dan QR.',
    });
  } catch (error) {
    return handleError(res, error, 'Gagal memulai sesi QR.', 400);
  }
});

// ---------- WhatsApp: pairing code ----------

router.post('/whatsapp/pairing-code', auth, allow('ADMIN', 'BOS'), async (req, res) => {
  try {
    const requestedSessionId = String(req.body?.sessionId || '').trim();
    const phoneNumber = String(req.body?.phoneNumber || '').trim();

    if (!phoneNumber) {
      return res.status(400).json({ ok: false, error: 'Nomor telepon wajib diisi.' });
    }

    // Validasi format lebih awal supaya nomor tidak valid tidak memicu
    // pembuatan socket Baileys yang sia-sia.
    const digits = phoneNumber.replace(/\D/g, '');

    if (digits.length < 8 || digits.length > 15) {
      return res.status(400).json({
        ok: false,
        error: 'Nomor telepon tidak valid. Gunakan kode negara tanpa tanda +.',
      });
    }

    let sessionId = requestedSessionId;

    if (!sessionId) {
      // Pakai ulang sesi 'code' yang belum terdaftar bila ada, supaya pairing
      // berulang tidak menumpuk sesi baru dan menghabiskan kuota sesi aktif.
      sessionId = findReusableCodeSession();

      if (!sessionId) {
        const created = await createNewWhatsAppSession('code');
        sessionId = created.sessionId;
      }
    } else {
      const current = getWhatsAppStatus(sessionId);

      if (current.connected) {
        const created = await createNewWhatsAppSession('code');
        sessionId = created.sessionId;
      } else {
        await startSession(sessionId, 'code');
      }
    }

    const result = await requestPairingCode(sessionId, phoneNumber);

    return res.json({
      ok: true,
      ...result,
      sessionId,
      message:
        'Pairing code diminta. Masukkan kode di WhatsApp pada ponsel yang ingin ditautkan.',
    });
  } catch (error) {
    // Nomor yang sudah 4 kali gagal pairing berturut-turut dikunci sementara.
    if (error.code === 'PAIRING_COOLDOWN') {
      const retryAfterSec = Math.max(Math.ceil((error.retryAfterMs || 0) / 1000), 1);
      res.set('Retry-After', String(retryAfterSec));
      return res.status(429).json({
        ok: false,
        error: error.message,
        code: 'PAIRING_COOLDOWN',
        retryAfterMs: error.retryAfterMs || null,
      });
    }

    return handleError(res, error, 'Gagal meminta pairing code.', 400);
  }
});

// ---------- WhatsApp: session status ----------

router.get('/whatsapp/status', auth, allow('ADMIN', 'BOS'), async (req, res) => {
  try {
    const sessionId = String(req.query.sessionId || 'device-01').trim();
    const result = getWhatsAppStatus(sessionId);

    let qrImage = null;

    if (result.qr) {
      qrImage = await QRCode.toDataURL(result.qr);
    }

    return res.json({ ok: true, ...result, sessionId, qrImage });
  } catch (error) {
    return handleError(res, error, 'Gagal mengambil status sesi.', 400);
  }
});

// ---------- WhatsApp: list sessions ----------

router.get('/whatsapp/sessions', auth, allow('ADMIN', 'BOS'), (_req, res) => {
  return res.json({ ok: true, sessions: listWhatsAppSessions() });
});

// ---------- WhatsApp: read-only connection summary (semua role) ----------
// Halaman USER hanya boleh melihat apakah gateway siap dipakai, tanpa
// kendali administratif (connect / pairing / logout tetap khusus ADMIN & BOS).
router.get('/whatsapp/connected', auth, (_req, res) => {
  const sessions = listWhatsAppSessions();
  const active = sessions.find((s) => s.status === 'connected') || null;

  return res.json({
    ok: true,
    connected: Boolean(active),
    sessionId: active ? active.sessionId : null,
    status: active ? active.status : sessions[0] ? sessions[0].status : 'disconnected',
    totalSessions: sessions.length,
  });
});

// ---------- WhatsApp: disconnect / logout ----------

router.post('/whatsapp/disconnect', auth, allow('ADMIN', 'BOS'), async (req, res) => {
  try {
    const sessionId = String(req.body?.sessionId || '').trim();

    if (!sessionId) {
      return res.status(400).json({ ok: false, error: 'ID sesi wajib diisi.' });
    }

    const result = await disconnectWhatsApp(sessionId);

    return res.json({
      ok: true,
      ...result,
      sessionId,
      message: 'Socket sesi diputus. Kredensial tersimpan tidak dihapus.',
    });
  } catch (error) {
    return handleError(res, error, 'Gagal memutus sesi.', 400);
  }
});

router.post('/whatsapp/logout', auth, allow('ADMIN', 'BOS'), async (req, res) => {
  try {
    const sessionId = String(req.body?.sessionId || '').trim();

    if (!sessionId) {
      return res.status(400).json({ ok: false, error: 'ID sesi wajib diisi.' });
    }

    const result = await logoutWhatsApp(sessionId);

    return res.json({
      ok: true,
      ...result,
      sessionId,
      message: 'Sesi di-logout dan kredensial dihapus. Silakan hubungkan ulang.',
    });
  } catch (error) {
    return handleError(res, error, 'Gagal logout sesi.', 400);
  }
});

// ---------- Translate (pesan WhatsApp) ----------
// Semua role boleh memakai fitur terjemahan untuk menyiapkan pesan.
router.get('/translate/languages', auth, (_req, res) => {
  res.json({ ok: true, languages: LANGUAGES });
});

router.post(
  '/translate',
  auth,
  asyncHandler(async (req, res) => {
    const text = clampString(req.body?.text ?? req.body?.message, 8000);
    const target = clampString(req.body?.target || req.body?.to, 10).toLowerCase();
    const source = clampString(req.body?.source || req.body?.from || 'auto', 10).toLowerCase();

    if (!text) {
      return res.status(400).json({ ok: false, error: 'Teks yang diterjemahkan tidak boleh kosong.' });
    }

    if (!isSupportedLang(target) || target === 'auto') {
      return res.status(400).json({ ok: false, error: 'Bahasa tujuan tidak didukung.' });
    }

    if (!isSupportedLang(source)) {
      return res.status(400).json({ ok: false, error: 'Bahasa sumber tidak didukung.' });
    }

    try {
      const result = await translateText(text, target, source);

      return res.json({
        ok: true,
        text: result.text,
        source: result.detectedSource,
        target: result.target,
        original: text,
      });
    } catch (error) {
      return handleError(res, error, 'Gagal menerjemahkan teks.', 502);
    }
  })
);

// ---------- Compatibility Endpoints for new UI ----------
router.post('/auth/logout', (_req, res) => {
  return res.json({ ok: true });
});

router.get('/member/summary', auth, (req, res) => {
  const store = readStore();
  const user = store.users.find(u => u.username === req.user.username) || {};
  const sessions = listWhatsAppSessions();
  const withdrawals = (store.withdrawals || []).filter(w => w.username === req.user.username);
  return res.json({
    ok: true,
    balance: user.balance || 50000,
    earned: user.earned || 1019450,
    sent: user.sent || 48,
    ref: user.ref || 'Y760EO',
    min: 20000,
    fee: 1000,
    account: user.account || 'GoPay · 0858****7467 a/n ' + (user.name || req.user.username),
    remaining: user.remaining || 314907,
    photo: user.photo || '',
    devices: sessions.map((s, idx) => ({
      id: idx + 1,
      num: s.sessionId,
      slot: idx + 1,
      online: s.status === 'connected',
      earn: 0,
      speed: 30,
      mode: 'safe',
      limit: false,
      n: 100,
      ok: 0,
      fail: 0,
      sent: 0,
      pend: 0
    })),
    wd: withdrawals.map(w => ({
      id: w.id,
      date: w.createdAt ? new Date(w.createdAt).toLocaleString('id-ID') : '30 Okt 2026, 14.08',
      amt: w.amount,
      st: w.status === 'APPROVED' || w.status === 'PAID' ? 'Sukses' : (w.status === 'REJECTED' ? 'Ditolak' : 'Proses')
    })),
    team: []
  });
});

router.get('/wa/devices', auth, (req, res) => {
  const sessions = listWhatsAppSessions();
  const devices = sessions.map((s, idx) => ({
    id: idx + 1,
    num: s.sessionId,
    slot: idx + 1,
    online: s.status === 'connected',
    earn: 0,
    speed: 30,
    mode: 'safe',
    limit: false,
    n: 100,
    ok: 0,
    fail: 0,
    sent: 0,
    pend: 0
  }));
  return res.json(devices.length ? devices : [{ id: 1, num: '+627078230544', slot: 1, online: false, earn: 0, speed: 30, mode: 'safe', limit: false, n: 100, ok: 0, fail: 0, sent: 0, pend: 0 }]);
});

router.get('/wa/qr', auth, async (req, res) => {
  try {
    const result = await createNewWhatsAppSession('qr');
    let qrImage = null;
    if (result.qr) {
      qrImage = await QRCode.toDataURL(result.qr);
    }
    return res.json({ ok: true, qr: qrImage || result.qr, sessionId: result.sessionId });
  } catch (err) {
    return res.json({ ok: false, qr: null, error: err.message });
  }
});

router.post('/wa/pair-code', auth, async (req, res) => {
  try {
    const phone = String(req.body?.phone || req.body?.phoneNumber || '').trim();
    if (!phone) return res.status(400).json({ ok: false, error: 'Nomor telepon wajib diisi.' });
    const created = await createNewWhatsAppSession('code');
    const result = await requestPairingCode(created.sessionId, phone);
    return res.json({ ok: true, code: result.code, sessionId: created.sessionId });
  } catch (err) {
    return res.status(400).json({ ok: false, error: err.message });
  }
});

router.post('/wallet/withdraw', auth, allow('USER'), (req, res) => {
  const amount = Number(req.body?.amount);
  if (!amount || amount < 1000) {
    return res.status(400).json({ ok: false, error: 'Minimal penarikan Rp1.000' });
  }
  const store = readStore();
  const user = store.users.find(u => u.username === req.user.username);
  if (user && user.balance && user.balance < amount) {
    return res.status(400).json({ ok: false, error: 'Saldo tidak mencukupi!' });
  }
  if (user) {
    user.balance = (user.balance || 0) - amount;
  }
  if (!store.withdrawals) store.withdrawals = [];
  const item = {
    id: `wd_${crypto.randomUUID()}`,
    username: req.user.username,
    amount,
    method: 'E-Wallet',
    destination: user?.account || 'GoPay',
    status: 'PENDING',
    createdAt: new Date().toISOString(),
  };
  store.withdrawals.unshift(item);
  saveStore(store);
  return res.json({ ok: true, withdrawal: item });
});

router.post('/blast/start', auth, allow('USER'), (req, res) => {
  return res.json({ ok: true, message: 'Mesin broadcast dimulai.' });
});

router.post('/blast/start-all', auth, allow('USER'), (req, res) => {
  return res.json({ ok: true, message: 'Semua mesin broadcast dimulai.' });
});

router.post('/blast/stop-all', auth, allow('USER'), (req, res) => {
  return res.json({ ok: true, message: 'Semua mesin broadcast dihentikan.' });
});

// ---------- Fallback ----------

router.use((req, res) => {
  res.status(404).json({ ok: false, error: `Endpoint tidak ditemukan: ${req.method} ${req.originalUrl}` });
});

module.exports = router;
