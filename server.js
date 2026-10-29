'use strict';
/**
 * JonoDesh – zero-dependency Node server.
 * Serves the single-page site (index.html) and a small JSON API backed by data/db.json.
 *
 * Environment:
 *   PORT              HTTP port (default 3000)
 *   ADMIN_USER        super-admin username (default "nhmunna2004")
 *   ADMIN_PASSWORD    optional: overrides the built-in default admin password
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const INDEX_HTML = path.join(__dirname, 'index.html');

const ADMIN_USER = process.env.ADMIN_USER || 'nhmunna2004';
// Default admin password is stored only as a SHA-256 hash. Set ADMIN_PASSWORD in the environment to override it.
const DEFAULT_ADMIN_SHA256 = 'fff4eb753d3bb4f9245f11defb9c0b08e2169d1789760eb5388c5401d6a3cc45';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || null;

function adminPasswordOk(password) {
  if (ADMIN_PASSWORD) return safeEqual(password, ADMIN_PASSWORD);
  const given = crypto.createHash('sha256').update(String(password)).digest('hex');
  return safeEqual(given, DEFAULT_ADMIN_SHA256);
}

const MAX_JSON_BYTES = 1024 * 1024; // 1 MB
const MAX_UPLOAD_BYTES = 12 * 1024 * 1024; // 12 MB (base64 image payloads)

/* ---------------------------------------------------------------- DB */
const DEFAULT_DB = {
  news: [], breaking: [], reports: [], subscribers: [], users: [], trash: [], searchLog: [],
};
let db = null;

function loadDb() {
  try {
    db = Object.assign({}, DEFAULT_DB, JSON.parse(fs.readFileSync(DB_FILE, 'utf8')));
  } catch (e) {
    db = JSON.parse(JSON.stringify(DEFAULT_DB));
  }
  for (const k of Object.keys(DEFAULT_DB)) if (!Array.isArray(db[k])) db[k] = [];
}

let writeQueued = false;
function saveDb() {
  if (writeQueued) return;
  writeQueued = true;
  setImmediate(() => {
    writeQueued = false;
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      const tmp = DB_FILE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(db, null, 2), 'utf8');
      fs.renameSync(tmp, DB_FILE);
    } catch (e) {
      console.error('Error writing DB:', e.message);
    }
  });
}
loadDb();

/* ---------------------------------------------------------------- helpers */
function sendJson(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(payload));
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(Object.assign(new Error('Payload too large'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (e) {
        reject(Object.assign(new Error('Invalid JSON'), { status: 400 }));
      }
    });
    req.on('error', reject);
  });
}

const escapeText = (v, max = 2000) =>
  String(v == null ? '' : v).replace(/[<>]/g, (c) => (c === '<' ? '&lt;' : '&gt;')).slice(0, max);

// Admin-authored article HTML: drop script-capable constructs.
function cleanHtml(html) {
  return String(html || '')
    .replace(/<\s*(script|style|iframe|object|embed|link|meta)[\s\S]*?(<\s*\/\s*\1\s*>|$)/gi, '')
    .replace(/\son\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    .replace(/(href|src)\s*=\s*("|')\s*javascript:[^"']*\2/gi, '$1=$2#$2')
    .slice(0, 200000);
}

const safeUrl = (u) => {
  const s = String(u || '').trim();
  return /^(https?:\/\/|\/uploads\/|data:image\/)/i.test(s) ? s.slice(0, 2000000) : '';
};

const newId = (p) => `${p}-${Date.now().toString(36)}${crypto.randomBytes(2).toString('hex')}`;

function saveDataUrl(dataUrl) {
  const m = /^data:(image\/(png|jpeg|jpg|gif|webp|svg\+xml));base64,([A-Za-z0-9+/=]+)$/.exec(String(dataUrl || ''));
  if (!m) throw Object.assign(new Error('Unsupported file'), { status: 400 });
  const ext = { png: 'png', jpeg: 'jpg', jpg: 'jpg', gif: 'gif', webp: 'webp', 'svg+xml': 'svg' }[m[2]];
  const buf = Buffer.from(m[3], 'base64');
  if (buf.length > 8 * 1024 * 1024) throw Object.assign(new Error('File too large'), { status: 413 });
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  const name = `${Date.now()}-${crypto.randomBytes(4).toString('hex')}.${ext}`;
  fs.writeFileSync(path.join(UPLOAD_DIR, name), buf);
  return `/uploads/${name}`;
}

/* ---------------------------------------------------------------- auth */
const sessions = new Map(); // token -> { username, role, exp }
const SESSION_MS = 12 * 60 * 60 * 1000;
const loginAttempts = new Map(); // ip -> { n, reset }

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(password, salt, 64).toString('hex') };
}
function verifyPassword(password, salt, hash) {
  const a = Buffer.from(crypto.scryptSync(password, salt, 64).toString('hex'));
  const b = Buffer.from(hash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const safeEqual = (a, b) => {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
};

function getSession(req) {
  const h = req.headers['authorization'] || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  const s = token && sessions.get(token);
  if (!s) return null;
  if (s.exp < Date.now()) {
    sessions.delete(token);
    return null;
  }
  return Object.assign({ token }, s);
}

const ROLE_RANK = { 'Super Admin': 5, Admin: 4, Editor: 3, Moderator: 2, Reporter: 1 };
const rankOf = (role) => ROLE_RANK[role] || 0;
// Minimum roles for each admin capability
const NEED = { admin: 4, editor: 3, moderator: 2, writer: 1 };

function requireRole(req, res, min) {
  const s = getSession(req);
  if (!s) {
    sendJson(res, 401, { error: 'লগইন প্রয়োজন' });
    return null;
  }
  if (rankOf(s.role) < min) {
    sendJson(res, 403, { error: 'এই কাজের অনুমতি নেই' });
    return null;
  }
  return s;
}

const publicUsers = () => db.users.map(({ salt, hash, ...u }) => u);

/* ---------------------------------------------------------------- views */
const publicReport = ({ phone, ...r }) => r;

function publicData(isAdmin) {
  const out = {
    news: db.news,
    breaking: db.breaking,
    reports: isAdmin ? db.reports : db.reports.map(publicReport),
    branding: db.branding,
    theme: db.theme,
    ads: db.ads,
    settings: db.settings,
  };
  if (isAdmin) out.users = publicUsers();
  return out;
}

/* ---------------------------------------------------------------- API */
async function handleApi(req, res, pathname) {
  const method = req.method;
  const seg = pathname.split('/').filter(Boolean).slice(1); // after "api"
  const ip = req.socket.remoteAddress || 'x';

  // ----- auth
  if (seg[0] === 'login' && method === 'POST') {
    const a = loginAttempts.get(ip) || { n: 0, reset: Date.now() + 15 * 60 * 1000 };
    if (a.reset < Date.now()) { a.n = 0; a.reset = Date.now() + 15 * 60 * 1000; }
    if (a.n >= 10) return sendJson(res, 429, { error: 'অনেকবার ভুল চেষ্টা হয়েছে, কিছুক্ষণ পর আবার চেষ্টা করুন' });
    const { username = '', password = '' } = await readBody(req, MAX_JSON_BYTES);
    let role = null;
    let permissions = 'পূর্ণ নিয়ন্ত্রণ';
    if (safeEqual(username, ADMIN_USER) && adminPasswordOk(password)) {
      role = 'Super Admin';
    } else {
      const u = db.users.find((x) => x.username === username && x.status !== 'নিষ্ক্রিয়');
      if (u && u.hash && verifyPassword(String(password), u.salt, u.hash)) {
        role = u.role;
        permissions = u.permissions;
      }
    }
    if (!role) {
      a.n += 1;
      loginAttempts.set(ip, a);
      return sendJson(res, 401, { error: 'ভুল ইউজারনেম বা পাসওয়ার্ড' });
    }
    loginAttempts.delete(ip);
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { username, role, exp: Date.now() + SESSION_MS });
    return sendJson(res, 200, { token, username, role, permissions });
  }
  if (seg[0] === 'logout' && method === 'POST') {
    const s = getSession(req);
    if (s) sessions.delete(s.token);
    return sendJson(res, 200, { success: true });
  }
  if (seg[0] === 'session' && method === 'GET') {
    const s = getSession(req);
    return s ? sendJson(res, 200, { username: s.username, role: s.role }) : sendJson(res, 401, { error: 'no session' });
  }

  // ----- public data
  if (seg[0] === 'data' && method === 'GET') {
    return sendJson(res, 200, publicData(!!getSession(req)));
  }

  // ----- news
  if (seg[0] === 'news') {
    const id = seg[1];
    if (id && seg[2] === 'view' && method === 'POST') {
      const art = db.news.find((n) => n.id === id);
      if (!art) return sendJson(res, 404, { error: 'not found' });
      art.views = (art.views || 0) + 1;
      saveDb();
      return sendJson(res, 200, { views: art.views });
    }
    if (!id && method === 'POST') {
      if (!requireRole(req, res, NEED.writer)) return;
      const b = await readBody(req, MAX_JSON_BYTES);
      const art = {
        id: newId('art'),
        title: escapeText(b.title, 300),
        cat: escapeText(b.cat, 60),
        area: escapeText(b.area, 60),
        author: escapeText(b.author, 100) || 'অনলাইন ডেস্ক',
        img: safeUrl(b.img),
        videoUrl: safeUrl(b.videoUrl),
        body: cleanHtml(b.body),
        isHero: !!b.isHero,
        summary: escapeText(b.summary, 400),
        date: escapeText(b.date, 60),
        views: 0,
      };
      if (!art.title || !art.body) return sendJson(res, 400, { error: 'শিরোনাম ও বিস্তারিত প্রয়োজন' });
      if (art.isHero) db.news.forEach((n) => { n.isHero = false; });
      db.news.unshift(art);
      saveDb();
      return sendJson(res, 201, { success: true, article: art, news: db.news });
    }
    if (id && method === 'PUT') {
      if (!requireRole(req, res, NEED.writer)) return;
      const art = db.news.find((n) => n.id === id);
      if (!art) return sendJson(res, 404, { error: 'not found' });
      const b = await readBody(req, MAX_JSON_BYTES);
      if (b.title != null) art.title = escapeText(b.title, 300);
      if (b.cat != null) art.cat = escapeText(b.cat, 60);
      if (b.area != null) art.area = escapeText(b.area, 60);
      if (b.author != null) art.author = escapeText(b.author, 100);
      if (b.img != null) art.img = safeUrl(b.img);
      if (b.videoUrl != null) art.videoUrl = safeUrl(b.videoUrl);
      if (b.body != null) art.body = cleanHtml(b.body);
      if (b.summary != null) art.summary = escapeText(b.summary, 400);
      if (b.isHero != null) {
        art.isHero = !!b.isHero;
        if (art.isHero) db.news.forEach((n) => { if (n.id !== id) n.isHero = false; });
      }
      saveDb();
      return sendJson(res, 200, { success: true, article: art, news: db.news });
    }
    if (id && method === 'DELETE') {
      if (!requireRole(req, res, NEED.editor)) return;
      const idx = db.news.findIndex((n) => n.id === id);
      if (idx < 0) return sendJson(res, 404, { error: 'not found' });
      const [removed] = db.news.splice(idx, 1);
      db.trash.unshift({ ...removed, type: 'news', deletedAt: new Date().toISOString() });
      saveDb();
      return sendJson(res, 200, { success: true, news: db.news, trash: db.trash });
    }
  }

  // ----- breaking news
  if (seg[0] === 'breaking') {
    if (method === 'POST') {
      if (!requireRole(req, res, NEED.editor)) return;
      const b = await readBody(req, MAX_JSON_BYTES);
      const headline = escapeText(b.headline, 300).trim();
      if (!headline) return sendJson(res, 400, { error: 'শিরোনাম প্রয়োজন' });
      db.breaking.unshift(headline);
      saveDb();
      return sendJson(res, 200, { success: true, breaking: db.breaking });
    }
    if (method === 'DELETE') {
      if (!requireRole(req, res, NEED.editor)) return;
      const b = await readBody(req, MAX_JSON_BYTES);
      const i = Number(b.index);
      if (Number.isInteger(i) && i >= 0 && i < db.breaking.length) db.breaking.splice(i, 1);
      saveDb();
      return sendJson(res, 200, { success: true, breaking: db.breaking });
    }
  }

  // ----- citizen reports
  if (seg[0] === 'reports') {
    const id = seg[1];
    if (!id && method === 'GET') {
      return sendJson(res, 200, getSession(req) ? db.reports : db.reports.map(publicReport));
    }
    if (!id && method === 'POST') {
      const b = await readBody(req, MAX_UPLOAD_BYTES);
      const title = escapeText(b.title, 300).trim();
      if (!title) return sendJson(res, 400, { error: 'শিরোনাম প্রয়োজন' });
      let rid = /^[A-Za-z0-9-]{3,40}$/.test(String(b.id || '')) ? String(b.id) : newId('rep');
      if (db.reports.some((r) => r.id === rid)) rid = newId('rep');
      let photo = '';
      try { photo = String(b.photo || '').startsWith('data:') ? saveDataUrl(b.photo) : safeUrl(b.photo); } catch (e) { photo = ''; }
      const report = {
        id: rid,
        title,
        category: escapeText(b.category, 80),
        area: escapeText(b.area, 80),
        date: escapeText(b.date, 60) || new Date().toLocaleDateString('bn-BD'),
        desc: escapeText(b.desc, 8000),
        reporter: b.isAnonymous ? 'বেনামী নাগরিক' : escapeText(b.reporter, 100) || 'বেনামী নাগরিক',
        phone: escapeText(b.phone, 30),
        isAnonymous: !!b.isAnonymous,
        evidence: escapeText(b.evidence, 500),
        photo,
        videoUrl: safeUrl(b.videoUrl),
        status: b.status === 'তদন্তাধীন' ? 'তদন্তাধীন' : 'অপেক্ষমাণ',
        witnessCount: Math.min(Math.max(parseInt(b.witnessCount, 10) || 1, 1), 5),
      };
      db.reports.unshift(report);
      saveDb();
      return sendJson(res, 201, { success: true, report: publicReport(report), reports: db.reports.map(publicReport) });
    }
    if (id && seg[2] === 'vote' && method === 'POST') {
      const r = db.reports.find((x) => x.id === id);
      if (!r) return sendJson(res, 404, { error: 'not found' });
      r.witnessCount = (r.witnessCount || 0) + 1;
      saveDb();
      return sendJson(res, 200, { witnessCount: r.witnessCount });
    }
    if (id && method === 'PUT') {
      if (!requireRole(req, res, NEED.moderator)) return;
      const r = db.reports.find((x) => x.id === id);
      if (!r) return sendJson(res, 404, { error: 'not found' });
      const b = await readBody(req, MAX_JSON_BYTES);
      if (b.status != null) r.status = escapeText(b.status, 40);
      saveDb();
      return sendJson(res, 200, { success: true, reports: db.reports });
    }
    if (id && method === 'DELETE') {
      if (!requireRole(req, res, NEED.moderator)) return;
      const idx = db.reports.findIndex((x) => x.id === id);
      if (idx < 0) return sendJson(res, 404, { error: 'not found' });
      const [removed] = db.reports.splice(idx, 1);
      db.trash.unshift({ ...removed, type: 'report', deletedAt: new Date().toISOString() });
      saveDb();
      return sendJson(res, 200, { success: true, reports: db.reports, trash: db.trash });
    }
  }

  // ----- trash
  if (seg[0] === 'trash') {
    if (!requireRole(req, res, NEED.admin)) return;
    const id = seg[1];
    if (!id && method === 'GET') return sendJson(res, 200, db.trash);
    if (!id && method === 'DELETE') {
      db.trash = [];
      saveDb();
      return sendJson(res, 200, { success: true, trash: db.trash });
    }
    if (id && seg[2] === 'restore' && method === 'POST') {
      const idx = db.trash.findIndex((t) => t.id === id);
      if (idx < 0) return sendJson(res, 404, { error: 'not found' });
      const [{ type, deletedAt, ...item }] = db.trash.splice(idx, 1);
      (type === 'report' ? db.reports : db.news).unshift(item);
      saveDb();
      return sendJson(res, 200, { success: true, news: db.news, reports: db.reports, trash: db.trash });
    }
    if (id && method === 'DELETE') {
      db.trash = db.trash.filter((t) => t.id !== id);
      saveDb();
      return sendJson(res, 200, { success: true, trash: db.trash });
    }
  }

  // ----- users
  if (seg[0] === 'users') {
    if (!requireRole(req, res, NEED.admin)) return;
    if (!seg[1] && method === 'GET') return sendJson(res, 200, { users: publicUsers() });
    if (!seg[1] && method === 'POST') {
      const b = await readBody(req, MAX_JSON_BYTES);
      const username = String(b.username || '').trim();
      const role = Object.keys(ROLE_RANK).includes(b.role) && b.role !== 'Super Admin' ? b.role : 'Reporter';
      if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) return sendJson(res, 400, { error: 'ইউজারনেম ৩-৩২ অক্ষরের ইংরেজি হতে হবে' });
      if (String(b.password || '').length < 8) return sendJson(res, 400, { error: 'পাসওয়ার্ড কমপক্ষে ৮ অক্ষরের হতে হবে' });
      if (username === ADMIN_USER || db.users.some((u) => u.username === username)) return sendJson(res, 409, { error: 'ইউজারনেমটি আগেই আছে' });
      db.users.push({ username, role, permissions: escapeText(b.permissions, 200), status: 'সক্রিয়', ...hashPassword(String(b.password)) });
      saveDb();
      return sendJson(res, 201, { success: true, users: publicUsers() });
    }
    if (seg[1] && method === 'DELETE') {
      db.users = db.users.filter((u) => u.username !== decodeURIComponent(seg[1]));
      for (const [t, s] of sessions) if (s.username === decodeURIComponent(seg[1])) sessions.delete(t);
      saveDb();
      return sendJson(res, 200, { success: true, users: publicUsers() });
    }
  }

  // ----- site settings (branding, theme, ads, settings)
  if (['branding', 'theme', 'ads', 'settings'].includes(seg[0]) && method === 'POST') {
    if (!requireRole(req, res, NEED.admin)) return;
    const b = await readBody(req, MAX_UPLOAD_BYTES);
    if (!b || typeof b !== 'object' || Array.isArray(b)) return sendJson(res, 400, { error: 'Invalid body' });
    db[seg[0]] = b;
    saveDb();
    return sendJson(res, 200, { success: true });
  }

  // ----- upload
  if (seg[0] === 'upload' && method === 'POST') {
    if (!requireRole(req, res, NEED.writer)) return;
    const b = await readBody(req, MAX_UPLOAD_BYTES);
    return sendJson(res, 200, { url: saveDataUrl(b.dataUrl) });
  }
  // Citizens may attach a photo to a report (rate-limited by body size and type).
  if (seg[0] === 'upload-public' && method === 'POST') {
    const b = await readBody(req, MAX_UPLOAD_BYTES);
    if (/^data:image\/svg/i.test(String(b.dataUrl || ''))) return sendJson(res, 400, { error: 'SVG নয়' });
    return sendJson(res, 200, { url: saveDataUrl(b.dataUrl) });
  }

  // ----- search log
  if (seg[0] === 'search' && seg[1] === 'log' && method === 'POST') {
    const b = await readBody(req, MAX_JSON_BYTES);
    const q = escapeText(b.query, 80).trim();
    if (q.length >= 2) {
      db.searchLog.unshift({ query: q, timestamp: Date.now() });
      db.searchLog = db.searchLog.slice(0, 500);
      saveDb();
    }
    return sendJson(res, 200, { success: true });
  }
  if (seg[0] === 'search' && seg[1] === 'popular' && method === 'GET') {
    const counts = new Map();
    for (const l of db.searchLog) {
      const k = l.query.toLowerCase();
      counts.set(k, { term: l.query, count: (counts.get(k)?.count || 0) + 1 });
    }
    const popular = [...counts.values()].sort((a, b) => b.count - a.count).slice(0, 10);
    const isAdmin = !!getSession(req);
    return sendJson(res, 200, { popular, recent: isAdmin ? db.searchLog.slice(0, 20) : [] });
  }

  // ----- newsletter
  if (seg[0] === 'subscribers') {
    if (method === 'POST') {
      const b = await readBody(req, MAX_JSON_BYTES);
      const email = escapeText(b.email, 200).trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return sendJson(res, 400, { error: 'ইমেইল সঠিক নয়' });
      if (db.subscribers.some((s) => s.email === email)) return sendJson(res, 200, { success: true, duplicate: true });
      const sub = {
        id: newId('sub'), email, name: escapeText(b.name, 100), date: escapeText(b.date, 40),
        time: escapeText(b.time, 40), status: 'সক্রিয়', source: escapeText(b.source, 80),
      };
      db.subscribers.unshift(sub);
      saveDb();
      return sendJson(res, 201, { success: true });
    }
    if (method === 'GET') {
      if (!requireRole(req, res, NEED.admin)) return;
      return sendJson(res, 200, { subscribers: db.subscribers });
    }
  }

  return sendJson(res, 404, { error: 'Not found' });
}

/* ---------------------------------------------------------------- static */
const MIME = {
  '.png': 'image/png', '.jpg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
};

function securityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
}

function serveUpload(res, pathname) {
  const name = path.basename(decodeURIComponent(pathname));
  const file = path.join(UPLOAD_DIR, name);
  const type = MIME[path.extname(name).toLowerCase()];
  if (!type || !file.startsWith(UPLOAD_DIR + path.sep)) {
    res.writeHead(404);
    return res.end('Not found');
  }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, {
      'Content-Type': type,
      'Cache-Control': 'public, max-age=86400',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'", // neutralises SVG scripts
    });
    res.end(buf);
  });
}

function serveIndex(res) {
  fs.readFile(INDEX_HTML, (err, content) => {
    if (err) { res.writeHead(500); return res.end('Server Error'); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    res.end(content);
  });
}

/* ---------------------------------------------------------------- server */
const server = http.createServer(async (req, res) => {
  securityHeaders(res);
  let pathname;
  try {
    pathname = new URL(req.url, 'http://localhost').pathname;
  } catch (e) {
    res.writeHead(400);
    return res.end('Bad request');
  }

  if (pathname.startsWith('/api/')) {
    // Same-origin only; no wildcard CORS on an API that has admin endpoints.
    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
    try {
      return await handleApi(req, res, pathname);
    } catch (err) {
      const status = err.status || 500;
      if (status === 500) console.error(err);
      if (!res.headersSent) sendJson(res, status, { error: status === 500 ? 'Server error' : err.message });
      return;
    }
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405);
    return res.end('Method not allowed');
  }
  if (pathname.startsWith('/uploads/')) return serveUpload(res, pathname);
  // Everything else is the single-page app. Source files, .env and the database are never served.
  return serveIndex(res);
});

if (require.main === module) {
  server.listen(PORT, () => console.log(`JonoDesh server running on port ${PORT}`));
}
module.exports = server;
