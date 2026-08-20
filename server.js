const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.set('trust proxy', 1);

const JWT_SECRET = process.env.JWT_SECRET || '63fd9d9f11c6d8f7d0f30dfb217e044357e28e0ffe86c6b060bf12f4f67b731a0ae4dc9c145aa5696488f15ef6531a71';
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://yarishdz2_db_user:7cp3VZH9aXK77wXa@ikgmxer.8tj7kfa.mongodb.net/hubsilent?appName=ikgmxer';
const OBFUSCATOR_URL = process.env.OBFUSCATOR_URL || 'https://qyrexobf.onrender.com/api/obfuscate';
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || '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';
const OPENROUTER_MODEL = process.env.OPENROUTER_MODEL || 'openrouter/auto';
const PORT = process.env.PORT || 8080;

app.use(helmet({
  contentSecurityPolicy: false,
  frameguard: { action: 'deny' },
  referrerPolicy: { policy: 'no-referrer' },
  hidePoweredBy: true
}));
app.disable('x-powered-by');
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));

function clientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (xf) return String(xf).split(',')[0].trim();
  return (req.socket?.remoteAddress || req.ip || '?').replace(/^::ffff:/, '');
}

// --- Rate limits por capa ---
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => clientIp(req),
  message: { error: 'Demasiadas peticiones. Espera un poco.' }
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  keyGenerator: (req) => clientIp(req),
  message: { error: 'Demasiados intentos de login/registro' }
});
const rawLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20, // max 20 hits / minuto / IP al raw
  keyGenerator: (req) => clientIp(req),
  message: { error: 'Rate limit raw: máx 20/min por IP' }
});
const rawBurstLimiter = rateLimit({
  windowMs: 10 * 1000,
  max: 8, // anti-burst 8 / 10s
  keyGenerator: (req) => clientIp(req),
  message: { error: 'Burst bloqueado' }
});
const verifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 40,
  keyGenerator: (req) => clientIp(req),
  message: { success: false, error: 'Rate limit verify' }
});

app.use('/api/', apiLimiter);
app.use('/api/auth/', authLimiter);

// Contadores en memoria para auto-ban
const abuseHits = new Map(); // ip -> { n, t }
const AUTO_BAN_THRESHOLD = 80; // hits raw en 2 min
const AUTO_BAN_WINDOW = 2 * 60 * 1000;

function trackAbuse(ip) {
  const now = Date.now();
  let e = abuseHits.get(ip);
  if (!e || now - e.t > AUTO_BAN_WINDOW) e = { n: 0, t: now };
  e.n += 1;
  e.t = e.t || now;
  abuseHits.set(ip, e);
  return e.n;
}

// Limpieza periódica
setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of abuseHits) {
    if (now - e.t > AUTO_BAN_WINDOW * 2) abuseHits.delete(ip);
  }
}, 60000).unref?.();

app.use(async (req, res, next) => {
  try {
    if (!req.path.startsWith('/api') && !req.originalUrl.startsWith('/api')) return next();
    const ip = clientIp(req);
    if (!ip || ip === '?') return next();
    if (mongoose.connection.readyState === 1) {
      const Model = mongoose.models.QrexBlacklistIP;
      if (Model) {
        const banned = await Model.findOne({ ip }).lean();
        if (banned) return res.status(403).json({ error: 'IP bloqueada', reason: banned.reason || 'abuse' });
      }
    }
    next();
  } catch { next(); }
});


let mongoReady = false;
let lastMongoError = '';
let useMemory = false;
const fs = require('fs');
const MEM_FILE = process.env.MEM_FILE || '/tmp/qrex-mem.json';
const memDB = { users: [], scripts: [], executions: [] };
function memLoad() {
  try {
    if (fs.existsSync(MEM_FILE)) Object.assign(memDB, JSON.parse(fs.readFileSync(MEM_FILE, 'utf8')));
  } catch (e) {}
}
function memSave() {
  try { fs.writeFileSync(MEM_FILE, JSON.stringify(memDB)); } catch (e) {}
}
memLoad();
async function dbCreateScript(data) {
  if (useMemory || !mongoReady) {
    const doc = { id: crypto.randomBytes(12).toString('hex'), executions: 0, createdAt: new Date().toISOString(), ...data };
    memDB.scripts.push(doc);
    memSave();
    return doc;
  }
  return Script.create(data);
}


async function connectMongo() {
  if (!MONGO_URI) {
    lastMongoError = 'MONGO_URI vacío';
    useMemory = true;
    console.error(lastMongoError, '→ memoria');
    return;
  }
  try {
    console.log('Connecting MongoDB...');
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 10000 });
    mongoReady = true;
    useMemory = false;
    lastMongoError = '';
    console.log('Mongo OK');
  } catch (e) {
    mongoReady = false;
    useMemory = true;
    lastMongoError = e.message || String(e);
    console.error('Mongo fail → memoria:', lastMongoError);
  }
}
connectMongo();

mongoose.connection.on('connected', () => { mongoReady = true; console.log('Mongo connected'); });
mongoose.connection.on('disconnected', () => { mongoReady = false; console.log('Mongo disconnected'); });
mongoose.connection.on('error', (e) => { mongoReady = false; lastMongoError = e.message || String(e); console.error('Mongo conn error:', lastMongoError); });

const User = mongoose.models.QrexUser || mongoose.model('QrexUser', new mongoose.Schema({
  username: { type: String, unique: true, required: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  role: { type: String, default: 'user' }, // user | admin
  premium: { type: Boolean, default: false },
  premiumUntil: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now }
}));

function isPremiumUser(u) {
  if (!u) return false;
  if (u.role === 'admin') return true;
  if (!u.premium) return false;
  if (u.premiumUntil && new Date(u.premiumUntil) < new Date()) return false;
  return true;
}

async function ensureOwnerAdmin() {
  try {
    const u = await User.findOne({ username: 'owner' });
    if (u && u.role !== 'admin') {
      u.role = 'admin';
      u.premium = true;
      await u.save();
      console.log('OWNER promoted to admin');
    }
  } catch (e) {}
}
mongoose.connection.on('connected', () => { ensureOwnerAdmin(); });

const Script = mongoose.models.QrexScript || mongoose.model('QrexScript', new mongoose.Schema({
  id: { type: String, default: () => crypto.randomBytes(12).toString('hex') },
  ownerId: String,
  name: String,
  description: { type: String, default: '' },
  source: String,
  obfuscated: String,
  executions: { type: Number, default: 0 },
  keyMode: { type: String, default: 'keyless' }, // keyless | key
  providerId: { type: String, default: '' },
  providerName: { type: String, default: '' },
  doObfuscate: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
}));

const ScriptVersion = mongoose.models.QrexScriptVersion || mongoose.model('QrexScriptVersion', new mongoose.Schema({
  scriptId: String,
  ownerId: String,
  name: String,
  source: String,
  obfuscated: String,
  note: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
}));

const Webhook = mongoose.models.QrexWebhook || mongoose.model('QrexWebhook', new mongoose.Schema({
  ownerId: String,
  url: String,
  events: { type: [String], default: ['key_verify', 'script_exec'] },
  enabled: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
}));

const Asset = mongoose.models.QrexAsset || mongoose.model('QrexAsset', new mongoose.Schema({
  ownerId: String,
  name: String,
  type: { type: String, default: 'text' }, // text | url | image
  content: String,
  createdAt: { type: Date, default: Date.now }
}));

const BlacklistIP = mongoose.models.QrexBlacklistIP || mongoose.model('QrexBlacklistIP', new mongoose.Schema({
  ip: { type: String, unique: true },
  reason: { type: String, default: '' },
  createdBy: String,
  createdAt: { type: Date, default: Date.now }
}));


const CloudUI = mongoose.models.QrexCloudUI || mongoose.model('QrexCloudUI', new mongoose.Schema({
  id: { type: String, default: () => crypto.randomBytes(8).toString('hex') },
  ownerId: String,
  name: String,
  description: { type: String, default: '' },
  code: String, // Lua UI module source
  public: { type: Boolean, default: true },
  downloads: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
}));

const RemoteAlert = mongoose.models.QrexRemoteAlert || mongoose.model('QrexRemoteAlert', new mongoose.Schema({
  ownerId: String,
  scriptId: { type: String, default: '*' }, // * = all owner scripts
  message: String,
  title: { type: String, default: 'Alert' },
  active: { type: Boolean, default: true },
  expiresAt: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now }
}));

const PromoCode = mongoose.models.QrexPromoCode || mongoose.model('QrexPromoCode', new mongoose.Schema({
  code: { type: String, unique: true, uppercase: true },
  ownerId: String,
  providerId: String,
  extraHours: { type: Number, default: 24 },
  maxUses: { type: Number, default: 100 },
  uses: { type: Number, default: 0 },
  enabled: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
}));

const BugReport = mongoose.models.QrexBugReport || mongoose.model('QrexBugReport', new mongoose.Schema({
  ownerId: String, // script owner
  scriptId: String,
  fromUser: { type: String, default: 'anonymous' },
  message: String,
  meta: { type: String, default: '' },
  status: { type: String, default: 'open' }, // open | done
  createdAt: { type: Date, default: Date.now }
}));

const Telemetry = mongoose.models.QrexTelemetry || mongoose.model('QrexTelemetry', new mongoose.Schema({
  ownerId: String,
  event: String,
  ip: String,
  detail: String,
  createdAt: { type: Date, default: Date.now }
}));

const EndpointRoute = mongoose.models.QrexEndpointRoute || mongoose.model('QrexEndpointRoute', new mongoose.Schema({
  ownerId: String,
  slug: { type: String, unique: true },
  target: { type: String, default: 'raw' }, // raw
  scriptId: String,
  enabled: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
}));

const FREE_SCRIPT_LIMIT = 15;

async function logTelemetry(ownerId, event, ip, detail) {
  try {
    if (!ownerId || mongoose.connection.readyState !== 1) return;
    await Telemetry.create({
      ownerId: String(ownerId),
      event: String(event || 'event').slice(0, 80),
      ip: String(ip || '').slice(0, 80),
      detail: String(detail || '').slice(0, 400)
    });
    // keep last ~500 per owner roughly by occasional cleanup
  } catch {}
}


async function fireWebhooks(ownerId, event, payload) {
  try {
    const hooks = await Webhook.find({ ownerId, enabled: true, events: event });
    const body = JSON.stringify({
      content: null,
      embeds: [{
        title: event === 'key_verify' ? 'Key verificada' : event === 'script_exec' ? 'Script ejecutado' : event,
        description: '```json\n' + JSON.stringify(payload, null, 2).slice(0, 1500) + '\n```',
        color: event === 'key_verify' ? 0x7c3aed : 0x34d399,
        timestamp: new Date().toISOString()
      }]
    });
    await Promise.all(hooks.map(h =>
      fetch(h.url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body }).catch(() => {})
    ));
  } catch (e) { console.error('webhook', e.message); }
}

const Execution = mongoose.models.QrexExecution || mongoose.model('QrexExecution', new mongoose.Schema({
  scriptId: String,
  scriptName: String,
  ownerId: String,
  ip: String,
  userAgent: String,
  createdAt: { type: Date, default: Date.now }
}));

const HubScript = mongoose.models.QrexHubScript || mongoose.model('QrexHubScript', new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, default: '' },
  loadstring: { type: String, required: true },
  scriptId: String,
  ownerId: String,
  ownerUsername: String,
  executionsAtPublish: { type: Number, default: 0 },
  views: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
}));

const Provider = mongoose.models.QrexProvider || mongoose.model('QrexProvider', new mongoose.Schema({
  name: { type: String, required: true },
  ownerId: { type: String, required: true },
  keyValidityHours: { type: Number, default: 24 },
  hwidLimit: { type: Number, default: 1 },
  enabled: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
}));

const LicenseKey = mongoose.models.QrexLicenseKey || mongoose.model('QrexLicenseKey', new mongoose.Schema({
  key: { type: String, unique: true, required: true },
  providerId: { type: String, required: true },
  providerName: String,
  ownerId: { type: String, required: true },
  hwidLimit: { type: Number, default: 1 },
  hwids: { type: [String], default: [] },
  expiresAt: { type: Date, default: null },
  enabled: { type: Boolean, default: true },
  note: { type: String, default: '' },
  uses: { type: Number, default: 0 },
  lastUsedAt: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now }
}));

function genKey() {
  return crypto.randomUUID ? crypto.randomUUID() : [
    crypto.randomBytes(4).toString('hex'),
    crypto.randomBytes(2).toString('hex'),
    crypto.randomBytes(2).toString('hex'),
    crypto.randomBytes(2).toString('hex'),
    crypto.randomBytes(6).toString('hex')
  ].join('-');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + hash;
}

function verifyPassword(password, stored) {
  const [salt, hash] = (stored || '').split(':');
  if (!salt || !hash) return false;
  try {
    const test = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(test, 'hex'));
  } catch {
    return false;
  }
}

function signToken(user) {
  return jwt.sign(
    { sub: String(user._id || user.id), username: user.username },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token invalido' });
  }
}

function needMongo(req, res, next) {
  useMemory = !(mongoReady || mongoose.connection.readyState === 1);
  next();
}

async function obfuscateWithQyrex(code) {
  const r = await fetch(OBFUSCATOR_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code })
  });
  const data = await r.json();
  if (!data || !data.success || !data.code) {
    throw new Error((data && data.error) || 'Obfuscator failed');
  }
  return data.code;
}

function xorBytes(buf, key) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ key[i % key.length];
  return out;
}

/** 5 capas: XOR aleatorio + Base64 repetido (Lua decoder al final) */
async function resolveObfuscated(source, mode) {
  // mode: 'none' | 'qrex' | 'local'
  if (mode === 'none') return { code: source, doObfuscate: false, obfMode: 'none' };
  if (mode === 'local') return { code: localObfuscate(source), doObfuscate: true, obfMode: 'local' };
  const code = await obfuscateWithQyrex(source);
  return { code, doObfuscate: true, obfMode: 'qrex' };
}

function localObfuscate(code) {
  const src = Buffer.from(String(code), 'utf8');
  let data = src;
  const keys = [];
  for (let layer = 0; layer < 5; layer++) {
    const key = crypto.randomBytes(16);
    keys.push(key);
    data = xorBytes(data, key);
    data = Buffer.from(data.toString('base64'), 'utf8');
  }
  const keyLits = keys.map(k => '{' + Array.from(k).join(',') + '}').join(',');
  const payload = data.toString('utf8').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const lines = [
    '-- Qrex local protect (5x XOR+B64)',
    'local _k={' + keyLits + '}',
    'local _d="' + payload + '"',
    'local function _xb(s,key)',
    '  local t={}',
    '  for i=1,#s do t[i]=string.char(bit32.bxor(string.byte(s,i), key[((i-1)%#key)+1])) end',
    '  return table.concat(t)',
    'end',
    'local function _b64(data)',
    "  local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'",
    "  data=string.gsub(data,'[^'..b..'=]','')",
    "  return (data:gsub('.',function(x)",
    "    if x=='=' then return '' end",
    "    local r,f='',(b:find(x)-1)",
    "    for i=6,1,-1 do r=r..(f%2^i - f%2^(i-1) > 0 and '1' or '0') end",
    '    return r',
    "  end):gsub('%d%d%d?%d?%d?%d?%d?%d?',function(x)",
    '    if #x~=8 then return \'\' end',
    '    local c=0',
    "    for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end",
    '    return string.char(c)',
    '  end))',
    'end',
    'for i=5,1,-1 do',
    '  _d=_b64(_d)',
    '  _d=_xb(_d,_k[i])',
    'end',
    'assert((loadstring or load)(_d))()'
  ];
  return lines.join('\n');
}


app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    service: 'QrexApi',
    mongo: mongoReady || mongoose.connection.readyState === 1,
    mongoState: mongoose.connection.readyState,
    storage: mongoReady ? 'mongo' : 'memory',
    mongoError: lastMongoError || null,
    mongoError: lastMongoError || null
  });
});

app.post('/api/auth/register', needMongo, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const user = (username || '').trim().toLowerCase();
    const pass = password || '';
    if (!user || user.length < 3) return res.status(400).json({ error: 'Usuario mínimo 3 caracteres' });
    if (!pass || pass.length < 4) return res.status(400).json({ error: 'Contraseña mínimo 4 caracteres' });
    if (useMemory) {
      if (memDB.users.find(u => u.username === user)) return res.status(400).json({ error: 'Usuario ya existe' });
      const isOwner = user === 'owner';
      const doc = { _id: crypto.randomBytes(12).toString('hex'), username: user, passwordHash: hashPassword(pass), role: isOwner ? 'admin' : 'user', premium: isOwner, createdAt: new Date().toISOString() };
      memDB.users.push(doc); memSave();
      return res.json({ token: signToken(doc), user: { id: doc._id, username: doc.username, role: doc.role, premium: !!doc.premium } });
    }
    const exists = await User.findOne({ username: user });
    if (exists) return res.status(400).json({ error: 'Usuario ya existe' });
    const isOwnerName = user === 'owner';
    const doc = await User.create({ username: user, passwordHash: hashPassword(pass), role: isOwnerName ? 'admin' : 'user', premium: !!isOwnerName });
    res.json({ token: signToken(doc), user: { id: doc._id, username: doc.username, role: doc.role, premium: isPremiumUser(doc) } });
  } catch (e) {
    console.error('register', e);
    res.status(500).json({ error: 'Error al registrar: ' + (e.message || 'desconocido') });
  }
});
app.post('/api/auth/login', needMongo, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const user = (username || '').trim().toLowerCase();
    const pass = password || '';
    if (!user || !pass) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
    if (useMemory) {
      const doc = memDB.users.find(u => u.username === user);
      if (!doc || !verifyPassword(pass, doc.passwordHash)) return res.status(401).json({ error: 'Credenciales inválidas' });
      if (doc.username === 'owner') { doc.role = 'admin'; doc.premium = true; memSave(); }
      return res.json({ token: signToken(doc), user: { id: doc._id, username: doc.username, role: doc.role || 'user', premium: isPremiumUser(doc) } });
    }
    const doc = await User.findOne({ username: user });
    if (!doc || !verifyPassword(pass, doc.passwordHash)) return res.status(401).json({ error: 'Credenciales inválidas' });
    if (doc.username === 'owner' && doc.role !== 'admin') { doc.role = 'admin'; doc.premium = true; await doc.save(); }
    res.json({ token: signToken(doc), user: { id: doc._id, username: doc.username, role: doc.role || 'user', premium: isPremiumUser(doc) } });
  } catch (e) {
    console.error('login', e);
    res.status(500).json({ error: 'Error al iniciar sesion: ' + (e.message || 'desconocido') });
  }
});
app.get('/api/me', auth, needMongo, async (req, res) => {
  if (useMemory) {
    const user = memDB.users.find(u => String(u._id) === String(req.user.sub));
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    if (user.username === 'owner') { user.role = 'admin'; user.premium = true; memSave(); }
    return res.json({ id: user._id, username: user.username, role: user.role || 'user', premium: isPremiumUser(user) });
  }
  const user = await User.findById(req.user.sub);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  if (user.username === 'owner' && user.role !== 'admin') { user.role = 'admin'; user.premium = true; await user.save(); }
  res.json({ id: user._id, username: user.username, role: user.role || 'user', premium: isPremiumUser(user) });
});
app.get('/api/scripts', auth, needMongo, async (req, res) => {
  if (useMemory) {
    return res.json(memDB.scripts.filter(s => s.ownerId === req.user.sub).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)).map(({source,obfuscated,...r})=>r));
  }
  const list = await Script.find({ ownerId: req.user.sub }).sort({ createdAt: -1 }).select('-source -obfuscated');
  res.json(list);
});
app.get('/api/scripts/:id', auth, needMongo, async (req, res) => {
  if (useMemory) {
    const s = memDB.scripts.find(x => x.id === req.params.id && x.ownerId === req.user.sub);
    if (!s) return res.status(404).json({ error: 'No encontrado' });
    return res.json(s);
  }
  const s = await Script.findOne({ id: req.params.id, ownerId: req.user.sub });
  if (!s) return res.status(404).json({ error: 'No encontrado' });
  res.json(s);
});
app.post('/api/scripts', auth, needMongo, async (req, res) => {
  try {
    const { name, description, source, keyMode, providerId } = req.body || {};
    if (!name || !source) return res.status(400).json({ error: 'name y source requeridos' });

    let me, prem, count;
    if (useMemory) {
      me = memDB.users.find(u => String(u._id) === String(req.user.sub));
      prem = isPremiumUser(me);
      count = memDB.scripts.filter(s => s.ownerId === req.user.sub).length;
    } else {
      me = await User.findById(req.user.sub);
      prem = isPremiumUser(me);
      count = await Script.countDocuments({ ownerId: req.user.sub });
    }
    if (!prem && count >= FREE_SCRIPT_LIMIT) {
      return res.status(403).json({ error: 'Límite de ' + FREE_SCRIPT_LIMIT + ' scripts. Activa VIP/Premium para ilimitados.' });
    }

    let providerName = '';
    let pid = '';
    const mode = keyMode === 'key' ? 'key' : 'keyless';
    if (mode === 'key' && providerId) {
      const prov = await Provider.findOne({ _id: providerId, ownerId: req.user.sub });
      if (!prov) return res.status(400).json({ error: 'Provider inválido' });
      providerName = prov.name;
      pid = String(prov._id);
    }

    let obfMode = (req.body?.obfMode || '').toString();
    if (!obfMode) {
      const wantObf = req.body?.doObfuscate !== false && req.body?.doObfuscate !== 'false';
      obfMode = wantObf ? 'qrex' : 'none';
    }
    if (!['none', 'qrex', 'local'].includes(obfMode)) obfMode = 'local';
    const resolved = await resolveObfuscated(source, obfMode);
    const doc = await dbCreateScript({
      ownerId: req.user.sub,
      name,
      description: description || '',
      source,
      obfuscated: resolved.code,
      doObfuscate: resolved.doObfuscate,
      obfMode: resolved.obfMode,
      keyMode: mode,
      providerId: pid,
      providerName
    });

    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const proto = req.headers['x-forwarded-proto'] || 'https';

    res.json({
      id: doc.id,
      name: doc.name,
      loadstring: `loadstring(game:HttpGet("${proto}://${host}/api/raw/${doc.id}"))()`
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message || 'Error al crear' });
  }
});

app.put('/api/scripts/:id', auth, needMongo, async (req, res) => {
  try {
    const { name, description, source, keyMode, providerId } = req.body || {};
    const s = await Script.findOne({ id: req.params.id, ownerId: req.user.sub });
    if (!s) return res.status(404).json({ error: 'No encontrado' });

    // version snapshot before change
    if (source || name || description !== undefined) {
      await ScriptVersion.create({
        scriptId: s.id,
        ownerId: req.user.sub,
        name: s.name,
        source: s.source,
        obfuscated: s.obfuscated,
        note: 'Auto-save before edit'
      });
      const vers = await ScriptVersion.find({ scriptId: s.id }).sort({ createdAt: -1 });
      if (vers.length > 15) {
        const drop = vers.slice(15);
        await ScriptVersion.deleteMany({ _id: { $in: drop.map(v => v._id) } });
      }
    }

    if (name) s.name = name;
    if (description !== undefined) s.description = description;
    if (keyMode === 'key' || keyMode === 'keyless') {
      s.keyMode = keyMode;
      if (keyMode === 'key' && providerId) {
        const prov = await Provider.findOne({ _id: providerId, ownerId: req.user.sub });
        if (prov) { s.providerId = String(prov._id); s.providerName = prov.name; }
      } else if (keyMode === 'keyless') {
        s.providerId = ''; s.providerName = '';
      }
    }
    if (req.body?.obfMode && ['none','qrex','local'].includes(req.body.obfMode)) {
      s.obfMode = req.body.obfMode;
      s.doObfuscate = s.obfMode !== 'none';
    } else if (req.body?.doObfuscate !== undefined) {
      s.doObfuscate = req.body.doObfuscate !== false && req.body.doObfuscate !== 'false';
      s.obfMode = s.doObfuscate ? (s.obfMode === 'local' ? 'local' : 'qrex') : 'none';
    }
    if (source) {
      s.source = source;
      const resolved = await resolveObfuscated(source, s.obfMode || (s.doObfuscate ? 'qrex' : 'none'));
      s.obfuscated = resolved.code;
      s.doObfuscate = resolved.doObfuscate;
      s.obfMode = resolved.obfMode;
    } else if ((req.body?.obfMode || req.body?.doObfuscate !== undefined) && s.source) {
      const resolved = await resolveObfuscated(s.source, s.obfMode || 'qrex');
      s.obfuscated = resolved.code;
      s.doObfuscate = resolved.doObfuscate;
      s.obfMode = resolved.obfMode;
    }
    await s.save();
    res.json({ success: true, id: s.id });
  } catch (e) {
    res.status(500).json({ error: e.message || 'Error' });
  }
});

app.delete('/api/scripts/:id', auth, needMongo, async (req, res) => {
  if (useMemory) {
    memDB.scripts = memDB.scripts.filter(s => !(s.id === req.params.id && s.ownerId === req.user.sub));
    memSave();
    return res.json({ success: true });
  }
  await Script.deleteOne({ id: req.params.id, ownerId: req.user.sub });
  res.json({ success: true });
});
app.get('/api/raw/:id', rawBurstLimiter, rawLimiter, async (req, res) => {
  const ip = clientIp(req);
  const hits = trackAbuse(ip);
  if (hits >= AUTO_BAN_THRESHOLD) {
    try {
      if (mongoose.connection.readyState === 1 && mongoose.models.QrexBlacklistIP) {
        await mongoose.models.QrexBlacklistIP.findOneAndUpdate(
          { ip },
          { ip, reason: 'Auto-ban: flood /api/raw (' + hits + ' hits/2min)', createdBy: 'system' },
          { upsert: true }
        );
      }
    } catch {}
    return res.status(403).type('text/plain').send('-- banned');
  }

  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const accept = (req.headers['accept'] || '').toLowerCase();
  const isBrowser =
    accept.includes('text/html') &&
    /mozilla|chrome|firefox|safari|edg/i.test(ua) &&
    !/roblox|executor|synapse|fluxus|solara/i.test(ua);

  if (isBrowser) {
    return res.status(403).type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Access Denied — QrexApi</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0a0a0f;font-family:Inter,system-ui,sans-serif;color:#e4e4ed;overflow:hidden}
  body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse at 50% 30%,rgba(124,58,237,.12),transparent 60%);pointer-events:none}
  .card{position:relative;background:#111118;border:1px solid #1e1e2a;border-radius:20px;padding:40px 44px;max-width:520px;width:90%;box-shadow:0 25px 80px rgba(0,0,0,.5);animation:rise .6s cubic-bezier(.22,1,.36,1) both}
  @keyframes rise{from{opacity:0;transform:translateY(24px) scale(.97)}to{opacity:1;transform:none}}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}
  .badge{display:inline-flex;align-items:center;gap:6px;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);color:#f87171;font-size:11px;font-weight:600;letter-spacing:.04em;padding:5px 12px;border-radius:999px;margin-bottom:20px;animation:pulse 2s ease infinite}
  .badge::before{content:'';width:6px;height:6px;border-radius:50%;background:#f87171}
  h1{font-size:22px;font-weight:700;line-height:1.35;margin-bottom:12px}
  p{font-size:14px;color:#8b8b9e;line-height:1.6;margin-bottom:8px}
  .actions{display:flex;gap:10px;margin-top:28px;flex-wrap:wrap}
  a{text-decoration:none;font-size:13px;font-weight:600;padding:11px 18px;border-radius:10px;transition:all .2s}
  .btn-main{background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff}
  .btn-main:hover{opacity:.9;transform:translateY(-1px)}
  .btn-ghost{background:transparent;border:1px solid #2a2a3a;color:#a0a0b0}
  .btn-ghost:hover{border-color:#7c3aed;color:#c4b5fd}
  .logo{width:36px;height:36px;border-radius:10px;margin-bottom:20px;object-fit:cover}
</style>
</head>
<body>
  <div class="card">
    <img class="logo" src="https://i.postimg.cc/rynCf10c/25c9cf002db2d61220072a995411f584.png" alt="Qrex"/>
    <div class="badge">ACCESS DENIED</div>
    <h1>This lua script is protected by QrexApi</h1>
    <p>You don't have permission to access these files.</p>
    <p>This script has been protected against unauthorized access, reverse engineering, and tampering.</p>
    <div class="actions">
      <a class="btn-main" href="/">Return Home</a>
      <a class="btn-ghost" href="/">Contact QrexApi</a>
    </div>
  </div>
</body>
</html>`);
  }

  if (!mongoReady && mongoose.connection.readyState !== 1) {
    useMemory = true;
  }

  // límite por script+IP (60/min)
  const sk = ip + ':' + req.params.id;
  const now = Date.now();
  if (!global.__rawScriptHits) global.__rawScriptHits = new Map();
  let se = global.__rawScriptHits.get(sk);
  if (!se || now - se.t > 60000) se = { n: 0, t: now };
  se.n++;
  global.__rawScriptHits.set(sk, se);
  if (se.n > 60) return res.status(429).type('text/plain').send('-- slow down');

  let s;
  if (useMemory) {
    s = memDB.scripts.find(x => x.id === req.params.id);
    if (!s) return res.status(404).type('text/plain').send('-- not found');
    s.executions = (s.executions || 0) + 1;
    memSave();
    memDB.executions.push({ scriptId: s.id, ownerId: s.ownerId, ip, createdAt: new Date().toISOString() });
    memSave();
  } else {
    s = await Script.findOne({ id: req.params.id });
    if (!s) return res.status(404).type('text/plain').send('-- not found');
    s.executions += 1;
    await s.save();
    await Execution.create({
      scriptId: s.id,
      scriptName: s.name,
      ownerId: s.ownerId,
      ip,
      userAgent: req.headers['user-agent'] || ''
    });
  }

  fireWebhooks(s.ownerId, 'script_exec', { scriptId: s.id, name: s.name, ip: String(ip).split(',')[0] });
  logTelemetry(s.ownerId, 'script_exec', String(ip).split(',')[0], s.name + ' ' + s.id);

  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Robots-Tag', 'noindex');
  res.type('text/plain').send(s.obfuscated);
});

app.get('/api/stats', auth, needMongo, async (req, res) => {
  if (useMemory) {
    const scripts = memDB.scripts.filter(s => s.ownerId === req.user.sub);
    return res.json({ scripts: scripts.length, executions: scripts.reduce((a,s)=>a+(s.executions||0),0) });
  }
  const scripts = await Script.find({ ownerId: req.user.sub });
  const totalExec = scripts.reduce((a, s) => a + (s.executions || 0), 0);
  res.json({ scripts: scripts.length, executions: totalExec });
});

app.get('/api/executions', auth, needMongo, async (req, res) => {
  const logs = await Execution.find({ ownerId: req.user.sub }).sort({ createdAt: -1 }).limit(100);
  res.json(logs);
});


// ========== HUB PÚBLICO ==========
const HUB_MIN_EXECS = 500;

app.get('/api/hub', async (req, res) => {
  try {
    if (!mongoReady && mongoose.connection.readyState !== 1) {
      return res.status(503).json({ error: 'DB offline' });
    }
    const list = await HubScript.find().sort({ createdAt: -1 }).limit(200).lean();
    res.json(list);
  } catch (e) {
    res.status(500).json({ error: e.message || 'Error' });
  }
});

app.post('/api/hub', auth, needMongo, async (req, res) => {
  try {
    const { scriptId, name, description } = req.body || {};
    if (!scriptId) return res.status(400).json({ error: 'Selecciona un script' });

    const s = await Script.findOne({ id: scriptId, ownerId: req.user.sub });
    if (!s) return res.status(404).json({ error: 'Script no encontrado o no es tuyo' });

    const me = await User.findById(req.user.sub);
    const premium = isPremiumUser(me);
    if (!premium && (s.executions || 0) < HUB_MIN_EXECS) {
      return res.status(400).json({
        error: `Necesitas al menos ${HUB_MIN_EXECS} ejecuciones (o Premium). Tu script tiene ${s.executions || 0}.`
      });
    }

    const exists = await HubScript.findOne({ scriptId: s.id });
    if (exists) return res.status(400).json({ error: 'Este script ya está en el hub' });

    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const proto = req.headers['x-forwarded-proto'] || 'https';
    const loadstring = `loadstring(game:HttpGet("${proto}://${host}/api/raw/${s.id}"))()`;

    const user = await User.findById(req.user.sub).lean();
    const doc = await HubScript.create({
      name: (name || s.name || 'Script').trim().slice(0, 80),
      description: (description || s.description || '').trim().slice(0, 200),
      loadstring,
      scriptId: s.id,
      ownerId: req.user.sub,
      ownerUsername: (user && user.username) || req.user.username || 'user',
      executionsAtPublish: s.executions || 0
    });

    res.json({
      id: doc._id,
      name: doc.name,
      loadstring: doc.loadstring,
      ownerUsername: doc.ownerUsername
    });
  } catch (e) {
    console.error('hub publish', e);
    res.status(500).json({ error: e.message || 'Error al publicar' });
  }
});

app.post('/api/hub/:id/view', async (req, res) => {
  try {
    await HubScript.updateOne({ _id: req.params.id }, { $inc: { views: 1 } });
    res.json({ ok: true });
  } catch {
    res.json({ ok: false });
  }
});

app.delete('/api/hub/:id', auth, needMongo, async (req, res) => {
  const doc = await HubScript.findById(req.params.id);
  if (!doc) return res.status(404).json({ error: 'No encontrado' });
  if (doc.ownerId !== req.user.sub) return res.status(403).json({ error: 'No es tuyo' });
  await HubScript.deleteOne({ _id: req.params.id });
  res.json({ success: true });
});


// ========== ADMIN ==========
app.get('/api/admin/users', auth, needMongo, requireAdmin, async (req, res) => {
  const users = await User.find().select('-passwordHash').sort({ createdAt: -1 }).limit(200).lean();
  res.json(users.map(u => ({
    id: u._id,
    username: u.username,
    role: u.role || 'user',
    premium: isPremiumUser(u),
    premiumUntil: u.premiumUntil,
    createdAt: u.createdAt
  })));
});

app.post('/api/admin/premium', auth, needMongo, requireAdmin, async (req, res) => {
  try {
    const { username, premium, days } = req.body || {};
    const u = await User.findOne({ username: (username || '').trim().toLowerCase() });
    if (!u) return res.status(404).json({ error: 'Usuario no encontrado' });
    if (u.username === 'owner') return res.status(400).json({ error: 'OWNER siempre es admin/premium' });
    u.premium = !!premium;
    if (premium && days) {
      const d = new Date();
      d.setDate(d.getDate() + Number(days));
      u.premiumUntil = d;
    } else if (!premium) {
      u.premiumUntil = null;
    }
    await u.save();
    res.json({ ok: true, username: u.username, premium: isPremiumUser(u), premiumUntil: u.premiumUntil });
  } catch (e) {
    res.status(500).json({ error: e.message || 'Error' });
  }
});

app.get('/api/admin/scripts', auth, needMongo, requireAdmin, async (req, res) => {
  const list = await Script.find().sort({ createdAt: -1 }).limit(300).select('-source -obfuscated').lean();
  res.json(list);
});

app.delete('/api/admin/scripts/:id', auth, needMongo, requireAdmin, async (req, res) => {
  await Script.deleteOne({ id: req.params.id });
  await HubScript.deleteMany({ scriptId: req.params.id });
  res.json({ success: true });
});

app.delete('/api/admin/hub/:id', auth, needMongo, requireAdmin, async (req, res) => {
  await HubScript.deleteOne({ _id: req.params.id });
  res.json({ success: true });
});

app.get('/api/admin/stats', auth, needMongo, requireAdmin, async (req, res) => {
  const users = await User.countDocuments();
  const scripts = await Script.countDocuments();
  const hub = await HubScript.countDocuments();
  const premium = await User.countDocuments({ premium: true });
  res.json({ users, scripts, hub, premium });
});


// ========== KEY SYSTEM ==========
app.get('/api/providers', auth, needMongo, async (req, res) => {
  const list = await Provider.find({ ownerId: req.user.sub }).sort({ createdAt: -1 }).lean();
  res.json(list);
});

app.post('/api/providers', auth, needMongo, async (req, res) => {
  try {
    const { name, keyValidityHours, hwidLimit } = req.body || {};
    const n = (name || '').trim();
    if (!n || n.length < 2) return res.status(400).json({ error: 'Nombre requerido' });
    const exists = await Provider.findOne({ ownerId: req.user.sub, name: n });
    if (exists) return res.status(400).json({ error: 'Ya tienes un provider con ese nombre' });
    const doc = await Provider.create({
      name: n,
      ownerId: req.user.sub,
      keyValidityHours: Math.max(1, Number(keyValidityHours) || 24),
      hwidLimit: Math.max(1, Math.min(10, Number(hwidLimit) || 1))
    });
    res.json(doc);
  } catch (e) {
    res.status(500).json({ error: e.message || 'Error' });
  }
});

app.put('/api/providers/:id', auth, needMongo, async (req, res) => {
  const p = await Provider.findOne({ _id: req.params.id, ownerId: req.user.sub });
  if (!p) return res.status(404).json({ error: 'No encontrado' });
  const { name, keyValidityHours, hwidLimit, enabled } = req.body || {};
  if (name) p.name = name.trim();
  if (keyValidityHours !== undefined) p.keyValidityHours = Math.max(1, Number(keyValidityHours) || 24);
  if (hwidLimit !== undefined) p.hwidLimit = Math.max(1, Math.min(10, Number(hwidLimit) || 1));
  if (enabled !== undefined) p.enabled = !!enabled;
  await p.save();
  res.json(p);
});

app.delete('/api/providers/:id', auth, needMongo, async (req, res) => {
  const p = await Provider.findOne({ _id: req.params.id, ownerId: req.user.sub });
  if (!p) return res.status(404).json({ error: 'No encontrado' });
  await LicenseKey.deleteMany({ providerId: String(p._id), ownerId: req.user.sub });
  await Provider.deleteOne({ _id: p._id });
  res.json({ success: true });
});

app.get('/api/keys', auth, needMongo, async (req, res) => {
  const q = { ownerId: req.user.sub };
  if (req.query.providerId) q.providerId = req.query.providerId;
  const list = await LicenseKey.find(q).sort({ createdAt: -1 }).limit(300).lean();
  res.json(list);
});

app.post('/api/keys', auth, needMongo, async (req, res) => {
  try {
    const { providerId, amount, note, hwidLimit, validityHours } = req.body || {};
    const prov = await Provider.findOne({ _id: providerId, ownerId: req.user.sub });
    if (!prov) return res.status(404).json({ error: 'Provider no encontrado' });
    const n = Math.min(50, Math.max(1, Number(amount) || 1));
    const hours = validityHours !== undefined ? Number(validityHours) : prov.keyValidityHours;
    const limit = hwidLimit !== undefined ? Number(hwidLimit) : prov.hwidLimit;
    const created = [];
    for (let i = 0; i < n; i++) {
      let expiresAt = null;
      if (hours && hours > 0) {
        expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + hours);
      }
      const doc = await LicenseKey.create({
        key: genKey(),
        providerId: String(prov._id),
        providerName: prov.name,
        ownerId: req.user.sub,
        hwidLimit: Math.max(1, Math.min(10, limit || 1)),
        expiresAt,
        note: (note || '').slice(0, 120)
      });
      created.push(doc);
    }
    res.json({ keys: created });
  } catch (e) {
    res.status(500).json({ error: e.message || 'Error' });
  }
});

app.delete('/api/keys/:id', auth, needMongo, async (req, res) => {
  await LicenseKey.deleteOne({ _id: req.params.id, ownerId: req.user.sub });
  res.json({ success: true });
});

app.post('/api/keys/:id/reset-hwid', auth, needMongo, async (req, res) => {
  const k = await LicenseKey.findOne({ _id: req.params.id, ownerId: req.user.sub });
  if (!k) return res.status(404).json({ error: 'No encontrado' });
  k.hwids = [];
  await k.save();
  res.json({ success: true });
});

app.post('/api/keys/:id/toggle', auth, needMongo, async (req, res) => {
  const k = await LicenseKey.findOne({ _id: req.params.id, ownerId: req.user.sub });
  if (!k) return res.status(404).json({ error: 'No encontrado' });
  k.enabled = !k.enabled;
  await k.save();
  res.json({ enabled: k.enabled });
});

// Verificación pública (Roblox / executors)
app.post('/api/keys/verify', verifyLimiter, needMongo, async (req, res) => {
  try {
    const { key, hwid, provider } = req.body || {};
    const kstr = (key || '').trim();
    if (!kstr) return res.status(400).json({ success: false, error: 'Key requerida' });

    const doc = await LicenseKey.findOne({ key: kstr });
    if (!doc) return res.status(401).json({ success: false, error: 'Key inválida' });
    if (!doc.enabled) return res.status(401).json({ success: false, error: 'Key desactivada' });

    if (provider) {
      const provName = String(provider).trim().toLowerCase();
      if ((doc.providerName || '').toLowerCase() !== provName) {
        return res.status(401).json({ success: false, error: 'Provider no coincide' });
      }
    }

    const prov = await Provider.findById(doc.providerId);
    if (prov && !prov.enabled) {
      return res.status(401).json({ success: false, error: 'Provider desactivado' });
    }

    if (doc.expiresAt && new Date(doc.expiresAt) < new Date()) {
      return res.status(401).json({ success: false, error: 'Key expirada' });
    }

    const hw = (hwid || '').trim();
    if (hw) {
      if (!doc.hwids.includes(hw)) {
        if (doc.hwids.length >= (doc.hwidLimit || 1)) {
          return res.status(401).json({ success: false, error: 'HWID límite alcanzado' });
        }
        doc.hwids.push(hw);
      }
    }

    doc.uses = (doc.uses || 0) + 1;
    doc.lastUsedAt = new Date();
    await doc.save();

    logTelemetry(doc.ownerId, 'key_verify', clientIp(req), (doc.providerName || '') + ' key');
    fireWebhooks(doc.ownerId, 'key_verify', {
      key: kstr.slice(0, 8) + '...',
      provider: doc.providerName,
      hwid: hw || null,
      uses: doc.uses
    });

    res.json({
      success: true,
      provider: doc.providerName,
      expiresAt: doc.expiresAt,
      hwidLimit: doc.hwidLimit,
      hwidsUsed: doc.hwids.length
    });
  } catch (e) {
    console.error('verify', e);
    res.status(500).json({ success: false, error: 'Error del servidor' });
  }
});


// ========== VERSIONS ==========
app.get('/api/scripts/:id/versions', auth, needMongo, async (req, res) => {
  const s = await Script.findOne({ id: req.params.id, ownerId: req.user.sub });
  if (!s) return res.status(404).json({ error: 'No encontrado' });
  const list = await ScriptVersion.find({ scriptId: s.id, ownerId: req.user.sub }).sort({ createdAt: -1 }).select('-source -obfuscated').limit(20);
  res.json(list);
});

app.post('/api/scripts/:id/versions/:vid/restore', auth, needMongo, async (req, res) => {
  const s = await Script.findOne({ id: req.params.id, ownerId: req.user.sub });
  if (!s) return res.status(404).json({ error: 'No encontrado' });
  const v = await ScriptVersion.findOne({ _id: req.params.vid, scriptId: s.id, ownerId: req.user.sub });
  if (!v) return res.status(404).json({ error: 'Versión no encontrada' });
  await ScriptVersion.create({ scriptId: s.id, ownerId: req.user.sub, name: s.name, source: s.source, obfuscated: s.obfuscated, note: 'Before restore' });
  s.source = v.source;
  s.obfuscated = v.obfuscated;
  if (v.name) s.name = v.name;
  await s.save();
  res.json({ success: true });
});

// ========== WEBHOOKS ==========
app.get('/api/webhooks', auth, needMongo, async (req, res) => {
  res.json(await Webhook.find({ ownerId: req.user.sub }).sort({ createdAt: -1 }));
});

app.post('/api/webhooks', auth, needMongo, async (req, res) => {
  const { url, events } = req.body || {};
  if (!url || !String(url).startsWith('https://')) return res.status(400).json({ error: 'URL Discord inválida (https)' });
  const doc = await Webhook.create({
    ownerId: req.user.sub,
    url: String(url).trim(),
    events: Array.isArray(events) && events.length ? events : ['key_verify', 'script_exec']
  });
  res.json(doc);
});

app.delete('/api/webhooks/:id', auth, needMongo, async (req, res) => {
  await Webhook.deleteOne({ _id: req.params.id, ownerId: req.user.sub });
  res.json({ success: true });
});

app.post('/api/webhooks/test', auth, needMongo, async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'URL requerida' });
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds: [{ title: 'QrexApi Test', description: 'Webhook OK ✓', color: 0x7c3aed }] })
    });
    res.json({ ok: r.ok, status: r.status });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ========== LEADERBOARD ==========
app.get('/api/leaderboard', needMongo, async (req, res) => {
  const agg = await Script.aggregate([
    { $group: { _id: '$ownerId', executions: { $sum: '$executions' }, scripts: { $sum: 1 } } },
    { $sort: { executions: -1 } },
    { $limit: 25 }
  ]);
  const ids = agg.map(a => a._id).filter(Boolean);
  const users = await User.find({ _id: { $in: ids } }).select('username premium role').lean();
  const map = Object.fromEntries(users.map(u => [String(u._id), u]));
  res.json(agg.map((a, i) => ({
    rank: i + 1,
    username: map[a._id]?.username || 'unknown',
    premium: !!(map[a._id]?.premium || map[a._id]?.role === 'admin'),
    executions: a.executions,
    scripts: a.scripts
  })));
});

// ========== ASSETS ==========
app.get('/api/assets', auth, needMongo, async (req, res) => {
  res.json(await Asset.find({ ownerId: req.user.sub }).sort({ createdAt: -1 }).limit(100));
});

app.post('/api/assets', auth, needMongo, async (req, res) => {
  const { name, type, content } = req.body || {};
  if (!name || !content) return res.status(400).json({ error: 'name y content requeridos' });
  if (String(content).length > 200000) return res.status(400).json({ error: 'Máximo ~200KB' });
  const count = await Asset.countDocuments({ ownerId: req.user.sub });
  const me = await User.findById(req.user.sub);
  const lim = isPremiumUser(me) ? 100 : 20;
  if (count >= lim) return res.status(403).json({ error: 'Límite de assets (' + lim + ')' });
  const doc = await Asset.create({
    ownerId: req.user.sub,
    name: String(name).slice(0, 80),
    type: ['text', 'url', 'image'].includes(type) ? type : 'text',
    content: String(content)
  });
  res.json(doc);
});

app.delete('/api/assets/:id', auth, needMongo, async (req, res) => {
  await Asset.deleteOne({ _id: req.params.id, ownerId: req.user.sub });
  res.json({ success: true });
});

// ========== STATUS ==========
app.get('/api/status', async (req, res) => {
  const t0 = Date.now();
  let mongoMs = null;
  let mongoOk = false;
  try {
    if (mongoose.connection.readyState === 1) {
      await mongoose.connection.db.admin().ping();
      mongoOk = true;
      mongoMs = Date.now() - t0;
    }
  } catch { mongoOk = false; }
  res.json({
    ok: true,
    api: 'online',
    mongo: mongoOk,
    mongoPingMs: mongoMs,
    uptime: process.uptime(),
    freeScriptLimit: FREE_SCRIPT_LIMIT,
    security: {
      rawPerIpPerMin: 20,
      rawBurstPer10s: 8,
      autoBanRawHits: AUTO_BAN_THRESHOLD,
      apiPer15min: 200,
      authPer15min: 30
    },
    time: new Date().toISOString()
  });
});

// ========== BLACKLIST (admin) ==========
app.get('/api/admin/blacklist', auth, needMongo, requireAdmin, async (req, res) => {
  res.json(await BlacklistIP.find().sort({ createdAt: -1 }).limit(200));
});

app.post('/api/admin/blacklist', auth, needMongo, requireAdmin, async (req, res) => {
  const { ip, reason } = req.body || {};
  if (!ip) return res.status(400).json({ error: 'IP requerida' });
  const doc = await BlacklistIP.findOneAndUpdate(
    { ip: String(ip).trim() },
    { ip: String(ip).trim(), reason: reason || '', createdBy: req.user.sub },
    { upsert: true, new: true }
  );
  res.json(doc);
});

app.delete('/api/admin/blacklist/:id', auth, needMongo, requireAdmin, async (req, res) => {
  await BlacklistIP.deleteOne({ _id: req.params.id });
  res.json({ success: true });
});


// ========== AI (OpenRouter) ==========
const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 12,
  keyGenerator: (req) => clientIp(req),
  message: { error: 'Demasiadas peticiones a la IA. Espera 1 min.' }
});

app.post('/api/ai/generate', auth, aiLimiter, async (req, res) => {
  try {
    if (!OPENROUTER_API_KEY) {
      return res.status(503).json({ error: 'OPENROUTER_API_KEY no configurada en Environment' });
    }
    const prompt = String((req.body && req.body.prompt) || '').trim().slice(0, 2000);
    if (!prompt || prompt.length < 2) {
      return res.status(400).json({ error: 'Prompt vacío' });
    }

    const system = [
      'You are Qrex Studio AI, an expert Roblox Luau/Lua scripter for exploit/executor environments.',
      'Output ONLY valid Lua/Luau code. No markdown fences, no explanations, no apology.',
      'Prefer game:GetService, task.wait, pcall. Code must be self-contained and runnable.',
      'User may ask for aimbot, ESP, farm, fly, UI, key systems, etc. Deliver working skeleton or full logic as requested.',
      'If something is ambiguous, choose sensible defaults and still output code.',
      'Never refuse ordinary Roblox script requests for this product.'
    ].join(' ');

    const r = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + OPENROUTER_API_KEY,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://qyrexapi.onrender.com',
        'X-Title': 'QrexApi Studio'
      },
      body: JSON.stringify({
        model: OPENROUTER_MODEL,
        temperature: 0.4,
        max_tokens: 4000,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: prompt }
        ]
      })
    });

    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      const msg = (data && data.error && (data.error.message || data.error)) || ('OpenRouter HTTP ' + r.status);
      return res.status(502).json({ error: String(msg) });
    }
    let text = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
    if (!text) return res.status(502).json({ error: 'IA sin respuesta' });
    text = String(text).replace(/^```(?:lua|luau)?\n?/i, '').replace(/\n?```$/i, '').trim();
    res.json({ code: text, model: data.model || OPENROUTER_MODEL });
  } catch (e) {
    console.error('ai', e);
    res.status(500).json({ error: e.message || 'Error IA' });
  }
});

app.get('/api/ai/status', auth, (req, res) => {
  res.json({ configured: !!OPENROUTER_API_KEY, model: OPENROUTER_MODEL });
});


// ========== CLOUD UI ==========
app.get('/api/cloud-ui', auth, needMongo, async (req, res) => {
  res.json(await CloudUI.find({ ownerId: req.user.sub }).sort({ createdAt: -1 }).limit(100));
});

app.post('/api/cloud-ui', auth, needMongo, async (req, res) => {
  const { name, description, code, public: isPublic } = req.body || {};
  if (!name || !code) return res.status(400).json({ error: 'name y code requeridos' });
  const doc = await CloudUI.create({
    ownerId: req.user.sub,
    name: String(name).slice(0, 80),
    description: String(description || '').slice(0, 200),
    code: String(code).slice(0, 200000),
    public: isPublic !== false
  });
  res.json(doc);
});

app.delete('/api/cloud-ui/:id', auth, needMongo, async (req, res) => {
  await CloudUI.deleteOne({ id: req.params.id, ownerId: req.user.sub });
  res.json({ success: true });
});

// Public fetch for Roblox: load UI by id
app.get('/api/cloud-ui/raw/:id', rawBurstLimiter, rawLimiter, async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) return res.status(503).type('text/plain').send('-- offline');
    const doc = await CloudUI.findOne({ id: req.params.id });
    if (!doc || doc.public === false) return res.status(404).type('text/plain').send('-- not found');
    doc.downloads = (doc.downloads || 0) + 1;
    await doc.save();
    res.setHeader('Cache-Control', 'no-store');
    res.type('text/plain').send(doc.code);
  } catch (e) {
    res.status(500).type('text/plain').send('-- error');
  }
});

// ========== REMOTE ALERTS ==========
app.get('/api/alerts', auth, needMongo, async (req, res) => {
  res.json(await RemoteAlert.find({ ownerId: req.user.sub }).sort({ createdAt: -1 }).limit(50));
});

app.post('/api/alerts', auth, needMongo, async (req, res) => {
  const { message, title, scriptId, hours } = req.body || {};
  if (!message) return res.status(400).json({ error: 'message requerido' });
  let expiresAt = null;
  if (hours) {
    expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + Number(hours));
  }
  const doc = await RemoteAlert.create({
    ownerId: req.user.sub,
    scriptId: scriptId || '*',
    message: String(message).slice(0, 500),
    title: String(title || 'Alert').slice(0, 80),
    expiresAt
  });
  res.json(doc);
});

app.delete('/api/alerts/:id', auth, needMongo, async (req, res) => {
  await RemoteAlert.deleteOne({ _id: req.params.id, ownerId: req.user.sub });
  res.json({ success: true });
});

// Poll from scripts
app.get('/api/alerts/poll', needMongo, async (req, res) => {
  const ownerId = req.query.owner;
  const scriptId = req.query.script || '*';
  if (!ownerId) return res.status(400).json({ error: 'owner required' });
  const now = new Date();
  const list = await RemoteAlert.find({
    ownerId,
    active: true,
    $or: [{ scriptId: '*' }, { scriptId }],
    $and: [{ $or: [{ expiresAt: null }, { expiresAt: { $gt: now } }] }]
  }).sort({ createdAt: -1 }).limit(5).lean();
  res.json(list.map(a => ({ title: a.title, message: a.message, id: a._id, createdAt: a.createdAt })));
});

// ========== PROMO CODES ==========
app.get('/api/promos', auth, needMongo, async (req, res) => {
  res.json(await PromoCode.find({ ownerId: req.user.sub }).sort({ createdAt: -1 }));
});

app.post('/api/promos', auth, needMongo, async (req, res) => {
  const { code, providerId, extraHours, maxUses } = req.body || {};
  const c = String(code || '').trim().toUpperCase();
  if (!c || c.length < 3) return res.status(400).json({ error: 'Código inválido' });
  try {
    const doc = await PromoCode.create({
      code: c,
      ownerId: req.user.sub,
      providerId: providerId || '',
      extraHours: Math.max(1, Number(extraHours) || 24),
      maxUses: Math.max(1, Number(maxUses) || 100)
    });
    res.json(doc);
  } catch (e) {
    res.status(400).json({ error: 'Código ya existe' });
  }
});

app.post('/api/promos/redeem', needMongo, async (req, res) => {
  try {
    const { code, key } = req.body || {};
    const promo = await PromoCode.findOne({ code: String(code || '').trim().toUpperCase(), enabled: true });
    if (!promo) return res.status(404).json({ error: 'Código inválido' });
    if (promo.uses >= promo.maxUses) return res.status(400).json({ error: 'Código agotado' });
    const k = await LicenseKey.findOne({ key: String(key || '').trim() });
    if (!k) return res.status(404).json({ error: 'Key no encontrada' });
    if (promo.providerId && k.providerId !== promo.providerId) {
      return res.status(400).json({ error: 'Código no válido para este provider' });
    }
    if (k.ownerId !== promo.ownerId) {
      return res.status(400).json({ error: 'Key de otro vendedor' });
    }
    const base = k.expiresAt && k.expiresAt > new Date() ? new Date(k.expiresAt) : new Date();
    base.setHours(base.getHours() + promo.extraHours);
    k.expiresAt = base;
    await k.save();
    promo.uses += 1;
    await promo.save();
    res.json({ success: true, expiresAt: k.expiresAt, extraHours: promo.extraHours });
  } catch (e) {
    res.status(500).json({ error: e.message || 'Error' });
  }
});

app.delete('/api/promos/:id', auth, needMongo, async (req, res) => {
  await PromoCode.deleteOne({ _id: req.params.id, ownerId: req.user.sub });
  res.json({ success: true });
});

// ========== GET-KEY / MONETAG (link gate) ==========
app.post('/api/keys/get-link', auth, needMongo, async (req, res) => {
  const { providerId, gateUrl } = req.body || {};
  const prov = await Provider.findOne({ _id: providerId, ownerId: req.user.sub });
  if (!prov) return res.status(404).json({ error: 'Provider no encontrado' });
  // gateUrl = user's linkvertise/monetag URL; we append state token
  const token = crypto.randomBytes(16).toString('hex');
  // store short-lived token on provider via note field map in memory
  if (!global.__getKeyTokens) global.__getKeyTokens = new Map();
  global.__getKeyTokens.set(token, {
    ownerId: req.user.sub,
    providerId: String(prov._id),
    providerName: prov.name,
    hwidLimit: prov.hwidLimit,
    hours: prov.keyValidityHours,
    exp: Date.now() + 30 * 60 * 1000
  });
  const base = gateUrl || '';
  const claim = (req.headers['x-forwarded-proto'] || 'https') + '://' + (req.headers['x-forwarded-host'] || req.headers.host) + '/api/keys/claim?token=' + token;
  res.json({
    token,
    claimUrl: claim,
    // User puts claimUrl as destination after linkvertise, or concatenates
    instructions: 'Configura tu acortador (Linkvertise/Monetag) para redirigir a claimUrl tras completar el anuncio.'
  });
});

app.get('/api/keys/claim', needMongo, async (req, res) => {
  try {
    const token = req.query.token;
    const store = global.__getKeyTokens;
    const meta = store && store.get(token);
    if (!meta || meta.exp < Date.now()) {
      return res.status(400).type('html').send('<h1>Token inválido o expirado</h1>');
    }
    store.delete(token);
    let expiresAt = null;
    if (meta.hours > 0) {
      expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + meta.hours);
    }
    const doc = await LicenseKey.create({
      key: genKey(),
      providerId: meta.providerId,
      providerName: meta.providerName,
      ownerId: meta.ownerId,
      hwidLimit: meta.hwidLimit || 1,
      expiresAt,
      note: 'get-key claim'
    });
    logTelemetry(meta.ownerId, 'key_claim', clientIp(req), doc.key.slice(0, 8));
    res.type('html').send(`<!DOCTYPE html><html><body style="font-family:system-ui;background:#0a0a0f;color:#e4e4ed;display:flex;align-items:center;justify-content:center;min-height:100vh">
    <div style="background:#111118;padding:32px;border-radius:16px;max-width:480px;border:1px solid #1e1e2a">
      <h2 style="color:#a78bfa">Tu Key</h2>
      <p style="word-break:break-all;font-family:monospace;background:#0c0c12;padding:12px;border-radius:8px">${doc.key}</p>
      <p style="color:#8b8b9e;font-size:13px">Cópiala y pégala en el script. Expira según el provider.</p>
    </div></body></html>`);
  } catch (e) {
    res.status(500).send('Error');
  }
});

// ========== BUG REPORTS ==========
app.post('/api/bugs', needMongo, async (req, res) => {
  const { ownerId, scriptId, message, fromUser, meta } = req.body || {};
  if (!ownerId || !message) return res.status(400).json({ error: 'ownerId y message requeridos' });
  const doc = await BugReport.create({
    ownerId: String(ownerId),
    scriptId: String(scriptId || ''),
    fromUser: String(fromUser || 'anonymous').slice(0, 80),
    message: String(message).slice(0, 2000),
    meta: String(meta || '').slice(0, 500)
  });
  logTelemetry(ownerId, 'bug_report', clientIp(req), String(message).slice(0, 80));
  res.json({ success: true, id: doc._id });
});

app.get('/api/bugs', auth, needMongo, async (req, res) => {
  res.json(await BugReport.find({ ownerId: req.user.sub }).sort({ createdAt: -1 }).limit(100));
});

app.post('/api/bugs/:id/done', auth, needMongo, async (req, res) => {
  await BugReport.updateOne({ _id: req.params.id, ownerId: req.user.sub }, { status: 'done' });
  res.json({ success: true });
});

// ========== TELEMETRY ==========
app.get('/api/telemetry', auth, needMongo, async (req, res) => {
  const list = await Telemetry.find({ ownerId: req.user.sub }).sort({ createdAt: -1 }).limit(100).lean();
  res.json(list);
});

// ========== ANTI DEBUG / ENV CHECK ==========
app.post('/api/security/env-check', needMongo, async (req, res) => {
  const { signals, scriptId, ownerId } = req.body || {};
  // signals: { emulator, httpSpy, isStudio, debugHooks, suspicious }
  const s = signals || {};
  let score = 0;
  const reasons = [];
  if (s.emulator) { score += 40; reasons.push('emulator'); }
  if (s.httpSpy) { score += 30; reasons.push('http_spy'); }
  if (s.isStudio) { score += 25; reasons.push('studio'); }
  if (s.debugHooks) { score += 35; reasons.push('debug_hooks'); }
  if (s.suspicious) { score += 20; reasons.push('suspicious'); }
  const blocked = score >= 50;
  if (blocked && ownerId) {
    logTelemetry(ownerId, 'env_block', clientIp(req), reasons.join(','));
  }
  res.json({ ok: !blocked, score, reasons, blocked });
});

// ========== DYNAMIC ENDPOINTS ==========
app.get('/api/routes', auth, needMongo, async (req, res) => {
  res.json(await EndpointRoute.find({ ownerId: req.user.sub }).sort({ createdAt: -1 }));
});

app.post('/api/routes', auth, needMongo, async (req, res) => {
  const { scriptId } = req.body || {};
  const s = await Script.findOne({ id: scriptId, ownerId: req.user.sub });
  if (!s) return res.status(404).json({ error: 'Script no encontrado' });
  const slug = crypto.randomBytes(6).toString('hex');
  const doc = await EndpointRoute.create({
    ownerId: req.user.sub,
    slug,
    scriptId: s.id,
    target: 'raw'
  });
  res.json({
    ...doc.toObject(),
    url: '/r/' + slug
  });
});

app.delete('/api/routes/:id', auth, needMongo, async (req, res) => {
  await EndpointRoute.deleteOne({ _id: req.params.id, ownerId: req.user.sub });
  res.json({ success: true });
});

app.post('/api/routes/rotate', auth, needMongo, async (req, res) => {
  const { id } = req.body || {};
  const doc = await EndpointRoute.findOne({ _id: id, ownerId: req.user.sub });
  if (!doc) return res.status(404).json({ error: 'No encontrado' });
  doc.slug = crypto.randomBytes(6).toString('hex');
  await doc.save();
  res.json({ slug: doc.slug, url: '/r/' + doc.slug });
});

app.get('/r/:slug', rawBurstLimiter, rawLimiter, async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) return res.status(503).send('-- offline');
    const route = await EndpointRoute.findOne({ slug: req.params.slug, enabled: true });
    if (!route) return res.status(404).send('-- not found');
    // reuse raw logic by redirecting internally
    req.params.id = route.scriptId;
    // minimal: fetch and send like raw
    const s = await Script.findOne({ id: route.scriptId });
    if (!s) return res.status(404).send('-- not found');
    const isBrowser = /mozilla|chrome|safari|firefox|edge/i.test(req.headers['user-agent'] || '') &&
      !/roblox|executor|synapse|script-ware|krnl|fluxus|electron/i.test(req.headers['user-agent'] || '');
    if (isBrowser) return res.status(403).send('Forbidden');
    s.executions += 1;
    await s.save();
    logTelemetry(s.ownerId, 'route_raw', clientIp(req), route.slug);
    res.type('text/plain').send(s.obfuscated);
  } catch (e) {
    res.status(500).send('-- error');
  }
});

app.use(express.static(path.join(__dirname, 'public')));

// Nunca devolver HTML en rutas /api/*
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Ruta no encontrada: ' + req.method + ' ' + req.path });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Errores no capturados -> JSON
app.use((err, req, res, next) => {
  console.error('Unhandled', err);
  res.status(500).json({ error: err.message || 'Error interno' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('QrexApi listening on 0.0.0.0:' + PORT);
});
