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

const JWT_SECRET = process.env.JWT_SECRET || 'cambia-este-secret-por-uno-largo';
const MONGO_URI = process.env.MONGO_URI || '';
const VOLTILS_URL = process.env.VOLTILS_URL || 'https://voltils.nxtdev.xyz/v1/obfuscate';
const VOLTILS_KEY = process.env.VOLTILS_KEY || 'voltils_1267954195982581782_b24de9d9410f9e7a0dcb7db05b18cda598f9415f';
const VOLTILS_PRESET = process.env.VOLTILS_PRESET || 'normal';
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || '';
const OPENROUTER_MODEL = process.env.OPENROUTER_MODEL || 'openrouter/auto';

const PORT = process.env.PORT || 10000;

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

async function connectMongo() {
  if (!MONGO_URI) {
    console.error('FATAL: MONGO_URI no esta configurado en Environment Variables');
    return;
  }
  try {
    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 10000
    });
    mongoReady = true;
    console.log('Mongo OK');
  } catch (err) {
    mongoReady = false;
    console.error('Mongo error:', err.message);
  }
}
connectMongo();

mongoose.connection.on('connected', () => { mongoReady = true; console.log('Mongo connected'); });
mongoose.connection.on('disconnected', () => { mongoReady = false; console.log('Mongo disconnected'); });
mongoose.connection.on('error', (e) => { mongoReady = false; console.error('Mongo conn error:', e.message); });

const User = mongoose.models.QrexUser || mongoose.model('QrexUser', new mongoose.Schema({
  username: { type: String, unique: true, required: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  role: { type: String, default: 'user' }, // user | admin
  premium: { type: Boolean, default: false },
  premiumUntil: { type: Date, default: null },
  lastVipRedeemAt: { type: Date, default: null },
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

const FREE_SCRIPT_LIMIT = 15;

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
  // linkvertise | lootlabs | workink | custom | none
  linkType: { type: String, default: 'custom' },
  // URL del anuncio (Linkvertise / Lootlabs / Work.ink). Debe redirigir a /getkey/:providerId
  adLink: { type: String, default: '' },
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


const VipCode = mongoose.models.QrexVipCode || mongoose.model('QrexVipCode', new mongoose.Schema({
  code: { type: String, unique: true, required: true, uppercase: true, trim: true },
  days: { type: Number, default: 10 },
  used: { type: Boolean, default: false },
  usedBy: { type: String, default: null },
  usedAt: { type: Date, default: null },
  createdBy: { type: String, default: 'system' },
  note: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
}));

const BOOTSTRAP_VIP_KEYS = [
  "QYREX-VIP-E13F-520E-164079",
  "QYREX-VIP-4EC0-79EE-C72E92",
  "QYREX-VIP-B1FC-1CFB-928515",
  "QYREX-VIP-1BAB-2B17-E385B8",
  "QYREX-VIP-D567-E462-7B586A",
  "QYREX-VIP-E02B-C3AA-EAA997",
  "QYREX-VIP-5F4A-B79E-093EC1",
  "QYREX-VIP-705A-0FBE-F807A9",
  "QYREX-VIP-B72D-EC5C-25EE03",
  "QYREX-VIP-0357-C159-B37CAB",
  "QYREX-VIP-6845-6F86-A6AA32",
  "QYREX-VIP-CA88-B276-7AD428",
  "QYREX-VIP-957A-8576-3005B1",
  "QYREX-VIP-D9C8-404C-84374A",
  "QYREX-VIP-B48C-511B-42069C",
  "QYREX-VIP-2A97-76F0-DA3DAD",
  "QYREX-VIP-37EA-A4DE-04F9CC",
  "QYREX-VIP-51CE-DCDA-FE352C",
  "QYREX-VIP-72F0-07BF-E27516",
  "QYREX-VIP-51E8-954E-06A868",
  "QYREX-VIP-7BAF-CE84-E9F4E9",
  "QYREX-VIP-F062-E538-9CE073",
  "QYREX-VIP-6CEC-4362-694B38",
  "QYREX-VIP-6B16-BADE-FEEC7F",
  "QYREX-VIP-A24C-CF36-F986A8",
  "QYREX-VIP-F1E1-C28A-C1783B",
  "QYREX-VIP-6257-6E1A-977A02",
  "QYREX-VIP-7BF7-6E70-B9DD8B",
  "QYREX-VIP-D1D9-942F-21883B",
  "QYREX-VIP-3881-4939-143D40",
  "QYREX-VIP-FA48-7E1B-4B5B46",
  "QYREX-VIP-9580-EC09-A36C4E",
  "QYREX-VIP-F956-FE91-0DA808",
  "QYREX-VIP-F420-8961-E26A8A",
  "QYREX-VIP-7A6A-826B-A3EB2E",
  "QYREX-VIP-E8DB-1DFD-BD1F75",
  "QYREX-VIP-DFBE-1551-F2D4EB",
  "QYREX-VIP-6C8B-AAA9-F05A61",
  "QYREX-VIP-7FFE-1676-3AD751",
  "QYREX-VIP-814E-7BB8-080F11",
  "QYREX-VIP-5FAE-B230-6419A9",
  "QYREX-VIP-6A6A-C171-095C8D",
  "QYREX-VIP-518A-D491-EEA75E",
  "QYREX-VIP-4B53-B67B-C90B60",
  "QYREX-VIP-427E-6264-1E8A12",
  "QYREX-VIP-64AC-46DC-BAF4A9",
  "QYREX-VIP-DAF5-C082-F3F0A0",
  "QYREX-VIP-B595-BCB7-F9E64A",
  "QYREX-VIP-57D6-79C1-8EFB99",
  "QYREX-VIP-55FF-14BD-3FFB06"
];

async function seedVipKeysIfEmpty() {
  try {
    if (mongoose.connection.readyState !== 1) return;
    const count = await VipCode.countDocuments();
    if (count > 0) return;
    const docs = BOOTSTRAP_VIP_KEYS.map(code => ({
      code: code.toUpperCase(),
      days: 10,
      note: 'batch-50-bootstrap',
      createdBy: 'system'
    }));
    await VipCode.insertMany(docs, { ordered: false }).catch(() => {});
    console.log('VIP keys seeded:', docs.length);
  } catch (e) {
    console.error('VIP seed error', e.message);
  }
}
mongoose.connection.on('connected', () => { seedVipKeysIfEmpty(); });

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
    { sub: user._id.toString(), username: user.username },
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
  if (!MONGO_URI) {
    return res.status(503).json({ error: 'MONGO_URI no configurado en Render Environment' });
  }
  if (!mongoReady && mongoose.connection.readyState !== 1) {
    return res.status(503).json({ error: 'MongoDB no conectado. Revisa MONGO_URI y Network Access en Atlas (0.0.0.0/0)' });
  }
  next();
}

async function obfuscateWithVoltils(code) {
  if (!VOLTILS_KEY) throw new Error('VOLTILS_KEY no configurada');
  const r = await fetch(VOLTILS_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + VOLTILS_KEY,
      'Accept': 'application/json'
    },
    body: JSON.stringify({
      code: String(code || ''),
      preset: VOLTILS_PRESET || 'normal'
    }),
    signal: AbortSignal.timeout(90000)
  });
  const text = await r.text();
  let data = null;
  try { data = JSON.parse(text); } catch {}
  // Accept several response shapes from Voltils
  let out = null;
  if (data) {
    if (typeof data === 'string') out = data;
    else if (typeof data.code === 'string') out = data.code;
    else if (typeof data.result === 'string') out = data.result;
    else if (typeof data.obfuscated === 'string') out = data.obfuscated;
    else if (typeof data.output === 'string') out = data.output;
    else if (data.data && typeof data.data === 'string') out = data.data;
    else if (data.data && typeof data.data.code === 'string') out = data.data.code;
  }
  if (!out && text && !text.trim().startsWith('{') && !text.trim().startsWith('[')) {
    out = text;
  }
  if (!r.ok || !out) {
    const err = (data && (data.error || data.message || data.detail)) || ('Voltils HTTP ' + r.status + (text ? ': ' + text.slice(0, 120) : ''));
    throw new Error(String(err));
  }
  return String(out);
}

function xorBytes(buf, key) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ key[i % key.length];
  return out;
}

/** 5 capas: XOR aleatorio + Base64 repetido (Lua decoder al final) */
const ENV_GATE_LUA = "--[[ Qrex Env Logger + anti-steal ]]\nlocal function __qrexEnvGate()\n  local _ok = true\n  local function fail() _ok = false end\n\n  -- 1) getgenv / debug\n  do\n    local a = true\n    local b = getgenv\n    local c = debug\n    local d = c and c.getinfo\n    local e = c and (c.getupvalue or c.getupvalues)\n    local f = getmetatable\n    local g = iscclosure\n    if not b or not d then\n      a = false\n    else\n      local h = b()\n      if f(h) and (f(h).__index or f(h).__newindex or f(h).__metatable) then a = false end\n      local k = d(b)\n      if not k or k.what ~= \"C\" or k.source ~= \"=[C]\" then a = false end\n      if g and not g(b) then a = false end\n      if e then\n        local l, m = pcall(e, b, 1)\n        if l and m ~= nil then a = false end\n      end\n      local x = \"_t\"\n      h[x] = 1\n      if rawget(h, x) ~= 1 then a = false end\n      h[x] = nil\n    end\n    if not a then fail() end\n  end\n\n  -- 2) TerrainRegion\n  do\n    local success = pcall(function()\n      local c = Instance.new(\"TerrainRegion\")\n      assert(typeof(c) == \"Instance\")\n      assert(c.ClassName == \"TerrainRegion\")\n      assert(c:IsA(\"TerrainRegion\"))\n      assert(c:IsA(\"Instance\"))\n      local workspaceTerrain = workspace:FindFirstChildOfClass(\"Terrain\")\n      if workspaceTerrain then\n        local ok, region = pcall(function()\n          return workspaceTerrain:CopyRegion(Region3.new(Vector3.new(0,0,0), Vector3.new(4,4,4)))\n        end)\n        if ok and region then\n          assert(typeof(region) == \"TerrainRegion\")\n          assert(region.ClassName == \"TerrainRegion\")\n          local size = region.Size\n          assert(typeof(size) == \"Vector3int16\")\n        end\n      end\n      local part = Instance.new(\"Part\")\n      local _ = part.Position\n      part:Destroy()\n    end)\n    if not success then fail() end\n  end\n\n  -- 3) DataModel check (NO infinite loop - that bricks legit users)\n  do\n    if game.ClassName ~= \"DataModel\" then fail() end\n  end\n\n  -- 4) OverlapParams\n  do\n    local w = workspace\n    local a = Instance.new(\"Part\")\n    local b = Instance.new(\"Part\")\n    a.Anchored = true\n    b.Anchored = true\n    a.CFrame = CFrame.new(0,0,0)\n    b.CFrame = CFrame.new(0,0,0)\n    a.Parent = w\n    b.Parent = w\n    local q = OverlapParams.new()\n    q.IncludeInstances = {a, b}\n    local x = w:GetPartBoundsInBox(CFrame.new(), Vector3.new(4,4,4), q)\n    q.ExcludeInstances = {b}\n    local y = w:GetPartBoundsInBox(CFrame.new(), Vector3.new(4,4,4), q)\n    q.IncludeInstances = {}\n    local z = w:GetPartBoundsInBox(CFrame.new(), Vector3.new(4,4,4), q)\n    local function has(t, inst)\n      for _, v in t do if v == inst then return true end end\n      return false\n    end\n    local ok = has(x,a) and has(x,b) and has(y,a) and not has(y,b) and #z == 0\n    a:Destroy(); b:Destroy()\n    if not ok then fail() end\n  end\n\n  -- 5) TweenService\n  do\n    local ok = pcall(function()\n      local ts = game:GetService(\"TweenService\")\n      local obj = Instance.new(\"NumberValue\")\n      obj.Value = 0\n      obj.Parent = workspace\n      local tween = ts:Create(obj, TweenInfo.new(1, Enum.EasingStyle.Linear, Enum.EasingDirection.In), {Value = 1})\n      tween:Play()\n      task.wait(0.5)\n      local mid = obj.Value\n      if mid <= 0 or mid >= 1 or mid < 0.3 or mid > 0.7 then error(\"dtc\") end\n      tween.Completed:Wait()\n      if obj.Value ~= 1 then error(\"dtc\") end\n      obj:Destroy()\n    end)\n    if not ok then fail() end\n  end\n\n  if not _ok then\n    error(\"dtc bro\")\n  end\nend\n__qrexEnvGate()\n";

function wrapWithEnvLogger(source) {
  return ENV_GATE_LUA + "\n" + String(source || "");
}

async function resolveObfuscated(source, mode) {
  // Ofuscación obligatoria vía Voltils API. Sin env logger.
  const src = String(source || '');
  try {
    let code = await obfuscateWithVoltils(src);
    code = String(code || '');
    if (!code.trim().startsWith('-- Protected by Voltils')) {
      code = '-- Protected by Voltils · https://discord.gg/f4HRYHTCnz\n' + code;
    }
    return { code, doObfuscate: true, obfMode: 'qrex' };
  } catch (e) {
    console.error('Obfuscator fail:', e.message);
    // Re-lanzar para que el create muestre error (no guardar sin ofuscar)
    throw new Error('Ofuscación falló: ' + (e.message || 'error'));
  }
}


function localObfuscate(code) {
  const raw = String(code || '');
  if (!raw) return '-- empty';
  if (raw.length > 1500000) throw new Error('Script demasiado grande para ofuscar');
  const src = Buffer.from(raw, 'utf8');
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
    mongoState: mongoose.connection.readyState // 0=off 1=on 2=connecting 3=disconnecting
  });
});

app.post('/api/auth/register', needMongo, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const user = (username || '').trim().toLowerCase();
    const pass = password || '';

    if (!user || user.length < 3) {
      return res.status(400).json({ error: 'Usuario minimo 3 caracteres' });
    }
    if (!/^[a-z0-9_]+$/.test(user)) {
      return res.status(400).json({ error: 'Solo letras, numeros y _' });
    }
    if (pass.length < 4) {
      return res.status(400).json({ error: 'Contraseña minimo 4 caracteres' });
    }

    const exists = await User.findOne({ username: user });
    if (exists) {
      return res.status(400).json({ error: 'Ese usuario ya existe' });
    }

    const isOwnerName = user === 'owner';
    const doc = await User.create({
      username: user,
      passwordHash: hashPassword(pass),
      role: isOwnerName ? 'admin' : 'user',
      premium: isOwnerName ? true : false
    });

    const token = signToken(doc);
    res.json({
      token,
      user: {
        id: doc._id,
        username: doc.username,
        role: doc.role,
        premium: isPremiumUser(doc)
      }
    });
  } catch (e) {
    console.error('register', e);
    if (e.code === 11000) {
      return res.status(400).json({ error: 'Ese usuario ya existe' });
    }
    res.status(500).json({ error: 'Error al registrar: ' + (e.message || 'desconocido') });
  }
});

app.post('/api/auth/login', needMongo, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const user = (username || '').trim().toLowerCase();
    const pass = password || '';

    if (!user || !pass) {
      return res.status(400).json({ error: 'Falta usuario o contraseña' });
    }

    const doc = await User.findOne({ username: user });
    if (!doc || !verifyPassword(pass, doc.passwordHash)) {
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }

    if (doc.username === 'owner' && doc.role !== 'admin') {
      doc.role = 'admin';
      doc.premium = true;
      await doc.save();
    }

    const token = signToken(doc);
    res.json({
      token,
      user: {
        id: doc._id,
        username: doc.username,
        role: doc.role || 'user',
        premium: isPremiumUser(doc)
      }
    });
  } catch (e) {
    console.error('login', e);
    res.status(500).json({ error: 'Error al iniciar sesion: ' + (e.message || 'desconocido') });
  }
});

app.get('/api/me', auth, needMongo, async (req, res) => {
  const user = await User.findById(req.user.sub);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  if (user.username === 'owner' && user.role !== 'admin') {
    user.role = 'admin';
    user.premium = true;
    await user.save();
  }
  res.json({
    id: user._id,
    username: user.username,
    role: user.role || 'user',
    premium: isPremiumUser(user)
  });
});

function requireAdmin(req, res, next) {
  User.findById(req.user.sub).then(u => {
    if (!u || u.role !== 'admin') return res.status(403).json({ error: 'Solo admin' });
    req.adminUser = u;
    next();
  }).catch(() => res.status(403).json({ error: 'Solo admin' }));
}

app.get('/api/scripts', auth, needMongo, async (req, res) => {
  const list = await Script.find({ ownerId: req.user.sub })
    .sort({ createdAt: -1 })
    .select('-source -obfuscated');
  res.json(list);
});

app.get('/api/scripts/:id', auth, needMongo, async (req, res) => {
  const s = await Script.findOne({ id: req.params.id, ownerId: req.user.sub });
  if (!s) return res.status(404).json({ error: 'No encontrado' });
  res.json(s);
});

app.post('/api/scripts', auth, needMongo, async (req, res) => {
  try {
    const { name, description, source, keyMode, providerId } = req.body || {};
    if (!name || !source) return res.status(400).json({ error: 'name y source requeridos' });

    const me = await User.findById(req.user.sub);
    const prem = isPremiumUser(me);
    const count = await Script.countDocuments({ ownerId: req.user.sub });
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
    if (!['none', 'qrex', 'local'].includes(obfMode)) obfMode = 'qrex';
    const resolved = await resolveObfuscated(source, obfMode);
    const doc = await Script.create({
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
      loadstring: `loadstring(game:HttpGet("${proto}://${host}/api/v1/luascripts/public/${doc.id}/download"))()`
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
      const resolved = await resolveObfuscated(source, 'qrex');
      s.obfuscated = resolved.code;
      s.doObfuscate = resolved.doObfuscate;
      s.obfMode = resolved.obfMode;
    } else if ((req.body?.obfMode || req.body?.doObfuscate !== undefined) && s.source) {
      const resolved = await resolveObfuscated(s.source, 'qrex');
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
  await Script.deleteOne({ id: req.params.id, ownerId: req.user.sub });
  res.json({ success: true });
});


// ========== DOUBLE LINK LOADER ==========
// Capa 1 (público): solo stub que hace HttpGet a /cache/...
// Capa 2 (cache): script real ofuscado (+ key gate si aplica)
function buildDoubleLinkStub(cacheUrl) {
  const u = String(cacheUrl).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const junk = [];
  for (let i = 0; i < 8; i++) {
    junk.push('local _' + crypto.randomBytes(2).toString('hex') + '="' + crypto.randomBytes(4).toString('hex') + '"');
  }
  return [
    '-- QrexApi Protected Loader',
    '-- Protected by Voltils · https://discord.gg/f4HRYHTCnz',
    ...junk,
    'local function _g()',
    '  local u="' + u + '"',
    '  local a=game.HttpGet',
    '  local b=game["Http".."Get"]',
    '  local src=(type(a)=="function" and a(game,u)) or (type(b)=="function" and b(game,u)) or game:HttpGet(u)',
    '  local fn,err=loadstring(src)',
    '  if type(fn)~="function" then error(err or "loader fail") end',
    '  return fn()',
    'end',
    'return _g()'
  ].join('\n');
}

function publicBase(req) {
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const proto = req.headers['x-forwarded-proto'] || 'https';
  return proto + '://' + host;
}

function isBrowserReq(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const accept = (req.headers['accept'] || '').toLowerCase();
  return accept.includes('text/html') &&
    /mozilla|chrome|firefox|safari|edg/i.test(ua) &&
    !/roblox|executor|synapse|fluxus|solara|wave|delta|electron/i.test(ua);
}

const DENY_HTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Access Denied — QrexApi</title>
<style>
body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0a0a0f;font-family:system-ui;color:#e4e4ed}
.card{background:#111118;border:1px solid #1e1e2a;border-radius:20px;padding:40px;max-width:520px}
.badge{color:#f87171;font-size:12px;font-weight:700;margin-bottom:12px}
a{color:#a78bfa;text-decoration:none}a:hover{text-decoration:underline}
.cred{margin-top:18px;font-size:12px;color:#6b6b80;line-height:1.5}
</style></head><body><div class="card"><div class="badge">ACCESS DENIED</div>
<h1>Protected by QrexApi</h1>
<p>This lua script cannot be viewed in a browser.</p>
<p class="cred">Ofuscacion y proteccion por <b style="color:#c4b5fd">Voltils</b><br/>
<a href="https://discord.gg/f4HRYHTCnz" target="_blank" rel="noopener">discord.gg/f4HRYHTCnz</a></p>
</div></body></html>`;

async function serveRealScript(req, res, scriptId) {
  const ip = clientIp(req);
  if (!mongoReady && mongoose.connection.readyState !== 1) {
    return res.status(503).type('text/plain').send('-- db offline');
  }
  const sk = 'cache:' + ip + ':' + scriptId;
  const now = Date.now();
  if (!global.__rawScriptHits) global.__rawScriptHits = new Map();
  let se = global.__rawScriptHits.get(sk);
  if (!se || now - se.t > 60000) se = { n: 0, t: now };
  se.n++;
  global.__rawScriptHits.set(sk, se);
  if (se.n > 60) return res.status(429).type('text/plain').send('-- slow down');

  const s = await Script.findOne({ id: scriptId });
  if (!s) return res.status(404).type('text/plain').send('-- not found');

  s.executions = (s.executions || 0) + 1;
  await s.save();
  await Execution.create({
    scriptId: s.id,
    scriptName: s.name,
    ownerId: s.ownerId,
    ip,
    userAgent: req.headers['user-agent'] || ''
  });
  fireWebhooks(s.ownerId, 'script_exec', { scriptId: s.id, name: s.name, ip: String(ip).split(',')[0] });

  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Robots-Tag', 'noindex');
  res.setHeader('X-Qrex-Layer', 'cache');

  let payload = s.obfuscated || '';
  if (s.keyMode === 'key' && s.providerId) {
    try {
      const prov = await Provider.findById(s.providerId);
      const base = publicBase(req);
      const claimUrl = base + '/getkey/' + s.providerId;
      const getKeyLink = (prov && prov.adLink) ? prov.adLink : claimUrl;
      payload = buildKeyGateLua({
        apiBase: base,
        providerName: (prov && prov.name) || s.providerName || 'Qrex',
        getKeyLink,
        scriptCode: s.obfuscated
      });
    } catch (e) {
      console.error('key gate wrap', e);
    }
  }
  res.type('text/plain').send(payload);
}


app.get(['/api/raw/:id', '/api/v1/luascripts/public/:id/download', '/api/v1/luascripts/public/:id'], rawBurstLimiter, rawLimiter, async (req, res) => {
  // CAPA 1: solo loader doble (no entrega el script real)
  const ip = clientIp(req);
  const hits = trackAbuse(ip);
  if (hits >= AUTO_BAN_THRESHOLD) {
    try {
      if (mongoose.connection.readyState === 1 && mongoose.models.QrexBlacklistIP) {
        await mongoose.models.QrexBlacklistIP.findOneAndUpdate(
          { ip },
          { ip, reason: 'Auto-ban: flood layer1 (' + hits + ' hits/2min)', createdBy: 'system' },
          { upsert: true }
        );
      }
    } catch {}
    return res.status(403).type('text/plain').send('-- banned');
  }

  if (isBrowserReq(req)) {
    return res.status(403).type('html').send(DENY_HTML);
  }

  if (!mongoReady && mongoose.connection.readyState !== 1) {
    return res.status(503).type('text/plain').send('-- db offline');
  }

  const s = await Script.findOne({ id: req.params.id }).select('id');
  if (!s) return res.status(404).type('text/plain').send('-- not found');

  const base = publicBase(req);
  const cacheUrl = base + '/api/v1/luascripts/cache/public/' + s.id + '/download';

  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Robots-Tag', 'noindex');
  res.setHeader('X-Qrex-Layer', 'public');
  res.type('text/plain').send(buildDoubleLinkStub(cacheUrl));
});

// CAPA 2: script real ofuscado (+ key system)
app.get(['/api/v1/luascripts/cache/public/:id/download', '/api/cache/:id', '/api/raw/cache/:id'], rawBurstLimiter, rawLimiter, async (req, res) => {
  const ip = clientIp(req);
  const hits = trackAbuse(ip);
  if (hits >= AUTO_BAN_THRESHOLD) {
    return res.status(403).type('text/plain').send('-- banned');
  }
  if (isBrowserReq(req)) {
    return res.status(403).type('html').send(DENY_HTML);
  }
  return serveRealScript(req, res, req.params.id);
});


// ========== VIP REDEEM ==========
app.post('/api/vip/redeem', auth, needMongo, async (req, res) => {
  try {
    const code = String((req.body || {}).code || '').trim().toUpperCase();
    if (!code || code.length < 6) return res.status(400).json({ error: 'Codigo invalido' });

    const vip = await VipCode.findOne({ code });
    if (!vip) return res.status(404).json({ error: 'Codigo no existe' });
    if (vip.used) return res.status(400).json({ error: 'Codigo ya canjeado' });

    const user = await User.findById(req.user.sub);
    if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });

    const now = new Date();
    const COOLDOWN_MS = 5 * 60 * 60 * 1000; // 5 horas
    if (user.lastVipRedeemAt) {
      const elapsed = now - new Date(user.lastVipRedeemAt);
      if (elapsed < COOLDOWN_MS) {
        const left = COOLDOWN_MS - elapsed;
        const hours = Math.floor(left / 3600000);
        const mins = Math.ceil((left % 3600000) / 60000);
        const wait = hours > 0 ? (hours + 'h ' + mins + 'm') : (mins + ' min');
        return res.status(429).json({
          error: 'Cooldownoldown activo. Puedes canjear otra key en ' + wait,
          retryAfterMs: left,
          retryAfterHours: Math.ceil(left / 3600000)
        });
      }
    }

    const days = Math.max(1, Number(vip.days) || 10);
    let base = now;
    if (user.premium && user.premiumUntil && new Date(user.premiumUntil) > now) {
      base = new Date(user.premiumUntil);
    }
    const until = new Date(base);
    until.setDate(until.getDate() + days);

    user.premium = true;
    user.premiumUntil = until;
    user.lastVipRedeemAt = now;
    await user.save();

    vip.used = true;
    vip.usedBy = user.username;
    vip.usedAt = now;
    await vip.save();

    res.json({
      success: true,
      premium: true,
      premiumUntil: until,
      days,
      nextRedeemAt: new Date(now.getTime() + COOLDOWN_MS),
      message: 'VIP activado por ' + days + ' dias. Proximo canje en 5 horas.'
    });
  } catch (e) {
    res.status(500).json({ error: e.message || 'Error' });
  }
});

app.get('/api/vip/status', auth, needMongo, async (req, res) => {
  const user = await User.findById(req.user.sub).lean();
  if (!user) return res.status(401).json({ error: 'No auth' });
  res.json({
    premium: isPremiumUser(user),
    premiumUntil: user.premiumUntil || null,
    role: user.role
  });
});

app.post('/api/admin/vip-keys', auth, needMongo, requireAdmin, async (req, res) => {
  try {
    const amount = Math.min(100, Math.max(1, Number((req.body || {}).amount) || 10));
    const days = Math.max(1, Number((req.body || {}).days) || 10);
    const note = String((req.body || {}).note || '').slice(0, 80);
    const created = [];
    for (let i = 0; i < amount; i++) {
      const code = ('QYREX-VIP-' + crypto.randomBytes(2).toString('hex') + '-' + crypto.randomBytes(2).toString('hex') + '-' + crypto.randomBytes(3).toString('hex')).toUpperCase();
      const doc = await VipCode.create({
        code,
        days,
        note,
        createdBy: req.user.username || req.user.sub
      });
      created.push({ code: doc.code, days: doc.days });
    }
    res.json({ keys: created });
  } catch (e) {
    res.status(500).json({ error: e.message || 'Error' });
  }
});

app.get('/api/admin/vip-keys', auth, needMongo, requireAdmin, async (req, res) => {
  const list = await VipCode.find().sort({ createdAt: -1 }).limit(200).lean();
  res.json(list);
});


app.get('/api/stats', auth, needMongo, async (req, res) => {
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
    const loadstring = `loadstring(game:HttpGet("${proto}://${host}/api/v1/luascripts/public/${s.id}/download"))()`;

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
    const { name, keyValidityHours, hwidLimit, linkType, adLink } = req.body || {};
    const n = (name || '').trim();
    if (!n || n.length < 2) return res.status(400).json({ error: 'Nombre requerido' });
    const exists = await Provider.findOne({ ownerId: req.user.sub, name: n });
    if (exists) return res.status(400).json({ error: 'Ya tienes un provider con ese nombre' });
    const lt = ['linkvertise','lootlabs','workink','custom','none'].includes(linkType) ? linkType : 'custom';
    const doc = await Provider.create({
      name: n,
      ownerId: req.user.sub,
      keyValidityHours: Math.max(1, Number(keyValidityHours) || 24),
      hwidLimit: Math.max(1, Math.min(10, Number(hwidLimit) || 1)),
      linkType: lt,
      adLink: String(adLink || '').trim().slice(0, 500)
    });
    res.json(doc);
  } catch (e) {
    res.status(500).json({ error: e.message || 'Error' });
  }
});

app.put('/api/providers/:id', auth, needMongo, async (req, res) => {
  const p = await Provider.findOne({ _id: req.params.id, ownerId: req.user.sub });
  if (!p) return res.status(404).json({ error: 'No encontrado' });
  const { name, keyValidityHours, hwidLimit, enabled, linkType, adLink } = req.body || {};
  if (name) p.name = name.trim();
  if (keyValidityHours !== undefined) p.keyValidityHours = Math.max(1, Number(keyValidityHours) || 24);
  if (hwidLimit !== undefined) p.hwidLimit = Math.max(1, Math.min(10, Number(hwidLimit) || 1));
  if (enabled !== undefined) p.enabled = !!enabled;
  if (linkType && ['linkvertise','lootlabs','workink','custom','none'].includes(linkType)) p.linkType = linkType;
  if (adLink !== undefined) p.adLink = String(adLink || '').trim().slice(0, 500);
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


// ========== KEY GATE (GUI) + CLAIM (Linkvertise/Lootlabs/Work.ink) ==========
function buildKeyGateLua({ apiBase, providerName, getKeyLink, scriptCode }) {
  const api = String(apiBase || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const prov = String(providerName || 'Qrex').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const link = String(getKeyLink || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  // script as long string - escape for Lua long brackets
  let body = String(scriptCode || '');
  let eq = '';
  while (body.includes(']' + eq + ']')) eq += '=';
  const open = '[' + eq + '[';
  const close = ']' + eq + ']';

  return `-- QrexApi Key System
-- Protected by Voltils · https://discord.gg/f4HRYHTCnz
local HttpService = game:GetService("HttpService")
local TweenService = game:GetService("TweenService")
local UserInputService = game:GetService("UserInputService")
local CoreGui = game:GetService("CoreGui")
local Players = game:GetService("Players")
local Workspace = game:GetService("Workspace")
local SoundService = game:GetService("SoundService")

local _API = "${api}"
local _PROVIDER = "${prov}"
local _GETKEY = "${link}"
local _SCRIPT = ${open}${body}${close}

local function GetGuiParent()
  local hOk, hui = pcall(function() return gethui() end)
  if hOk and hui then return hui end
  local cOk = pcall(function() return CoreGui.Name end)
  if cOk then return CoreGui end
  local plr = Players.LocalPlayer
  if plr then
    local pg = plr:FindFirstChildOfClass("PlayerGui")
    if pg then return pg end
  end
  return CoreGui
end

local function getHwid()
  local ok, id = pcall(function()
    return game:GetService("RbxAnalyticsService"):GetClientId()
  end)
  if ok and id then return tostring(id) end
  local ok2, id2 = pcall(function() return game.JobId end)
  local uid = (Players.LocalPlayer and Players.LocalPlayer.UserId) or 0
  return tostring(uid) .. "-" .. tostring(ok2 and id2 or "0")
end

local function httpRequest(opts)
  local fn = (syn and syn.request) or (http and http.request) or http_request or request or (fluxus and fluxus.request)
  if type(fn) == "function" then return fn(opts) end
  error("No request function")
end

local QyrexAPI = {}
function QyrexAPI.GetKeyLink()
  return _GETKEY
end
function QyrexAPI.VerifyKey(key)
  key = tostring(key or ""):gsub("%s+", "")
  if key == "" then return false end
  local body = HttpService:JSONEncode({ key = key, hwid = getHwid(), provider = _PROVIDER })
  local ok, res = pcall(function()
    return httpRequest({
      Url = _API .. "/api/keys/verify",
      Method = "POST",
      Headers = { ["Content-Type"] = "application/json" },
      Body = body
    })
  end)
  if not ok or not res or not res.Body then return false end
  local ok2, data = pcall(function() return HttpService:JSONDecode(res.Body) end)
  return ok2 and data and data.success == true
end

local cfg = {
  title = "QyrexApi",
  keyFile = "QyrexApi_Key.txt",
  accentA = Color3.fromRGB(168, 85, 247),
  accentB = Color3.fromRGB(236, 72, 199),
  accentC = Color3.fromRGB(96, 200, 255),
}

local function saveKey(key)
  if writefile then pcall(writefile, cfg.keyFile, key) end
end
local function loadKey()
  if isfile and isfile(cfg.keyFile) then
    local ok, data = pcall(readfile, cfg.keyFile)
    if ok and data then return tostring(data) end
  end
  return ""
end

local function notify(kind, title, content)
  local colors = { Info = Color3.fromRGB(96,165,250), Success = Color3.fromRGB(52,211,153), Error = Color3.fromRGB(248,113,113) }
  local accent = colors[kind] or colors.Info
  local sg = Instance.new("ScreenGui")
  sg.Name = "QyrexApi_Notif"
  sg.ResetOnSpawn = false
  sg.DisplayOrder = 999999
  sg.Parent = GetGuiParent()
  local f = Instance.new("Frame")
  f.Size = UDim2.fromOffset(280, 58)
  f.Position = UDim2.new(1, -16, 1, -16)
  f.AnchorPoint = Vector2.new(1, 1)
  f.BackgroundColor3 = Color3.fromRGB(20, 18, 32)
  f.Parent = sg
  local c = Instance.new("UICorner"); c.CornerRadius = UDim.new(0, 10); c.Parent = f
  local st = Instance.new("UIStroke"); st.Color = accent; st.Thickness = 1.2; st.Parent = f
  local t = Instance.new("TextLabel")
  t.BackgroundTransparency = 1
  t.Position = UDim2.fromOffset(12, 8)
  t.Size = UDim2.new(1, -24, 0, 18)
  t.Font = Enum.Font.GothamBold
  t.TextSize = 13
  t.TextXAlignment = Enum.TextXAlignment.Left
  t.TextColor3 = Color3.fromRGB(240,240,245)
  t.Text = title
  t.Parent = f
  local d = Instance.new("TextLabel")
  d.BackgroundTransparency = 1
  d.Position = UDim2.fromOffset(12, 28)
  d.Size = UDim2.new(1, -24, 0, 22)
  d.Font = Enum.Font.Gotham
  d.TextSize = 11
  d.TextXAlignment = Enum.TextXAlignment.Left
  d.TextColor3 = Color3.fromRGB(170,168,182)
  d.Text = content
  d.Parent = f
  task.delay(3, function() if sg then sg:Destroy() end end)
end

local function runScript()
  local fn, err = loadstring(_SCRIPT)
  if type(fn) == "function" then
    local ok, e = pcall(fn)
    if not ok then warn("[QyrexApi] script error:", e) end
  else
    warn("[QyrexApi] load failed:", err)
  end
end

-- auto verify saved key
do
  local saved = loadKey()
  if saved ~= "" and QyrexAPI.VerifyKey(saved) then
    notify("Success", "Welcome", "Key valida · cargando script")
    task.wait(0.2)
    runScript()
    return
  end
end

local Screen = Instance.new("ScreenGui")
Screen.Name = "QyrexApi_KeySystem"
Screen.ResetOnSpawn = false
Screen.IgnoreGuiInset = true
Screen.Parent = GetGuiParent()

local Main = Instance.new("Frame")
Main.Size = UDim2.fromOffset(380, 340)
Main.Position = UDim2.fromScale(0.5, 0.5)
Main.AnchorPoint = Vector2.new(0.5, 0.5)
Main.BackgroundColor3 = Color3.fromRGB(6, 5, 10)
Main.BackgroundTransparency = 0.05
Main.Parent = Screen
local mc = Instance.new("UICorner"); mc.CornerRadius = UDim.new(0, 20); mc.Parent = Main
local ms = Instance.new("UIStroke"); ms.Thickness = 1.4; ms.Color = cfg.accentA; ms.Parent = Main

local Titlebar = Instance.new("Frame")
Titlebar.Size = UDim2.new(1, 0, 0, 36)
Titlebar.BackgroundColor3 = Color3.fromRGB(11, 9, 17)
Titlebar.BackgroundTransparency = 0.35
Titlebar.Parent = Main
local Title = Instance.new("TextLabel")
Title.BackgroundTransparency = 1
Title.Position = UDim2.fromOffset(14, 0)
Title.Size = UDim2.new(1, -50, 1, 0)
Title.Font = Enum.Font.GothamBold
Title.TextSize = 13
Title.TextXAlignment = Enum.TextXAlignment.Left
Title.TextColor3 = Color3.fromRGB(205, 200, 218)
Title.Text = "QyrexApi KeySystem"
Title.Parent = Titlebar

local CloseBtn = Instance.new("TextButton")
CloseBtn.Size = UDim2.fromOffset(24, 24)
CloseBtn.Position = UDim2.new(1, -30, 0.5, -12)
CloseBtn.BackgroundColor3 = Color3.fromRGB(18, 14, 28)
CloseBtn.Text = "X"
CloseBtn.TextColor3 = Color3.fromRGB(200, 190, 210)
CloseBtn.Font = Enum.Font.GothamBold
CloseBtn.TextSize = 12
CloseBtn.Parent = Titlebar
local cc = Instance.new("UICorner"); cc.CornerRadius = UDim.new(1, 0); cc.Parent = CloseBtn
CloseBtn.MouseButton1Click:Connect(function() Screen:Destroy() end)

local Head = Instance.new("TextLabel")
Head.BackgroundTransparency = 1
Head.Position = UDim2.fromOffset(16, 150)
Head.Size = UDim2.new(1, -32, 0, 22)
Head.Font = Enum.Font.GothamBold
Head.TextSize = 16
Head.TextColor3 = Color3.fromRGB(244, 242, 250)
Head.Text = "Verificacion de acceso"
Head.Parent = Main

local Sub = Instance.new("TextLabel")
Sub.BackgroundTransparency = 1
Sub.Position = UDim2.fromOffset(16, 172)
Sub.Size = UDim2.new(1, -32, 0, 16)
Sub.Font = Enum.Font.Gotham
Sub.TextSize = 12
Sub.TextColor3 = Color3.fromRGB(150, 145, 165)
Sub.Text = "Ingresa tu key para continuar"
Sub.Parent = Main

local InputFrame = Instance.new("Frame")
InputFrame.Size = UDim2.new(1, -32, 0, 44)
InputFrame.Position = UDim2.fromOffset(16, 200)
InputFrame.BackgroundColor3 = Color3.fromRGB(3, 2, 6)
InputFrame.Parent = Main
local ic = Instance.new("UICorner"); ic.CornerRadius = UDim.new(0, 10); ic.Parent = InputFrame
local ist = Instance.new("UIStroke"); ist.Color = cfg.accentA; ist.Thickness = 1.2; ist.Parent = InputFrame

local KeyBox = Instance.new("TextBox")
KeyBox.Size = UDim2.new(1, -20, 1, 0)
KeyBox.Position = UDim2.fromOffset(12, 0)
KeyBox.BackgroundTransparency = 1
KeyBox.Text = loadKey()
KeyBox.PlaceholderText = "00000000-0000-0000-0000-000000000000"
KeyBox.PlaceholderColor3 = Color3.fromRGB(100, 96, 118)
KeyBox.TextColor3 = Color3.fromRGB(232, 228, 244)
KeyBox.TextSize = 13
KeyBox.Font = Enum.Font.Code
KeyBox.TextXAlignment = Enum.TextXAlignment.Left
KeyBox.ClearTextOnFocus = false
KeyBox.Parent = InputFrame

local GetKeyBtn = Instance.new("TextButton")
GetKeyBtn.Size = UDim2.new(0.42, -5, 0, 42)
GetKeyBtn.Position = UDim2.fromOffset(16, 254)
GetKeyBtn.BackgroundColor3 = Color3.fromRGB(16, 13, 24)
GetKeyBtn.Text = "Get Key"
GetKeyBtn.TextColor3 = Color3.fromRGB(255,255,255)
GetKeyBtn.Font = Enum.Font.GothamBold
GetKeyBtn.TextSize = 13
GetKeyBtn.Parent = Main
local gk = Instance.new("UICorner"); gk.CornerRadius = UDim.new(0, 10); gk.Parent = GetKeyBtn
local gks = Instance.new("UIStroke"); gks.Color = cfg.accentC; gks.Parent = GetKeyBtn

local VerifyBtn = Instance.new("TextButton")
VerifyBtn.Size = UDim2.new(0.58, -5, 0, 42)
VerifyBtn.Position = UDim2.new(0.42, 21, 0, 254)
VerifyBtn.BackgroundColor3 = Color3.fromRGB(88, 40, 160)
VerifyBtn.Text = "Verify"
VerifyBtn.TextColor3 = Color3.fromRGB(255,255,255)
VerifyBtn.Font = Enum.Font.GothamBold
VerifyBtn.TextSize = 13
VerifyBtn.Parent = Main
local vk = Instance.new("UICorner"); vk.CornerRadius = UDim.new(0, 10); vk.Parent = VerifyBtn

local Hint = Instance.new("TextLabel")
Hint.BackgroundTransparency = 1
Hint.Position = UDim2.fromOffset(16, 308)
Hint.Size = UDim2.new(1, -32, 0, 18)
Hint.Font = Enum.Font.Gotham
Hint.TextSize = 10
Hint.TextColor3 = Color3.fromRGB(110, 105, 128)
Hint.Text = "La key se guarda localmente · QrexApi"
Hint.Parent = Main

GetKeyBtn.MouseButton1Click:Connect(function()
  local link = QyrexAPI.GetKeyLink()
  if not link or link == "" then
    notify("Error", "No configurado", "El owner no puso link de key")
    return
  end
  notify("Info", "Getting Key...", "Abriendo link de key")
  if setclipboard then pcall(setclipboard, link) end
  local opened = false
  if typeof(open_browser) == "function" then pcall(open_browser, link); opened = true end
  if not opened and typeof(request) == "function" then
    -- algunos executors
  end
  notify("Success", "Link listo", "Link copiado. Completa el checkpoint y pega tu key.")
end)

local verifying = false
local function doVerify()
  if verifying then return end
  local key = KeyBox.Text:gsub("%s+", "")
  if key == "" then notify("Error", "Key Required", "Ingresa una key"); return end
  verifying = true
  notify("Info", "Checking...", "Validando key")
  task.spawn(function()
    local ok = QyrexAPI.VerifyKey(key)
    verifying = false
    if ok then
      saveKey(key)
      notify("Success", "Success!", "Key verificada")
      Screen:Destroy()
      task.wait(0.15)
      runScript()
    else
      notify("Error", "Invalid Key", "Key incorrecta o expirada")
    end
  end)
end
VerifyBtn.MouseButton1Click:Connect(doVerify)
KeyBox.FocusLost:Connect(function(enter) if enter then doVerify() end end)

-- drag
do
  local dragging, start, pos
  Titlebar.InputBegan:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
      dragging = true; start = input.Position; pos = Main.Position
    end
  end)
  UserInputService.InputChanged:Connect(function(input)
    if dragging and (input.UserInputType == Enum.UserInputType.MouseMovement or input.UserInputType == Enum.UserInputType.Touch) then
      local d = input.Position - start
      Main.Position = UDim2.new(pos.X.Scale, pos.X.Offset + d.X, pos.Y.Scale, pos.Y.Offset + d.Y)
    end
  end)
  UserInputService.InputEnded:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then dragging = false end
  end)
end
`;
}

function claimPageHtml(key, providerName, hours) {
  const k = String(key).replace(/</g, '');
  const p = String(providerName || 'Qrex').replace(/</g, '');
  return `<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Tu Key · QrexApi</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0a0a0f;font-family:Inter,system-ui,sans-serif;color:#e8e8f0;padding:16px}
.card{background:#12121c;border:1px solid #2a2a3d;border-radius:18px;padding:28px;max-width:480px;width:100%;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.badge{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.08em;color:#a78bfa;background:rgba(124,58,237,.15);border:1px solid rgba(124,58,237,.35);padding:4px 10px;border-radius:999px;margin-bottom:12px}
h1{font-size:20px;margin:0 0 8px}p{color:#8b8b9e;font-size:13px;line-height:1.5}
.keybox{margin-top:16px;background:#0c0c14;border:1px solid #2a2a3d;border-radius:12px;padding:14px;font-family:ui-monospace,monospace;font-size:13px;word-break:break-all;color:#c4b5fd}
button{margin-top:14px;width:100%;border:0;border-radius:12px;padding:12px;font-weight:700;background:linear-gradient(135deg,#7c3aed,#6d28d9);color:#fff;cursor:pointer}
.meta{margin-top:12px;font-size:11px;color:#5a5a6e}
</style></head><body><div class="card">
<div class="badge">QYREXAPI KEY</div>
<h1>Key generada</h1>
<p>Provider: <b style="color:#ddd">${p}</b>. Copia la key y pégala en el KeySystem del script.</p>
<div class="keybox" id="k">${k}</div>
<button onclick="navigator.clipboard.writeText(document.getElementById('k').innerText);this.textContent='¡Copiada!'">Copiar key</button>
<div class="meta">Protected by <b style="color:#c4b5fd">Voltils</b> · <a href="https://discord.gg/f4HRYHTCnz" style="color:#a78bfa">Discord</a></div>
<div class="meta">Validez aprox: ${hours || 24}h · cada visita genera una key unica</div>
</div></body></html>`;
}

app.get('/getkey/:providerId', needMongo, async (req, res) => {
  try {
    const prov = await Provider.findById(req.params.providerId);
    if (!prov || !prov.enabled) return res.status(404).type('html').send('<h1>Provider no encontrado</h1>');
    const ip = clientIp(req);
    // rate: max 5 keys / 10 min per IP+provider
    if (!global.__claimHits) global.__claimHits = new Map();
    const ck = ip + ':' + prov._id;
    const now = Date.now();
    let e = global.__claimHits.get(ck);
    if (!e || now - e.t > 10 * 60 * 1000) e = { n: 0, t: now };
    e.n++;
    global.__claimHits.set(ck, e);
    if (e.n > 8) return res.status(429).type('html').send('<h1>Demasiadas keys. Espera unos minutos.</h1>');

    const hours = prov.keyValidityHours || 24;
    let expiresAt = null;
    if (hours > 0) {
      expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + hours);
    }
    const doc = await LicenseKey.create({
      key: genKey(),
      providerId: String(prov._id),
      providerName: prov.name,
      ownerId: prov.ownerId,
      hwidLimit: prov.hwidLimit || 1,
      expiresAt,
      note: 'claimed:' + String(ip).split(',')[0]
    });
    res.type('html').send(claimPageHtml(doc.key, prov.name, hours));
  } catch (e) {
    console.error(e);
    res.status(500).type('html').send('<h1>Error generando key</h1>');
  }
});

app.get('/api/keys/claim-info/:providerId', needMongo, async (req, res) => {
  const prov = await Provider.findById(req.params.providerId).lean();
  if (!prov) return res.status(404).json({ error: 'No encontrado' });
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const claimUrl = proto + '://' + host + '/getkey/' + prov._id;
  res.json({
    providerId: prov._id,
    name: prov.name,
    linkType: prov.linkType || 'custom',
    adLink: prov.adLink || '',
    claimUrl,
    tip: 'Pon claimUrl como destino final de Linkvertise / Lootlabs / Work.ink'
  });
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
      return res.status(503).json({ error: 'OPENROUTER_API_KEY no configurada en Render Environment' });
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


app.get('/api/env-logger', (req, res) => {
  res.type('text/plain').send(ENV_GATE_LUA);
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
  console.log('MONGO_URI set:', !!MONGO_URI);
});
