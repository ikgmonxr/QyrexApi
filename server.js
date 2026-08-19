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
const OBFUSCATOR_URL = process.env.OBFUSCATOR_URL || 'https://qyrexobf.onrender.com/api/obfuscate';
const PORT = process.env.PORT || 3000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

app.use(async (req, res, next) => {
  try {
    if (!req.path.startsWith('/api')) return next();
    const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').split(',')[0].trim();
    if (!ip || mongoose.connection.readyState !== 1) return next();
    const Model = mongoose.models.QrexBlacklistIP;
    if (!Model) return next();
    const banned = await Model.findOne({ ip }).lean();
    if (banned) return res.status(403).json({ error: 'IP bloqueada' });
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

    const obfuscated = await obfuscateWithQyrex(source);
    const doc = await Script.create({
      ownerId: req.user.sub,
      name,
      description: description || '',
      source,
      obfuscated,
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
    if (source) {
      s.source = source;
      s.obfuscated = await obfuscateWithQyrex(source);
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

app.get('/api/raw/:id', async (req, res) => {
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
    return res.status(503).type('text/plain').send('-- db offline');
  }

  const s = await Script.findOne({ id: req.params.id });
  if (!s) return res.status(404).type('text/plain').send('-- not found');

  s.executions += 1;
  await s.save();

  const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '?';
  await Execution.create({
    scriptId: s.id,
    scriptName: s.name,
    ownerId: s.ownerId,
    ip,
    userAgent: req.headers['user-agent'] || ''
  });

  fireWebhooks(s.ownerId, 'script_exec', { scriptId: s.id, name: s.name, ip: String(ip).split(',')[0] });

  res.setHeader('Cache-Control', 'no-store');
  res.type('text/plain').send(s.obfuscated);
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
app.post('/api/keys/verify', needMongo, async (req, res) => {
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

app.listen(PORT, () => {
  console.log('QrexApi listening on port', PORT);
  console.log('MONGO_URI set:', !!MONGO_URI);
});
