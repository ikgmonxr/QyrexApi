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
  createdAt: { type: Date, default: Date.now }
}));

const Script = mongoose.models.QrexScript || mongoose.model('QrexScript', new mongoose.Schema({
  id: { type: String, default: () => crypto.randomBytes(12).toString('hex') },
  ownerId: String,
  name: String,
  description: { type: String, default: '' },
  source: String,
  obfuscated: String,
  executions: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
}));

const Execution = mongoose.models.QrexExecution || mongoose.model('QrexExecution', new mongoose.Schema({
  scriptId: String,
  scriptName: String,
  ownerId: String,
  ip: String,
  userAgent: String,
  createdAt: { type: Date, default: Date.now }
}));

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

    const doc = await User.create({
      username: user,
      passwordHash: hashPassword(pass)
    });

    const token = signToken(doc);
    res.json({
      token,
      user: { id: doc._id, username: doc.username }
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

    const token = signToken(doc);
    res.json({
      token,
      user: { id: doc._id, username: doc.username }
    });
  } catch (e) {
    console.error('login', e);
    res.status(500).json({ error: 'Error al iniciar sesion: ' + (e.message || 'desconocido') });
  }
});

app.get('/api/me', auth, needMongo, async (req, res) => {
  const user = await User.findById(req.user.sub).lean();
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.json({ id: user._id, username: user.username });
});

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
    const { name, description, source } = req.body || {};
    if (!name || !source) return res.status(400).json({ error: 'name y source requeridos' });

    const obfuscated = await obfuscateWithQyrex(source);
    const doc = await Script.create({
      ownerId: req.user.sub,
      name,
      description: description || '',
      source,
      obfuscated
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
    const { name, description, source } = req.body || {};
    const s = await Script.findOne({ id: req.params.id, ownerId: req.user.sub });
    if (!s) return res.status(404).json({ error: 'No encontrado' });

    if (name) s.name = name;
    if (description !== undefined) s.description = description;
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

  await Execution.create({
    scriptId: s.id,
    scriptName: s.name,
    ownerId: s.ownerId,
    ip: req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '?',
    userAgent: req.headers['user-agent'] || ''
  });

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

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log('QrexApi listening on port', PORT);
  console.log('MONGO_URI set:', !!MONGO_URI);
});
