const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');

const app = express();
app.set('trust proxy', 1);

const JWT_SECRET = process.env.JWT_SECRET || 'cambia-este-secret-por-uno-largo';
const MONGO_URI = process.env.MONGO_URI || '';
const OBFUSCATOR_URL = process.env.OBFUSCATOR_URL || 'https://qyrexobf.onrender.com/api/obfuscate';

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

if (MONGO_URI) {
  mongoose.connect(MONGO_URI).catch(err => console.error('Mongo error:', err.message));
}

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
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const test = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(test, 'hex'));
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
  res.json({ ok: true, service: 'QrexApi' });
});

// ========== AUTH: registro y login con usuario/contraseña ==========

app.post('/api/auth/register', async (req, res) => {
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
    res.status(500).json({ error: 'Error al registrar' });
  }
});

app.post('/api/auth/login', async (req, res) => {
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
    res.status(500).json({ error: 'Error al iniciar sesion' });
  }
});

app.get('/api/me', auth, async (req, res) => {
  const user = await User.findById(req.user.sub).lean();
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.json({
    id: user._id,
    username: user.username
  });
});

// ========== SCRIPTS ==========

app.get('/api/scripts', auth, async (req, res) => {
  const list = await Script.find({ ownerId: req.user.sub })
    .sort({ createdAt: -1 })
    .select('-source -obfuscated');
  res.json(list);
});

app.get('/api/scripts/:id', auth, async (req, res) => {
  const s = await Script.findOne({ id: req.params.id, ownerId: req.user.sub });
  if (!s) return res.status(404).json({ error: 'No encontrado' });
  res.json(s);
});

app.post('/api/scripts', auth, async (req, res) => {
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

app.put('/api/scripts/:id', auth, async (req, res) => {
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

app.delete('/api/scripts/:id', auth, async (req, res) => {
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
    return res.status(403).type('html').send('<!doctype html><title>403</title><h1>Forbidden</h1><p>Roblox only</p>');
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

app.get('/api/stats', auth, async (req, res) => {
  const scripts = await Script.find({ ownerId: req.user.sub });
  const totalExec = scripts.reduce((a, s) => a + (s.executions || 0), 0);
  res.json({ scripts: scripts.length, executions: totalExec });
});

app.get('/api/executions', auth, async (req, res) => {
  const logs = await Execution.find({ ownerId: req.user.sub }).sort({ createdAt: -1 }).limit(100);
  res.json(logs);
});

module.exports = app;
