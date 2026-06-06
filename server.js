const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Load .env if present (no extra dependency)
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf8').split('\n').forEach(line => {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)?\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = (m[2] || '').replace(/^["']|["']$/g, '');
  });
}

const app = express();
const DATA_FILE = path.join(__dirname, 'data', 'notes.json');
const LOCAL_MITRE = path.join(__dirname, 'data', 'enterprise-attack.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

const AUTH_USER = process.env.AUTH_USER || 'NINJAS';
const AUTH_PASSWORD = process.env.AUTH_PASSWORD || 'NINJAS';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

if (!process.env.AUTH_PASSWORD) {
  console.warn('[auth] AUTH_PASSWORD not set — using default "NINJAS". Set AUTH_PASSWORD in .env before deploying');
}

const sessions = new Map();

app.use(express.json());

if (!fs.existsSync(path.join(__dirname, 'data'))) fs.mkdirSync(path.join(__dirname, 'data'));
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '{}');

const read  = () => JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
const write = (d) => fs.writeFileSync(DATA_FILE, JSON.stringify(d, null, 2));

// ── Auth helpers ───────────────────────────────────────────────────────
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i === -1) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}

function signSessionId(id) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(id).digest('hex');
}

function createSession(username) {
  const id = crypto.randomBytes(32).toString('hex');
  sessions.set(id, { username, createdAt: Date.now(), lastSeen: Date.now() });
  return `${id}.${signSessionId(id)}`;
}

function getSession(req) {
  const token = parseCookies(req).sid;
  if (!token) return null;
  const dot = token.lastIndexOf('.');
  if (dot === -1) return null;
  const id = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!id || sig !== signSessionId(id)) return null;
  const session = sessions.get(id);
  if (!session) return null;
  if (Date.now() - session.createdAt > SESSION_TTL_MS) {
    sessions.delete(id);
    return null;
  }
  session.lastSeen = Date.now();
  return session;
}

function setSessionCookie(res, token) {
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  res.setHeader('Set-Cookie', `sid=${encodeURIComponent(token)}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=Strict`);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict');
}

function destroySession(req) {
  const token = parseCookies(req).sid;
  if (!token) return;
  const dot = token.lastIndexOf('.');
  if (dot !== -1) sessions.delete(token.slice(0, dot));
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function requireAuth(req, res, next) {
  if (getSession(req)) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  return res.redirect('/login');
}

// Purge expired sessions hourly
setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (now - s.createdAt > SESSION_TTL_MS) sessions.delete(id);
  }
}, 60 * 60 * 1000).unref();

// ── Auth routes (public) ───────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!safeEqual(username || '', AUTH_USER) || !safeEqual(password || '', AUTH_PASSWORD)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  const token = createSession(username);
  setSessionCookie(res, token);
  res.json({ ok: true, username });
});

app.post('/api/auth/logout', (req, res) => {
  destroySession(req);
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: 'Unauthorized' });
  res.json({ username: session.username });
});

app.get('/login', (req, res) => {
  if (getSession(req)) return res.redirect('/');
  res.sendFile(path.join(PUBLIC_DIR, 'login.html'));
});

// ── Protected app ──────────────────────────────────────────────────────
app.get('/', requireAuth, (_, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.use(requireAuth);

// ── Official MITRE tactic order ────────────────────────────────────────
const TACTIC_ORDER = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'stealth',
  'defense-impairment',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
];

// ── Notes ──────────────────────────────────────────────────────────────
app.get('/api/notes',        (_, res) => res.json(read()));
app.put('/api/notes/:id',    (req, res) => {
  const notes = read();
  notes[req.params.id] = { ...req.body, updatedAt: new Date().toISOString() };
  write(notes);
  res.json(notes[req.params.id]);
});
app.delete('/api/notes',     (_, res) => { write({}); res.json({ ok: true }); });

// ── MITRE cache ────────────────────────────────────────────────────────
let mitreCache  = null;
let rawObjects  = null;

function ensureCache() {
  if (mitreCache) return true;
  if (!fs.existsSync(LOCAL_MITRE)) return false;
  const raw = JSON.parse(fs.readFileSync(LOCAL_MITRE, 'utf8'));
  rawObjects  = raw.objects;
  mitreCache  = { data: parseMitre(raw), source: 'local' };
  return true;
}

function parseMitre(raw) {
  const tactics = {};

  raw.objects.forEach(o => {
    if (o.type === 'x-mitre-tactic') {
      const id = o.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id;
      tactics[o.x_mitre_shortname] = {
        id,
        name: o.name,
        shortName: o.x_mitre_shortname,
        techniques: [],
      };
    }
  });

  raw.objects.forEach(o => {
    if (o.type === 'attack-pattern' && !o.x_mitre_deprecated && !o.revoked) {
      const id = o.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id;
      if (!id) return;
      const isSub = id.includes('.');
      o.kill_chain_phases?.forEach(kc => {
        if (tactics[kc.phase_name]) {
          tactics[kc.phase_name].techniques.push({ id, name: o.name, isSub });
        }
      });
    }
  });

  Object.values(tactics).forEach(tac => {
    tac.techniques.sort((a, b) => {
      const parentCmp = a.id.split('.')[0].localeCompare(b.id.split('.')[0]);
      if (parentCmp !== 0) return parentCmp;
      if (a.isSub !== b.isSub) return a.isSub ? 1 : -1;
      return a.id.localeCompare(b.id);
    });
  });

  return Object.values(tactics).sort((a, b) => {
    const ai = TACTIC_ORDER.indexOf(a.shortName);
    const bi = TACTIC_ORDER.indexOf(b.shortName);
    return (ai === -1 ? Infinity : ai) - (bi === -1 ? Infinity : bi);
  });
}

app.get('/api/mitre', (_, res) => {
  try {
    if (!ensureCache()) return res.status(503).json({ error: 'enterprise-attack.json not found in data/' });
    res.json(mitreCache);
  } catch (e) {
    res.status(500).json({ error: 'Failed to parse enterprise-attack.json', detail: e.message });
  }
});

app.get('/api/mitre/:id', (req, res) => {
  try {
    if (!ensureCache()) return res.status(503).json({ error: 'enterprise-attack.json not found in data/' });

    const techId = req.params.id.toUpperCase();

    const obj = rawObjects.find(o => {
      if (o.type !== 'attack-pattern' || o.x_mitre_deprecated || o.revoked) return false;
      const extId = o.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id;
      return extId === techId;
    });

    if (!obj) return res.status(404).json({ error: `Technique ${techId} not found` });

    const extRef = obj.external_references?.find(r => r.source_name === 'mitre-attack');
    const url    = extRef?.url ?? null;

    const subs = rawObjects
      .filter(o => {
        if (o.type !== 'attack-pattern' || o.x_mitre_deprecated || o.revoked) return false;
        const subId = o.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id;
        return subId?.startsWith(techId + '.');
      })
      .map(o => {
        const subRef = o.external_references?.find(r => r.source_name === 'mitre-attack');
        return { id: subRef?.external_id, name: o.name, url: subRef?.url ?? null };
      })
      .sort((a, b) => a.id.localeCompare(b.id));

    const isSub = techId.includes('.');
    let parentTechnique = null;
    if (isSub) {
      const parentId = techId.split('.')[0];
      const parentObj = rawObjects.find(o => {
        if (o.type !== 'attack-pattern' || o.x_mitre_deprecated || o.revoked) return false;
        const extId = o.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id;
        return extId === parentId;
      });
      if (parentObj) parentTechnique = { id: parentId, name: parentObj.name };
    }

    res.json({
      id: techId,
      name: obj.name,
      description: obj.description ?? '',
      url,
      platforms: obj.x_mitre_platforms ?? [],
      isSub,
      parentTechnique,
      subTechniques: isSub ? [] : subs,
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to retrieve technique detail', detail: e.message });
  }
});

app.listen(8002, () => console.log('http://localhost:8002'));
