// MediStock Pro API: shared data, login, and user management (Upstash Redis).
const crypto = require('crypto');
const U = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const T = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const SEC = () => process.env.APP_PASSWORD;
const rd = async (c) => (await fetch(U, { method: 'POST', headers: { Authorization: 'Bearer ' + T }, body: JSON.stringify(c) })).json();
const get = async (k) => { const o = await rd(['GET', k]); return o.result ? JSON.parse(o.result) : null; };
const set = (k, v) => rd(['SET', k, JSON.stringify(v)]);
const mac = (b) => crypto.createHmac('sha256', SEC()).update(b).digest('base64url');
const sign = (p) => { const b = Buffer.from(JSON.stringify(p)).toString('base64url'); return b + '.' + mac(b); };
const verify = (t) => {
  try { const [b, s] = (t || '').split('.'); if (!b || s !== mac(b)) return null;
    const p = JSON.parse(Buffer.from(b, 'base64url').toString()); return p.e > Date.now() ? p : null; } catch (e) { return null; }
};
const hash = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');

module.exports = async (req, res) => {
  if (!SEC() || !U || !T) return res.status(500).json({ error: 'Server not configured' });
  const a = req.query.a || 'data', body = req.body || {};

  if (a === 'login' && req.method === 'POST') {
    const u = String(body.u || '').trim().toLowerCase(), p = String(body.p || '');
    let me = null;
    if (u === 'admin' && p === SEC()) me = { u: 'admin', n: 'Admin', r: 'admin' };
    else { const x = (await get('ms_users') || {})[u]; if (x && hash(p, x.s) === x.h) me = { u, n: x.n, r: x.r || 'staff' }; }
    if (!me) return res.status(401).json({ error: 'auth' });
    return res.status(200).json({ ...me, token: sign({ ...me, e: Date.now() + 7 * 864e5 }) });
  }

  const me = verify((req.headers.authorization || '').replace('Bearer ', ''));
  if (!me) return res.status(401).json({ error: 'auth' });

  if (a === 'data') {
    if (req.method === 'GET') return res.status(200).json(await get('medistock'));
    if (req.method === 'POST') { await set('medistock', body); return res.status(200).json({ ok: true }); }
  }

  if (a === 'users') {
    if (me.r !== 'admin') return res.status(403).json({ error: 'forbidden' });
    const us = (await get('ms_users')) || {};
    if (req.method === 'GET') return res.status(200).json(Object.keys(us).map((u) => ({ u, n: us[u].n, r: us[u].r })));
    if (req.method === 'POST') {
      const u = String(body.u || '').trim().toLowerCase(), n = String(body.n || '').trim().slice(0, 60), p = String(body.p || '');
      if (!/^[a-z0-9._-]{2,30}$/.test(u) || u === 'admin' || !n || p.length < 6) return res.status(400).json({ error: 'invalid' });
      const s = crypto.randomBytes(8).toString('hex');
      us[u] = { n, s, h: hash(p, s), r: body.r === 'admin' ? 'admin' : 'staff' };
      await set('ms_users', us); return res.status(200).json({ ok: true });
    }
    if (req.method === 'DELETE') { delete us[String(req.query.u || '')]; await set('ms_users', us); return res.status(200).json({ ok: true }); }
  }
  res.status(405).end();
};
