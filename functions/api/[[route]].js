// Máy chủ dữ liệu cho Công cụ Quản lý KH & CN (Cloudflare Pages Functions + D1).
// Chỉ lưu dữ liệu ĐÃ MÃ HÓA từ trình duyệt; máy chủ không có khóa giải mã.
// Mọi yêu cầu phải có vé đăng nhập Cloudflare Access hợp lệ (kiểm tra chữ ký JWT),
// thiếu cấu hình thì từ chối tất cả (fail closed).
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
const b64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0));
let JWKS = null, JWKS_AT = 0;
// TEAM_DOMAIN chấp nhận: 'ten-nhom', 'ten-nhom.cloudflareaccess.com' hoặc URL đầy đủ.
const teamBase = env => { let t = String(env.TEAM_DOMAIN).trim().replace(/\/$/, ''); if (/^https?:\/\//.test(t)) return t; if (!t.includes('.')) t += '.cloudflareaccess.com'; return 'https://' + t; };
async function keys(env) {
  if (JWKS && Date.now() - JWKS_AT < 3600e3) return JWKS;
  const base = teamBase(env);
  const r = await fetch(base.replace(/\/$/, '') + '/cdn-cgi/access/certs');
  if (!r.ok) throw new Error('certs ' + r.status);
  JWKS = (await r.json()).keys || []; JWKS_AT = Date.now(); return JWKS;
}
async function auth(req, env) {
  if (!env.DB) return 'Chưa gắn kho dữ liệu D1 (biến DB).';
  if (!env.TEAM_DOMAIN || !env.ALLOWED_EMAIL) return 'Chưa cấu hình bảo mật (TEAM_DOMAIN, ALLOWED_EMAIL).';
  const tok = req.headers.get('cf-access-jwt-assertion');
  if (!tok) return 'Chưa đăng nhập.';
  const [h, p, s] = tok.split('.');
  if (!h || !p || !s) return 'Vé đăng nhập không hợp lệ.';
  let H, P;
  try { H = JSON.parse(new TextDecoder().decode(b64u(h))); P = JSON.parse(new TextDecoder().decode(b64u(p))); } catch (e) { return 'Vé đăng nhập không hợp lệ.'; }
  if (H.alg !== 'RS256') return 'Vé đăng nhập không hợp lệ.';
  let ks = await keys(env); let k = ks.find(x => x.kid === H.kid);
  if (!k) { JWKS = null; ks = await keys(env); k = ks.find(x => x.kid === H.kid); }
  if (!k) return 'Vé đăng nhập không hợp lệ.';
  const key = await crypto.subtle.importKey('jwk', k, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64u(s), new TextEncoder().encode(h + '.' + p));
  if (!ok) return 'Vé đăng nhập không hợp lệ.';
  const now = Math.floor(Date.now() / 1000);
  if (!P.exp || P.exp < now - 30 || (P.nbf && P.nbf > now + 30)) return 'Phiên đăng nhập đã hết hạn.';
  if (env.POLICY_AUD) { const aud = Array.isArray(P.aud) ? P.aud : [P.aud]; if (!aud.includes(env.POLICY_AUD.trim())) return 'Vé đăng nhập không dành cho trang này.'; }
  if (P.iss && String(P.iss).replace(/\/$/, '') !== teamBase(env).replace(/\/$/, '')) return 'Vé đăng nhập không do nhóm của anh cấp.';
  const allowed = env.ALLOWED_EMAIL.toLowerCase().split(',').map(x => x.trim()).filter(Boolean);
  if (!allowed.includes(String(P.email || '').toLowerCase())) return 'Email này không được phép.';
  return null;
}
const SCHEMA = ['CREATE TABLE IF NOT EXISTS docs (p TEXT PRIMARY KEY, d TEXT NOT NULL, t INTEGER NOT NULL)', 'CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)'];
let schemaOk = false;
async function schema(db) { if (schemaOk) return; await db.batch(SCHEMA.map(s => db.prepare(s))); schemaOk = true; }
async function rev(db) { const r = await db.prepare("SELECT v FROM kv WHERE k='rev'").first(); return r ? +r.v : 0; }
const merge = (a, b) => { for (const k in b) { if (b[k] && typeof b[k] === 'object' && !Array.isArray(b[k]) && a[k] && typeof a[k] === 'object') merge(a[k], b[k]); else a[k] = b[k]; } return a; };
const okPath = p => typeof p === 'string' && p.length > 0 && p.length < 300 && /^[A-Za-z0-9_\-.]+(\/[A-Za-z0-9_\-.]+)*$/.test(p);
export async function onRequest({ request, env, params }) {
  let why;
  try { why = await auth(request, env); } catch (e) { return J({ error: 'auth_unavailable', message: 'Không kiểm tra được đăng nhập: ' + e.message }, 503); }
  if (why) return J({ error: 'unauthorized', message: why }, 401);
  const db = env.DB; await schema(db);
  const route = (params.route || []).join('/');
  if (request.method === 'GET' && route === 'rev') return J({ rev: await rev(db) });
  if (request.method === 'GET' && route === 'all') {
    const r = await db.prepare('SELECT p, d FROM docs').all(); const docs = {};
    for (const x of r.results || []) docs[x.p] = JSON.parse(x.d);
    return J({ rev: await rev(db), docs });
  }
  if (request.method === 'POST' && route === 'ops') {
    let body; try { body = await request.json(); } catch (e) { return J({ error: 'bad_request' }, 400); }
    const ops = body.ops;
    if (!Array.isArray(ops) || ops.length > 500) return J({ error: 'bad_request' }, 400);
    // Phát hiện xung đột: máy khác đã ghi sau lần đồng bộ gần nhất của máy này.
    if (typeof body.base === 'number' && !body.force) {
      const cur = await rev(db);
      if (cur !== body.base) {
        const ch = await db.prepare('SELECT p FROM docs WHERE t > ?').bind(body.base).all();
        return J({ error: 'conflict', rev: cur, changed: (ch.results || []).map(x => x.p) }, 409);
      }
    }
    const now = Math.max(Date.now(), (await rev(db)) + 1); const st = [];
    const cache = new Map();
    for (const o of ops) {
      if (!o || !okPath(o.p) || !['set', 'update', 'delete'].includes(o.op)) return J({ error: 'bad_request', message: 'op' }, 400);
      if (o.op === 'delete') { cache.set(o.p, null); st.push(db.prepare('DELETE FROM docs WHERE p=?').bind(o.p)); continue; }
      let d = o.d;
      if (o.op === 'update') {
        let cur = cache.has(o.p) ? cache.get(o.p) : undefined;
        if (cur === undefined) { const r = await db.prepare('SELECT d FROM docs WHERE p=?').bind(o.p).first(); cur = r ? JSON.parse(r.d) : null; }
        d = merge(cur || {}, d || {});
      }
      cache.set(o.p, d);
      const s = JSON.stringify(d);
      if (s.length > 1900000) return J({ error: 'too_large', message: o.p }, 413);
      st.push(db.prepare('INSERT INTO docs (p, d, t) VALUES (?, ?, ?) ON CONFLICT(p) DO UPDATE SET d=excluded.d, t=excluded.t').bind(o.p, s, now));
    }
    st.push(db.prepare("INSERT INTO kv (k, v) VALUES ('rev', ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(String(now)));
    await db.batch(st);
    return J({ ok: true, rev: now });
  }
  return J({ error: 'not_found' }, 404);
}
