// MAX INTENSITY — AI relay server (Cloudflare Worker) v7
// Holds the Anthropic API key server-side and answers only to the Max Intensity app.
//
// Routes (all need the x-mi-app token):
//   POST /board, GET /board          community leaderboard (KV: BOARD)
//   POST /wall,  GET /wall           transformations & testimonials (KV: BOARD)
//   POST /event                      app analytics {name, props, sid} → stored in KV + logged
//   GET  /event                      last 100 events (needs a member code in x-mi-code)
//   GET  /push/key                   VAPID public key for PushManager.subscribe
//   POST /push/subscribe             {sid, subscription} → stored in KV
//   POST /nudge                      {sid, kind} → send a web-push nudge now
//   POST /                           Anthropic relay (system prompt is built by the app)
//   scheduled (cron)                 sends queued nudges when they fall due
//
// Secrets: ANTHROPIC_API_KEY, APP_TOKEN, VAPID_PRIVATE_KEY (wrangler secret put …)
// Vars:    ACCESS_CODES, VAPID_PUBLIC_KEY, VAPID_SUBJECT

// The app is served from maxintensity.app (GitHub Pages CNAME). The old github.io
// address still works, so both are allowed and the matching one is echoed back.
const ALLOWED_ORIGINS = [
  "https://maxintensity.app",
  "https://www.maxintensity.app",
  "https://maxmurray4026.github.io",
];
const ALLOWED_ORIGIN = ALLOWED_ORIGINS[0];
const MAX_TOKENS_CAP = 1200; // cost guard — no request can exceed this
const EVENT_TTL = 90 * 24 * 3600; // events live 90 days in KV
const NUDGE_DELAY_MS = 3 * 3600 * 1000; // "not going today" → nudge three hours later

// The nudges, in Max's voice. Keyed by the event name that queues them.
const NUDGES = {
  not_going_gym: {
    title: "Max Intensity",
    body: "Not going today? Alright. Then the next best move is half a session. Go in, do the work sets, leave. Half beats none.",
    tag: "not-going-gym",
    url: "https://maxintensity.app/",
  },
};
// Any of these event names queue the not-going nudge.
const NOT_GOING_EVENTS = ["not_going_gym", "not_going_today", "skip_gym", "skip_session"];

const json = (obj, status, headers) => new Response(JSON.stringify(obj), { status: status || 200, headers: { ...headers, "Content-Type": "application/json" } });

// ---------- base64url ----------
const b64u = {
  enc(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  dec(str) {
    let s = String(str || "").replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
};
const concat = (...parts) => {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const utf8 = (s) => new TextEncoder().encode(s);

// ---------- Web Push: VAPID (RFC 8292) ----------
async function vapidHeaders(env, endpoint) {
  const pub = b64u.dec(env.VAPID_PUBLIC_KEY || "");
  const priv = b64u.dec(env.VAPID_PRIVATE_KEY || "");
  if (pub.length !== 65 || priv.length !== 32) throw new Error("VAPID keys missing or malformed");
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", d: b64u.enc(priv), x: b64u.enc(pub.slice(1, 33)), y: b64u.enc(pub.slice(33, 65)), ext: true },
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"],
  );
  const aud = new URL(endpoint).origin;
  const header = b64u.enc(utf8(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const payload = b64u.enc(utf8(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: env.VAPID_SUBJECT || ALLOWED_ORIGIN })));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, utf8(header + "." + payload));
  const jwt = header + "." + payload + "." + b64u.enc(sig);
  return { Authorization: "vapid t=" + jwt + ", k=" + b64u.enc(pub) };
}

// ---------- Web Push: payload encryption (RFC 8291, aes128gcm) ----------
async function hkdf(salt, ikm, info, bits) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, bits));
}
async function encryptPayload(subscription, plaintext) {
  const uaPublic = b64u.dec(subscription.keys.p256dh);
  const authSecret = b64u.dec(subscription.keys.auth);
  if (uaPublic.length !== 65 || authSecret.length !== 16) throw new Error("bad subscription keys");
  const local = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", local.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, local.privateKey, 256));
  const ikm = await hkdf(authSecret, shared, concat(utf8("WebPush: info\0"), uaPublic, asPublic), 256);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, utf8("Content-Encoding: aes128gcm\0"), 128);
  const nonce = await hkdf(salt, ikm, utf8("Content-Encoding: nonce\0"), 96);
  const aesKey = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const padded = concat(utf8(plaintext), new Uint8Array([2])); // 0x02 = last record
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, padded));
  const rs = new Uint8Array(4); new DataView(rs.buffer).setUint32(0, 4096);
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, cipher);
}

// Send one push. Resolves { ok, status } — 404/410 means the subscription is dead.
async function sendPush(env, subscription, payload) {
  const auth = await vapidHeaders(env, subscription.endpoint);
  const body = await encryptPayload(subscription, JSON.stringify(payload));
  const res = await fetch(subscription.endpoint, {
    method: "POST",
    headers: { ...auth, "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: "86400", Urgency: "normal" },
    body,
  });
  return { ok: res.status >= 200 && res.status < 300, status: res.status, gone: res.status === 404 || res.status === 410 };
}

// Send a named nudge to one sid. Returns what happened so callers can report it.
async function sendNudge(env, sid, kind) {
  const nudge = NUDGES[kind] || NUDGES.not_going_gym;
  if (!env.BOARD) return { ok: false, error: "KV not set up" };
  let sub; try { sub = JSON.parse(await env.BOARD.get("p:" + sid)); } catch { sub = null; }
  if (!sub || !sub.endpoint) return { ok: false, error: "no subscription for sid" };
  try {
    const r = await sendPush(env, sub, { ...nudge, kind, sid });
    if (r.gone) await env.BOARD.delete("p:" + sid);
    console.log("nudge", kind, sid, r.status);
    return { ok: r.ok, status: r.status, gone: r.gone };
  } catch (e) {
    console.log("nudge failed", kind, sid, String(e));
    return { ok: false, error: String(e && e.message || e) };
  }
}

// Cron: send every queued nudge that has fallen due.
async function runDueNudges(env) {
  if (!env.BOARD) return { sent: 0 };
  const now = Date.now();
  const list = await env.BOARD.list({ prefix: "n:", limit: 500 });
  let sent = 0;
  for (const k of list.keys) {
    let q; try { q = JSON.parse(await env.BOARD.get(k.name)); } catch { q = null; }
    if (!q) { await env.BOARD.delete(k.name); continue; }
    if (q.due > now) continue;
    await env.BOARD.delete(k.name); // one shot, even if the send fails
    const r = await sendNudge(env, q.sid, q.kind);
    if (r.ok) sent++;
  }
  return { sent };
}

const cleanSid = (v) => String(v || "").replace(/[^A-Za-z0-9._:-]/g, "").slice(0, 64);

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runDueNudges(env));
  },

  async fetch(request, env, ctx) {
    const reqOrigin = (request.headers.get("Origin") || "").trim();
    const allowOrigin = ALLOWED_ORIGINS.includes(reqOrigin) ? reqOrigin : ALLOWED_ORIGINS[0];
    const cors = {
      "Access-Control-Allow-Origin": allowOrigin,
      Vary: "Origin",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, x-mi-app, x-mi-code, x-mi-usage, x-mi-tier, x-mi-feature",
      "Access-Control-Expose-Headers": "x-mi-member",
    };

    if (request.method === "OPTIONS") return new Response(null, { headers: cors });

    const url = new URL(request.url);
    const jh = { ...cors, "Content-Type": "application/json" };
    const tokenOk = () => {
      const tok = (request.headers.get("x-mi-app") || "").trim();
      const envTok = (env.APP_TOKEN || "").trim();
      return !!envTok && tok === envTok;
    };
    const validCodes = (env.ACCESS_CODES || "").split(",").map((c) => c.trim().toUpperCase()).filter(Boolean);
    const codeOk = () => { const c = (request.headers.get("x-mi-code") || "").trim().toUpperCase(); return !!c && validCodes.includes(c); };
    const readJSON = async () => { try { return await request.json(); } catch { return null; } };

    // ---------- Community leaderboard (KV binding: BOARD) ----------
    if (url.pathname === "/board") {
      if (!env.BOARD) return new Response(JSON.stringify({ error: "board not set up" }), { status: 503, headers: jh });
      const tok = (request.headers.get("x-mi-app") || "").trim();
      if (tok !== (env.APP_TOKEN || "").trim()) return new Response(JSON.stringify({ error: "no" }), { status: 401, headers: jh });

      if (request.method === "POST") {
        let b; try { b = await request.json(); } catch { return new Response(JSON.stringify({ error: "bad" }), { status: 400, headers: jh }); }
        const handle = String(b.handle || "").replace(/^@/, "").toLowerCase().trim();
        if (!/^[a-z0-9._]{2,30}$/.test(handle)) return new Response(JSON.stringify({ error: "bad handle" }), { status: 400, headers: jh });
        const entry = {
          handle,
          points: Math.max(0, Math.min(9999999, Number(b.points) || 0)),
          streak: Math.max(0, Math.min(9999, Number(b.streak) || 0)),
          gymDays: Math.max(0, Math.min(99999, Number(b.gymDays) || 0)),
          bestName: String(b.bestName || "").slice(0, 60),
          bestKg: Math.max(0, Math.min(2000, Number(b.bestKg) || 0)),
          at: Date.now(),
        };
        await env.BOARD.put("u:" + handle, JSON.stringify(entry));
        return new Response(JSON.stringify({ ok: true }), { headers: jh });
      }

      // GET: top 50 by points
      const list = await env.BOARD.list({ prefix: "u:", limit: 1000 });
      const rows = (await Promise.all(list.keys.map(async (k) => {
        try { return JSON.parse(await env.BOARD.get(k.name)); } catch { return null; }
      }))).filter(Boolean);
      rows.sort((a, b) => b.points - a.points);
      return new Response(JSON.stringify({ rows: rows.slice(0, 50) }), { headers: jh });
    }

    // ---------- The Wall: transformations & testimonials ----------
    if (url.pathname === "/wall") {
      if (!env.BOARD) return new Response(JSON.stringify({ error: "not set up" }), { status: 503, headers: jh });
      const tok = (request.headers.get("x-mi-app") || "").trim();
      if (tok !== (env.APP_TOKEN || "").trim()) return new Response(JSON.stringify({ error: "no" }), { status: 401, headers: jh });

      if (request.method === "POST") {
        let b; try { b = await request.json(); } catch { return new Response(JSON.stringify({ error: "bad" }), { status: 400, headers: jh }); }
        const handle = String(b.handle || "").replace(/^@/, "").toLowerCase().trim();
        const text = String(b.text || "").slice(0, 280).trim();
        if (!/^[a-z0-9._]{2,30}$/.test(handle) || text.length < 3) return new Response(JSON.stringify({ error: "bad post" }), { status: 400, headers: jh });
        await env.BOARD.put("t:" + Date.now() + ":" + handle, JSON.stringify({ handle, text, at: Date.now() }));
        return new Response(JSON.stringify({ ok: true }), { headers: jh });
      }

      const list = await env.BOARD.list({ prefix: "t:", limit: 200 });
      const rows = (await Promise.all(list.keys.map(async (k) => {
        try { return JSON.parse(await env.BOARD.get(k.name)); } catch { return null; }
      }))).filter(Boolean);
      rows.sort((a, b) => b.at - a.at);
      return new Response(JSON.stringify({ rows: rows.slice(0, 50) }), { headers: jh });
    }

    // ---------- Events: app analytics ----------
    if (url.pathname === "/event") {
      if (!tokenOk()) return json({ error: "no" }, 401, cors);

      if (request.method === "POST") {
        const b = await readJSON();
        if (!b) return json({ error: "bad" }, 400, cors);
        const name = String(b.name || "").trim().toLowerCase().replace(/[^a-z0-9_.:-]/g, "").slice(0, 64);
        if (name.length < 1) return json({ error: "bad name" }, 400, cors);
        const sid = cleanSid(b.sid);
        let props = b.props && typeof b.props === "object" && !Array.isArray(b.props) ? b.props : {};
        if (JSON.stringify(props).length > 2048) props = { _truncated: true };
        const at = Date.now();
        const event = { name, props, sid, at, ua: (request.headers.get("User-Agent") || "").slice(0, 120), country: request.cf && request.cf.country || "" };
        console.log("event", name, sid, JSON.stringify(props));
        if (env.BOARD) {
          const key = "e:" + at + ":" + Math.random().toString(36).slice(2, 7) + ":" + name;
          const puts = [env.BOARD.put(key, JSON.stringify(event), { expirationTtl: EVENT_TTL })];
          // "Not going today" queues the nudge for later — one per sid, latest wins.
          if (NOT_GOING_EVENTS.includes(name) && sid) {
            puts.push(env.BOARD.put("n:" + sid, JSON.stringify({ sid, kind: "not_going_gym", due: at + NUDGE_DELAY_MS, at }), { expirationTtl: 2 * 24 * 3600 }));
          }
          if (ctx && ctx.waitUntil) ctx.waitUntil(Promise.all(puts)); else await Promise.all(puts);
        }
        return json({ ok: true }, 200, cors);
      }

      // GET: last 100 events, member code required
      if (!codeOk()) return json({ error: "no" }, 401, cors);
      if (!env.BOARD) return json({ rows: [] }, 200, cors);
      const list = await env.BOARD.list({ prefix: "e:", limit: 1000 });
      const keys = list.keys.map((k) => k.name).sort().slice(-100);
      const rows = (await Promise.all(keys.map(async (k) => { try { return JSON.parse(await env.BOARD.get(k)); } catch { return null; } }))).filter(Boolean);
      rows.sort((a, b) => b.at - a.at);
      return json({ rows }, 200, cors);
    }

    // ---------- Web push: public key + subscriptions ----------
    if (url.pathname === "/push/key") {
      if (!tokenOk()) return json({ error: "no" }, 401, cors);
      return json({ key: env.VAPID_PUBLIC_KEY || "" }, 200, cors);
    }
    if (url.pathname === "/push/subscribe") {
      if (!tokenOk()) return json({ error: "no" }, 401, cors);
      if (request.method !== "POST") return json({ error: "POST only" }, 405, cors);
      if (!env.BOARD) return json({ error: "not set up" }, 503, cors);
      const b = await readJSON();
      const sid = cleanSid(b && b.sid);
      const s = b && b.subscription;
      if (!sid || !s || typeof s.endpoint !== "string" || !/^https:\/\//.test(s.endpoint) || !s.keys || !s.keys.p256dh || !s.keys.auth) return json({ error: "bad subscription" }, 400, cors);
      await env.BOARD.put("p:" + sid, JSON.stringify({ endpoint: s.endpoint.slice(0, 1024), keys: { p256dh: String(s.keys.p256dh).slice(0, 200), auth: String(s.keys.auth).slice(0, 64) }, at: Date.now() }));
      return json({ ok: true }, 200, cors);
    }

    // ---------- Nudge now (also what the cron calls when a queued nudge is due) ----------
    if (url.pathname === "/nudge") {
      if (!tokenOk()) return json({ error: "no" }, 401, cors);
      if (request.method !== "POST") return json({ error: "POST only" }, 405, cors);
      const b = await readJSON();
      const sid = cleanSid(b && b.sid);
      if (!sid) return json({ error: "sid required" }, 400, cors);
      const kind = NUDGES[b.kind] ? b.kind : "not_going_gym";
      const r = await sendNudge(env, sid, kind);
      return json(r, r.ok ? 200 : 502, cors);
    }

    // Health check: shows whether the secrets are wired (never shows their values)
    if (request.method !== "POST") {
      const status =
        "Max Intensity relay v7.1" +
        " | board: " + (env.BOARD ? "ok" : "NOT SET UP") +
        " | key: " + (env.ANTHROPIC_API_KEY ? "ok" : "MISSING") +
        " | token: " + (env.APP_TOKEN ? "ok" : "MISSING") +
        " | codes: " + (env.ACCESS_CODES ? "ok" : "none") +
        " | vapid: " + (env.VAPID_PRIVATE_KEY && env.VAPID_PUBLIC_KEY ? "ok" : (env.VAPID_PRIVATE_KEY ? "PUBLIC KEY MISSING" : "MISSING"));
      return new Response(status, { headers: cors });
    }

    // 1) Must come from the app (shared app token baked into the app build)
    const appToken = (request.headers.get("x-mi-app") || "").trim();
    const envToken = (env.APP_TOKEN || "").trim();
    if (!envToken || appToken !== envToken) {
      return new Response(JSON.stringify({ error: { message: "Not authorised (token mismatch)" } }), {
        status: 401, headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    // 2) Optional member code (comma-separated list in env.ACCESS_CODES)
    const code = (request.headers.get("x-mi-code") || "").trim().toUpperCase();
    const isMember = code && validCodes.includes(code);

    // 3) Forward to Anthropic with the server-held key
    let body;
    try { body = await request.json(); } catch {
      return new Response(JSON.stringify({ error: { message: "Bad request" } }), {
        status: 400, headers: { ...cors, "Content-Type": "application/json" },
      });
    }
    body.max_tokens = Math.min(Number(body.max_tokens) || 1000, MAX_TOKENS_CAP);
    // model allowlist: coach on Sonnet, quick jobs on Haiku (faster + cheaper)
    const ALLOWED_MODELS = ["claude-sonnet-4-6", "claude-haiku-4-5-20251001"];
    if (!ALLOWED_MODELS.includes(body.model)) body.model = "claude-sonnet-4-6";
    // prompt caching: big system prompts get cached so repeat calls answer faster
    if (typeof body.system === "string" && body.system.length > 2000) {
      body.system = [{ type: "text", text: body.system, cache_control: { type: "ephemeral" } }];
    }

    const upstream = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": (env.ANTHROPIC_API_KEY || "").trim(),
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(body),
    });

    const text = await upstream.text();
    return new Response(text, {
      status: upstream.status,
      headers: { ...cors, "Content-Type": "application/json", "x-mi-member": isMember ? "1" : "0" },
    });
  },
};
