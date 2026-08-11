// MAX INTENSITY — AI relay server (Cloudflare Worker) v2
// Holds the Anthropic API key server-side and answers only to the Max Intensity app.

const ALLOWED_ORIGIN = "https://maxmurray4026.github.io";
const MAX_TOKENS_CAP = 1200; // cost guard — no request can exceed this

export default {
  async fetch(request, env) {
    const cors = {
      "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, x-mi-app, x-mi-code",
    };

    if (request.method === "OPTIONS") return new Response(null, { headers: cors });

    const url = new URL(request.url);

    // ---------- Community leaderboard (KV binding: BOARD) ----------
    if (url.pathname === "/board") {
      const jh = { ...cors, "Content-Type": "application/json" };
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

    // Health check: shows whether the secrets are wired (never shows their values)
    if (request.method !== "POST") {
      const status =
        "Max Intensity relay v4" +
        " | board: " + (env.BOARD ? "ok" : "NOT SET UP") +
        " | key: " + (env.ANTHROPIC_API_KEY ? "ok" : "MISSING") +
        " | token: " + (env.APP_TOKEN ? "ok" : "MISSING") +
        " | codes: " + (env.ACCESS_CODES ? "ok" : "none");
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
    const validCodes = (env.ACCESS_CODES || "").split(",").map((c) => c.trim().toUpperCase()).filter(Boolean);
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
