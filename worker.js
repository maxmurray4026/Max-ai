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

    // Health check: shows whether the secrets are wired (never shows their values)
    if (request.method !== "POST") {
      const status =
        "Max Intensity relay v2" +
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
    body.model = "claude-sonnet-4-6"; // pin the model server-side

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
