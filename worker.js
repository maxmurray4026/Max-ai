// MAX INTENSITY — AI relay server (Cloudflare Worker)
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
    if (request.method !== "POST") return new Response("Max Intensity relay", { headers: cors });

    // 1) Must come from the app (shared app token baked into the app build)
    const appToken = request.headers.get("x-mi-app") || "";
    if (appToken !== env.APP_TOKEN) {
      return new Response(JSON.stringify({ error: { message: "Not authorised" } }), {
        status: 401, headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    // 2) Optional member code (comma-separated list in env.ACCESS_CODES, e.g. "MAX2026,MAXBETA")
    //    Right now trial users pass without a code; codes exist so you can revoke/rotate later.
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
        "x-api-key": env.ANTHROPIC_API_KEY,
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
