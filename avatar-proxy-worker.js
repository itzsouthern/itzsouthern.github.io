/*
 * Twitch Helix avatar proxy + cloud data store for SOUTHYY Giveaways.
 *
 * Problems this solves:
 *  1. Twitch's Helix API doesn't send CORS headers, so the browser can't call
 *     it directly from a static page. This worker forwards the request
 *     server-side (where CORS doesn't apply) and adds CORS headers itself.
 *  2. Manually-generated user tokens have to be minted against the exact
 *     Client ID you send alongside them, which third-party "token generator"
 *     sites usually get wrong (401 Unauthorized). This worker sidesteps that
 *     entirely by fetching its own app access token straight from Twitch
 *     using your Client ID + Client Secret — no token copy/paste, and it
 *     always matches.
 *  3. Winner history and trade links are stored server-side (Cloudflare KV)
 *     instead of only in the browser's localStorage, so they survive
 *     private/incognito tabs closing, a PC restart, or switching devices —
 *     the pages fetch/push this data over HTTP instead of relying solely on
 *     what's saved locally.
 *
 * Deploy (no CLI needed):
 *   1. https://dash.cloudflare.com -> sign up free -> Workers & Pages
 *   2. Create application -> Create Worker -> give it a name -> Deploy
 *   3. Edit code -> replace the default script with this whole file -> Save & Deploy
 *   4. Workers & Pages -> KV -> Create a namespace (any name, e.g. "giveaways")
 *   5. On this Worker -> Settings -> Bindings -> Add binding -> KV Namespace
 *        Variable name: GIVEAWAY_KV       Namespace: the one you just created
 *   6. Settings -> Variables and Secrets -> Add:
 *        TWITCH_CLIENT_ID     (Secret) - from dev.twitch.tv/console/apps
 *        TWITCH_CLIENT_SECRET (Secret) - generated on that same app page
 *        DATA_KEY              (Secret) - make up any long random password;
 *                                          this is what protects your stored
 *                                          winner history / trade links from
 *                                          strangers who find this Worker URL
 *      Save & Deploy again after adding them.
 *   7. Copy the *.workers.dev URL it gives you, paste it into the "Avatar
 *      proxy URL" field on the giveaways page, and paste the same DATA_KEY
 *      value into the "Cloud sync key" field next to it. The key only ever
 *      lives in your browser's local storage and in this Worker's secret —
 *      it's never part of the site's published files, so visitors can't see
 *      or extract it just by browsing your site or viewing its source.
 */

// Locked to your actual site so other websites' scripts can't ride along using
// visitors' browsers. If you ever host this somewhere else too, add that origin.
const ALLOWED_ORIGINS = ['https://itzsouthern.github.io'];
const MAX_HISTORY = 100;

function resolveOrigin(request) {
  const origin = request.headers.get('Origin');
  if (origin && ALLOWED_ORIGINS.includes(origin)) return origin;
  // Non-browser requests (curl, server-to-server) send no Origin header at all;
  // let those through since the API key is still required — this only affects
  // which *browser* origins get a CORS-approved response.
  return ALLOWED_ORIGINS[0];
}
function corsHeaders(request) {
  return {
    'Access-Control-Allow-Origin': resolveOrigin(request),
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Api-Key',
    'Vary': 'Origin',
  };
}
function jsonResponse(request, data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(request) },
  });
}
function notFound(request) {
  return new Response('Not found', { status: 404, headers: corsHeaders(request) });
}
function checkApiKey(request, env) {
  if (!env.DATA_KEY) return false;
  return request.headers.get('X-Api-Key') === env.DATA_KEY;
}

// Cached across requests within the same isolate; refetched once expired.
let cachedToken = null;
let cachedTokenExpiresAt = 0;

async function getAppAccessToken(env) {
  if (cachedToken && Date.now() < cachedTokenExpiresAt) return cachedToken;

  const params = new URLSearchParams({
    client_id: env.TWITCH_CLIENT_ID,
    client_secret: env.TWITCH_CLIENT_SECRET,
    grant_type: 'client_credentials',
  });
  const resp = await fetch(`https://id.twitch.tv/oauth2/token?${params}`, { method: 'POST' });
  if (!resp.ok) {
    throw new Error(`token request failed: ${resp.status} ${await resp.text()}`);
  }
  const data = await resp.json();
  cachedToken = data.access_token;
  // refresh a bit early to avoid edge-of-expiry failures
  cachedTokenExpiresAt = Date.now() + (data.expires_in - 300) * 1000;
  return cachedToken;
}

async function handleUsers(request, env, url) {
  if (request.method !== 'GET') return notFound(request);
  if (!env.TWITCH_CLIENT_ID || !env.TWITCH_CLIENT_SECRET) {
    return jsonResponse(request, { error: 'Worker is missing TWITCH_CLIENT_ID / TWITCH_CLIENT_SECRET env vars' }, 500);
  }
  try {
    const token = await getAppAccessToken(env);
    const twitchResponse = await fetch('https://api.twitch.tv/helix/users' + url.search, {
      headers: { 'Client-Id': env.TWITCH_CLIENT_ID, Authorization: `Bearer ${token}` },
    });
    const body = await twitchResponse.text();
    return new Response(body, {
      status: twitchResponse.status,
      headers: { 'Content-Type': 'application/json', ...corsHeaders(request) },
    });
  } catch (err) {
    return jsonResponse(request, { error: String(err) }, 502);
  }
}

async function handleWinners(request, env, url) {
  if (!env.GIVEAWAY_KV) return jsonResponse(request, { error: 'Worker is missing the GIVEAWAY_KV binding' }, 500);
  if (!checkApiKey(request, env)) return jsonResponse(request, { error: 'Missing or wrong X-Api-Key' }, 401);

  const type = (url.searchParams.get('type') === 'wheel') ? 'wheel' : 'reel';
  const kvKey = `winners_${type}`;

  if (request.method === 'GET') {
    const raw = await env.GIVEAWAY_KV.get(kvKey);
    return jsonResponse(request, { history: raw ? JSON.parse(raw) : [] });
  }
  if (request.method === 'POST') {
    let winner;
    try { winner = await request.json(); } catch (err) { return jsonResponse(request, { error: 'Invalid JSON body' }, 400); }
    const raw = await env.GIVEAWAY_KV.get(kvKey);
    const history = raw ? JSON.parse(raw) : [];
    history.unshift(winner);
    const trimmed = history.slice(0, MAX_HISTORY);
    await env.GIVEAWAY_KV.put(kvKey, JSON.stringify(trimmed));
    return jsonResponse(request, { history: trimmed });
  }
  if (request.method === 'DELETE') {
    await env.GIVEAWAY_KV.put(kvKey, JSON.stringify([]));
    return jsonResponse(request, { history: [] });
  }
  return notFound(request);
}

async function handleTradelinks(request, env, url) {
  if (!env.GIVEAWAY_KV) return jsonResponse(request, { error: 'Worker is missing the GIVEAWAY_KV binding' }, 500);
  if (!checkApiKey(request, env)) return jsonResponse(request, { error: 'Missing or wrong X-Api-Key' }, 401);

  const kvKey = 'tradelinks';

  if (request.method === 'GET') {
    const raw = await env.GIVEAWAY_KV.get(kvKey);
    return jsonResponse(request, { tradelinks: raw ? JSON.parse(raw) : {} });
  }
  if (request.method === 'POST') {
    let entry;
    try { entry = await request.json(); } catch (err) { return jsonResponse(request, { error: 'Invalid JSON body' }, 400); }
    if (!entry.username || !entry.tradeLink) return jsonResponse(request, { error: 'username and tradeLink are required' }, 400);
    const raw = await env.GIVEAWAY_KV.get(kvKey);
    const store = raw ? JSON.parse(raw) : {};
    store[entry.username] = {
      displayName: entry.displayName || entry.username,
      tradeLink: entry.tradeLink,
      capturedAt: entry.capturedAt || Date.now(),
    };
    await env.GIVEAWAY_KV.put(kvKey, JSON.stringify(store));
    return jsonResponse(request, { tradelinks: store });
  }
  if (request.method === 'DELETE') {
    const username = url.searchParams.get('username');
    const raw = await env.GIVEAWAY_KV.get(kvKey);
    const store = raw ? JSON.parse(raw) : {};
    if (username) {
      delete store[username];
    } else {
      for (const k of Object.keys(store)) delete store[k];
    }
    await env.GIVEAWAY_KV.put(kvKey, JSON.stringify(store));
    return jsonResponse(request, { tradelinks: store });
  }
  return notFound(request);
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }
    const url = new URL(request.url);
    if (url.pathname === '/users') return handleUsers(request, env, url);
    if (url.pathname === '/winners') return handleWinners(request, env, url);
    if (url.pathname === '/tradelinks') return handleTradelinks(request, env, url);
    return notFound(request);
  },
};
