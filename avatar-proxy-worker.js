/*
 * SOUTHYY GIVEAWAYS — shared backend Worker.
 *
 * Does three jobs for the whole multi-streamer site:
 *  1. Twitch avatar proxy — Twitch's Helix API has no CORS headers, so the
 *     browser can't call it directly. This forwards the request server-side
 *     and adds CORS itself. Also sidesteps the classic "token doesn't match
 *     Client ID" problem by minting its own app access token from your
 *     Client ID + Secret rather than requiring a pasted-in user token.
 *  2. Sign-in with Twitch — the ONLY login mechanism for streamers using
 *     this site. No passwords exist anywhere in this system. New accounts
 *     require a valid, unused invite code; the whole beta is hard-capped at
 *     MAX_ACCOUNTS total accounts, enforced here, not just by how many
 *     invite links get handed out.
 *  3. Per-streamer storage — winner history, trade links, display name, and
 *     background image are all scoped to the signed-in streamer's own
 *     Twitch ID, stored in D1 (accounts/invites) + KV (giveaway data) + R2
 *     (background images), so streamers only ever see their own data.
 *
 * Auth model: after Twitch OAuth completes, this Worker hands the frontend
 * a signed bearer token (HMAC-SHA256, not a cookie). It's carried in a URL
 * fragment back to the static site, which stores it in localStorage and
 * sends it as `Authorization: Bearer <token>` on every API call from then
 * on. A cookie won't work reliably here because the frontend
 * (itzsouthern.github.io) and this Worker (*.workers.dev) are different
 * sites — cross-site cookies are exactly what Safari's ITP and Chrome's
 * third-party-cookie changes block. A bearer token sidesteps that entirely.
 *
 * ---------------------------------------------------------------------
 * DEPLOY (no CLI needed — everything from the Cloudflare dashboard):
 *
 *  1. https://dash.cloudflare.com -> Workers & Pages -> this Worker ->
 *     Edit code -> replace everything with this file -> Save and Deploy.
 *
 *  2. D1 database:
 *       Workers & Pages -> D1 -> Create database (any name, e.g. "giveaways")
 *       Open it -> Console tab -> paste and run the SQL below, once:
 *
 *         CREATE TABLE IF NOT EXISTS streamers (
 *           id TEXT PRIMARY KEY,
 *           login TEXT NOT NULL,
 *           twitch_display_name TEXT,
 *           display_name TEXT,
 *           avatar_url TEXT,
 *           background_key TEXT,
 *           tagline TEXT,
 *           is_owner INTEGER NOT NULL DEFAULT 0,
 *           created_at INTEGER NOT NULL
 *         );
 *         CREATE TABLE IF NOT EXISTS invites (
 *           code TEXT PRIMARY KEY,
 *           created_at INTEGER NOT NULL,
 *           used_by TEXT,
 *           used_at INTEGER
 *         );
 *
 *       Then: this Worker -> Settings -> Bindings -> Add -> D1 database.
 *         Variable name: DB       Database: the one you just created.
 *
 *  3. R2 bucket (background images):
 *       Workers & Pages -> R2 -> Create bucket (any name, e.g. "backgrounds")
 *       This Worker -> Settings -> Bindings -> Add -> R2 bucket.
 *         Variable name: BACKGROUNDS       Bucket: the one you just created.
 *
 *  4. Settings -> Variables and Secrets -> Add these Secrets:
 *       TWITCH_CLIENT_ID      - from dev.twitch.tv/console/apps (same app
 *                                as before is fine)
 *       TWITCH_CLIENT_SECRET  - generated on that same app page
 *       DATA_KEY               - (existing, no longer used by /winners or
 *                                 /tradelinks, but harmless to leave)
 *       SESSION_SECRET         - make up a new long random value; this signs
 *                                 login tokens, keep it private
 *       OWNER_TWITCH_ID        - YOUR Twitch numeric user ID (not your
 *                                 username) — https://twitchapi.com or any
 *                                 "twitch user id lookup" tool can find it
 *                                 from your username. This is what makes
 *                                 your account (and only yours) see the
 *                                 invite-generation option.
 *
 *  5. On your Twitch app (dev.twitch.tv/console/apps -> your app -> Manage):
 *     add this exact URL under "OAuth Redirect URLs":
 *       https://<your-worker-subdomain>.workers.dev/auth/callback
 *
 *  6. Save & Deploy again after adding the bindings/secrets.
 *
 *  7. One-time data migration: your winner history / trade links from
 *     before this multi-streamer rewrite live under old flat KV keys
 *     (winners_reel, winners_wheel, tradelinks). To pull them into your
 *     new account: open the live site, sign in with Twitch (your account,
 *     matching OWNER_TWITCH_ID, doesn't need an invite), then open the
 *     browser console (F12) on any page and run:
 *
 *       fetch('https://<your-worker-subdomain>.workers.dev/admin/migrate-legacy', {
 *         method: 'POST',
 *         headers: { Authorization: 'Bearer ' + localStorage.getItem('southyy_session_token') }
 *       }).then(r => r.json()).then(console.log)
 *
 *     Safe to run more than once — it only fills in keys that are still
 *     empty, never overwrites data you've already collected since signing in.
 *
 *  8. Schema update (only needed if you deployed before the tagline field
 *     existed): your D1 database -> Console tab -> run once:
 *
 *       ALTER TABLE streamers ADD COLUMN tagline TEXT;
 *
 *     A fresh deployment following step 2 above already includes this
 *     column, so this step only applies to upgrading an existing database.
 */

// ---------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------
const ALLOWED_ORIGINS = ['https://itzsouthern.github.io'];
const MAX_ACCOUNTS = 8;
const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
const MAX_HISTORY = 100;
const MAX_BG_BYTES = 5 * 1024 * 1024; // 5MB
const ALLOWED_BG_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

// ---------------------------------------------------------------------
// CORS / response helpers
// ---------------------------------------------------------------------
function resolveOrigin(request) {
  const origin = request.headers.get('Origin');
  if (origin && ALLOWED_ORIGINS.includes(origin)) return origin;
  return ALLOWED_ORIGINS[0];
}
function corsHeaders(request) {
  return {
    'Access-Control-Allow-Origin': resolveOrigin(request),
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
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

// ---------------------------------------------------------------------
// base64url + signed-token helpers (used for both the OAuth "state" and
// the login bearer token — same primitive, different payloads)
// ---------------------------------------------------------------------
function bytesToBase64url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64urlToBytes(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
async function hmacKey(env) {
  return crypto.subtle.importKey(
    'raw', new TextEncoder().encode(env.SESSION_SECRET),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  );
}
async function signPayload(env, payloadObj) {
  const payload = bytesToBase64url(new TextEncoder().encode(JSON.stringify(payloadObj)));
  const key = await hmacKey(env);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const sig = bytesToBase64url(new Uint8Array(sigBuf));
  return `${payload}.${sig}`;
}
async function verifySignedPayload(env, token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  try {
    const key = await hmacKey(env);
    const valid = await crypto.subtle.verify('HMAC', key, base64urlToBytes(sig), new TextEncoder().encode(payload));
    if (!valid) return null;
    return JSON.parse(new TextDecoder().decode(base64urlToBytes(payload)));
  } catch (err) {
    return null;
  }
}
async function verifySessionToken(env, token) {
  const data = await verifySignedPayload(env, token);
  if (!data || !data.sid || !data.exp) return null;
  if (Math.floor(Date.now() / 1000) > data.exp) return null;
  return data;
}
async function getAuthedStreamerId(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const data = await verifySessionToken(env, m[1]);
  return data ? data.sid : null;
}
function generateInviteCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// ---------------------------------------------------------------------
// Twitch app-token avatar proxy (unchanged behavior, public, no auth)
// ---------------------------------------------------------------------
let cachedAppToken = null;
let cachedAppTokenExpiresAt = 0;
async function getAppAccessToken(env) {
  if (cachedAppToken && Date.now() < cachedAppTokenExpiresAt) return cachedAppToken;
  const params = new URLSearchParams({
    client_id: env.TWITCH_CLIENT_ID,
    client_secret: env.TWITCH_CLIENT_SECRET,
    grant_type: 'client_credentials',
  });
  const resp = await fetch(`https://id.twitch.tv/oauth2/token?${params}`, { method: 'POST' });
  if (!resp.ok) throw new Error(`token request failed: ${resp.status} ${await resp.text()}`);
  const data = await resp.json();
  cachedAppToken = data.access_token;
  cachedAppTokenExpiresAt = Date.now() + (data.expires_in - 300) * 1000;
  return cachedAppToken;
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

// ---------------------------------------------------------------------
// Sign-in with Twitch
// ---------------------------------------------------------------------
async function handleAuthLogin(request, env, url) {
  const invite = url.searchParams.get('invite') || '';
  const state = await signPayload(env, { invite, nonce: crypto.randomUUID(), t: Math.floor(Date.now() / 1000) });
  const redirectUri = `${url.origin}/auth/callback`;
  const authUrl = new URL('https://id.twitch.tv/oauth2/authorize');
  authUrl.searchParams.set('client_id', env.TWITCH_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', '');
  authUrl.searchParams.set('state', state);
  return Response.redirect(authUrl.toString(), 302);
}

async function handleAuthCallback(request, env, url) {
  const frontendBase = ALLOWED_ORIGINS[0];
  const fail = (reason) => Response.redirect(`${frontendBase}/index.html?auth_error=${reason}`, 302);

  const code = url.searchParams.get('code');
  const stateToken = url.searchParams.get('state');
  const stateData = await verifySignedPayload(env, stateToken || '');
  if (!code || !stateData) return fail('invalid_state');
  const invite = stateData.invite || '';

  const redirectUri = `${url.origin}/auth/callback`;
  const tokenParams = new URLSearchParams({
    client_id: env.TWITCH_CLIENT_ID,
    client_secret: env.TWITCH_CLIENT_SECRET,
    code,
    grant_type: 'authorization_code',
    redirect_uri: redirectUri,
  });
  const tokenResp = await fetch(`https://id.twitch.tv/oauth2/token?${tokenParams}`, { method: 'POST' });
  if (!tokenResp.ok) return fail('token_exchange_failed');
  const tokenData = await tokenResp.json();

  const userResp = await fetch('https://api.twitch.tv/helix/users', {
    headers: { 'Client-Id': env.TWITCH_CLIENT_ID, Authorization: `Bearer ${tokenData.access_token}` },
  });
  if (!userResp.ok) return fail('profile_fetch_failed');
  const userData = await userResp.json();
  const u = (userData.data || [])[0];
  if (!u) return fail('no_profile');

  if (!env.DB) return fail('server_misconfigured');
  const existing = await env.DB.prepare('SELECT * FROM streamers WHERE id = ?').bind(u.id).first();

  if (!existing) {
    // The owner's own Twitch ID bootstraps in without an invite — otherwise
    // there'd be no way to ever create the first account that can mint
    // invites in the first place. Everyone else needs a valid, unused code.
    const isOwnerSignup = !!(env.OWNER_TWITCH_ID && u.id === env.OWNER_TWITCH_ID);
    if (!isOwnerSignup) {
      if (!invite) return fail('invite_required');
      const inviteRow = await env.DB.prepare('SELECT * FROM invites WHERE code = ?').bind(invite).first();
      if (!inviteRow || inviteRow.used_by) return fail('invite_invalid');
      const countRow = await env.DB.prepare('SELECT COUNT(*) as c FROM streamers').first();
      if ((countRow?.c || 0) >= MAX_ACCOUNTS) return fail('full');
    }

    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      'INSERT INTO streamers (id, login, twitch_display_name, display_name, avatar_url, is_owner, created_at) VALUES (?,?,?,?,?,?,?)'
    ).bind(u.id, u.login, u.display_name, u.display_name, u.profile_image_url, isOwnerSignup ? 1 : 0, now).run();
    if (!isOwnerSignup) {
      await env.DB.prepare('UPDATE invites SET used_by = ?, used_at = ? WHERE code = ?').bind(u.id, now, invite).run();
    }
  } else {
    await env.DB.prepare('UPDATE streamers SET login = ?, twitch_display_name = ?, avatar_url = ? WHERE id = ?')
      .bind(u.login, u.display_name, u.profile_image_url, u.id).run();
  }

  const sessionToken = await signPayload(env, { sid: u.id, exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS });
  return Response.redirect(`${frontendBase}/index.html#session=${sessionToken}`, 302);
}

// ---------------------------------------------------------------------
// Profile / settings / background
// ---------------------------------------------------------------------
async function handleMe(request, env) {
  if (!env.DB) return jsonResponse(request, { error: 'server misconfigured' }, 500);
  const sid = await getAuthedStreamerId(request, env);
  if (!sid) return jsonResponse(request, { error: 'unauthorized' }, 401);
  const row = await env.DB.prepare('SELECT * FROM streamers WHERE id = ?').bind(sid).first();
  if (!row) return jsonResponse(request, { error: 'not found' }, 404);
  const origin = new URL(request.url).origin;
  return jsonResponse(request, {
    id: row.id,
    login: row.login,
    displayName: row.display_name || row.twitch_display_name || row.login,
    avatarUrl: row.avatar_url,
    backgroundImageUrl: row.background_key ? `${origin}/bg/${row.id}?v=${encodeURIComponent(row.background_key)}` : null,
    tagline: row.tagline || '',
    isOwner: !!row.is_owner,
  });
}

// Accepts a partial update — only the fields actually present in the body
// get validated and written, so the header's quick tagline edit doesn't
// need to resend displayName, and the Customize modal doesn't need to
// resend tagline.
async function handleUpdateSettings(request, env) {
  if (!env.DB) return jsonResponse(request, { error: 'server misconfigured' }, 500);
  const sid = await getAuthedStreamerId(request, env);
  if (!sid) return jsonResponse(request, { error: 'unauthorized' }, 401);
  let body;
  try { body = await request.json(); } catch (err) { return jsonResponse(request, { error: 'invalid JSON body' }, 400); }

  const setClauses = [];
  const bindValues = [];
  const result = {};

  if (body.displayName !== undefined) {
    const displayName = (body.displayName || '').toString().trim().slice(0, 40);
    if (!displayName) return jsonResponse(request, { error: 'displayName cannot be empty' }, 400);
    setClauses.push('display_name = ?');
    bindValues.push(displayName);
    result.displayName = displayName;
  }
  if (body.tagline !== undefined) {
    const tagline = (body.tagline || '').toString().trim().slice(0, 100);
    setClauses.push('tagline = ?');
    bindValues.push(tagline);
    result.tagline = tagline;
  }
  if (setClauses.length === 0) return jsonResponse(request, { error: 'nothing to update' }, 400);

  bindValues.push(sid);
  await env.DB.prepare(`UPDATE streamers SET ${setClauses.join(', ')} WHERE id = ?`).bind(...bindValues).run();
  return jsonResponse(request, { ok: true, ...result });
}

async function handleUploadBackground(request, env) {
  if (!env.DB) return jsonResponse(request, { error: 'server misconfigured' }, 500);
  const sid = await getAuthedStreamerId(request, env);
  if (!sid) return jsonResponse(request, { error: 'unauthorized' }, 401);
  if (!env.BACKGROUNDS) return jsonResponse(request, { error: 'Worker is missing the BACKGROUNDS R2 binding' }, 500);

  const contentType = request.headers.get('Content-Type') || '';
  if (!ALLOWED_BG_TYPES.includes(contentType)) {
    return jsonResponse(request, { error: 'Unsupported image type — use JPG, PNG, or WEBP' }, 400);
  }
  const bodyBuf = await request.arrayBuffer();
  if (bodyBuf.byteLength === 0) return jsonResponse(request, { error: 'Empty upload' }, 400);
  if (bodyBuf.byteLength > MAX_BG_BYTES) return jsonResponse(request, { error: 'Image too large — 5MB max' }, 400);

  const previous = await env.DB.prepare('SELECT background_key FROM streamers WHERE id = ?').bind(sid).first();

  const key = `bg-${sid}-${Date.now()}`;
  await env.BACKGROUNDS.put(key, bodyBuf, { httpMetadata: { contentType } });
  await env.DB.prepare('UPDATE streamers SET background_key = ? WHERE id = ?').bind(key, sid).run();

  if (previous && previous.background_key && previous.background_key !== key) {
    await env.BACKGROUNDS.delete(previous.background_key);
  }

  const origin = new URL(request.url).origin;
  return jsonResponse(request, { ok: true, backgroundImageUrl: `${origin}/bg/${sid}?v=${encodeURIComponent(key)}` });
}

async function handleServeBackground(request, env, streamerId) {
  if (!env.DB || !env.BACKGROUNDS) return notFound(request);
  const row = await env.DB.prepare('SELECT background_key FROM streamers WHERE id = ?').bind(streamerId).first();
  if (!row || !row.background_key) return notFound(request);
  const obj = await env.BACKGROUNDS.get(row.background_key);
  if (!obj) return notFound(request);
  return new Response(obj.body, {
    headers: {
      'Content-Type': obj.httpMetadata?.contentType || 'image/jpeg',
      'Cache-Control': 'public, max-age=3600',
      ...corsHeaders(request),
    },
  });
}

// ---------------------------------------------------------------------
// Owner-only invite administration
// ---------------------------------------------------------------------
async function handleAdminInvites(request, env) {
  if (!env.DB) return jsonResponse(request, { error: 'server misconfigured' }, 500);
  const sid = await getAuthedStreamerId(request, env);
  if (!sid || !env.OWNER_TWITCH_ID || sid !== env.OWNER_TWITCH_ID) {
    return jsonResponse(request, { error: 'unauthorized' }, 403);
  }

  if (request.method === 'GET') {
    const rows = await env.DB.prepare('SELECT * FROM invites ORDER BY created_at DESC').all();
    const countRow = await env.DB.prepare('SELECT COUNT(*) as c FROM streamers').first();
    return jsonResponse(request, { invites: rows.results || [], accountCount: countRow?.c || 0, maxAccounts: MAX_ACCOUNTS });
  }
  if (request.method === 'POST') {
    const countRow = await env.DB.prepare('SELECT COUNT(*) as c FROM streamers').first();
    const pendingRow = await env.DB.prepare('SELECT COUNT(*) as c FROM invites WHERE used_by IS NULL').first();
    const claimed = (countRow?.c || 0) + (pendingRow?.c || 0);
    if (claimed >= MAX_ACCOUNTS) {
      return jsonResponse(request, { error: `Already at the ${MAX_ACCOUNTS}-account limit (accounts + unredeemed invites) — no new invites needed.` }, 400);
    }
    const code = generateInviteCode();
    await env.DB.prepare('INSERT INTO invites (code, created_at) VALUES (?, ?)').bind(code, Math.floor(Date.now() / 1000)).run();
    return jsonResponse(request, { code, inviteUrl: `${ALLOWED_ORIGINS[0]}/index.html?invite=${code}` });
  }
  return notFound(request);
}

// ---------------------------------------------------------------------
// One-time migration: copy data from the old single-tenant KV keys
// (winners_reel, winners_wheel, tradelinks — no streamer suffix, from
// before this Worker supported multiple accounts) into the owner's new
// per-streamer keys. Safe to call more than once — skips any destination
// key that already has data, so it never overwrites newer entries.
// ---------------------------------------------------------------------
async function handleAdminMigrateLegacy(request, env) {
  if (!env.GIVEAWAY_KV) return jsonResponse(request, { error: 'Worker is missing the GIVEAWAY_KV binding' }, 500);
  const sid = await getAuthedStreamerId(request, env);
  if (!sid || !env.OWNER_TWITCH_ID || sid !== env.OWNER_TWITCH_ID) {
    return jsonResponse(request, { error: 'unauthorized' }, 403);
  }
  if (request.method !== 'POST') return notFound(request);

  const moves = [
    ['winners_reel', `winners_reel:${sid}`],
    ['winners_wheel', `winners_wheel:${sid}`],
    ['tradelinks', `tradelinks:${sid}`],
  ];
  const results = {};
  for (const [oldKey, newKey] of moves) {
    const oldRaw = await env.GIVEAWAY_KV.get(oldKey);
    if (!oldRaw) { results[oldKey] = 'no legacy data found'; continue; }
    const existingNew = await env.GIVEAWAY_KV.get(newKey);
    if (existingNew) { results[oldKey] = 'skipped — destination already has data'; continue; }
    await env.GIVEAWAY_KV.put(newKey, oldRaw);
    results[oldKey] = `copied to ${newKey}`;
  }
  return jsonResponse(request, { results });
}

// ---------------------------------------------------------------------
// Per-streamer winner history + trade links (KV, keyed by streamer id)
// ---------------------------------------------------------------------
async function handleWinners(request, env, url) {
  if (!env.GIVEAWAY_KV) return jsonResponse(request, { error: 'Worker is missing the GIVEAWAY_KV binding' }, 500);
  const sid = await getAuthedStreamerId(request, env);
  if (!sid) return jsonResponse(request, { error: 'unauthorized' }, 401);

  const type = (url.searchParams.get('type') === 'wheel') ? 'wheel' : 'reel';
  const kvKey = `winners_${type}:${sid}`;

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
  const sid = await getAuthedStreamerId(request, env);
  if (!sid) return jsonResponse(request, { error: 'unauthorized' }, 401);

  const kvKey = `tradelinks:${sid}`;

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

// ---------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }
    const url = new URL(request.url);

    if (url.pathname === '/users') return handleUsers(request, env, url);
    if (url.pathname === '/auth/login') return handleAuthLogin(request, env, url);
    if (url.pathname === '/auth/callback') return handleAuthCallback(request, env, url);
    if (url.pathname === '/me' && request.method === 'GET') return handleMe(request, env);
    if (url.pathname === '/me/settings' && request.method === 'POST') return handleUpdateSettings(request, env);
    if (url.pathname === '/me/background' && request.method === 'POST') return handleUploadBackground(request, env);
    const bgMatch = url.pathname.match(/^\/bg\/([^/]+)$/);
    if (bgMatch && request.method === 'GET') return handleServeBackground(request, env, bgMatch[1]);
    if (url.pathname === '/admin/invites') return handleAdminInvites(request, env, url);
    if (url.pathname === '/admin/migrate-legacy') return handleAdminMigrateLegacy(request, env);
    if (url.pathname === '/winners') return handleWinners(request, env, url);
    if (url.pathname === '/tradelinks') return handleTradelinks(request, env, url);

    return notFound(request);
  },
};
