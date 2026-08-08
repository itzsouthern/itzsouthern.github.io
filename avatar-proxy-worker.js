/*
 * Twitch Helix avatar proxy for SOUTHYY Giveaways.
 *
 * Two problems this solves:
 *  1. Twitch's Helix API doesn't send CORS headers, so the browser can't call
 *     it directly from a static page. This worker forwards the request
 *     server-side (where CORS doesn't apply) and adds CORS headers itself.
 *  2. Manually-generated user tokens have to be minted against the exact
 *     Client ID you send alongside them, which third-party "token generator"
 *     sites usually get wrong (401 Unauthorized). This worker sidesteps that
 *     entirely by fetching its own app access token straight from Twitch
 *     using your Client ID + Client Secret — no token copy/paste, and it
 *     always matches.
 *
 * Deploy (no CLI needed):
 *   1. https://dash.cloudflare.com -> sign up free -> Workers & Pages
 *   2. Create application -> Create Worker -> give it a name -> Deploy
 *   3. Edit code -> replace the default script with this whole file -> Save & Deploy
 *   4. Go to Settings -> Variables and Secrets -> Add:
 *        TWITCH_CLIENT_ID     (Secret) - from dev.twitch.tv/console/apps
 *        TWITCH_CLIENT_SECRET (Secret) - generated on that same app page
 *      Save & Deploy again after adding them.
 *   5. Copy the *.workers.dev URL it gives you
 *   6. Paste that URL into the "Avatar proxy URL" field on the giveaways page
 *      -- no Client ID or token fields needed on the page anymore.
 */

const ALLOWED_ORIGIN = '*'; // tighten to your page's origin if you host it somewhere fixed

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
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

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    const url = new URL(request.url);
    if (url.pathname !== '/users' || request.method !== 'GET') {
      return new Response('Not found', { status: 404, headers: corsHeaders() });
    }

    if (!env.TWITCH_CLIENT_ID || !env.TWITCH_CLIENT_SECRET) {
      return new Response(
        JSON.stringify({ error: 'Worker is missing TWITCH_CLIENT_ID / TWITCH_CLIENT_SECRET env vars' }),
        { status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders() } }
      );
    }

    try {
      const token = await getAppAccessToken(env);
      const twitchResponse = await fetch('https://api.twitch.tv/helix/users' + url.search, {
        headers: { 'Client-Id': env.TWITCH_CLIENT_ID, Authorization: `Bearer ${token}` },
      });
      const body = await twitchResponse.text();
      return new Response(body, {
        status: twitchResponse.status,
        headers: { 'Content-Type': 'application/json', ...corsHeaders() },
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: String(err) }), {
        status: 502,
        headers: { 'Content-Type': 'application/json', ...corsHeaders() },
      });
    }
  },
};
