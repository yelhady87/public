/**
 * End-to-end smoke test using a mock FusionAuth (OIDC + management API).
 *
 * Run with Node 18+:
 *   npm test
 *
 * The mock issues REAL RS256-signed ID tokens backed by a real JWKS, so
 * openid-client's signature validation is genuinely exercised rather than
 * stubbed out.
 *
 * Verifies: /login -> FusionAuth authorize (PKCE S256) -> /callback code
 * exchange -> tile list -> /launch/:appId redirect, plus the negative paths.
 *
 * Ports are deliberately high/odd so these mocks cannot collide with a real
 * FusionAuth (9011) or a running dev instance (3000).
 */
const http = require('http');
const crypto = require('crypto');
const assert = require('assert');
const { spawn } = require('child_process');
const path = require('path');

const FA_PORT = Number(process.env.SMOKE_FA_PORT || 19011);
const APP_PORT = Number(process.env.SMOKE_APP_PORT || 13000);
const TENANT = 'test-tenant';
// This is what the launcher is configured with - tenant scoped, like production.
const ISSUER = `http://localhost:${FA_PORT}/${TENANT}`;

// FusionAuth's tenant-scoped discovery document reports a BARE origin as the
// issuer and points its endpoints at the root, without the tenant segment.
// Verified against a real 1.62.1 instance, so the mock reproduces that quirk -
// it is exactly the shape openid-client sees in production.
const AUTH_BASE = `http://localhost:${FA_PORT}`;
const AUTHORIZATION_ENDPOINT = `${AUTH_BASE}/oauth2/authorize`;
const CLIENT_ID = 'launcher-client-id';
const CLIENT_SECRET = 'launcher-client-secret';
const KID = 'smoke-test-key';
const USER_SUB = '11111111-2222-3333-4444-555555555555';

const APP_ID = 'aaaaaaaa-0000-0000-0000-000000000001';
const APP_ID_INACTIVE = 'aaaaaaaa-0000-0000-0000-000000000002';
const APP_ID_NO_REDIRECT = 'aaaaaaaa-0000-0000-0000-000000000003';
const APP_ID_UNASSIGNED = 'aaaaaaaa-0000-0000-0000-000000000004';
// Lists the LAUNCHER'S OWN /callback first, then its real one - the exact shape
// of Schema_Browser in a stock local install. Launching must skip the first.
const APP_ID_SHARED_CALLBACK = 'aaaaaaaa-0000-0000-0000-000000000005';
// Only lists the launcher's own callback, so nothing is left to launch into.
const APP_ID_ONLY_LAUNCHER_CB = 'aaaaaaaa-0000-0000-0000-000000000006';
// FusionAuth-hosted UI: path-only redirect URI needing origin resolution.
const APP_ID_RELATIVE = 'aaaaaaaa-0000-0000-0000-000000000007';
const SELF_ID = CLIENT_ID; // launcher is also an application
const LAUNCHER_CALLBACK = `http://localhost:${APP_PORT}/callback`;

// ---- Signing key material for the mock IdP ----
const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicJwk = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
const JWKS = { keys: [{ ...publicJwk, kid: KID, alg: 'RS256', use: 'sig' }] };

// ---- What the mock observed, for assertions ----
const observed = {
  authorizeQuery: null,
  tokenRequestBody: null,
  apiCalls: [],
};

function base64url(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function signJwt(payload) {
  const header = { alg: 'RS256', typ: 'JWT', kid: KID };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(
    JSON.stringify(payload)
  )}`;
  const signature = crypto.sign(
    'RSA-SHA256',
    Buffer.from(signingInput),
    privateKey
  );
  return `${signingInput}.${base64url(signature)}`;
}

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

function appFixture(overrides) {
  return {
    active: true,
    id: APP_ID,
    name: 'Incorta Analytics',
    state: 'Active',
    tenantId: 'tenant-id',
    oauthConfiguration: {
      authorizedRedirectURLs: ['http://localhost:3000/oauth-redirect'],
      authorizedOriginURLs: ['http://localhost:3000'],
    },
    ...overrides,
  };
}

const APPLICATIONS = [
  appFixture({}),
  // Inactive: registered to the user but must not appear.
  appFixture({ id: APP_ID_INACTIVE, name: 'Retired App', active: false }),
  // No redirect URI: nothing to launch into, so it must not appear.
  appFixture({
    id: APP_ID_NO_REDIRECT,
    name: 'No Redirect App',
    oauthConfiguration: { authorizedRedirectURLs: [] },
  }),
  // Active but NOT registered to this user: must not leak into the list.
  appFixture({ id: APP_ID_UNASSIGNED, name: 'Someone Elses App' }),
  // The launcher itself: registered, but must be filtered out.
  appFixture({
    id: SELF_ID,
    name: 'My Apps',
    oauthConfiguration: { authorizedRedirectURLs: [LAUNCHER_CALLBACK] },
  }),
  // Lists the launcher's own /callback FIRST, then a real one. The launcher
  // must pick the second; picking the first sends the code back to the launcher
  // and the user gets a CSRF error instead of the app.
  appFixture({
    id: APP_ID_SHARED_CALLBACK,
    name: 'Schema Browser',
    oauthConfiguration: {
      authorizedRedirectURLs: [
        LAUNCHER_CALLBACK,
        'http://localhost:3001/callback',
      ],
    },
  }),
  // Only the launcher's own callback: after filtering, nothing is launchable.
  appFixture({
    id: APP_ID_ONLY_LAUNCHER_CB,
    name: 'Loopback Only App',
    oauthConfiguration: { authorizedRedirectURLs: [LAUNCHER_CALLBACK] },
  }),
  // Path-only URI, as FusionAuth-hosted UIs use. Must be resolved against the
  // FusionAuth origin before use.
  appFixture({
    id: APP_ID_RELATIVE,
    name: 'Admin UI',
    oauthConfiguration: { authorizedRedirectURLs: ['/admin/login'] },
  }),
];

// ---- Mock FusionAuth ----
const fusionAuth = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${FA_PORT}`);

  if (url.pathname === `/${TENANT}/.well-known/openid-configuration`) {
    return json(res, 200, {
      issuer: AUTH_BASE,
      authorization_endpoint: AUTHORIZATION_ENDPOINT,
      token_endpoint: `${AUTH_BASE}/oauth2/token`,
      userinfo_endpoint: `${AUTH_BASE}/oauth2/userinfo`,
      jwks_uri: `${AUTH_BASE}/.well-known/jwks.json`,
      end_session_endpoint: `${AUTH_BASE}/oauth2/logout`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
    });
  }

  if (url.pathname === '/.well-known/jwks.json') {
    return json(res, 200, JWKS);
  }

  // Authorize endpoint: verify PKCE was actually offered, then bounce back.
  if (url.pathname === '/oauth2/authorize') {
    observed.authorizeQuery = Object.fromEntries(url.searchParams);

    const redirectUri = url.searchParams.get('redirect_uri');
    const target = new URL(redirectUri);
    target.searchParams.set('code', 'mock-auth-code');
    target.searchParams.set('state', url.searchParams.get('state') || '');
    return redirect(res, target.toString());
  }

  if (url.pathname === '/oauth2/token' && req.method === 'POST') {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      observed.tokenRequestBody = new URLSearchParams(body);

      const now = Math.floor(Date.now() / 1000);
      // openid-client validates the nonce because the launcher passes one in its
      // `checks`, so the mock IdP has to echo it back in the ID token.
      const nonce =
        (observed.authorizeQuery && observed.authorizeQuery.nonce) || undefined;
      const idToken = signJwt({
        iss: AUTH_BASE,
        aud: CLIENT_ID,
        sub: USER_SUB,
        email: 'tester@example.com',
        preferred_username: 'tester',
        ...(nonce ? { nonce } : {}),
        iat: now,
        exp: now + 3600,
      });

      return json(res, 200, {
        access_token: 'mock-access-token',
        id_token: idToken,
        token_type: 'Bearer',
        expires_in: 3600,
      });
    });
    return;
  }

  // ---- Management API ----
  if (url.pathname === '/api/application') {
    observed.apiCalls.push({
      path: url.pathname,
      auth: req.headers.authorization,
      tenant: req.headers['x-fusionauth-tenantid'],
    });
    return json(res, 200, { applications: APPLICATIONS });
  }

  if (url.pathname === `/api/user/${USER_SUB}/applications`) {
    observed.apiCalls.push({
      path: url.pathname,
      auth: req.headers.authorization,
      tenant: req.headers['x-fusionauth-tenantid'],
    });
    return json(res, 200, {
      user: {
        id: USER_SUB,
        email: 'tester@example.com',
        registrations: [
          { applicationId: APP_ID, roles: ['admin', 'analyst'] },
          { applicationId: APP_ID_INACTIVE, roles: [] },
          { applicationId: APP_ID_NO_REDIRECT, roles: [] },
          { applicationId: APP_ID_SHARED_CALLBACK, roles: [] },
          { applicationId: APP_ID_ONLY_LAUNCHER_CB, roles: [] },
          { applicationId: APP_ID_RELATIVE, roles: [] },
          { applicationId: SELF_ID, roles: [] },
        ],
        memberships: [],
      },
    });
  }

  return json(res, 404, { generalErrors: [{ code: '[NotFound]', message: 'no route' }] });
});

// ---- Tiny cookie-aware HTTP client for driving the launcher ----
function makeClient(baseUrl) {
  const jar = new Map();

  function cookieHeader() {
    return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  function absorb(res) {
    const raw = res.headers.getSetCookie
      ? res.headers.getSetCookie()
      : [].concat(res.headers.get('set-cookie') || []);
    raw.filter(Boolean).forEach((c) => {
      const [pair] = c.split(';');
      const idx = pair.indexOf('=');
      if (idx > 0) jar.set(pair.slice(0, idx).trim(), pair.slice(idx + 1).trim());
    });
  }

  return {
    clearCookies() {
      jar.clear();
    },
    async get(pathname, { redirect = 'manual' } = {}) {
      const res = await fetch(`${baseUrl}${pathname}`, {
        redirect,
        headers: jar.size ? { Cookie: cookieHeader() } : {},
      });
      absorb(res);
      return res;
    },
  };
}

function waitForServer(baseUrl, attempts = 60) {
  return new Promise((resolve, reject) => {
    const tick = async (n) => {
      try {
        const res = await fetch(`${baseUrl}/health`);
        if (res.ok) return resolve();
      } catch (err) {
        // not up yet
      }
      if (n <= 0) return reject(new Error('launcher did not become healthy'));
      setTimeout(() => tick(n - 1), 250);
    };
    tick(attempts);
  });
}

async function run() {
  await new Promise((resolve) => fusionAuth.listen(FA_PORT, resolve));

  const child = spawn(process.execPath, ['server.js'], {
    cwd: __dirname ? path.join(__dirname, '..') : '.',
    env: {
      ...process.env,
      FUSION_AUTH_ISSUER: ISSUER,
      FUSION_AUTH_CLIENT_ID: CLIENT_ID,
      FUSION_AUTH_CLIENT_SECRET: CLIENT_SECRET,
      FUSION_AUTH_SCOPES: 'openid profile email',
      FUSION_AUTH_API_KEY: 'mock-api-key',
      FUSION_AUTH_TENANT_ID: 'tenant-id',
      FUSION_AUTH_API_URL: `http://localhost:${FA_PORT}`,
      APP_PORT: String(APP_PORT),
      APP_BASE_URL: `http://localhost:${APP_PORT}`,
      SESSION_SECRET: 'smoke-test-secret',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const serverLog = [];
  child.stdout.on('data', (d) => serverLog.push(d.toString()));
  child.stderr.on('data', (d) => serverLog.push(d.toString()));

  const app = `http://localhost:${APP_PORT}`;
  const client = makeClient(app);

  try {
    await waitForServer(app);

    // 1. Signed out: /api/my-apps must be 401.
    let res = await client.get('/api/my-apps');
    assert.strictEqual(res.status, 401, '/api/my-apps should be 401 when signed out');
    console.log('  ✓ /api/my-apps is 401 when signed out');

    // 2. /login redirects into FusionAuth's authorize endpoint with PKCE S256.
    res = await client.get('/login');
    assert.strictEqual(res.status, 302, '/login should redirect');
    const loginLocation = res.headers.get('location');
    assert.ok(
      loginLocation.startsWith(AUTHORIZATION_ENDPOINT),
      `/login should redirect to the FusionAuth authorize endpoint, got ${loginLocation}`
    );
    console.log('  ✓ /login redirects to FusionAuth authorize');

    // 3. Complete the flow by bouncing through the mock authorize endpoint.
    //    Fetched directly (not via the launcher client) because loginLocation
    //    points at the mock IdP, not the launcher. This is what populates
    //    observed.authorizeQuery, so the PKCE/scope/state assertions below must
    //    come after this request.
    const authorizeRes = await fetch(loginLocation, { redirect: 'manual' });
    assert.strictEqual(
      authorizeRes.status,
      302,
      'mock authorize endpoint should redirect back to the launcher'
    );
    const callbackLocation = authorizeRes.headers.get('location');
    assert.ok(callbackLocation.includes('/callback'), 'should land on /callback');

    const q = observed.authorizeQuery;
    assert.ok(q, 'mock authorize endpoint should have been reached');
    assert.strictEqual(q.response_type, 'code');
    assert.strictEqual(q.code_challenge_method, 'S256', 'PKCE S256 required');
    assert.ok(q.code_challenge, 'code_challenge must be sent');
    assert.strictEqual(q.scope, 'openid profile email');
    assert.strictEqual(q.client_id, CLIENT_ID);
    assert.ok(q.state, 'state must be sent for CSRF protection');
    console.log('  ✓ authorize request carries PKCE S256, scopes and state');

    res = await client.get(new URL(callbackLocation).pathname + new URL(callbackLocation).search);
    assert.strictEqual(res.status, 302, 'callback should redirect to /');
    assert.strictEqual(res.headers.get('location'), '/');
    console.log('  ✓ code exchange succeeded and session established');

    // The verifier must have been sent on the token request.
    const tokenBody = observed.tokenRequestBody;
    assert.ok(tokenBody, 'token endpoint should have been called');
    assert.ok(tokenBody.get('code_verifier'), 'PKCE code_verifier must be sent');
    console.log('  ✓ token request included the PKCE code_verifier');

    // 4. The tile list.
    res = await client.get('/api/my-apps');
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    const byId = new Map(data.apps.map((a) => [a.applicationId, a]));

    // Sorted by name: "Admin UI" sorts before "Incorta Analytics" and
    // "Schema Browser". "Loopback Only App" and "My Apps" are filtered out.
    assert.deepStrictEqual(
      data.apps.map((a) => a.name),
      ['Admin UI', 'Incorta Analytics', 'Schema Browser'],
      `unexpected tile list: ${JSON.stringify(data.apps.map((a) => a.name))}`
    );
    assert.strictEqual(data.count, 3, `expected 3 launchable apps, got ${data.count}`);
    assert.deepStrictEqual(
      byId.get(APP_ID).roles,
      ['admin', 'analyst']
    );
    assert.strictEqual(
      byId.get(APP_ID).redirectUri,
      'http://localhost:3000/oauth-redirect'
    );
    assert.strictEqual(data.user.email, 'tester@example.com');

    // An application whose only authorized redirect URI is the launcher's own
    // callback has nowhere to launch into, so it must not be offered as a tile.
    assert.ok(
      !byId.has(APP_ID_ONLY_LAUNCHER_CB),
      'app whose only redirect URI is the launcher callback must be filtered out'
    );

    // A path-only redirect URI must be resolved against the FusionAuth origin.
    assert.strictEqual(
      byId.get(APP_ID_RELATIVE).redirectUri,
      `${AUTH_BASE}/admin/login`,
      'relative redirect URI should resolve against the FusionAuth origin'
    );
    console.log('  ✓ tile list applies every launchability filter');

    // 4b. Regression: Schema_Browser lists the launcher's own callback first.
    //      The launcher must skip it, or the code comes back to the launcher and
    //      the user sees a CSRF error instead of the application.
    const schemaTile = byId.get(APP_ID_SHARED_CALLBACK);
    assert.ok(schemaTile, 'app with a usable redirect URI should be listed');
    assert.strictEqual(
      schemaTile.redirectUri,
      'http://localhost:3001/callback',
      'must skip the launcher own callback and pick the app real redirect URI'
    );
    assert.notStrictEqual(schemaTile.redirectUri, LAUNCHER_CALLBACK);
    console.log('  ✓ launcher own /callback is never chosen as a launch target');

    // 5. Tenant header on every management API call.
    assert.ok(observed.apiCalls.length >= 2, 'management API should have been called');
    observed.apiCalls.forEach((call) => {
      assert.strictEqual(call.auth, 'mock-api-key', 'API key must be sent');
      assert.strictEqual(call.tenant, 'tenant-id', 'tenant header must be sent');
    });
    console.log('  ✓ management API calls carry the API key and tenant header');

    // 6. Launching an assigned app redirects to authorize with that app's id.
    res = await client.get(`/launch/${APP_ID}`);
    assert.strictEqual(res.status, 302, '/launch should redirect');
    const launch = new URL(res.headers.get('location'));
    assert.strictEqual(launch.origin + launch.pathname, AUTHORIZATION_ENDPOINT);
    assert.strictEqual(launch.searchParams.get('client_id'), APP_ID);
    assert.strictEqual(launch.searchParams.get('response_type'), 'code');
    assert.strictEqual(
      launch.searchParams.get('redirect_uri'),
      'http://localhost:3000/oauth-redirect'
    );
    assert.ok(
      launch.searchParams.get('state') === null,
      'launch must NOT send a state the target app cannot validate'
    );
    assert.strictEqual(
      launch.searchParams.get('redirect_uri'),
      'http://localhost:3000/oauth-redirect'
    );
    console.log('  ✓ /launch redirects to the app authorize URL with no state');

    // 6b. Regression: the app whose first redirect URI is the launcher own
    //      callback must still launch to its real, second redirect URI.
    res = await client.get(`/launch/${APP_ID_SHARED_CALLBACK}`);
    assert.strictEqual(res.status, 302, 'should redirect');
    const sharedLaunch = new URL(res.headers.get('location'));
    assert.strictEqual(
      sharedLaunch.searchParams.get('redirect_uri'),
      'http://localhost:3001/callback',
      'launching must not bounce the code back to the launcher callback'
    );
    console.log('  ✓ /launch avoids the launcher callback collision');

    // 7. An unassigned app must be refused.
    res = await client.get(`/launch/${APP_ID_UNASSIGNED}`);
    assert.strictEqual(res.status, 403, 'unassigned app must be 403');
    console.log('  ✓ /launch refuses an application the user is not assigned to');

    // 8. Inactive and no-redirect apps are never launchable either.
    res = await client.get(`/launch/${APP_ID_INACTIVE}`);
    assert.strictEqual(res.status, 403, 'inactive app must be 403');
    res = await client.get(`/launch/${APP_ID_NO_REDIRECT}`);
    assert.strictEqual(res.status, 403, 'app with no redirect URI must be 403');
    res = await client.get(`/launch/${APP_ID_ONLY_LAUNCHER_CB}`);
    assert.strictEqual(
      res.status,
      403,
      'app whose only redirect URI is the launcher callback must be 403'
    );
    console.log('  ✓ /launch refuses inactive, redirect-less and loopback-only apps');

    // 9. /me reflects the session.
    res = await client.get('/me');
    const me = await res.json();
    assert.strictEqual(me.authenticated, true);
    assert.strictEqual(me.user.sub, USER_SUB);
    console.log('  ✓ /me reports the signed-in user');

    // 10. Logout clears the session.
    res = await client.get('/logout');
    assert.strictEqual(res.status, 302);
    res = await client.get('/api/my-apps');
    assert.strictEqual(res.status, 401, 'session should be gone after logout');
    console.log('  ✓ logout clears the session');

    console.log('\nAll smoke tests passed.\n');
  } finally {
    child.kill('SIGTERM');
    fusionAuth.close();
    if (process.env.SMOKE_VERBOSE) {
      console.log('--- launcher log ---');
      console.log(serverLog.join(''));
    }
  }
}

run().catch((err) => {
  console.error('\n✗ Smoke test failed:', err.message);
  console.error(err.stack);
  process.exit(1);
});
