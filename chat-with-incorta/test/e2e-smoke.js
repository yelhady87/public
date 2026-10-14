/**
 * End-to-end smoke test using a mock OIDC provider + mock Incorta.
 *
 * Run with Node 18+ (uses global fetch and JWK export):
 *   node test/e2e-smoke.js
 *
 * The mock Keycloak issues REAL RS256-signed ID tokens backed by a real
 * JWKS, so openid-client's signature validation is genuinely exercised.
 *
 * Verifies: /login redirect -> OIDC provider -> /callback code exchange ->
 *           Incorta client-credentials token (with for_user) -> schema list API.
 */
const http = require('http');
const crypto = require('crypto');
const assert = require('assert');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

// Deliberately high/odd ports so these mocks never collide with a real
// Keycloak (8888), Incorta (80/8080), or a running dev instance (3000).
const INCORTA_PORT = Number(process.env.SMOKE_INCORTA_PORT || 18080);
const APP_PORT = Number(process.env.SMOKE_APP_PORT || 13000);
const KID = 'smoke-test-key';
// Fixed so the trace-id assertions are exact, not pattern matches
const INCORTA_TRACE_ID = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
const INCORTA_ERROR_TRACE_ID = 'ffffffff00112233445566778899';
// Deliberately NOT the same as the issuer's tenant segment, so a hardcoded
// tenant in the route cannot pass by accident.
const SMOKE_INCORTA_TENANT = 'tenant_from_env';
let failNextSchemaList = false;
let failNextChat = false;

let capturedForUser = null;
let capturedGrantType = null;
let capturedAuthHeader = null;
let capturedIncortaPath = null;
let incortaTokenCalls = 0;

// Copilot A2A request capture
let capturedA2aPath = null;
let capturedA2aAgent = null;
let capturedA2aHeaders = null;
let capturedA2aBody = null;

// ---- Signing key material for the mock IdP ----
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});
const publicJwk = crypto
  .createPublicKey(privateKey)
  .export({ format: 'jwk' });
const JWKS = { keys: [{ ...publicJwk, kid: KID, alg: 'RS256', use: 'sig' }] };

function base64url(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Build a real RS256-signed JWT
 */
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

/**
 * Extract the home page's replyText() from the served HTML and return a callable
 * that runs it against a sample A2A reply.
 *
 * replyText lives in a template literal inside server.js, so the only way to test
 * the shipped code rather than a copy of it is to pull the function text back out
 * of the rendered page and evaluate it. Brace matching is deliberate rather than a
 * regex: the body contains string literals with braces in them, so counting
 * braces from the opening one finds the real end.
 *
 * Evaluating this text is also the only automated check that the inlined script
 * parses at all. A template literal resolves escape sequences before the browser
 * sees the code, so a stray '\n' written in server.js arrives at the browser as a
 * real newline inside a string literal - a syntax error that silently kills every
 * handler on the page. The test failed on exactly that, which is the point.
 */
function makeReplyTextRunner(homeHtml) {
  const start = homeHtml.indexOf('function replyText(data)');
  assert.ok(start !== -1, 'home page should ship a replyText() function');

  let depth = 0;
  let end = -1;
  for (let i = homeHtml.indexOf('{', start); i < homeHtml.length; i += 1) {
    const ch = homeHtml[i];
    if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  assert.ok(end !== -1, 'replyText() body should be brace-balanced so it can be extracted');

  const source = homeHtml.slice(start, end + 1);
  let replyText;
  try {
    // eslint-disable-next-line no-new-func
    replyText = new Function(`${source}; return replyText;`)();
  } catch (err) {
    throw new Error(
      `the home page's inline script does not parse, so every button on it would be dead: ${err.message}\n` +
        `--- extracted source ---\n${source}`
    );
  }
  return (reply) => replyText(reply);
}

/**
 * Parse the whole inline <script> block of the logged-in page.
 *
 * Stronger than the replyText check because it covers the chat handlers and the
 * schema renderer together. A single unescaped '\\n' anywhere in the server-side
 * template literal breaks the entire block at once, taking the logout link's
 * sibling buttons with it - and nothing else in the suite would notice, since the
 * server-rendered HTML is still served fine.
 */
function assertInlineScriptParses(homeHtml) {
  const scripts = homeHtml.match(/<script>([\s\S]*?)<\/script>/g) || [];
  assert.ok(scripts.length, 'the logged-in page should include an inline script');

  for (const tag of scripts) {
    const body = tag.replace(/^<script>/, '').replace(/<\/script>$/, '');
    try {
      // eslint-disable-next-line no-new-func
      new Function(body);
    } catch (err) {
      throw new Error(
        `the logged-in page's inline script does not parse: ${err.message}\n` +
          'This usually means an escape sequence in the server-side template literal was written ' +
          'unescaped, which would leave every button on the page dead in the browser.'
      );
    }
  }
}

/**
 * Execute the home page's client-side renderSchemas() against a sample payload
 * and return the HTML it produces.
 *
 * The renderer lives in a template literal inside server.js, so the only way to
 * actually test it is to extract that function and run it here. Deliberately
 * mirrors the shim in the browser: same escaping, same date formatting, same
 * em dash for missing values.
 */
function renderSchemasHtml(data) {
  const esc = (v) =>
    String(v == null || v === '' ? '' : v)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');

  const fmtDate = (ms) => {
    if (typeof ms !== 'number' || !isFinite(ms) || ms <= 0) return '—';
    const d = new Date(ms);
    if (isNaN(d.getTime())) return '—';
    return d.toLocaleString();
  };

  const rows = (data && data.schemasDetails) || [];
  const total = typeof data.total === 'number' ? data.total : rows.length;

  const head =
    '<tr><th>Schema</th><th>Type</th><th>Owner</th><th>Last modified</th></tr>';
  const body = rows
    .map(
      (s) =>
        '<tr>' +
        `<td>${esc(s.schemaName)}</td>` +
        `<td>${esc(s.schemaType)}</td>` +
        `<td>${esc(s.owner)}</td>` +
        `<td>${esc(fmtDate(s.lastModified))}</td>` +
        '</tr>'
    )
    .join('');

  return head + (body || '<tr><td colspan="4" class="muted">No schemas returned.</td></tr>');
}

/**
 * Exercise resolveTenant()/incortaApiUrl() directly. These read process.env at
 * call time, so each case is isolated by saving and restoring the value.
 */
function testTenantResolution() {
  const original = {
    tenant: process.env.INCORTA_TENANT,
    issuer: process.env.INCORTA_OIDC_ISSUER,
    base: process.env.INCORTA_BASE_URL,
  };
  const { resolveTenant, incortaApiUrl } = require('../lib/oidc-incorta');

  const withEnv = (env, fn) => {
    for (const k of ['INCORTA_TENANT', 'INCORTA_OIDC_ISSUER', 'INCORTA_BASE_URL']) {
      delete process.env[k];
    }
    Object.assign(process.env, env);
    try {
      return fn();
    } finally {
      for (const k of ['INCORTA_TENANT', 'INCORTA_OIDC_ISSUER', 'INCORTA_BASE_URL']) {
        delete process.env[k];
      }
      Object.assign(process.env, original);
    }
  };

  const expectThrows = (env, matcher, label) => {
    try {
      withEnv(env, () => resolveTenant());
    } catch (e) {
      assert.ok(
        matcher.test(e.message),
        `${label}: message should explain the problem. Got: ${e.message}`
      );
      return;
    }
    assert.fail(`${label}: expected resolveTenant() to throw`);
  };

  // Explicit value wins over the issuer's tenant segment
  assert.strictEqual(
    withEnv(
      { INCORTA_TENANT: 'explicit_tenant', INCORTA_OIDC_ISSUER: 'http://x/incorta/oauth/from_issuer' },
      () => resolveTenant()
    ),
    'explicit_tenant',
    'INCORTA_TENANT should override the issuer segment'
  );

  // Fallback to the issuer, including with a trailing slash
  assert.strictEqual(
    withEnv({ INCORTA_OIDC_ISSUER: 'http://x/incorta/oauth/demo_sso' }, () => resolveTenant()),
    'demo_sso',
    'should fall back to the issuer tenant segment'
  );
  assert.strictEqual(
    withEnv({ INCORTA_OIDC_ISSUER: 'http://x/incorta/oauth/demo_sso/' }, () => resolveTenant()),
    'demo_sso',
    'trailing slash in the issuer should not leak into the tenant'
  );

  // Blank/whitespace values fall through to the issuer rather than producing an
  // empty path segment
  assert.strictEqual(
    withEnv(
      { INCORTA_TENANT: '   ', INCORTA_OIDC_ISSUER: 'http://x/incorta/oauth/from_issuer' },
      () => resolveTenant()
    ),
    'from_issuer',
    'a whitespace-only INCORTA_TENANT should fall back to the issuer'
  );

  // Trailing slashes on the base URL must not produce a doubled path separator
  assert.strictEqual(
    withEnv(
      { INCORTA_TENANT: 't1', INCORTA_BASE_URL: 'http://host:8080///' },
      () => incortaApiUrl('/schema/list?schemaType=ALL')
    ),
    'http://host:8080/incorta/api/v2/t1/schema/list?schemaType=ALL',
    'base URL trailing slashes should be normalized'
  );

  expectThrows({}, /tenant is not configured/i, 'nothing configured');
  expectThrows({ INCORTA_TENANT: '../admin' }, /Invalid/, 'path traversal attempt');
  expectThrows({ INCORTA_TENANT: 'a/b' }, /Invalid/, 'slash in tenant');
  expectThrows({ INCORTA_TENANT: 'demo?x=1' }, /Invalid/, 'query string in tenant');
  expectThrows({ INCORTA_TENANT: '.hidden' }, /Invalid/, 'leading dot');
  assert.strictEqual(
    withEnv({ INCORTA_TENANT: 'Demo_Tenant-1.v2' }, () => resolveTenant()),
    'Demo_Tenant-1.v2',
    'mixed case, underscore, hyphen and dot are all valid'
  );

  console.log('✓ tenant resolution: explicit value, issuer fallback, and input validation');
}

function json(res, status, body, headers = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
    ...headers,
  });
  res.end(payload);
}

// ---- Mock Incorta ----
const incorta = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${INCORTA_PORT}`);
  const INCORTA_ISSUER = `http://localhost:${INCORTA_PORT}/incorta/oauth/demo_sso`;

  if (url.pathname === '/incorta/oauth/demo_sso/.well-known/openid-configuration') {
    return json(res, 200, {
      issuer: INCORTA_ISSUER,
      authorization_endpoint: `${INCORTA_ISSUER}/authorize`,
      token_endpoint: `${INCORTA_ISSUER}/token`,
      jwks_uri: `${INCORTA_ISSUER}/jwks`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      grant_types_supported: ['client_credentials'],
    });
  }

  if (url.pathname === '/incorta/oauth/demo_sso/token' && req.method === 'POST') {
    incortaTokenCalls += 1;
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const params = new URLSearchParams(body);
      capturedForUser = params.get('for_user');
      capturedGrantType = params.get('grant_type');
      if (params.get('grant_type') !== 'client_credentials') {
        return json(res, 400, { error: 'invalid_grant' });
      }
      json(res, 200, {
        access_token: 'incorta-access-token',
        token_type: 'Bearer',
        expires_in: 300,
      });
    });
    return;
  }

  // Match any project name. The route's project segment comes from
  // INCORTA_TENANT and changes with the tenant, and hardcoding it here means the
  // mock 404s whenever the env var changes - a failure unrelated to OAuth. The
  // tenant actually requested is captured in capturedIncortaPath.
  if (/^\/incorta\/api\/v2\/[^/]+\/schema\/list$/.test(url.pathname) && req.method === 'POST') {
    capturedIncortaPath = url.pathname;
    capturedAuthHeader = req.headers.authorization;
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const parsed = JSON.parse(body || '{}');
      // Fail the next call on demand, so the error path (which also reports the
      // trace-id) gets covered without needing a second real endpoint.
      if (failNextSchemaList) {
        failNextSchemaList = false;
        return json(
          res,
          500,
          { error: 'Mock Incorta failure' },
          { 'trace-id': INCORTA_ERROR_TRACE_ID }
        );
      }
      // Field names and shapes copied from a real Incorta schema/list response
      // so the UI rendering is exercised against the actual contract:
      //   { limit, offset, total, schemasDetails: [ { schemaID, schemaName,
      //     schemaDescription, schemaType, owner, lastModified, isEmpty,
      //     permission } ] }
      // Note lastModified is epoch MILLISECONDS, not seconds.
      return json(
        res,
        200,
        {
          limit: parsed.limit,
          offset: parsed.offset,
          total: 3,
          schemasDetails: [
            {
              schemaID: 2267,
              schemaName: 'Audit',
              schemaDescription: '',
              schemaType: 'PHYSICAL',
              owner: 'Super User',
              lastModified: 1791123993000,
              isEmpty: false,
              permission: 1,
            },
            {
              schemaID: 2269,
              schemaName: 'HR',
              schemaDescription: '',
              schemaType: 'VIRTUAL',
              owner: 'Super User',
              lastModified: 1791123993000,
              isEmpty: true,
              permission: 1,
            },
            {
              schemaID: 2270,
              schemaName: 'SALES',
              schemaDescription: 'Demo sales data',
              schemaType: 'VIRTUAL',
              owner: 'Someone Else',
              // Missing owner/lastModified on purpose: the UI must not blow up
              // on a sparse row.
              isEmpty: false,
              permission: 1,
            },
          ],
          receivedBody: parsed,
        },
        { 'trace-id': INCORTA_TRACE_ID }
      );
    });
    return;
  }

  // Mock Copilot A2A agent. Records exactly what the route sent so the tests can
  // assert on the request contract (minimal headers, Bearer token, JSON-RPC
  // envelope) and on the conversation id staying stable across messages.
  const a2aMatch = /^\/incorta\/api\/v2\/[^/]+\/copilot\/a2a\/agent\/([^/]+)$/.exec(
    url.pathname
  );
  if (a2aMatch && req.method === 'POST') {
    capturedA2aPath = url.pathname;
    capturedA2aAgent = a2aMatch[1];
    capturedA2aHeaders = req.headers;
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const rpc = JSON.parse(body || '{}');
      // Polled Copilot flow: a non-blocking send, and tasks/get
      if (
        rpc.method === 'tasks/get' ||
        (rpc.method === 'message/send' && !(rpc.params && rpc.params.configuration))
      ) {
        return handleCopilotRpc(rpc, req, res);
      }
      capturedA2aBody = rpc;

      if (failNextChat) {
        failNextChat = false;
        // Incorta reports a missing Copilot entitlement as a 500 with a readable
        // message and a trace-id, so the mock reproduces that real shape rather
        // than a tidy 4xx the app would never have to handle.
        return json(
          res,
          500,
          {
            message:
              'INC_05000301: Runtime exception occurred [You do not have the necessary permissions to access the Copilot.].',
          },
          { 'trace-id': INCORTA_ERROR_TRACE_ID }
        );
      }

      // JSON-RPC 2.0 envelope with the agent's text under result.message.parts,
      // mirroring the shape the real endpoint returns with the message-part
      // extension applied.
      return json(
        res,
        200,
        {
          jsonrpc: '2.0',
          id: capturedA2aBody.id,
          result: {
            role: 'agent',
            parts: [{ kind: 'text', text: `Echo: ${capturedA2aBody.params.message.parts[0].text}` }],
            messageId: 'agent-message-1',
            // Incorta assigns the conversation id on the first message and the
            // client echoes it back afterwards
            contextId: capturedA2aBody.params.contextId || 'ctx-from-incorta',
          },
        },
        { 'trace-id': INCORTA_TRACE_ID }
      );
    });
    return;
  }

  json(res, 404, { error: 'not_found' });
});

// ---- Mock Copilot task flow (non-blocking send + tasks/get) ----
// The message text picks the script, so one mock covers every case:
//   (default) submitted -> working (1 step) -> working (2 steps) -> completed
//   FAIL      -> failed after two polls, error text in status.message
//   NEEDINPUT -> input-required after two polls
//   NEVER     -> working forever
//   RPCERROR  -> a JSON-RPC error object under HTTP 200
//   NOTASK    -> a reply that is not a task
const copilotTasks = new Map();
let copilotSeq = 0;
let copilotReject401Next = false;
let capturedCopilotSend = null;
let capturedCopilotSendHeaders = null;
const copilotPollAuth = [];

function copilotStep(n) {
  return {
    kind: 'message',
    role: 'agent',
    metadata: { step_type: 'reasoning_chain', description: `Step ${n}`, status: 'DONE' },
    parts: [
      {
        kind: 'data',
        data: {
          title: `Step ${n} title`,
          status: 'DONE',
          subtitle: `doing ${n}`,
          output: ['secret-output'],
          metrics: { execution_time_ms: 10 * n },
          error: { message: 'step note', traceback: 'secret-traceback' },
        },
      },
    ],
  };
}

function handleCopilotRpc(rpc, req, res) {
  const headers = { 'trace-id': INCORTA_TRACE_ID };

  if (rpc.method === 'message/send') {
    capturedCopilotSend = rpc;
    capturedCopilotSendHeaders = req.headers;
    const text = rpc.params.message.parts[0].text;

    if (text.includes('RPCERROR')) {
      return json(res, 200, { jsonrpc: '2.0', id: rpc.id, error: { code: -32603, message: 'boom' } }, headers);
    }
    if (text.includes('NOTASK')) {
      return json(res, 200, { jsonrpc: '2.0', id: rpc.id, result: { kind: 'message', parts: [] } }, headers);
    }

    copilotSeq += 1;
    const contextId = rpc.params.contextId || `ctx-${copilotSeq}`;
    const id = `${contextId}_${copilotSeq}`;
    copilotTasks.set(id, { contextId, text, polls: 0 });
    return json(
      res,
      200,
      { jsonrpc: '2.0', id: rpc.id, result: { contextId, id, kind: 'task', status: { state: 'submitted' } } },
      headers
    );
  }

  // tasks/get
  copilotPollAuth.push(req.headers.authorization);
  if (copilotReject401Next) {
    copilotReject401Next = false;
    return json(res, 401, { message: 'token expired' });
  }

  const task = copilotTasks.get(rpc.params.id);
  if (!task) {
    return json(res, 200, { jsonrpc: '2.0', id: rpc.id, error: { code: -32001, message: 'Task not found' } }, headers);
  }

  task.polls += 1;
  const { text, polls } = task;
  const history = [
    { kind: 'message', role: 'user', parts: [{ kind: 'text', text }] },
  ];
  for (let n = 1; n <= Math.min(polls, 2); n += 1) history.push(copilotStep(n));

  const result = {
    id: rpc.params.id,
    contextId: task.contextId,
    kind: 'task',
    artifacts: [],
    history,
    status: { state: 'working' },
  };
  const statusMessage = (t) => ({ kind: 'message', role: 'agent', parts: [{ kind: 'text', text: t }] });

  if (text.includes('FAIL') && polls >= 2) {
    result.status = { state: 'failed', message: statusMessage('litellm.BadRequestError: Operation not allowed') };
  } else if (text.includes('NEEDINPUT') && polls >= 2) {
    result.status = { state: 'input-required', message: statusMessage('Which schema do you mean?') };
  } else if (!/FAIL|NEEDINPUT|NEVER/.test(text) && polls >= 3) {
    result.artifacts = [{ artifactId: 'a1', parts: [{ kind: 'text', text: `Answer to: ${text}` }] }];
    result.status = { state: 'completed', message: statusMessage('Response ready.') };
  }

  return json(res, 200, { jsonrpc: '2.0', id: rpc.id, result }, headers);
}

// ---- Mock Keycloak ----
// Mirrors the two Keycloak behaviors that broke the real login flow:
//   1. discovery advertises `authorization_response_iss_parameter_supported`
//   2. it echoes `iss` back on the redirect ONLY when the client sent `iss` on
//      the authorization request (RFC 9207)
const KC_PORT = Number(process.env.SMOKE_KC_PORT || 19012);
const KC_CLIENT_ID = 'test-kc-client-id';

const keycloak = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${KC_PORT}`);
  const KC_ISSUER = `http://localhost:${KC_PORT}/realms/test`;

  if (url.pathname === '/realms/test/.well-known/openid-configuration') {
    return json(res, 200, {
      issuer: KC_ISSUER,
      authorization_endpoint: `${KC_ISSUER}/protocol/openid-connect/auth`,
      token_endpoint: `${KC_ISSUER}/protocol/openid-connect/token`,
      jwks_uri: `${KC_ISSUER}/protocol/openid-connect/certs`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      // This flag is what makes openid-client REQUIRE iss on the callback
      authorization_response_iss_parameter_supported: true,
      // Deliberately NOT including 'none', because real Keycloak does not list
      // it. Verified against Keycloak 25 realm incorta:
      //   token_endpoint_auth_methods_supported = ['private_key_jwt',
      //     'client_secret_basic', 'client_secret_post', 'tls_client_auth',
      //     'client_secret_jwt']
      // even for a public client, which is inaccurate per RFC 8414 but is what
      // the server sends. A mock that advertised 'none' would hide the real
      // problem: openid-client defaults to client_secret_basic, and its
      // checkBasicSupport() helper only ever falls back to client_secret_post,
      // never to 'none'. So the app has to ask for 'none' explicitly.
      token_endpoint_auth_methods_supported: [
        'private_key_jwt',
        'client_secret_basic',
        'client_secret_post',
        'tls_client_auth',
        'client_secret_jwt',
      ],
    });
  }

  if (url.pathname === '/realms/test/protocol/openid-connect/auth') {
    const state = url.searchParams.get('state');
    const requestedIss = url.searchParams.get('iss');
    const code = `kc-mock-code-${++kcCodeSeq}`;
    kcCodes.set(code, {
      nonce: url.searchParams.get('nonce'),
      state,
      codeChallenge: url.searchParams.get('code_challenge'),
    });
    kcAuthorizeIss = requestedIss;
    // Keycloak only returns `iss` if the client asked for it
    const issParam = requestedIss ? `&iss=${encodeURIComponent(KC_ISSUER)}` : '';
    return res
      .writeHead(302, {
        Location: `http://localhost:${APP_PORT}/callback?code=${encodeURIComponent(
          code
        )}&state=${encodeURIComponent(state)}&session_state=mock-session${issParam}`,
      })
      .end();
  }

  if (url.pathname === '/realms/test/protocol/openid-connect/token' && req.method === 'POST') {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const record = kcCodes.get(params.get('code'));

      // Public client: Keycloak rejects any client authentication as
      // invalid_client. openid-client defaults to client_secret_basic and does
      // not downgrade to "none" by itself, so this also proves the app asks
      // for public-client auth explicitly.
      if (
        params.get('client_secret') ||
        (req.headers.authorization || '').startsWith('Basic ')
      ) {
        return json(res, 401, {
          error: 'invalid_client',
          error_description:
            'Client authentication failed: public client must not authenticate',
        });
      }
      assert.strictEqual(
        params.get('client_id'),
        KC_CLIENT_ID,
        'public client sends client_id in the token request body'
      );

      if (!record) {
        return json(res, 400, {
          error: 'invalid_grant',
          error_description: 'Code not valid',
        });
      }
      if (record.codeChallenge) {
        const verifier = params.get('code_verifier');
        const computed = verifier
          ? base64url(crypto.createHash('sha256').update(verifier).digest())
          : null;
        if (computed !== record.codeChallenge) {
          return json(res, 400, {
            error: 'invalid_request',
            error_description: 'Invalid parameter: code_verifier',
          });
        }
      }
      kcCodes.delete(params.get('code'));
      kcTokenCalls += 1;
      // PKCE is mandatory for this public client
      assert.ok(
        params.get('code_verifier'),
        'token request must include the PKCE code_verifier'
      );
      const idToken = signJwt({
        sub: 'kc-user-456',
        email: 'bob@example.com',
        email_verified: true,
        preferred_username: 'bob',
        aud: KC_CLIENT_ID,
        iss: KC_ISSUER,
        nonce: record.nonce,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      json(res, 200, {
        access_token: 'kc-access-token',
        id_token: idToken,
        refresh_token: 'kc-refresh-token',
        token_type: 'Bearer',
        expires_in: 3600,
        session_state: 'mock-session',
      });
    });
    return;
  }

  if (url.pathname === '/realms/test/protocol/openid-connect/certs') {
    return json(res, 200, JWKS);
  }

  json(res, 404, { error: 'not_found' });
});

const kcCodes = new Map();
let kcCodeSeq = 0;
let kcAuthorizeIss = null;
let kcTokenCalls = 0;

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// How long to wait for a spawned app to answer /health (250ms per attempt).
// Raise SMOKE_STARTUP_MS on a slow or heavily loaded machine.
const STARTUP_ATTEMPTS = Math.ceil((Number(process.env.SMOKE_STARTUP_MS) || 10000) / 250);

/**
 * public/copilot.js pollTask(): the polling rules, with a fake clock and a fake
 * fetch so nothing here waits for real time.
 */
async function testCopilotPolling() {
  const { pollTask } = require('../public/copilot');
  const src = fs.readFileSync(path.join(__dirname, '..', 'public', 'copilot.js'), 'utf8');

  assert.ok(
    !/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(src),
    'copilot.js must insert text only, never HTML'
  );

  // A clock that only moves when the poller sleeps
  const makeClock = () => {
    let t = 0;
    return { now: () => t, sleep: async (ms) => { t += ms; } };
  };
  const view = (state, done = false) => ({ state, done });

  // Stops at the first final view; polls never overlap
  {
    const clock = makeClock();
    const seq = [view('working'), view('working'), view('completed', true)];
    let inFlight = 0;
    let maxInFlight = 0;
    const seen = [];
    const out = await pollTask({
      ...clock,
      intervalMs: 100,
      timeoutMs: 10000,
      fetchView: async () => {
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await Promise.resolve();
        inFlight -= 1;
        return seq.shift();
      },
      onView: (v) => seen.push(v.state),
    });
    assert.deepStrictEqual(seen, ['working', 'working', 'completed']);
    assert.strictEqual(out.view.state, 'completed');
    assert.strictEqual(maxInFlight, 1, 'polls must not overlap');
    assert.strictEqual(clock.now(), 200, 'sleeps between polls only, not after the last');
  }

  // Transient errors (network, 5xx) are retried up to 3 times in a row
  {
    const clock = makeClock();
    let calls = 0;
    const out = await pollTask({
      ...clock,
      intervalMs: 10,
      timeoutMs: 10000,
      fetchView: async () => {
        calls += 1;
        if (calls <= 3) throw Object.assign(new Error('x'), calls === 2 ? { status: 503 } : {});
        return view('completed', true);
      },
      onView: () => {},
    });
    assert.strictEqual(out.view.state, 'completed');

    let failures = 0;
    await assert.rejects(
      pollTask({
        ...clock,
        intervalMs: 10,
        timeoutMs: 10000,
        fetchView: async () => { failures += 1; throw new Error('down'); },
        onView: () => {},
      }),
      /down/
    );
    assert.strictEqual(failures, 4, 'gives up after 3 retries');
  }

  // 401 (and any other 4xx) stops at once
  {
    let calls = 0;
    await assert.rejects(
      pollTask({
        ...makeClock(),
        intervalMs: 10,
        timeoutMs: 10000,
        fetchView: async () => { calls += 1; throw Object.assign(new Error('no'), { status: 401 }); },
        onView: () => {},
      }),
      (e) => e.status === 401
    );
    assert.strictEqual(calls, 1);
  }

  // Wall-clock timeout
  {
    const out = await pollTask({
      ...makeClock(),
      intervalMs: 50,
      timeoutMs: 120,
      fetchView: async () => view('working'),
      onView: () => {},
    });
    assert.strictEqual(out.timedOut, true);
  }

  // Cancelling (Retry / New chat) stops quietly, without rendering the stale result
  {
    let cancelled = false;
    let rendered = 0;
    const out = await pollTask({
      ...makeClock(),
      intervalMs: 10,
      timeoutMs: 10000,
      isCancelled: () => cancelled,
      fetchView: async () => { cancelled = true; return view('working'); },
      onView: () => { rendered += 1; },
    });
    assert.strictEqual(out.cancelled, true);
    assert.strictEqual(rendered, 0);
  }

  console.log('✓ polling: no overlap, stops at a final state, retries transient errors, times out, cancels');
}

/**
 * Runs public/copilot.js against a tiny fake DOM and a scripted fetch, to catch
 * runtime mistakes in the page code (not just syntax errors): sending, polling,
 * rendering steps and the answer, the error card with Retry, and New chat.
 */
async function testCopilotPageFlow() {
  class FakeEl {
    constructor(tag) {
      this.tag = tag;
      this.className = '';
      this.children = [];
      this.listeners = {};
      this.attrs = {};
      this.dataset = {};
      this.hidden = false;
      this.disabled = false;
      this.open = false;
      this.value = '';
      this.own = '';
    }
    set textContent(v) { this.own = String(v); this.children = []; }
    get textContent() { return this.own + this.children.map((c) => c.textContent).join(''); }
    appendChild(c) { this.children.push(c); return c; }
    replaceChildren() { this.children = []; this.own = ''; }
    setAttribute(k, v) { this.attrs[k] = v; }
    addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
    fire(t, ev = {}) { (this.listeners[t] || []).forEach((f) => f({ preventDefault() {}, ...ev })); }
    scrollIntoView() {}
    focus() {}
    find(pred) {
      const out = [];
      const walk = (n) => { if (pred(n)) out.push(n); n.children.forEach(walk); };
      walk(this);
      return out;
    }
  }

  const ids = {};
  ['transcript', 'form', 'input', 'send', 'newChat'].forEach((id) => (ids[id] = new FakeEl(id)));
  const body = new FakeEl('body');
  body.dataset = { pollMs: '1', timeoutMs: '5000' };
  const document = {
    body,
    getElementById: (id) => ids[id],
    createElement: (tag) => new FakeEl(tag),
    createTextNode: (text) => { const n = new FakeEl('#text'); n.textContent = text; return n; },
  };

  // Scripted server
  const sent = [];
  const polls = { n: 0 };
  let nextSend = null; // overrides the next POST /messages response
  const reply = (status, data) => ({ ok: status < 400, status, json: async () => data });
  const fetchStub = async (url, options = {}) => {
    if (options.method === 'POST') {
      sent.push(JSON.parse(options.body));
      if (nextSend) { const r = nextSend; nextSend = null; return r; }
      return reply(200, { taskId: 't1', contextId: 'c1' });
    }
    polls.n += 1;
    const steps = [{ title: 'Looking', status: 'DONE', subtitle: 'around', durationMs: 7 }];
    return polls.n % 2 === 1
      ? reply(200, { taskId: 't1', state: 'working', done: false, steps })
      : reply(200, { taskId: 't1', state: 'completed', done: true, steps, answer: 'the answer', error: null });
  };

  const src = fs.readFileSync(path.join(__dirname, '..', 'public', 'copilot.js'), 'utf8');
  require('vm').runInNewContext(src, {
    document,
    window: { addEventListener() {} },
    fetch: fetchStub,
    setTimeout,
    AbortController,
    console,
  });

  const settle = async (check, what) => {
    for (let i = 0; i < 400; i += 1) {
      if (check()) return;
      await new Promise((r) => setTimeout(r, 5));
    }
    throw new Error(`timed out waiting for: ${what}\n${ids.transcript.textContent}`);
  };
  const ask = (text) => { ids.input.value = text; ids.form.fire('submit'); };
  const cards = (cls) => ids.transcript.find((n) => n.className === cls);

  // 1. Ask, poll, answer
  ask('hello');
  assert.strictEqual(ids.input.disabled, true, 'input is disabled while a task runs');
  await settle(() => cards('card').length === 1, 'the answer card');
  assert.strictEqual(cards('card')[0].textContent, 'the answer');
  assert.ok(ids.transcript.textContent.includes('hello'), 'the user bubble is shown');
  assert.ok(ids.transcript.textContent.includes('Thought for'), 'the Thoughts header is summarised when done');
  assert.strictEqual(ids.input.disabled, false, 'input is enabled again');
  assert.deepStrictEqual(sent[0], { text: 'hello', contextId: null }, 'the first message has no conversation id');

  // 2. The follow-up carries the conversation id the page holds
  ask('again');
  await settle(() => cards('card').length === 2, 'second answer');
  assert.strictEqual(sent[1].contextId, 'c1');

  // 3. An error shows a card with details and Retry; Retry resends and clears it
  nextSend = reply(502, { error: 'boom', traceId: 'tr-9', details: { why: 'x' } });
  ask('third');
  await settle(() => cards('card error').length === 1, 'the error card');
  const errorCard = cards('card error')[0];
  assert.strictEqual(errorCard.attrs.role, 'alert');
  assert.ok(errorCard.textContent.includes('boom'));
  const buttons = errorCard.find((n) => n.tag === 'button');
  assert.deepStrictEqual(buttons.map((b) => b.textContent), ['View Error Details', 'Retry']);
  const detailsPre = errorCard.find((n) => n.tag === 'pre')[0];
  assert.strictEqual(detailsPre.hidden, true);
  buttons[0].fire('click');
  assert.strictEqual(detailsPre.hidden, false, 'View Error Details reveals the details');
  assert.ok(detailsPre.textContent.includes('tr-9'), 'the trace-id is in the details');
  buttons[1].fire('click');
  await settle(() => cards('card error').length === 0 && cards('card').length === 3, 'Retry to succeed');
  assert.strictEqual(sent[sent.length - 1].text, 'third', 'Retry resends the same message');

  // 4. A 401 asks the user to log in again, with no Retry
  nextSend = reply(401, { error: 'Not authenticated' });
  ask('fourth');
  await settle(() => cards('card error').length === 1, 'the 401 card');
  assert.ok(cards('card error')[0].textContent.includes('log in again'));
  assert.deepStrictEqual(
    cards('card error')[0].find((n) => n.tag === 'button').map((b) => b.textContent),
    ['View Error Details']
  );

  // 5. New chat clears the page and starts a fresh conversation
  ids.newChat.fire('click');
  assert.strictEqual(ids.transcript.children.length, 0);
  ask('fresh');
  await settle(() => cards('card').length === 1, 'answer after New chat');
  assert.strictEqual(sent[sent.length - 1].contextId, null, 'a new chat has no conversation id');

  console.log('✓ copilot page: send, poll, steps, answer, error card + Retry, 401, New chat (fake DOM)');
}

/**
 * Task parsing and request building for the polled Copilot page: pure functions,
 * checked against shapes condensed from real Incorta responses.
 */
function testCopilotLib() {
  const fx = require('./fixtures/copilot-tasks');
  const { extractAnswer, toView } = require('../lib/incorta-task-view');
  const { buildMessagePayload } = require('../lib/incorta-a2a');

  // --- extractAnswer: artifacts win; "Response ready." is never the answer ---
  assert.strictEqual(extractAnswer(fx.completed), fx.ANSWER_TEXT);
  assert.strictEqual(extractAnswer({ parts: [{ kind: 'text', text: 'blocking reply' }] }), 'blocking reply');
  assert.strictEqual(
    extractAnswer({ message: { parts: [{ kind: 'text', text: 'from message' }] } }),
    'from message'
  );
  assert.strictEqual(extractAnswer({ status: { message: { parts: [{ kind: 'text', text: 'Response ready.' }] } } }), '');

  // --- toView: completed ---
  const done = toView(fx.completed, 'trace-1');
  assert.strictEqual(done.state, 'completed');
  assert.strictEqual(done.done, true);
  assert.strictEqual(done.answer, fx.ANSWER_TEXT);
  assert.strictEqual(done.error, null, 'a completed task with failed steps is still an answer');
  assert.deepStrictEqual(
    done.steps.map((st) => st.title),
    ['Understanding the question', 'Discovering available data sources']
  );
  assert.deepStrictEqual(done.steps[0], {
    title: 'Understanding the question',
    description: 'Understanding the question',
    status: 'ERROR',
    subtitle: 'Clarifying the ask',
    durationMs: 104,
  });
  const wire = JSON.stringify(done);
  assert.ok(!wire.includes('traceback') && !wire.includes('secret.py'), 'no traceback in the view');
  assert.ok(!wire.includes('Schema discovery failed'), 'step outputs are not forwarded');
  assert.ok(!wire.includes('Response ready'), 'status.message is not shown');

  // --- toView: working ---
  const run = toView(fx.working);
  assert.strictEqual(run.state, 'working');
  assert.strictEqual(run.done, false);
  assert.strictEqual(run.steps.length, 1);
  assert.strictEqual(run.answer, '');

  // --- toView: failed uses status.message, then the last step error ---
  const bad = toView(fx.failed, 'trace-2');
  assert.strictEqual(bad.done, true);
  assert.strictEqual(bad.error.message, 'litellm.BadRequestError: Operation not allowed');
  assert.strictEqual(bad.error.traceId, 'trace-2');
  const noText = toView({ ...fx.failed, status: { state: 'failed' } });
  assert.strictEqual(noText.error.message, 'No relevant tables were found for your question.');

  // --- toView: other states ---
  assert.strictEqual(toView({ id: 'x', status: { state: 'input-required' } }).done, true);
  assert.strictEqual(toView({ id: 'x', status: { state: 'submitted' } }).done, false);
  assert.strictEqual(toView({ id: 'x', status: { state: 'completed' } }).answer, 'No answer returned.');
  assert.strictEqual(toView(undefined).state, 'unknown');

  // --- request building: blocking option and model key ---
  const saved = {};
  const setEnv = (k, v) => {
    if (!(k in saved)) saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  };
  try {
    const base = { text: 'hi', messageId: 'm', rpcId: 1 };

    setEnv('INCORTA_A2A_MODEL_KEY', undefined);
    const blocking = buildMessagePayload(base);
    assert.deepStrictEqual(blocking.params.configuration, { blocking: true });
    assert.ok(!('params' in blocking.params.message.metadata.conversation_context.client_context));

    const poll = buildMessagePayload({ ...base, blocking: false });
    assert.ok(!('configuration' in poll.params), 'a polled message sends no configuration');

    setEnv('INCORTA_A2A_MODEL_KEY', 'claude-opus-5-5');
    assert.deepStrictEqual(
      buildMessagePayload(base).params.message.metadata.conversation_context.client_context.params,
      [{ key: 'model_key', value: 'claude-opus-5-5' }],
      'model_key is sent when configured, for both modes'
    );
    assert.deepStrictEqual(
      buildMessagePayload({ ...base, blocking: false }).params.message.metadata.conversation_context
        .client_context.params,
      [{ key: 'model_key', value: 'claude-opus-5-5' }]
    );
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
  console.log('✓ task view, answer extraction, blocking option and model_key');
}

/**
 * lib/incorta-a2a-client: returns a plain result for 2xx and 4xx/5xx alike
 * (it must not throw on an error status) and logs both bodies.
 */
async function testA2aClient() {
  const keys = ['INCORTA_BASE_URL', 'INCORTA_TENANT'];
  const saved = {};
  keys.forEach((k) => (saved[k] = process.env[k]));
  process.env.INCORTA_BASE_URL = `http://localhost:${INCORTA_PORT}`;
  process.env.INCORTA_TENANT = SMOKE_INCORTA_TENANT;

  const logged = [];
  const origLog = console.log;
  console.log = (...args) => logged.push(args.join(' '));

  try {
    const { sendMessage } = require('../lib/incorta-a2a-client');
    const args = {
      accessToken: 'incorta-access-token',
      text: 'unit hello',
      messageId: 'm-1',
      contextId: 'c-1',
      rpcId: 7,
    };

    const ok = await sendMessage(args);
    assert.strictEqual(ok.status, 200);
    assert.strictEqual(ok.traceId, INCORTA_TRACE_ID);
    assert.strictEqual(ok.payload.id, 7);
    assert.strictEqual(ok.data.result.parts[0].text, 'Echo: unit hello');
    assert.ok(ok.url.includes(`/${SMOKE_INCORTA_TENANT}/copilot/a2a/agent/`));
    assert.ok(Number.isFinite(ok.durationMs));

    failNextChat = true;
    const failed = await sendMessage(args);
    assert.strictEqual(failed.status, 500, 'an error status is returned, not thrown');
    assert.strictEqual(failed.traceId, INCORTA_ERROR_TRACE_ID);
    assert.ok(String(failed.data.message).includes('INC_05000301'));

    const out = logged.join('\n');
    assert.ok(out.includes('Incorta A2A request body:') && out.includes('unit hello'));
    assert.ok(out.includes('Incorta A2A response body (200') && out.includes('Echo: unit hello'));
    assert.ok(out.includes('Incorta A2A response body (500'), 'error bodies are logged too');
    assert.ok(!out.includes('incorta-access-token'), 'the bearer token must not be logged');
  } finally {
    console.log = origLog;
    keys.forEach((k) => {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    });
  }
  console.log('✓ A2A client returns error statuses without throwing and logs both bodies');
}

/**
 * Generic OIDC client settings: label, scopes and the email claim are all
 * configurable, so the same client works for providers that do not use `email`.
 */
function testOidcProviderConfig() {
  const saved = {};
  const keys = ['OIDC_EMAIL_CLAIM', 'OIDC_PROVIDER_LABEL', 'OIDC_SCOPES'];
  keys.forEach((k) => {
    saved[k] = process.env[k];
    delete process.env[k];
  });
  try {
    const { OIDCProviderClient } = require('../lib/oidc-provider');
    const tokenSet = {
      claims: () => ({ email: 'a@example.com', upn: 'upn@example.com' }),
    };

    const def = new OIDCProviderClient();
    assert.strictEqual(def.label, 'SSO', 'label should default to SSO');
    assert.strictEqual(def.getUserEmail(tokenSet), 'a@example.com');
    assert.deepStrictEqual(def.scopes, ['openid', 'profile', 'email']);

    process.env.OIDC_EMAIL_CLAIM = 'upn';
    process.env.OIDC_PROVIDER_LABEL = 'Okta';
    const custom = new OIDCProviderClient();
    assert.strictEqual(custom.label, 'Okta');
    assert.strictEqual(custom.getUserEmail(tokenSet), 'upn@example.com');
    assert.strictEqual(custom.getUserEmail({ claims: () => null }), null);
    console.log('✓ OIDC client honours OIDC_PROVIDER_LABEL and OIDC_EMAIL_CLAIM');
  } finally {
    keys.forEach((k) => {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    });
  }
}

/**
 * Chat request construction: header set, JSON-RPC envelope.
 *
 * Pure functions, so this needs no server. The header assertions matter most
 * here: the point of the endpoint is that only the API contract and the Bearer
 * token are sent, so a test pins that down.
 */
function testA2aRequestBuilding() {
  const {
    buildMessagePayload,
    buildHeaders,
    buildConversationContext,
    agentUrl,
    DEFAULT_EXTENSIONS,
  } = require('../lib/incorta-a2a');

  const saved = {};
  const setEnv = (values) => {
    for (const [k, v] of Object.entries(values)) {
      // Capture the ORIGINAL value only once. Re-saving on every call would let
      // the last value assigned win in restore(), leaking test values into the
      // rest of the suite - and this process's env is inherited by the server it
      // spawns.
      if (!(k in saved)) saved[k] = process.env[k];
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  };
  const restore = () => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  };

  try {
    setEnv({ INCORTA_BASE_URL: 'http://localhost', INCORTA_TENANT: 'demo_keycloak' });

    // --- headers: only accept, content-type, authorization, x-a2a-extensions ---
    setEnv({ INCORTA_A2A_EXTENSIONS: undefined });
    const headers = buildHeaders('incorta-access-token');
    assert.strictEqual(
      headers.authorization,
      'Bearer incorta-access-token',
      'the Bearer token must be the Incorta access token'
    );
    assert.strictEqual(headers.accept, 'application/json');
    assert.strictEqual(headers['content-type'], 'application/json');
    assert.strictEqual(
      headers['x-a2a-extensions'],
      DEFAULT_EXTENSIONS.join(', '),
      'unset extensions should use the defaults'
    );

    // The browser-only headers from the original curl must not leak through:
    // they describe the page that made the request, not the API contract.
    for (const forbidden of [
      'user-agent',
      'origin',
      'referer',
      'cookie',
      'sec-fetch-site',
      'sec-fetch-mode',
      'sec-fetch-dest',
      'sec-ch-ua',
      'sec-ch-ua-mobile',
      'sec-ch-ua-platform',
      'accept-language',
      'cache-control',
      'pragma',
      'connection',
      // XSRF guards Incorta's cookie-authenticated UI; this call is
      // Bearer-authenticated and holds no cookies, so it is not forwarded.
      'x-xsrf-token',
    ]) {
      assert.ok(
        !(forbidden in headers),
        `browser-only header "${forbidden}" must not be sent to the A2A endpoint`
      );
    }

    // Only the four documented headers, so nothing sneaks in later
    assert.deepStrictEqual(
      Object.keys(headers).sort(),
      ['accept', 'authorization', 'content-type', 'x-a2a-extensions'],
      `unexpected header set: ${Object.keys(headers).join(', ')}`
    );

    // --- extensions: explicit value overrides, empty value sends none ---
    setEnv({ INCORTA_A2A_EXTENSIONS: 'https://example.com/ext/a, https://example.com/ext/b' });
    assert.strictEqual(
      buildHeaders('t')['x-a2a-extensions'],
      'https://example.com/ext/a, https://example.com/ext/b',
      'a configured extension list should be sent verbatim'
    );

    setEnv({ INCORTA_A2A_EXTENSIONS: '' });
    assert.ok(
      !('x-a2a-extensions' in buildHeaders('t')),
      'an explicitly empty extension list should send no header at all'
    );

    // --- conversation context ---
    setEnv({ INCORTA_A2A_VERBOSITY: 'detailed' });
    const ctx = buildConversationContext();
    assert.strictEqual(ctx.client, 'general');
    assert.strictEqual(ctx.client_context.verbosity, 'detailed');
    assert.strictEqual(ctx.client_context.enable_summary, true);
    // current_date must be stamped now, not cached, or the agent resolves
    // relative dates ("last quarter") against the wrong day
    assert.ok(
      /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(ctx.current_date),
      `current_date should be YYYY-MM-DD HH:MM:SS, got ${ctx.current_date}`
    );

    setEnv({ INCORTA_A2A_ENABLE_SUMMARY: 'false' });
    assert.strictEqual(
      buildConversationContext().client_context.enable_summary,
      false,
      'enable_summary=false should disable the summary'
    );

    // --- JSON-RPC envelope ---
    const body = buildMessagePayload({
      text: 'hi',
      messageId: 'mid-1',
      contextId: 'cid-1',
      rpcId: 7,
    });
    assert.strictEqual(body.jsonrpc, '2.0');
    assert.strictEqual(body.method, 'message/send');
    assert.ok(!('blocking' in body), 'no top-level blocking flag');
    assert.deepStrictEqual(
      body.params.configuration,
      { blocking: true },
      'params.configuration should request a blocking call'
    );
    assert.deepStrictEqual(
      Object.keys(body),
      ['jsonrpc', 'method', 'params', 'id'],
      'envelope keys should match the Copilot UI request'
    );
    assert.strictEqual(body.id, 7, 'the JSON-RPC id should be passed through');
    assert.strictEqual(body.params.contextId, 'cid-1');
    assert.strictEqual(body.params.message.messageId, 'mid-1');
    assert.strictEqual(body.params.message.role, 'user');
    assert.strictEqual(body.params.message.kind, 'message');
    assert.deepStrictEqual(body.params.message.parts, [{ kind: 'text', text: 'hi' }]);
    assert.ok(
      !('contextId' in buildMessagePayload({ text: 'hi', messageId: 'm', rpcId: 1 }).params),
      'the first message carries no contextId'
    );
    assert.ok(
      body.params.message.metadata.conversation_context,
      'the message should carry conversation_context metadata'
    );

    // --- agent URL uses the configured tenant and agent name ---
    setEnv({ INCORTA_BASE_URL: 'http://localhost', INCORTA_TENANT: 'demo_keycloak' });
    assert.strictEqual(
      agentUrl(),
      'http://localhost/incorta/api/v2/demo_keycloak/copilot/a2a/agent/smart-agent',
      'the agent URL should follow the tenant from config'
    );
    setEnv({ INCORTA_A2A_AGENT: 'other-agent' });
    assert.ok(
      agentUrl().endsWith('/copilot/a2a/agent/other-agent'),
      'the agent name should be configurable'
    );
    setEnv({ INCORTA_A2A_AGENT: '../admin' });
    assert.throws(
      () => agentUrl(),
      /Invalid Incorta A2A agent/,
      'a traversal attempt in the agent name must be rejected, since it becomes a URL path segment'
    );
  } finally {
    restore();
  }

  console.log('✓ A2A request sends only accept/content-type/authorization + extensions');
  console.log('✓ A2A request body is a JSON-RPC message/send envelope');
  console.log('✓ A2A extensions, agent name and conversation context are configurable');
}

// Pure config logic, so it runs before any server is spawned
testTenantResolution();
testA2aRequestBuilding();
testTokenLogging();

/**
 * Spawn server.js with the given env overrides, wait for /health, and return
 * `{ app, getLog }`. `unset` names env vars to delete, which matters because the
 * test process inherits a developer's real .env - a stray OIDC_ISSUER would
 * make the "Keycloak disabled" case pass for the wrong reason.
 */
/**
 * Access token logging: masked by default, full only when LOG_ACCESS_TOKENS is
 * set. Run as a unit check because the flag is read at call time and switching
 * it needs no server.
 */
function testTokenLogging() {
  const { logAccessToken, maskToken, isTokenLoggingEnabled } = require('../lib/log-tokens');

  const original = process.env.LOG_ACCESS_TOKENS;
  const lines = [];
  const realLog = console.log;
  const realWarn = console.warn;
  console.log = (...args) => lines.push(args.join(' '));
  console.warn = (...args) => lines.push(args.join(' '));

  try {
    // --- masking shape ---
    const long = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const masked = maskToken(long);
    assert.ok(!masked.includes('ghijklmnop'), 'mask must drop the middle of the token');
    assert.ok(masked.includes('abcdef'), 'mask keeps a short prefix');
    assert.ok(masked.includes('6789'), 'mask keeps a short suffix');
    assert.ok(masked.includes('36 chars'), 'mask reports the length');
    // A short value must not be printed whole, since prefix+suffix would cover it.
    // Note: assert on a value that does not appear in the masker's own wording.
    assert.ok(
      !maskToken('zyxwvu').includes('zyxwvu'),
      `a short token must not be printed in full by the masker, got: ${maskToken('zyxwvu')}`
    );
    assert.ok(
      maskToken('zyxwvu').includes('too short to mask'),
      'short tokens should be reported as such'
    );

    // --- disabled: masked only ---
    delete process.env.LOG_ACCESS_TOKENS;
    assert.strictEqual(isTokenLoggingEnabled(), false);
    lines.length = 0;
    logAccessToken('Incorta', long, { for_user: 'a@b.com' });
    const off = lines.join('\n');
    assert.ok(!off.includes(long), `default must not log the raw token: ${off}`);
    assert.ok(off.includes('Incorta'), 'label should be present');
    assert.ok(off.includes('abcdef'), 'masked fingerprint should be present');
    assert.ok(off.includes('for_user=a@b.com'), 'context should be present');
    assert.ok(
      off.includes('LOG_ACCESS_TOKENS=true'),
      'default output should say how to get the full token'
    );

    // --- enabled: full token ---
    for (const value of ['true', 'TRUE', '1', 'yes', 'on']) {
      process.env.LOG_ACCESS_TOKENS = value;
      assert.strictEqual(
        isTokenLoggingEnabled(),
        true,
        `${value} should count as enabled`
      );
    }
    for (const value of ['false', '0', 'no', '', '  ', 'maybe']) {
      process.env.LOG_ACCESS_TOKENS = value;
      assert.strictEqual(
        isTokenLoggingEnabled(),
        false,
        `${JSON.stringify(value)} should not count as enabled`
      );
    }

    process.env.LOG_ACCESS_TOKENS = 'true';
    lines.length = 0;
    logAccessToken('SSO', long, { user: 'a@b.com' });
    const on = lines.join('\n');
    assert.ok(on.includes(long), `enabled must log the raw token: ${on}`);
    assert.ok(on.includes('SSO'), 'label should be present');

    // --- falsy inputs are ignored rather than printed as "undefined" ---
    lines.length = 0;
    logAccessToken('Incorta', undefined);
    logAccessToken('Incorta', '');
    assert.strictEqual(
      lines.length,
      0,
      `a missing token should log nothing. Got: ${lines.join('\n')}`
    );
  } finally {
    if (original === undefined) delete process.env.LOG_ACCESS_TOKENS;
    else process.env.LOG_ACCESS_TOKENS = original;
    console.log = realLog;
    console.warn = realWarn;
  }

  console.log('✓ access tokens are masked by default and only printed in full when opted in');
}

/**
 * Kill a spawned server.js and resolve once it is actually gone. A fixed sleep
 * is a race: the next listen() can still hit EADDRINUSE.
 */
function stopApp(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    child.once('exit', resolve);
    child.kill();
  });
}

async function startApp({ port, env = {}, unset = [], isolateEnv = false }) {
  const childEnv = { ...process.env, ...env };
  for (const k of unset) delete childEnv[k];

  // server.js calls require('dotenv').config(), which reads ./.env relative to
  // ITS OWN cwd and fills in anything missing from childEnv. Deleting a var is
  // therefore not enough to simulate "unconfigured" - dotenv would put the
  // developer's real OIDC_* back. Running from a directory with no .env
  // makes childEnv the only source of config, which is what these cases need.
  // server.js is referenced by absolute path, so cwd does not affect module
  // resolution.
  let cwd;
  if (isolateEnv) {
    cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'smoke-noenv-'));
  }

  const child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: childEnv,
    stdio: ['ignore', 'pipe', 'pipe'],
    ...(cwd ? { cwd } : {}),
  });

  let log = '';
  child.stdout.on('data', (d) => (log += d.toString()));
  child.stderr.on('data', (d) => (log += d.toString()));

  let up = false;
  for (let i = 0; i < STARTUP_ATTEMPTS && !up; i += 1) {
    await wait(250);
    try {
      const r = await fetch(`http://localhost:${port}/health`);
      up = r.ok;
    } catch (e) {
      /* not up yet */
    }
  }
  if (!up) {
    child.kill();
    throw new Error(`app on :${port} never became healthy. Log:\n${log}`);
  }

  return { app: child, getLog: () => log };
}

/**
 * The logged-out page must offer only the providers that are actually usable.
 *
 * Uses the same readiness signal the login routes enforce (the discovered
 * openid-client), so a button can never link to a route that would 503.
 */
async function testLoginButtonVisibility() {
  // Distinct port from the main app, which is still running for the rest of the
  // suite at this point.
  // Reuses APP_PORT: the main app is stopped before this runs
  const port = APP_PORT;
  const common = {
    INCORTA_OIDC_ISSUER: `http://localhost:${INCORTA_PORT}/incorta/oauth/demo_sso`,
    INCORTA_CLIENT_ID: 'incorta-client-id',
    INCORTA_CLIENT_SECRET: 'incorta-client-secret',
    INCORTA_BASE_URL: `http://localhost:${INCORTA_PORT}`,
  };
  const baseEnv = {
    ...common,
    APP_PORT: String(port),
    APP_BASE_URL: `http://localhost:${port}`,
    SESSION_SECRET: 'smoke-test-secret',
  };

  const buttonsIn = (html) =>
    (html.match(/href="\/login[^"]*">Login with [^<]*<\/a>/g) || []).sort();

  // Case 1: Keycloak configured and reachable -> its button
  {
    const { app, getLog } = await startApp({
      port,
      env: {
        ...baseEnv,
        OIDC_ISSUER: `http://localhost:${KC_PORT}/realms/test`,
        OIDC_CLIENT_ID: KC_CLIENT_ID,
        OIDC_CLIENT_SECRET: '',
      },
      isolateEnv: true,
    });
    const html = await (await fetch(`http://localhost:${port}/`)).text();
    const buttons = buttonsIn(html);
    assert.strictEqual(
      buttons.length,
      1,
      `the Keycloak button expected when Keycloak works. Got: ${JSON.stringify(buttons)}\n${getLog()}`
    );
    assert.ok(
      buttons.some((b) => b.includes('href="/login"') && b.includes('Login with SSO')),
      `Keycloak button expected. Got: ${JSON.stringify(buttons)}`
    );
    console.log('✓ the Keycloak login button shows when Keycloak is configured');
    await stopApp(app);
  }

  // Case 2: Keycloak not configured at all -> no buttons. env is cleared
  // explicitly so an inherited real OIDC_* cannot mask the behavior.
  {
    const { app, getLog } = await startApp({
      port,
      env: baseEnv,
      unset: ['OIDC_ISSUER', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET', 'OIDC_SCOPES'],
      isolateEnv: true,
    });
    const html = await (await fetch(`http://localhost:${port}/`)).text();
    const buttons = buttonsIn(html);
    assert.strictEqual(
      buttons.length,
      0,
      `no login button should be offered. Got: ${JSON.stringify(buttons)}\n${getLog()}`
    );
    assert.ok(
      !html.includes('/login'),
      'the Keycloak button should be absent entirely, not just unlinked'
    );
    assert.ok(
      html.includes('No login provider is configured'),
      'page should say no login provider is configured'
    );
    console.log('✓ no login button shows when Keycloak is not configured');

    // The route still exists and still reports 503, so a bookmarked URL is a
    // clear error rather than a silent 404.
    const kcRoute = await fetch(`http://localhost:${port}/login`, {
      redirect: 'manual',
    });
    assert.strictEqual(
      kcRoute.status,
      503,
      'the Keycloak route should still answer 503 when unconfigured'
    );
    await stopApp(app);
  }

  // Case 3: Keycloak configured but unreachable -> no buttons. This
  // is the case a config-only check would get wrong.
  {
    const { app, getLog } = await startApp({
      port,
      env: {
        ...baseEnv,
        // Nothing is listening here, so discovery fails at startup
        OIDC_ISSUER: 'http://localhost:1/realms/unreachable',
        OIDC_CLIENT_ID: KC_CLIENT_ID,
        OIDC_CLIENT_SECRET: '',
      },
      isolateEnv: true,
    });
    const html = await (await fetch(`http://localhost:${port}/`)).text();
    const buttons = buttonsIn(html);
    assert.strictEqual(
      buttons.length,
      0,
      `a failed Keycloak discovery should hide its button. Got: ${JSON.stringify(buttons)}\n${getLog()}`
    );
    assert.ok(
      getLog().includes('/login will return 503'),
      `startup should still warn about the broken Keycloak config. Log:\n${getLog()}`
    );
    console.log('✓ an unreachable Keycloak hides its button instead of linking to a 503');
    await stopApp(app);
  }
}

async function main() {
  await new Promise((r) => incorta.listen(INCORTA_PORT, r));
  await new Promise((r) => keycloak.listen(KC_PORT, r));
  console.log(
    `✓ mock Incorta on :${INCORTA_PORT}, mock Keycloak on :${KC_PORT}`
  );

  const app = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: {
      ...process.env,
      APP_PORT: String(APP_PORT),
      APP_BASE_URL: `http://localhost:${APP_PORT}`,
      SESSION_SECRET: 'smoke-test-secret',
      INCORTA_OIDC_ISSUER: `http://localhost:${INCORTA_PORT}/incorta/oauth/demo_sso`,
      INCORTA_CLIENT_ID: 'incorta-client-id',
      INCORTA_CLIENT_SECRET: 'incorta-client-secret',
      INCORTA_BASE_URL: `http://localhost:${INCORTA_PORT}`,
      // The tenant must come from config now, not be hardcoded in the route
      INCORTA_TENANT: SMOKE_INCORTA_TENANT,
      INCORTA_A2A_MODEL_KEY: 'test-model',
      OIDC_ISSUER: `http://localhost:${KC_PORT}/realms/test`,
      OIDC_CLIENT_ID: KC_CLIENT_ID,
      OIDC_CLIENT_SECRET: '',
      OIDC_SCOPES: 'openid profile email',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let appLog = '';
  app.stdout.on('data', (d) => (appLog += d.toString()));
  app.stderr.on('data', (d) => (appLog += d.toString()));

  const shutdown = () => {
    app.kill();
    incorta.close();
    keycloak.close();
  };
  process.on('exit', shutdown);

  let up = false;
  for (let i = 0; i < STARTUP_ATTEMPTS && !up; i += 1) {
    await wait(250);
    try {
      const r = await fetch(`http://localhost:${APP_PORT}/health`);
      up = r.ok;
    } catch (e) {
      /* not up yet */
    }
  }
  if (!up) {
    console.error('✗ app never became healthy. Log:\n' + appLog);
    process.exit(1);
  }
  console.log('✓ app started and healthy');
  console.log(`--- app log ---\n${appLog.trim()}\n----------------`);

  // 1. Unauthenticated API call must be rejected
  const unauth = await fetch(`http://localhost:${APP_PORT}/api/incorta/schemas/list`, {
    method: 'POST',
  });
  assert.strictEqual(unauth.status, 401, 'unauthenticated request should be 401');
  console.log('✓ unauthenticated API call correctly returns 401');

  // 2. Login flow with a cookie jar
  const jar = [];
  const storeCookies = (res) => {
    const set = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    set.forEach((c) => jar.push(c.split(';')[0]));
  };
  const cookieHeader = () => jar.join('; ');

  const login = await fetch(`http://localhost:${APP_PORT}/login`, {
    redirect: 'manual',
  });
  storeCookies(login);
  assert.strictEqual(login.status, 302, '/login should redirect');
  const authUrl = login.headers.get('location');
  assert.ok(authUrl.includes('/protocol/openid-connect/auth'), 'should redirect to Keycloak authorize');
  const scopeParam = new URL(authUrl).searchParams.get('scope');
  assert.strictEqual(
    scopeParam,
    'openid profile email',
    `should request openid profile email, got: ${scopeParam}`
  );
  assert.ok(authUrl.includes('code_challenge='), 'should send a PKCE challenge');
  assert.ok(authUrl.includes('code_challenge_method=S256'), 'should use S256 PKCE');
  console.log('✓ /login redirects to Keycloak with scopes openid profile email + PKCE');

  // A code_challenge was sent on authorize, so the token request MUST carry a
  // matching code_verifier.
  const sentChallenge = new URL(authUrl).searchParams.get('code_challenge');
  assert.ok(sentChallenge, 'authorize request must include a PKCE code_challenge');

  // The authorize request must ask for iss (RFC 9207), otherwise Keycloak
  // omits it from the redirect and openid-client rejects the callback.
  assert.strictEqual(
    new URL(authUrl).searchParams.get('iss'),
    `http://localhost:${KC_PORT}/realms/test`,
    'authorize request must send iss for an RFC 9207 issuer'
  );

  // 3. Keycloak -> /callback, echoing iss because we asked for it
  const kcRedirect = await fetch(authUrl, { redirect: 'manual' });
  assert.strictEqual(kcRedirect.status, 302, 'Keycloak should redirect back');
  const callbackUrl = new URL(kcRedirect.headers.get('location'));
  assert.strictEqual(callbackUrl.pathname, '/callback');
  assert.strictEqual(
    callbackUrl.searchParams.get('iss'),
    `http://localhost:${KC_PORT}/realms/test`,
    'Keycloak should echo iss on the redirect'
  );
  console.log('✓ Keycloak redirects back to /callback with code + iss');

  // 4. Code exchange (validates the real RS256 signature)
  const callback = await fetch(callbackUrl.toString(), {
    redirect: 'manual',
    headers: { cookie: cookieHeader() },
  });
  storeCookies(callback);
  assert.strictEqual(
    callback.status,
    302,
    `callback should redirect to /, got ${callback.status}. Log:\n${appLog}`
  );
  console.log('✓ code exchanged for tokens, PKCE verifier + signature + nonce validated');

  // The token endpoint enforces PKCE, so reaching this point proves the
  // code_verifier actually arrived on the wire.
  assert.strictEqual(
    kcCodes.size,
    0,
    'the authorization code should have been consumed by the exchange'
  );
  console.log('✓ token request carried a valid code_verifier (enforced by mock IdP)');

  // 5. Session knows the user
  const me = await fetch(`http://localhost:${APP_PORT}/me`, {
    headers: { cookie: cookieHeader() },
  });
  const meBody = await me.json();
  assert.strictEqual(meBody.authenticated, true, 'session should be authenticated');
  assert.strictEqual(meBody.user.email, 'bob@example.com', 'email claim should be captured');
  assert.strictEqual(meBody.user.provider, 'oidc', 'session should record the provider');
  console.log(`✓ /me reports authenticated user: ${meBody.user.email}`);

  // 6. Home page shows the logged-in state
  const home = await fetch(`http://localhost:${APP_PORT}/`, {
    headers: { cookie: cookieHeader() },
  });
  const homeHtml = await home.text();
  assert.ok(homeHtml.includes('bob@example.com'), 'home page should show the email');
  assert.ok(!homeHtml.includes('Login with SSO'), 'home page should not show login button');
  assert.ok(homeHtml.includes('Chat with Incorta Copilot'), 'home page should show the chat window');
  assert.ok(
    homeHtml.includes("/api/incorta/chat"),
    'the chat window should post to the server-side chat route'
  );
  assert.ok(
    !homeHtml.includes('incorta-access-token') && !homeHtml.includes('authorization:'),
    'the chat window must not contain a token or an Authorization header value'
  );
  console.log('✓ home page renders the logged-in state');

  // 7. Call the Incorta API
  const apiRes = await fetch(`http://localhost:${APP_PORT}/api/incorta/schemas/list`, {
    method: 'POST',
    headers: { cookie: cookieHeader() },
  });
  const apiBody = await apiRes.json();
  assert.strictEqual(
    apiRes.status,
    200,
    `Incorta API call should succeed, got ${apiRes.status}: ${JSON.stringify(apiBody)}`
  );
  // Incorta's real response shape: rows live in `schemasDetails`, not `data`.
  assert.ok(
    Array.isArray(apiBody.schemasDetails),
    `response should include schemasDetails array, got keys: ${Object.keys(apiBody)}`
  );
  assert.strictEqual(apiBody.total, 3, 'total should be the unpaginated row count');
  assert.deepStrictEqual(
    apiBody.receivedBody,
    { limit: 0, offset: 0, sortBy: 'NAME_ASC' },
    'request body should match the curl example'
  );
  console.log('✓ Incorta schema list API returned data with the exact curl request body');

  // 7a. Chat: the request contract the A2A endpoint depends on
  const chatRes = await fetch(`http://localhost:${APP_PORT}/api/incorta/chat`, {
    method: 'POST',
    headers: { cookie: cookieHeader(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: 'hi' }),
  });
  const chatBody = await chatRes.json();
  assert.strictEqual(
    chatRes.status,
    200,
    `chat call should succeed, got ${chatRes.status}: ${JSON.stringify(chatBody)}`
  );

  assert.ok(
    capturedA2aPath &&
      capturedA2aPath.includes('/copilot/a2a/agent/smart-agent') &&
      capturedA2aPath.includes(SMOKE_INCORTA_TENANT),
    `agent URL should use the tenant from config, got ${capturedA2aPath}`
  );
  assert.strictEqual(capturedA2aAgent, 'smart-agent', 'agent name should come from config');

  // Only the API contract plus the Bearer token, and it must be the Incorta
  // token from the client_credentials exchange - not the user's IdP token.
  assert.strictEqual(
    capturedA2aHeaders.authorization,
    'Bearer incorta-access-token',
    'the A2A call must carry the Incorta access token'
  );
  // These must not be forwarded. Note user-agent is checked for the BROWSER's
  // signature, not its absence: axios always stamps its own User-Agent, and that
  // is harmless. What must not happen is the Chrome string from the original curl
  // being replayed.
  assert.ok(
    !/Chrome|Safari|Macintosh|AppleWebKit/i.test(capturedA2aHeaders['user-agent'] || ''),
    `the browser's User-Agent must not be forwarded, got ${capturedA2aHeaders['user-agent']}`
  );
  for (const forbidden of [
    'origin',
    'referer',
    'cookie',
    'sec-fetch-site',
    'sec-fetch-mode',
    'sec-fetch-dest',
    'sec-ch-ua',
    'sec-ch-ua-mobile',
    'sec-ch-ua-platform',
    'accept-language',
    'cache-control',
    'pragma',
    // XSRF guards Incorta's cookie-authenticated UI; this call is
    // Bearer-authenticated and holds no cookies, so there is nothing to protect.
    'x-xsrf-token',
  ]) {
    assert.ok(
      !capturedA2aHeaders[forbidden],
      `browser-only header "${forbidden}" must not reach Incorta`
    );
  }
  assert.ok(
    capturedA2aHeaders['x-a2a-extensions'],
    'the x-a2a-extensions header should still be sent'
  );

  // JSON-RPC envelope, matching the documented request
  assert.strictEqual(capturedA2aBody.jsonrpc, '2.0');
  assert.strictEqual(capturedA2aBody.method, 'message/send');
  assert.ok(!('blocking' in capturedA2aBody), 'no top-level blocking flag');
  assert.deepStrictEqual(
    capturedA2aBody.params.configuration,
    { blocking: true },
    'params.configuration.blocking should be sent'
  );
  assert.ok(!('contextId' in capturedA2aBody.params), 'first message carries no contextId');
  assert.deepStrictEqual(capturedA2aBody.params.message.parts, [
    { kind: 'text', text: 'hi' },
  ]);
  assert.ok(
    capturedA2aBody.params.message.metadata.conversation_context,
    'conversation_context should be sent with the message'
  );
  assert.strictEqual(capturedA2aBody.params.message.metadata.conversation_context.client, 'general');

  // The route passes the reply through and reports the trace-id for support
  assert.strictEqual(chatBody.reply.jsonrpc, '2.0', 'the JSON-RPC reply should be passed through');
  assert.strictEqual(chatBody.traceId, INCORTA_TRACE_ID, 'the trace-id should be reported');
  assert.ok(chatBody.contextId, 'the conversation id should be returned for the client');
  assert.ok(
    chatBody.reply.result.parts[0].text === 'Echo: hi',
    `agent reply should reach the client, got ${JSON.stringify(chatBody.reply)}`
  );
  console.log('✓ chat posts a JSON-RPC message/send with only the Incorta Bearer token');

  // Request and response bodies are logged for debugging; the bearer token is
  // not part of either body and must stay out of the log.
  assert.ok(
    appLog.includes('Incorta A2A request body:') && appLog.includes('"method": "message/send"'),
    `A2A request body should be logged. Log:\n${appLog}`
  );
  assert.ok(
    appLog.includes('Incorta A2A response body (200') && appLog.includes('Echo: hi'),
    `A2A response body should be logged. Log:\n${appLog}`
  );
  console.log('✓ A2A request and response bodies are logged');

  // The conversation id must persist across messages, or the agent treats every
  // message as a brand-new conversation and loses the thread.
  const second = await fetch(`http://localhost:${APP_PORT}/api/incorta/chat`, {
    method: 'POST',
    headers: { cookie: cookieHeader(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: 'and then?' }),
  });
  const secondBody = await second.json();
  assert.strictEqual(
    secondBody.contextId,
    chatBody.contextId,
    'consecutive messages should share one Incorta conversation'
  );
  assert.strictEqual(
    capturedA2aBody.params.contextId,
    chatBody.contextId,
    'follow-up messages should send the conversation id Incorta assigned'
  );
  assert.ok(
    capturedA2aBody.id !== chatBody.reply.id,
    'the JSON-RPC id should increment per request'
  );
  console.log('✓ conversation id persists across messages and the JSON-RPC id increments');

  // Empty input is rejected before any token is spent or Incorta is called
  const lastGoodChatBody = JSON.parse(JSON.stringify(capturedA2aBody));
  const empty = await fetch(`http://localhost:${APP_PORT}/api/incorta/chat`, {
    method: 'POST',
    headers: { cookie: cookieHeader(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: '   ' }),
  });
  assert.strictEqual(empty.status, 400, 'an empty message should be rejected');
  // The mock's last capture must still be the previous good message: a rejected
  // request would overwrite it. Compare against the whole body, not a substring
  // of it, so a new call with different text is caught too.
  assert.deepStrictEqual(
    capturedA2aBody,
    lastGoodChatBody,
    'a rejected message must not reach Incorta'
  );
  console.log('✓ empty chat messages are rejected without calling Incorta');

  // Copilot entitlement failures are 500s with a readable Incorta message and a
  // trace-id; the route must surface both rather than a bare status code.
  failNextChat = true;
  const denied = await fetch(`http://localhost:${APP_PORT}/api/incorta/chat`, {
    method: 'POST',
    headers: { cookie: cookieHeader(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: 'hi again' }),
  });
  const deniedBody = await denied.json();
  assert.strictEqual(denied.status, 500, 'an Incorta 500 should be passed through');
  assert.strictEqual(deniedBody.traceId, INCORTA_ERROR_TRACE_ID);
  assert.ok(
    deniedBody.details.message.includes('INC_05000301'),
    `Incorta's own message should be surfaced, got ${JSON.stringify(deniedBody)}`
  );
  console.log('✓ Copilot permission errors surface Incorta\'s message and trace-id');

  // 7b. replyText() is what makes the chat usable: the agent's reply can land
  // under several shapes depending on which output extensions the server applied,
  // so it has to find the text in any of them. It shows the reply text only,
  // never the raw JSON. Extracted from the served page and actually
  // executed, so this tests the shipped code and not a copy of it.
  const replyOf = makeReplyTextRunner(homeHtml);
  assert.strictEqual(
    replyOf({ jsonrpc: '2.0', result: { parts: [{ kind: 'text', text: 'from parts' }] } }),
    'from parts',
    'should read the text out of result.parts'
  );
  assert.strictEqual(
    replyOf({ result: { message: { text: 'from message.text' } } }),
    'from message.text',
    'should read the text out of result.message.text'
  );
  assert.strictEqual(replyOf({ result: { text: 'from text' } }), 'from text');
  assert.strictEqual(
    replyOf({
      result: {
        artifacts: [{ parts: [{ kind: 'text', text: 'the real answer' }] }],
        status: { state: 'completed', message: { parts: [{ kind: 'text', text: 'Response ready.' }] } },
      },
    }),
    'the real answer',
    'a finished task shows its artifacts, not the "Response ready." status note'
  );
  assert.strictEqual(
    replyOf({ result: { status: { message: { parts: [{ kind: 'text', text: 'from status' }] } } } }),
    'from status',
    'should read the text out of result.status.message.parts'
  );
  assert.strictEqual(
    replyOf({ result: { artifacts: [{ parts: [{ kind: 'text', text: 'artifact one' }] }] } }),
    'artifact one',
    'should read the text out of artifact parts'
  );
  assert.strictEqual(
    replyOf({ result: { parts: [{ kind: 'data', data: { a: 1 } }, { kind: 'text', text: 'only text' }] } }),
    'only text',
    'non-text parts should be ignored'
  );
  assert.strictEqual(
    replyOf({ error: { code: -32603, message: 'internal error' } }),
    'Error -32603: internal error',
    'a JSON-RPC error object should render readably, not as [object Object]'
  );
  // An unrecognized shape shows a short notice, never the raw JSON
  const unknown = replyOf({ result: { somethingNew: 'shape drift' } });
  assert.ok(
    !unknown.includes('shape drift') && unknown.length > 0,
    `an unknown response shape should not dump raw JSON, got: ${unknown}`
  );
  assert.ok(!homeHtml.includes('Raw JSON-RPC response'), 'no raw JSON panel in the chat window');
  console.log('✓ chat reply rendering handles every JSON-RPC result shape');

  assertInlineScriptParses(homeHtml);
  console.log('✓ the logged-in page\'s inline script parses as JavaScript');

  // 7b. The home page has to render those four columns from the real field
  // names, not a hand-written set. Evaluated in a minimal DOM shim so the
  // template string's JS is actually executed rather than pattern-matched.
  assert.ok(
    homeHtml.includes('renderSchemas') && homeHtml.includes('schemaName'),
    'home page should ship the schema table renderer'
  );
  const rendered = renderSchemasHtml(apiBody);
  for (const col of ['Schema', 'Type', 'Owner', 'Last modified']) {
    assert.ok(
      rendered.includes(`<th>${col}</th>`),
      `table should have a "${col}" column`
    );
  }
  assert.ok(
    rendered.includes('<td>Audit</td>'),
    'schemaName should be rendered in the Schema column'
  );
  assert.ok(
    rendered.includes('<td>PHYSICAL</td>') && rendered.includes('<td>VIRTUAL</td>'),
    'schemaType should be rendered in the Type column'
  );
  assert.ok(
    rendered.includes('<td>Super User</td>') && rendered.includes('<td>Someone Else</td>'),
    'owner should be rendered in the Owner column'
  );
  // lastModified is epoch millis, so this must be a real formatted date, and the
  // value must not be the raw millisecond number.
  const expectedDate = new Date(1791123993000).toLocaleString();
  assert.ok(
    rendered.includes(`<td>${expectedDate}</td>`),
    `lastModified should be formatted as a date. Expected "${expectedDate}", got:\n${rendered}`
  );
  assert.ok(
    !rendered.includes('1791123993000'),
    'lastModified should not be shown as raw epoch millis'
  );
  // Sparse row: missing owner/lastModified must render an em dash, not "null".
  assert.ok(
    !rendered.includes('null') && !rendered.includes('undefined'),
    `missing fields should render as —, not null/undefined:\n${rendered}`
  );
  console.log('✓ schema list renders as a table with name, type, owner, last modified');

  // 8. Assert the critical wiring
  assert.strictEqual(capturedForUser, 'bob@example.com', 'for_user must be the user email');
  assert.strictEqual(capturedGrantType, 'client_credentials', 'must use client_credentials grant');
  console.log('✓ Incorta token request: grant_type=client_credentials, for_user=bob@example.com');
  assert.strictEqual(
    capturedAuthHeader,
    'Bearer incorta-access-token',
    'API call must send the Incorta bearer token'
  );
  console.log('✓ Schema list call sent Authorization: Bearer <incorta token>');
  assert.strictEqual(
    capturedIncortaPath,
    `/incorta/api/v2/${SMOKE_INCORTA_TENANT}/schema/list`,
    `the tenant must come from INCORTA_TENANT, got path: ${capturedIncortaPath}`
  );
  console.log(`✓ Tenant is parameterized from INCORTA_TENANT (${SMOKE_INCORTA_TENANT})`);
  assert.strictEqual(incortaTokenCalls, 1, 'Incorta token should be requested once and cached');

  // Token logging: with LOG_ACCESS_TOKENS unset (this app's config) the raw
  // bearer tokens must never reach the log. The mock tokens are known literals,
  // so this is an exact check rather than a pattern match.
  for (const secret of ['incorta-access-token', 'kc-access-token']) {
    assert.ok(
      !appLog.includes(secret),
      `raw access token "${secret}" must not be logged when LOG_ACCESS_TOKENS is off:\n${appLog}`
    );
  }
  assert.ok(
    /🔒 Incorta access token: /.test(appLog),
    `Incorta token should be logged in masked form:\n${appLog}`
  );
  assert.ok(
    /🔒 SSO access token: /.test(appLog),
    `IdP access token should be logged in masked form:\n${appLog}`
  );
  console.log('✓ access tokens are logged masked by default (Incorta + IdP)');

  // trace-id must be logged on the success path, so it is available for support
  // requests about calls that happened to look fine
  assert.ok(
    appLog.includes(INCORTA_TRACE_ID),
    `server log should print Incorta's trace-id. Got:\n${appLog}`
  );
  assert.ok(
    appLog.includes('trace-id'),
    'trace-id should be labeled in the log line'
  );
  console.log('✓ Incorta trace-id response header is logged on schema list');

  // 9. Token caching
  await fetch(`http://localhost:${APP_PORT}/api/incorta/schemas/list`, {
    method: 'POST',
    headers: { cookie: cookieHeader() },
  });
  assert.strictEqual(incortaTokenCalls, 1, 'second call should reuse cached Incorta token');
  console.log('✓ Incorta token is cached in the session across calls');

  // 9b. Incorta error response: the trace-id has to survive an upstream failure
  // too, since that is exactly when it is needed for a support ticket.
  failNextSchemaList = true;
  const incortaErr = await fetch(`http://localhost:${APP_PORT}/api/incorta/schemas/list`, {
    method: 'POST',
    headers: { cookie: cookieHeader() },
  });
  const incortaErrBody = await incortaErr.json();
  assert.strictEqual(incortaErr.status, 500, 'upstream 500 should be passed through');
  assert.strictEqual(
    incortaErrBody.traceId,
    INCORTA_ERROR_TRACE_ID,
    'error response body should carry Incorta traceId'
  );
  assert.ok(
    appLog.includes(INCORTA_ERROR_TRACE_ID),
    `error log should include the Incorta trace-id. Got:\n${appLog}`
  );
  console.log('✓ Incorta trace-id is reported on error responses too');

  // 10. CSRF protection: bad state must be rejected
  const badState = await fetch(
    `http://localhost:${APP_PORT}/callback?code=abc&state=not-the-right-state`,
    { redirect: 'manual', headers: { cookie: cookieHeader() } }
  );
  assert.strictEqual(badState.status, 400, 'callback with bad state should be rejected');
  console.log('✓ callback rejects a mismatched state (CSRF protection)');

  // 10b. Polled Copilot page and API
  {
    const base = `http://localhost:${APP_PORT}`;
    const authed = { cookie: cookieHeader() };
    const jsonHeaders = { ...authed, 'Content-Type': 'application/json' };
    const send = (body, headers = jsonHeaders) =>
      fetch(`${base}/api/incorta/copilot/messages`, {
        method: 'POST',
        headers,
        body: typeof body === 'string' ? body : JSON.stringify(body),
      });
    const poll = async (taskId) => {
      const r = await fetch(`${base}/api/incorta/copilot/tasks/${encodeURIComponent(taskId)}`, { headers: authed });
      return { status: r.status, text: await r.clone().text(), body: await r.json() };
    };
    /** Poll a task until it is done; returns every view seen */
    const pollToEnd = async (taskId) => {
      const views = [];
      for (let i = 0; i < 10; i += 1) {
        const { body } = await poll(taskId);
        views.push(body);
        if (body.done) return views;
      }
      throw new Error(`task ${taskId} never finished: ${JSON.stringify(views)}`);
    };

    // The page and its script
    const noLogin = await fetch(`${base}/copilot`, { redirect: 'manual' });
    assert.strictEqual(noLogin.status, 302, 'a logged-out /copilot should redirect');
    assert.strictEqual(new URL(noLogin.headers.get('location'), base).pathname, '/');
    const page = await fetch(`${base}/copilot`, { headers: authed });
    const pageHtml = await page.text();
    assert.strictEqual(page.status, 200);
    assert.ok(pageHtml.includes('src="/copilot.js"') && pageHtml.includes('id="transcript"'));
    assert.ok(/data-poll-ms="\d+"/.test(pageHtml) && /data-timeout-ms="\d+"/.test(pageHtml), 'poll settings are filled in');
    assert.ok(!pageHtml.includes('__POLL_MS__'), 'no placeholder left behind');
    const script = await fetch(`${base}/copilot.js`);
    const scriptText = await script.text();
    assert.strictEqual(script.status, 200);
    new (require('vm').Script)(scriptText); // throws on a syntax error
    const homeAgain = await (await fetch(`${base}/`, { headers: authed })).text();
    assert.ok(homeAgain.includes('href="/copilot"'), 'the home page links to /copilot');
    console.log('✓ /copilot page: login redirect, script served, settings filled in, linked from home');

    // Input checks
    assert.strictEqual((await fetch(`${base}/api/incorta/copilot/messages`, { method: 'POST' })).status, 401);
    assert.strictEqual((await send('hi', { ...authed, 'Content-Type': 'text/plain' })).status, 415, 'non-JSON is rejected');
    assert.strictEqual((await send({ text: '   ' })).status, 400, 'empty text');
    assert.strictEqual((await send({ text: 'hi', contextId: 'bad id!' })).status, 400, 'bad contextId');
    assert.strictEqual((await send({ text: 'x'.repeat(9000) })).status, 400, 'too long');
    assert.strictEqual((await poll('bad id!')).status, 400, 'bad task id');
    console.log('✓ copilot API validates content type, text, contextId and task id');

    // A task, polled from start to finish
    const started = await (await send({ text: 'hello' })).json();
    assert.ok(started.taskId && started.contextId, 'send returns the task and conversation ids');
    assert.ok(!('configuration' in capturedCopilotSend.params), 'a polled send has no configuration block');
    assert.ok(!('contextId' in capturedCopilotSend.params), 'the first message carries no contextId');
    assert.strictEqual(capturedCopilotSend.id, 1);
    assert.deepStrictEqual(
      capturedCopilotSend.params.message.metadata.conversation_context.client_context.params,
      [{ key: 'model_key', value: 'test-model' }],
      'the configured model key is sent'
    );
    assert.strictEqual(capturedCopilotSendHeaders.authorization, 'Bearer incorta-access-token');

    const views = await pollToEnd(started.taskId);
    assert.deepStrictEqual(views.map((v) => v.state), ['working', 'working', 'completed']);
    assert.deepStrictEqual(views.map((v) => v.steps.length), [1, 2, 2], 'steps grow while working');
    assert.strictEqual(views[1].steps[1].title, 'Step 2 title');
    assert.strictEqual(views[2].answer, 'Answer to: hello', 'the answer comes from the artifacts');
    assert.strictEqual(views[2].error, null);
    const wire = JSON.stringify(views);
    for (const secret of ['secret-output', 'secret-traceback', 'incorta-access-token', 'Response ready']) {
      assert.ok(!wire.includes(secret), `"${secret}" must not reach the browser`);
    }
    assert.strictEqual(
      appLog.split(`task ${started.taskId}: working`).length - 1,
      1,
      'a poll is logged only when the state changes'
    );
    assert.ok(appLog.includes(`task ${started.taskId} final body`), 'the final body is logged');
    console.log('✓ copilot task: submitted -> working (steps grow) -> completed, answer from artifacts, nothing leaked');

    // A follow-up carries the conversation id the browser holds
    await send({ text: 'and then?', contextId: started.contextId });
    assert.strictEqual(capturedCopilotSend.params.contextId, started.contextId);
    console.log('✓ follow-up message carries the conversation id');

    // Failed, input-required, and upstream problems
    const failed = await (await send({ text: 'FAIL please' })).json();
    const failedView = (await pollToEnd(failed.taskId)).pop();
    assert.strictEqual(failedView.state, 'failed');
    assert.strictEqual(failedView.error.message, 'litellm.BadRequestError: Operation not allowed');
    assert.strictEqual(failedView.error.traceId, INCORTA_TRACE_ID);
    assert.strictEqual(failedView.answer, '');

    const needInput = await (await send({ text: 'NEEDINPUT' })).json();
    const needView = (await pollToEnd(needInput.taskId)).pop();
    assert.strictEqual(needView.state, 'input-required');
    assert.strictEqual(needView.done, true, 'a task waiting for the user is not polled forever');
    assert.strictEqual(needView.error.message, 'Which schema do you mean?');

    const rpcError = await send({ text: 'RPCERROR' });
    assert.strictEqual(rpcError.status, 502, 'a JSON-RPC error under HTTP 200 is an error');
    assert.strictEqual((await rpcError.json()).error, 'boom');
    assert.strictEqual((await send({ text: 'NOTASK' })).status, 502, 'a reply without a task id is an error');
    const unknown = await poll('no-such-task');
    assert.strictEqual(unknown.status, 502);
    assert.strictEqual(unknown.body.error, 'Task not found');
    console.log('✓ copilot failed / input-required tasks and upstream errors are reported');

    // Incorta rejects the token mid-task: refresh once and retry
    const refreshTask = await (await send({ text: 'hello again' })).json();
    const tokenCallsBefore = incortaTokenCalls;
    const authBefore = copilotPollAuth.length;
    copilotReject401Next = true;
    const afterRefresh = await poll(refreshTask.taskId);
    assert.strictEqual(afterRefresh.status, 200, 'the poll succeeds after a token refresh');
    assert.strictEqual(incortaTokenCalls, tokenCallsBefore + 1, 'exactly one fresh token was fetched');
    assert.strictEqual(copilotPollAuth.length - authBefore, 2, 'the poll was retried once');
    console.log('✓ an expired token mid-task is refreshed and the poll retried once');
  }

  // 11. Logout
  const logout = await fetch(`http://localhost:${APP_PORT}/logout`, {
    redirect: 'manual',
    headers: { cookie: cookieHeader() },
  });
  assert.strictEqual(logout.status, 302, 'logout should redirect');
  const afterLogout = await fetch(`http://localhost:${APP_PORT}/api/incorta/schemas/list`, {
    method: 'POST',
    headers: { cookie: cookieHeader() },
  });
  assert.strictEqual(afterLogout.status, 401, 'API should reject after logout');
  console.log('✓ logout clears the session and revokes API access');

  // Run last: the login-button cases stop the main app and reuse its port, so
  // every assertion that needs the main app has to come first.
  testOidcProviderConfig();
  testCopilotLib();
  await testCopilotPolling();
  await testCopilotPageFlow();
  await testA2aClient();
  await stopApp(app);
  await testLoginButtonVisibility();

  console.log('\n✓ ALL SMOKE TESTS PASSED');
  shutdown();
  process.exit(0);
}

main().catch((err) => {
  console.error('\n✗ SMOKE TEST FAILED:', err.message);
  process.exit(1);
});
