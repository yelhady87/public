require('dotenv').config();

const express = require('express');
const session = require('express-session');
const crypto = require('crypto');

const { FusionAuthClient } = require('./lib/oidc-fusion');
const { KeycloakOIDCClient } = require('./lib/oidc-keycloak');
const { IncortaOIDCClient } = require('./lib/oidc-incorta');
const { createAuthRouter } = require('./routes/auth');
const { createIncortaRouter } = require('./routes/incorta');

const PORT = process.env.APP_PORT || 3000;
const BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;

// Generate an ephemeral session secret if none is configured (dev convenience only)
if (!process.env.SESSION_SECRET) {
  process.env.SESSION_SECRET = crypto.randomBytes(32).toString('hex');
  console.log('⚠ SESSION_SECRET not set - using a random ephemeral secret (sessions reset on restart)');
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false, // set to true behind HTTPS
      sameSite: 'lax',
      maxAge: 60 * 60 * 1000, // 1 hour
    },
  })
);

const fusionAuth = new FusionAuthClient();
const keycloak = new KeycloakOIDCClient();
const incorta = new IncortaOIDCClient();

const PROVIDER_LABELS = { fusion: 'Fusion Auth', keycloak: 'Keycloak' };

// Mount the routers first so the home page can ask the auth router which
// providers are actually usable, rather than keeping its own copy of that check.
const authRouter = createAuthRouter({ fusionAuth, keycloak });
app.use('/', authRouter);
app.use('/api/incorta', createIncortaRouter(incorta));

/**
 * Login buttons for the providers that are usable right now.
 *
 * A provider whose discovery failed is omitted rather than rendered as a dead
 * button: /login-keycloak answers 503 in that case, so linking to it would just
 * hand the user an error. The message below the buttons covers the case where
 * nothing is available at all.
 */
function renderLoginButtons() {
  const available = authRouter.availableProviders();

  if (!available.length) {
    return (
      '<p class="muted">No login provider is configured. Set ' +
      '<code>FUSION_AUTH_ISSUER</code>, <code>FUSION_AUTH_CLIENT_ID</code> and ' +
      '<code>FUSION_AUTH_CLIENT_SECRET</code> in <code>.env</code>, then restart the app.</p>'
    );
  }

  const buttons = available
    .map(
      (p, i) =>
        `<a class="btn${i > 0 ? ' secondary' : ''}" href="${escapeHtml(
          p.path
        )}">Login with ${escapeHtml(p.label)}</a>`
    )
    .join('\n           ');

  return `${buttons}\n           <p class="muted">${
    available.length === 1
      ? 'Only one identity provider is configured.'
      : `${available.length} identity providers configured.`
  }</p>`;
}

/**
 * Home page - simple HTML UI
 */
app.get('/', (req, res) => {
  const user = req.session.user;
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Sample Incorta OAuth App</title>
  <style>
    body { font-family: -apple-system, system-ui, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #222; }
    h1 { font-size: 24px; }
    .card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 20px 0; }
    .btn { display: inline-block; padding: 10px 18px; background: #0073e6; color: #fff; text-decoration: none; border-radius: 6px; cursor: pointer; border: none; font-size: 15px; }
    .btn.secondary { background: #555; }
    .btn + .btn { margin-left: 8px; }
    code { background: #f0f0f0; padding: 1px 5px; border-radius: 4px; font-size: 13px; }
    pre { background: #f5f5f5; padding: 12px; border-radius: 6px; overflow: auto; max-height: 500px; }
    .muted { color: #666; font-size: 14px; }
    table { border-collapse: collapse; width: 100%; margin-top: 10px; font-size: 14px; }
    th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #e5e5e5; vertical-align: top; }
    th { background: #f5f5f5; font-weight: 600; }
    tbody tr:last-child td { border-bottom: none; }
    td:first-child { font-weight: 600; }
    .btn[disabled] { opacity: 0.6; cursor: default; }
  </style>
</head>
<body>
  <h1>Sample Incorta OAuth App</h1>
  ${
    user
      ? `<div class="card">
           <p><strong>Authenticated as:</strong> ${escapeHtml(user.email)}</p>
           <p class="muted">via ${escapeHtml(
             PROVIDER_LABELS[user.provider] || 'Fusion Auth'
           )}</p>
           <p class="muted">sub: ${escapeHtml(user.sub || 'n/a')}</p>
           <button class="btn" id="callBtn" onclick="callIncorta()">Call Incorta API (schema list)</button>
           <a class="btn secondary" href="/logout" style="margin-left:8px; text-decoration:none;">Logout</a>
         </div>
         <div id="output"></div>
         <script>
           // Escape before any innerHTML assignment. Schema names, owners and
           // descriptions come from the server and are not sanitized, so this is
           // what stops a value like "<img onerror=...>" from executing.
           function esc(v) {
             return String(v == null || v === '' ? '' : v)
               .replace(/&/g, '&amp;')
               .replace(/</g, '&lt;')
               .replace(/>/g, '&gt;')
               .replace(/"/g, '&quot;')
               .replace(/'/g, '&#39;');
           }

           // Incorta returns lastModified as epoch MILLISECONDS. Guard on the
           // value being plausible, since a bogus one would make
           // toLocaleString render "Invalid Date".
           function fmtDate(ms) {
             if (typeof ms !== 'number' || !isFinite(ms) || ms <= 0) return '—';
             var d = new Date(ms);
             if (isNaN(d.getTime())) return '—';
             return d.toLocaleString();
           }

           function renderSchemas(data) {
             // Incorta wraps the rows in schemasDetails; total is the row count
             // before this request's limit/offset slice.
             var rows = (data && data.schemasDetails) || [];
             var total = typeof data.total === 'number' ? data.total : rows.length;

             var head =
               '<tr><th>Schema</th><th>Type</th><th>Owner</th><th>Last modified</th></tr>';
             var body = rows.map(function (s) {
               return '<tr>' +
                 '<td>' + esc(s.schemaName) + '</td>' +
                 '<td>' + esc(s.schemaType) + '</td>' +
                 '<td>' + esc(s.owner) + '</td>' +
                 '<td>' + esc(fmtDate(s.lastModified)) + '</td>' +
                 '</tr>';
             }).join('');

             if (!rows.length) {
               body = '<tr><td colspan="4" class="muted">No schemas returned.</td></tr>';
             }

             var caption = 'Schemas (' + rows.length +
               (total > rows.length ? ' of ' + total : '') + ')';

             return '<div class="card">' +
               '<h3>' + caption + '</h3>' +
               '<table>' + head + body + '</table>' +
               '</div>';
           }

           async function callIncorta() {
             const out = document.getElementById('output');
             const btn = document.getElementById('callBtn');
             btn.disabled = true;
             out.innerHTML = '<div class="card">Loading…</div>';
             try {
               const res = await fetch('/api/incorta/schemas/list', { method: 'POST' });
               const data = await res.json();
               if (!res.ok) {
                 // The route surfaces Incorta's traceId on failures, which is
                 // what Incorta support needs to find the request server-side.
                 var trace = data.traceId
                   ? '<p class="muted">Incorta trace-id: ' + esc(data.traceId) + '</p>'
                   : '';
                 out.innerHTML = '<div class="card"><h3>Incorta error</h3>' +
                   '<p>' + esc(data.error || ('HTTP ' + res.status)) + '</p>' + trace +
                   '<pre>' + esc(JSON.stringify(data.details || data, null, 2)) + '</pre>' +
                   '</div>';
                 return;
               }
               out.innerHTML = renderSchemas(data);
             } catch (e) {
               out.innerHTML = '<div class="card"><strong>Error:</strong> ' + esc(e.message) + '</div>';
             } finally {
               btn.disabled = false;
             }
           }
         </script>`
      : `<div class="card">
           <p>You are not logged in.</p>
           ${renderLoginButtons()}
         </div>`
  }
</body>
</html>`);
});

/**
 * Escape HTML to prevent injection in the template above
 */
function escapeHtml(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// The auth router is mounted at the root so that its /callback path matches
// the redirect URI registered in Fusion Auth and Keycloak. Both providers use
// the same callback URL, so the router remembers which one started the flow.
// (Mounted earlier, above the home page, so the page can query its provider
// list.)

/**
 * Health check
 */
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

/**
 * Error handler
 */
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

/**
 * Start the server: initialize OIDC clients first (so config errors surface early),
 * then listen.
 */
async function start() {
  try {
    await fusionAuth.init();
  } catch (err) {
    console.error('✗ Failed to initialize Fusion Auth OIDC client:', err.message);
    console.error('  Check FUSION_AUTH_ISSUER, FUSION_AUTH_CLIENT_ID, and FUSION_AUTH_CLIENT_SECRET in .env');
    process.exit(1);
  }

  // Keycloak is an optional login provider: a missing KEYCLOAK_* entry or an
  // unreachable server downgrades /login-keycloak to 503 instead of taking the
  // whole app down, so Fusion Auth + Incorta keep working.
  if (!process.env.KEYCLOAK_ISSUER || !process.env.KEYCLOAK_CLIENT_ID) {
    console.log('⚠ Keycloak not configured - /login-keycloak is disabled');
  } else {
    try {
      await keycloak.init();
    } catch (err) {
      console.error('⚠ Failed to initialize Keycloak OIDC client:', err.message);
      console.error('  /login-keycloak will return 503 until this is fixed');
    }
  }

  try {
    await incorta.init();
  } catch (err) {
    console.error('✗ Failed to initialize Incorta OIDC client:', err.message);
    console.error('  Check INCORTA_OIDC_ISSUER, INCORTA_CLIENT_ID, and INCORTA_CLIENT_SECRET in .env');
    process.exit(1);
  }

  app.listen(PORT, () => {
    console.log('');
    console.log(`✓ Server running at ${BASE_URL}`);
    console.log('');
    console.log('  Redirect URI to register with the identity providers:');
    console.log(`    ${BASE_URL}/callback`);
    console.log('');
    console.log('  Login routes:');
    console.log(`    ${BASE_URL}/login            (Fusion Auth)`);
    console.log(`    ${BASE_URL}/login-keycloak   (Keycloak)`);
    console.log('');
  });
}

start();
