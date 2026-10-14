require('dotenv').config();

const express = require('express');
const session = require('express-session');
const crypto = require('crypto');

const { OIDCProviderClient } = require('./lib/oidc-provider');
const { IncortaOIDCClient } = require('./lib/oidc-incorta');
const { createAuthRouter } = require('./routes/auth');
const { createIncortaRouter } = require('./routes/incorta');
const { createCopilotRouter, copilotPage, copilotScript } = require('./routes/copilot');

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

const oidc = new OIDCProviderClient();
const incorta = new IncortaOIDCClient();


// Mount the routers first so the home page can ask the auth router which
// providers are actually usable, rather than keeping its own copy of that check.
const authRouter = createAuthRouter({ oidc });
app.use('/', authRouter);
app.use('/api/incorta', createIncortaRouter(incorta));
app.use('/api/incorta/copilot', createCopilotRouter(incorta));
app.get('/copilot', copilotPage);
app.get('/copilot.js', copilotScript);

/**
 * Login buttons for the providers that are usable right now.
 *
 * A provider whose discovery failed is omitted rather than rendered as a dead
 * button: /login answers 503 in that case, so linking to it would just
 * hand the user an error. The message below the buttons covers the case where
 * nothing is available at all.
 */
function renderLoginButtons() {
  const available = authRouter.availableProviders();

  if (!available.length) {
    return (
      '<p class="muted">No login provider is configured. Set ' +
      '<code>OIDC_ISSUER</code>, <code>OIDC_CLIENT_ID</code> and ' +
      '<code>OIDC_CLIENT_SECRET</code> in <code>.env</code>, then restart the app.</p>'
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
    .chat-log { border: 1px solid #e5e5e5; border-radius: 6px; padding: 10px; max-height: 420px; overflow-y: auto; background: #fafafa; margin-bottom: 10px; }
    .bubble { padding: 8px 12px; border-radius: 8px; margin-bottom: 8px; font-size: 14px; white-space: pre-wrap; word-break: break-word; max-width: 85%; }
    .bubble.user { background: #0073e6; color: #fff; margin-left: auto; }
    .bubble.agent { background: #fff; border: 1px solid #e5e5e5; }
    .bubble.agent.pending { color: #888; font-style: italic; }
    .bubble.agent.error { background: #fdecea; border-color: #f5c2c0; color: #8a1c14; }
    .chat-form { display: flex; gap: 8px; }
    .chat-form input { flex: 1; padding: 10px 12px; border: 1px solid #ccc; border-radius: 6px; font-size: 15px; }
    .chat-form input:focus { outline: 2px solid #0073e6; outline-offset: -1px; }
    .chat-log details { font-size: 13px; margin-bottom: 8px; }
    .chat-log summary { cursor: pointer; }
  </style>
</head>
<body>
  <h1>Sample Incorta OAuth App</h1>
  ${
    user
      ? `<div class="card">
           <p><strong>Authenticated as:</strong> ${escapeHtml(user.email)}</p>
           <p class="muted">via ${escapeHtml(oidc.label)}</p>
           <p class="muted">sub: ${escapeHtml(user.sub || 'n/a')}</p>
           <button class="btn" id="callBtn" onclick="callIncorta()">Call Incorta API (schema list)</button>
           <a class="btn secondary" href="/copilot" style="margin-left:8px; text-decoration:none;">Copilot chat (polled)</a>
           <a class="btn secondary" href="/logout" style="margin-left:8px; text-decoration:none;">Logout</a>
         </div>
         <div id="output"></div>

           <div class="card">
             <h3>Chat with Incorta Copilot</h3>
             <p class="muted">Messages go to the Incorta Copilot A2A agent
               (<code>smart-agent</code>) using the Incorta access token issued
               for ${escapeHtml(user.email)}.</p>
             <div id="chatLog" class="chat-log"></div>
             <form id="chatForm" class="chat-form" onsubmit="return sendChat(event)">
               <input id="chatInput" type="text" autocomplete="off"
                 placeholder="Ask about your Incorta data&hellip; (Enter to send)" />
               <button class="btn" type="submit" id="chatSend">Send</button>
               <button class="btn secondary" type="button" id="chatClear"
                 onclick="clearChat()">Clear</button>
             </form>
           </div>
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

           // --- Incorta Copilot chat ---

            // The A2A response is a JSON-RPC envelope; the agent's reply can sit
            // under several shapes depending on which output extensions the
            // server applied. Only the reply text is shown, never the raw JSON
            // (the full response body is logged by the server).
            function replyText(data) {
              // Text of the text parts only; other part kinds are ignored.
              function partsText(parts) {
                if (!Array.isArray(parts)) return '';
                return parts.map(function (p) {
                  return p && typeof p.text === 'string' ? p.text : '';
                }).filter(Boolean).join('\\n');
              }

              if (typeof data === 'string') return data;
              if (!data || typeof data !== 'object') return '';

              // JSON-RPC 2.0 puts the result in \`result\`; a bare object with no
              // envelope means the server answered without wrapping.
              var result = data.result || data;
              var message = result.message;
              var statusMessage = result.status && result.status.message;

              // The answer of a finished task is in its artifacts; its
              // status.message is only a note such as "Response ready.", so it
              // comes last.
              var candidates = [];
              if (Array.isArray(result.artifacts)) {
                candidates.push(result.artifacts.map(function (a) {
                  return a ? (typeof a.text === 'string' ? a.text : partsText(a.parts)) : '';
                }).filter(Boolean).join('\\n'));
              }
              candidates.push(
                result.text,
                message && message.text,
                partsText(result.parts),
                partsText(message && message.parts),
                partsText(statusMessage && statusMessage.parts)
              );

              for (var i = 0; i < candidates.length; i++) {
                if (typeof candidates[i] === 'string' && candidates[i].trim()) {
                  return candidates[i];
                }
              }

              // JSON-RPC error object
              if (data.error) {
                return 'Error ' + (data.error.code || '') + ': ' +
                  (data.error.message || JSON.stringify(data.error));
              }

              return 'The agent replied without any text.';
            }

            function addBubble(text, who) {
              var log = document.getElementById('chatLog');
              var el = document.createElement('div');
              el.className = 'bubble ' + who;
              // Agent output is rendered as text, never HTML: it contains
              // table/HTML fragments from Incorta data, and interpreting it
              // would let Incorta content inject markup into this page.
              el.textContent = text;
              log.appendChild(el);
              log.scrollTop = log.scrollHeight;
            }

            async function sendChat(event) {
              if (event) event.preventDefault();

              var input = document.getElementById('chatInput');
              var send = document.getElementById('chatSend');
              var text = input.value.trim();
              if (!text) return false;

              addBubble(text, 'user');
              input.value = '';
              send.disabled = true;
              send.textContent = 'Sending…';
              addBubble('…', 'agent pending');

              try {
                var res = await fetch('/api/incorta/chat', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ text: text })
                });
                var data = await res.json();

                // Replace the pending bubble in place rather than appending,
                // so the transcript does not keep the ellipsis around.
                var log = document.getElementById('chatLog');
                var pending = log.querySelector('.agent.pending');
                if (pending) pending.remove();

                if (!res.ok) {
                  var trace = data.traceId
                    ? '\\n\\nIncorta trace-id: ' + data.traceId : '';
                  var detail = '';
                  if (data.details) {
                    // Incorta returns a readable message here, e.g. INC_05000301
                    // "You do not have the necessary permissions to access the
                    // Copilot", which is more useful than a bare status code.
                    detail = '\\n\\n' + (
                      typeof data.details === 'string'
                        ? data.details
                        : (data.details.message || JSON.stringify(data.details))
                    );
                  }
                  addBubble((data.error || ('HTTP ' + res.status)) + detail + trace, 'agent error');
                  return false;
                }

                addBubble(replyText(data.reply), 'agent');
              } catch (e) {
                var log2 = document.getElementById('chatLog');
                var p2 = log2.querySelector('.agent.pending');
                if (p2) p2.remove();
                addBubble('Request failed: ' + e.message, 'agent error');
              } finally {
                send.disabled = false;
                send.textContent = 'Send';
                input.focus();
              }
              return false;
            }

            function clearChat() {
              document.getElementById('chatLog').innerHTML = '';
              document.getElementById('chatInput').focus();
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
// the redirect URI registered with the identity provider. (Mounted earlier, above the home
// page, so the page can query its provider list.)

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
  // A missing OIDC_* entry or an unreachable server downgrades /login to 503
  // instead of taking the whole app down.
  if (!process.env.OIDC_ISSUER || !process.env.OIDC_CLIENT_ID) {
    console.log('⚠ OIDC not configured - /login is disabled');
  } else {
    try {
      await oidc.init();
    } catch (err) {
      console.error('⚠ Failed to initialize OIDC client:', err.message);
      console.error('  /login will return 503 until this is fixed');
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
    console.log('  Redirect URI to register with your identity provider:');
    console.log(`    ${BASE_URL}/callback`);
    console.log('');
    console.log('  Login route:');
    console.log(`    ${BASE_URL}/login`);
    console.log('');
  });
}

start();
