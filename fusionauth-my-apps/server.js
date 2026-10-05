require('dotenv').config();

const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');

const { FusionAuthOidcClient } = require('./lib/oidc-fusion');
const { FusionAuthApiClient } = require('./lib/fusionauth-api');
const { createAuthRouter } = require('./routes/auth');
const { createLauncherRouter } = require('./routes/launcher');

const PORT = process.env.APP_PORT || 3000;
const BASE_URL =
  process.env.APP_BASE_URL || `http://localhost:${PORT}`;

// Ephemeral session secret so a missing .env does not block a dev run.
if (!process.env.SESSION_SECRET) {
  process.env.SESSION_SECRET = crypto.randomBytes(32).toString('hex');
  console.warn(
    '⚠ SESSION_SECRET not set - using a random ephemeral secret (sessions reset on restart)'
  );
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false, // set to true behind HTTPS
      sameSite: 'lax',
      maxAge: 60 * 60 * 1000,
    },
  })
);

const oidc = new FusionAuthOidcClient();
const api = new FusionAuthApiClient();

app.use(express.static(path.join(__dirname, 'public')));

// Both routers are mounted at the root: /callback has to stay exactly
// `${APP_BASE_URL}/callback` to match the redirect URI registered in FusionAuth.
app.use('/', createAuthRouter(oidc));
app.use('/', createLauncherRouter(oidc, api));

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

async function start() {
  try {
    await oidc.init();
  } catch (err) {
    console.error('✗ Failed to initialize FusionAuth OIDC client:', err.message);
    console.error(
      '  Check FUSION_AUTH_ISSUER, FUSION_AUTH_CLIENT_ID and FUSION_AUTH_CLIENT_SECRET in .env'
    );
    process.exit(1);
  }

  if (!process.env.FUSION_AUTH_API_KEY) {
    // Not fatal at boot: /api/my-apps will 502 with a clear message. Worth
    // surfacing now because it is the most common misconfiguration.
    console.warn(
      '⚠ FUSION_AUTH_API_KEY not set - the application tile list will fail. ' +
        'Create an API key in the FusionAuth admin UI.'
    );
  }

  app.listen(PORT, () => {
    console.log('');
    console.log(`✓ Launcher running at ${BASE_URL}`);
    console.log('');
    console.log('  FusionAuth redirect URI to register for this app:');
    console.log(`    ${BASE_URL}/callback`);
    console.log('');
    console.log(`  Reading assignments for tenant: ${process.env.FUSION_AUTH_TENANT_ID || '(not set)'}`);
    console.log('');
  });
}

start();

module.exports = app;
