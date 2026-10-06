const express = require('express');
const crypto = require('crypto');

const { logAccessToken } = require('../lib/log-tokens');

/**
 * Base64url-encode a buffer (works on older Node versions too)
 */
function base64url(buf) {
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Generate a PKCE code verifier
 */
function generateCodeVerifier() {
  return base64url(crypto.randomBytes(32));
}

/**
 * Generate the PKCE code challenge (S256) from a verifier
 */
function generateCodeChallenge(verifier) {
  return base64url(crypto.createHash('sha256').update(verifier).digest());
}

/**
 * Authentication routes for the user-facing OIDC provider (Keycloak).
 *
 * Runs the Authorization Code + PKCE flow. This router is mounted at the app
 * root (not under /auth): the callback path has to stay exactly
 * `${APP_BASE_URL}/callback` or the registered redirect URI stops matching.
 *
 * The provider that started the flow is recorded in the session
 * (req.session.oidc.provider) and the callback is routed back to its client.
 *
 * @param {object} options
 * @param {object} options.keycloak - KeycloakOIDCClient instance. Its inner
 *   openid-client (`.client`) stays null when Keycloak was not configured or
 *   discovery failed, in which case the Keycloak login routes report 503
 *   instead of crashing the app.
 */
function createAuthRouter({ keycloak }) {
  const router = express.Router();

  const providers = {
    keycloak: { idp: keycloak, label: 'Keycloak' },
  };

  // Kept next to the provider table so a provider and its login path cannot
  // drift apart. The home page links to these, so they are part of the contract.
  const LOGIN_PATHS = { keycloak: '/login-keycloak' };

  /**
   * Is this provider usable? It needs the wrapper plus a discovered
   * openid-client, which only exists after a successful init().
   */
  function isReady(provider) {
    return Boolean(provider && provider.idp && provider.idp.client);
  }

  /**
   * Which providers can actually complete a login right now, as
   * `{ name, label, path }`. Exposed on the router so the home page renders the
   * same readiness the login routes enforce, instead of a second copy of the
   * check that can drift.
   *
   * A provider that is not ready is not merely hidden: its route answers 503, so
   * a button that always renders would send users to a dead end.
   */
  router.availableProviders = () =>
    Object.keys(providers)
      .filter((name) => isReady(providers[name]))
      .map((name) => ({
        name,
        label: providers[name].label,
        path: LOGIN_PATHS[name],
      }));

  /**
   * GET /login-keycloak - start the login flow
   */
  function startLogin(providerName) {
    const provider = providers[providerName];

    return (req, res) => {
      if (!isReady(provider)) {
        return res.status(503).send(
          `${provider.label} login is not configured. Check the matching env vars in .env and restart the app.`
        );
      }

      const state = crypto.randomBytes(16).toString('hex');
      const nonce = crypto.randomBytes(16).toString('hex');
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = generateCodeChallenge(codeVerifier);

      // Store state, nonce, code verifier, and the provider for validation on
      // callback
      req.session.oidc = {
        provider: providerName,
        state,
        nonce,
        codeVerifier,
        createdAt: Date.now(),
      };

      const authorizationUrl = provider.idp.authorizationUrl(
        state,
        nonce,
        codeChallenge,
        'S256'
      );

      console.log(`→ Redirecting to ${provider.label} for authentication`);
      res.redirect(authorizationUrl);
    };
  }

  // Registered from LOGIN_PATHS so the route table and the buttons the home page
  // renders come from one source.
  for (const [name, path] of Object.entries(LOGIN_PATHS)) {
    router.get(path, startLogin(name));
  }
  /**
   * GET /callback - Handle the redirect back from the provider that started
   * the flow.
   */
  router.get('/callback', async (req, res) => {
    try {
      const { code, state, error, error_description: errorDescription } = req.query;

      const providerName =
        (req.session.oidc && req.session.oidc.provider) || 'keycloak';
      const provider = providers[providerName];
      const idp = provider.idp;

      if (error) {
        throw new Error(
          `${provider.label} returned an error: ${error}${errorDescription ? ` - ${errorDescription}` : ''}`
        );
      }

      if (!code) {
        throw new Error(`No authorization code received from ${provider.label}`);
      }

      if (!isReady(provider)) {
        return res
          .status(503)
          .send(`${provider.label} login is not configured. Check the matching env vars in .env and restart the app.`);
      }

      // Validate state to prevent CSRF
      if (!req.session.oidc || state !== req.session.oidc.state) {
        throw new Error('State validation failed - possible CSRF attack or expired session');
      }

      const { nonce, codeVerifier, state: expectedState } = req.session.oidc;

      // NOTE: req.session.oidc is intentionally NOT deleted before the
      // exchange. Authorization codes are single-use, so if the exchange fails
      // the user must start a fresh login - but wiping the state here would
      // also break any retry. It is cleared after a successful exchange below.
      const tokenSet = await idp.getTokenSet(
        req.query,
        codeVerifier,
        nonce,
        expectedState
      );
      delete req.session.oidc;

      const claims = idp.getUserClaims(tokenSet);

      // Logged here, once per login, rather than per API call.
      logAccessToken(provider.label, tokenSet.access_token, {
        user: claims.email || claims.preferred_username || 'unknown',
        expires_in: tokenSet.expires_in,
      });

      // Extract the user's email - this becomes the `for_user` for Incorta
      const userEmail = idp.getUserEmail(tokenSet);

      if (!userEmail) {
        throw new Error(missingEmailHint(providerName));
      }

      req.session.user = {
        email: userEmail,
        sub: claims.sub,
        name: claims.name || claims.preferred_username || userEmail,
        provider: providerName,
      };

      // Keep the IdP tokens for reference / userinfo calls
      req.session.idpTokens = {
        provider: providerName,
        accessToken: tokenSet.access_token,
        idToken: tokenSet.id_token,
        expiresAt: tokenSet.expires_at,
      };

      console.log(`✓ User authenticated via ${provider.label}: ${userEmail}`);

      req.session.save(() => {
        res.redirect('/');
      });
    } catch (err) {
      // The full upstream error body matters here: "Invalid Authorization
      // Code" has several very different root causes and error_reason
      // disambiguates them.
      console.error('✗ Authentication error:', err.message);
      if (err.error_reason) console.error('  reason:', err.error_reason);
      if (err.error_description) console.error('  description:', err.error_description);
      if (err.name === 'RPError' || err.name === 'OPError') {
        console.error('  (openid-client rejected the response)');
      }
      // Log WHICH params arrived, not their values. Keycloak omits `iss` from a
      // successful authorization redirect unless the client asked for it (RFC
      // 9207), and openid-client then fails with the unhelpful "iss missing
      // from the response" - seeing "code, session_state, state" and no `iss`
      // is what identifies that case.
      console.error(
        `  callback params received: ${Object.keys(req.query || {}).join(', ')}`
      );
      if (req.query && 'iss' in req.query) {
        console.error(`  iss: ${req.query.iss}`);
      }
      res.status(400).send(`Authentication failed: ${err.message}`);
    }
  });

  /**
   * GET /logout - Destroy the session
   */
  router.get('/logout', (req, res) => {
    const email = req.session.user ? req.session.user.email : 'unknown';
    req.session.destroy(() => {
      console.log(`✓ User logged out: ${email}`);
      res.redirect('/');
    });
  });

  /**
   * GET /me - Return the currently authenticated user
   */
  router.get('/me', (req, res) => {
    if (!req.session.user) {
      return res.status(401).json({ authenticated: false });
    }
    res.json({
      authenticated: true,
      user: req.session.user,
    });
  });

  return router;
}

/**
 * Hint for a missing email claim.
 */
function missingEmailHint() {
  return (
    'No email claim found in the Keycloak ID token. Set an Email address on the user in Keycloak ' +
    '(Users > select user > Details > Email) and make sure the `email` client scope is assigned to the client.'
  );
}

module.exports = { createAuthRouter };