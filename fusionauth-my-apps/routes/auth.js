const express = require('express');
const crypto = require('crypto');
const { launcherRedirectUri } = require('../lib/config');

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

function generateCodeVerifier() {
  return base64url(crypto.randomBytes(32));
}

function generateCodeChallenge(verifier) {
  return base64url(crypto.createHash('sha256').update(verifier).digest());
}

/**
 * Authentication routes for the FusionAuth OIDC login flow.
 *
 * NOTE: mounted at the app root (not under /auth) so the callback path is exactly
 * `${APP_BASE_URL}/callback`, which is the literal URL registered as an allowed
 * redirect URI in FusionAuth. The two must not drift apart.
 *
 * The session deliberately keeps only the user identity. No access or refresh
 * token is stored: the launcher has no reason to call anything as the user once
 * the ID token has been read.
 */
function createAuthRouter(oidc) {
  const router = express.Router();

  /**
   * GET /login - start the login flow, redirect to FusionAuth
   */
  router.get('/login', (req, res) => {
    const state = crypto.randomBytes(16).toString('hex');
    const nonce = crypto.randomBytes(16).toString('hex');
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);

    req.session.oidc = { state, nonce, codeVerifier, createdAt: Date.now() };

    res.redirect(
      oidc.authorizationUrl(state, nonce, codeChallenge, 'S256')
    );
  });

  /**
   * GET /callback - handle the redirect back from FusionAuth
   */
  router.get('/callback', async (req, res) => {
    try {
      const { code, state, error, error_description: errorDescription } = req.query;

      if (error) {
        throw new Error(
          `FusionAuth returned an error: ${error}${errorDescription ? ` - ${errorDescription}` : ''}`
        );
      }
      if (!code) {
        throw new Error('No authorization code received from FusionAuth');
      }

      // Validate state to prevent CSRF
      if (!req.session.oidc) {
        // Worth distinguishing: an authorization response arriving with no login
        // in progress is not a CSRF attack, it is a misconfigured redirect URI.
        // Saying "possible CSRF attack" here sent debugging in the wrong
        // direction - the real cause was a target application whose authorized
        // redirect URIs included the launcher's own /callback.
        throw new Error(
          'No sign-in was in progress in this browser. An application most ' +
            'likely redirected its authorization response here by mistake: check ' +
            'that its authorized redirect URLs in FusionAuth do not include ' +
            `${launcherRedirectUri()}`
        );
      }
      if (state !== req.session.oidc.state) {
        throw new Error(
          'State validation failed - possible CSRF attack or expired session'
        );
      }

      const { nonce, codeVerifier, state: expectedState } = req.session.oidc;

      // req.session.oidc is cleared only after a successful exchange. An
      // authorization code is single-use, so a failed exchange means the user
      // must start a fresh /login anyway.
      const tokenSet = await oidc.getTokenSet(
        code,
        codeVerifier,
        nonce,
        expectedState
      );
      delete req.session.oidc;

      const claims = oidc.getUserClaims(tokenSet) || {};

      if (!claims.email) {
        throw new Error(
          'No email claim in the ID token. Ensure the `email` scope is granted and the user has an email address.'
        );
      }

      req.session.user = {
        sub: claims.sub,
        email: claims.email,
        name: claims.name || claims.preferred_username || claims.email,
      };

      console.log(`✓ User authenticated: ${claims.email}`);

      req.session.save(() => res.redirect('/'));
    } catch (err) {
      console.error('✗ Authentication error:', err.message);
      if (err.error_reason) console.error('  reason:', err.error_reason);
      if (err.error_description) {
        console.error('  description:', err.error_description);
      }
      res.status(400).send(`Authentication failed: ${escapeHtml(err.message)}`);
    }
  });

  /**
   * GET /logout - destroy the session
   */
  router.get('/logout', (req, res) => {
    const email = req.session.user ? req.session.user.email : 'unknown';
    req.session.destroy(() => {
      console.log(`✓ User logged out: ${email}`);
      res.redirect('/');
    });
  });

  /**
   * GET /me - the currently authenticated user
   */
  router.get('/me', (req, res) => {
    if (!req.session.user) {
      return res.status(401).json({ authenticated: false });
    }
    res.json({ authenticated: true, user: req.session.user });
  });

  return router;
}

function escapeHtml(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

module.exports = { createAuthRouter };
