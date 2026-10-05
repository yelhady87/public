const express = require('express');
const path = require('path');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

/**
 * Launcher routes: the tile grid, the tile data, and the launch redirect.
 *
 * Mounted at the app root.
 */
function createLauncherRouter(oidc, api) {
  const router = express.Router();

  /**
   * GET / - serve the launcher shell. The page itself fetches tile data from
   * /api/my-apps; the server decides here whether a session exists.
   */
  router.get('/', (req, res) => {
    res.sendFile('index.html', { root: PUBLIC_DIR });
  });

  /**
   * GET /api/my-apps - applications assigned to the signed-in user.
   *
   * Server-side only: the browser never sees FUSION_AUTH_API_KEY.
   */
  router.get('/api/my-apps', async (req, res) => {
    if (!req.session.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
      const apps = await api.listAppsForUser(req.session.user.sub);
      res.json({
        user: req.session.user,
        count: apps.length,
        apps,
      });
    } catch (err) {
      console.error('✗ Failed to list applications:', err.message);
      res.status(502).json({
        error: 'Could not load your applications from FusionAuth',
        detail: err.message,
      });
    }
  });

  /**
   * GET /launch/:appId - redirect into an assigned application.
   *
   * The application is re-resolved through the signed-in user's own assignments
   * rather than trusted from the request, so a user cannot launch an app they
   * are not registered for just by guessing its id.
   *
   * The redirect goes to FusionAuth's authorize endpoint, not to the app itself.
   * The target app performs its own code exchange, and because the FusionAuth
   * browser session is still alive the hop is silent - the user is not asked to
   * sign in again.
   */
  router.get('/launch/:appId', async (req, res) => {
    if (!req.session.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
      const tile = await api.findAppForUser(
        req.session.user.sub,
        req.params.appId
      );

      if (!tile) {
        return res.status(403).json({
          error: 'You do not have access to that application',
        });
      }

      const url = new URL(oidc.getAuthorizationEndpoint());
      url.searchParams.set('client_id', tile.applicationId);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('redirect_uri', tile.redirectUri);
      url.searchParams.set('scope', oidc.getScopes().join(' '));

      // NOTE: no `state` is sent, deliberately.
      //
      // `state` exists so the client that STARTED a flow can prove the response
      // belongs to it. Here the client is the target application, and it is the
      // one that validates state at its own callback. A value invented here was
      // never seen by that application, so it could only ever fail validation -
      // and in this launcher it failed louder still, because a code arriving at
      // the launcher's own /callback was rejected outright as a CSRF attempt.
      // The launcher is a redirector, not the OIDC client, so it has no state to
      // correlate and must not fabricate one.

      res.redirect(url.toString());
    } catch (err) {
      console.error('✗ Failed to launch application:', err.message);
      res.status(502).json({
        error: 'Could not start that application',
        detail: err.message,
      });
    }
  });

  return router;
}

module.exports = { createLauncherRouter };
