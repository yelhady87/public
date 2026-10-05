const express = require('express');
const axios = require('axios');

const { incortaApiUrl } = require('../lib/oidc-incorta');

/**
 * Incorta API routes
 * @param {object} incorta - the IncortaOIDCClient instance
 */
function createIncortaRouter(incorta) {
  const router = express.Router();

  /**
   * Middleware: require an authenticated user
   */
  function requireAuth(req, res, next) {
    if (!req.session.user) {
      return res.status(401).json({
        error: 'Not authenticated',
        message: 'Login with Fusion Auth first',
      });
    }
    next();
  }

  /**
   * Helper: get an Incorta access token for the authenticated user, using the
   * session cache when it is still valid.
   */
  async function getIncortaToken(req) {
    const userEmail = req.session.user.email;
    const cached = req.session.incortaToken;

    const now = Math.floor(Date.now() / 1000);
    if (cached && cached.expiresAt && cached.expiresAt > now + 30) {
      return cached.accessToken;
    }

    const tokenData = await incorta.getAccessToken(userEmail);
    req.session.incortaToken = {
      accessToken: tokenData.access_token,
      expiresAt: now + (tokenData.expires_in || 300),
    };
    return tokenData.access_token;
  }

  /**
   * Handler: call Incorta's schema list API for the configured tenant.
   *
   * The tenant (project) comes from INCORTA_TENANT, falling back to the last
   * segment of INCORTA_OIDC_ISSUER. With INCORTA_TENANT=demo_keycloak this is:
   *
   * curl -X 'POST' \
   *   'http://localhost/incorta/api/v2/demo_keycloak/schema/list?schemaType=ALL' \
   *   -H 'accept: application/json' \
   *   -H 'Content-Type: application/json' \
   *   -d '{"limit": 0, "offset": 0, "sortBy": "NAME_ASC"}'
   */
  async function schemaListHandler(req, res) {
    try {
      const accessToken = await getIncortaToken(req);

      const response = await axios.post(
        incortaApiUrl('/schema/list?schemaType=ALL'),
        {
          limit: 0,
          offset: 0,
          sortBy: 'NAME_ASC',
        },
        {
          headers: {
            accept: 'application/json',
            'Content-Type': 'application/json',
            Authorization: `Bearer ${accessToken}`,
          },
          // Incorta may return 4xx/5xx with a JSON error body worth surfacing
          validateStatus: () => true,
        }
      );

      // Incorta stamps every API response with a `trace-id`, including 4xx/5xx
      // ones. It is the handle to quote when reporting a problem to Incorta
      // support, so log it on both the success and error paths rather than only
      // when things go wrong - by the time an error shows up you want the id
      // that correlates with the server-side log. Verified present on both
      // 200 and 500 responses from Incorta's own nginx.
      const traceId = response.headers['trace-id'];

      if (response.status >= 400) {
        console.error(
          `✗ Incorta API error (${response.status}):`,
          JSON.stringify(response.data)
        );
        console.error(
          `  Incorta trace-id: ${traceId || '(none returned)'}${
            traceId ? ` - quote this to Incorta support` : ''
          }`
        );
        return res.status(response.status).json({
          error: `Incorta API returned ${response.status}`,
          traceId: traceId || null,
          details: response.data,
        });
      }

      console.log(
        `✓ Incorta schema list fetched for ${req.session.user.email}` +
          (traceId ? ` (trace-id: ${traceId})` : '')
      );
      res.json(response.data);
    } catch (err) {
      // A failed request never reached Incorta, or the response was lost, so
      // there is no upstream trace-id to report here.
      console.error('✗ Incorta API request failed:', err.message);
      res.status(500).json({ error: err.message });
    }
  }

  router.post('/schemas/list', requireAuth, schemaListHandler);
  // Convenience GET alias for clicking a link in the browser
  router.get('/schemas/list', requireAuth, schemaListHandler);

  return router;
}

module.exports = { createIncortaRouter };
