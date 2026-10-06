const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

const { incortaApiUrl } = require('../lib/oidc-incorta');
const {
  buildMessagePayload,
  buildHeaders,
  agentUrl,
} = require('../lib/incorta-a2a');

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

  /**
   * Handler: forward one chat message to Incorta's Copilot A2A agent.
   *
   * Equivalent to the request the Incorta Copilot UI makes from the browser:
   *
   * curl -X 'POST' 'http://localhost/incorta/api/v2/<tenant>/copilot/a2a/agent/smart-agent' \
   *   -H 'accept: application/json' \
   *   -H 'content-type: application/json' \
   *   -H 'authorization: Bearer <incorta access token>' \
   *   -d '{"blocking":true,"jsonrpc":"2.0","method":"message/send", ... }'
   *
   * The conversation id lives in the session, so consecutive messages from one
   * browser tab land in the same Incorta conversation. The JSON-RPC id
   * increments per call, as the spec requires for correlating responses.
   */
  async function chatHandler(req, res) {
    try {
      const text = typeof req.body?.text === 'string' ? req.body.text.trim() : '';

      if (!text) {
        return res.status(400).json({
          error: 'Message text is required',
        });
      }

      // Bound the length so a pasted document cannot turn one click into an
      // unbounded agent call. Incorta's own UI caps input well below this.
      const maxLength = Number(process.env.INCORTA_A2A_MAX_MESSAGE_LENGTH) || 8000;
      if (text.length > maxLength) {
        return res.status(400).json({
          error: `Message is too long (${text.length} characters, limit ${maxLength})`,
        });
      }

      const accessToken = await getIncortaToken(req);

      if (!req.session.a2a) {
        req.session.a2a = {
          contextId: crypto.randomUUID(),
          rpcId: 0,
        };
      }
      req.session.a2a.rpcId += 1;

      const payload = buildMessagePayload({
        text,
        messageId: crypto.randomUUID(),
        contextId: req.session.a2a.contextId,
        rpcId: req.session.a2a.rpcId,
      });

      const started = Date.now();
      const response = await axios.post(agentUrl(), payload, {
        headers: buildHeaders(accessToken),
        // Surfaces Incorta's own JSON error body instead of an axios throw
        validateStatus: () => true,
        // A blocking agent call can take a while; axios defaults to none, but
        // being explicit keeps the failure mode a clear 504 rather than a hang.
        timeout: Number(process.env.INCORTA_A2A_TIMEOUT_MS) || 120000,
      });

      const traceId = response.headers['trace-id'];
      const durationMs = Date.now() - started;

      if (response.status >= 400) {
        // Incorta reports permission and configuration problems as 500s with a
        // readable message (e.g. INC_05000301 "You do not have the necessary
        // permissions to access the Copilot"), so its text is passed through
        // rather than replaced by a generic error.
        console.error(
          `✗ Incorta A2A error (${response.status}) after ${durationMs}ms:`,
          JSON.stringify(response.data)
        );
        console.error(`  Incorta trace-id: ${traceId || '(none returned)'}`);

        return res.status(response.status).json({
          error: `Incorta Copilot returned ${response.status}`,
          traceId: traceId || null,
          details: response.data,
          durationMs,
        });
      }

      console.log(
        `✓ Incorta A2A message sent for ${req.session.user.email}` +
          `${traceId ? ` (trace-id: ${traceId})` : ''} in ${durationMs}ms`
      );

      res.json({
        reply: response.data,
        contextId: req.session.a2a.contextId,
        traceId: traceId || null,
        durationMs,
      });
    } catch (err) {
      console.error('✗ Incorta A2A request failed:', err.message);
      res.status(500).json({ error: err.message });
    }
  }

  router.post('/chat', requireAuth, chatHandler);

  router.post('/schemas/list', requireAuth, schemaListHandler);
  // Convenience GET alias for clicking a link in the browser
  router.get('/schemas/list', requireAuth, schemaListHandler);

  return router;
}

module.exports = { createIncortaRouter };
