const express = require('express');
const crypto = require('crypto');

const { listSchemas } = require('../lib/incorta-schemas');
const { sendMessage } = require('../lib/incorta-a2a-client');
const { requireAuth, getIncortaToken } = require('../lib/incorta-session');

/**
 * Incorta API routes
 * @param {object} incorta - the IncortaOIDCClient instance
 */
function createIncortaRouter(incorta) {
  const router = express.Router();

  const getToken = (req) => getIncortaToken(req, incorta);

  /**
   * Handler: list the schemas for the configured tenant.
   */
  async function schemaListHandler(req, res) {
    try {
      const accessToken = await getToken(req);
      const response = await listSchemas({ accessToken });
      const { traceId } = response;

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
   *   -d '{"jsonrpc":"2.0","method":"message/send","params":{...},"id":1}'
   *
   * The first message carries no conversation id; Incorta assigns one in its
   * reply and it is kept in the session and sent on later messages, so consecutive messages from one
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

      const accessToken = await getToken(req);

      if (!req.session.a2a) {
        req.session.a2a = { contextId: undefined, rpcId: 0 };
      }
      req.session.a2a.rpcId += 1;

      const response = await sendMessage({
        accessToken,
        text,
        messageId: crypto.randomUUID(),
        contextId: req.session.a2a.contextId,
        rpcId: req.session.a2a.rpcId,
      });
      const { traceId, durationMs } = response;

      // Remember the conversation id Incorta assigned, to continue the thread
      if (!req.session.a2a.contextId && response.status < 400) {
        req.session.a2a.contextId = response.data?.result?.contextId;
      }

      if (response.status >= 400) {
        // Incorta reports permission and configuration problems as 500s with a
        // readable message (e.g. INC_05000301 "You do not have the necessary
        // permissions to access the Copilot"), so its text is passed through
        // rather than replaced by a generic error. The body itself is already
        // logged by sendMessage.
        console.error(
          `✗ Incorta A2A error (${response.status}) after ${durationMs}ms`
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
