const { incortaApiUrl } = require('./oidc-incorta');

/**
 * Incorta Copilot A2A (agent-to-agent) client.
 *
 * Wraps the JSON-RPC `message/send` endpoint that Incorta's Copilot UI calls
 * when you type into its chat box. The browser sends a large pile of headers
 * (sec-ch-ua, Sec-Fetch-*, Referer, Origin, User-Agent) because it is a page
 * talking to its own server; those are artifacts of the browser, not part of
 * the API contract, so none of them are forwarded. Only three are sent:
 *
 *   accept: application/json
 *   content-type: application/json
 *   authorization: Bearer <the access token obtained from Incorta>
 *
 * The XSRF header the browser also sends is deliberately NOT forwarded. It
 * protects Incorta's cookie-authenticated UI against CSRF; this server-to-server
 * call authenticates with a Bearer token and holds no cookies, so there is no
 * ambient credential for an attacker to ride. Sending it would be cargo cult.
 *
 * The `x-a2a-extensions` header is kept: it declares which output extensions
 * the agent should produce, so dropping it changes the response payload rather
 * than just the request.
 */

/**
 * Output extensions the Copilot UI requests. Configurable because these URLs
 * are deployment-specific; an Incorta install with custom extensions needs its
 * own list, and an install with none should be able to send an empty value.
 */
const DEFAULT_EXTENSIONS = [
  'https://crispy-disco-3ee5qrw.pages.github.io/external/extensions/intermediate-output',
  'https://crispy-disco-3ee5qrw.pages.github.io/external/extensions/nexus_parts',
  'https://crispy-disco-3ee5qrw.pages.github.io/external/extensions/task_metadata',
  'https://crispy-disco-3ee5qrw.pages.github.io/external/extensions/conversation_context',
];

/**
 * `client_context.params` selecting the model, from INCORTA_A2A_MODEL_KEY.
 * Omitted when unset, so Incorta uses its own default model.
 */
function modelKeyParams() {
  const value = (process.env.INCORTA_A2A_MODEL_KEY || '').trim();
  return value ? { params: [{ key: 'model_key', value }] } : {};
}

/**
 * Build the conversation_context metadata block sent with every message.
 *
 * `current_date` is stamped per request rather than cached, because the agent
 * uses it to resolve relative dates like "last quarter". Sending a stale one
 * would make the agent answer relative to the wrong day.
 */
function buildConversationContext() {
  return {
    client: process.env.INCORTA_A2A_CLIENT || 'general',
    current_date: new Date().toISOString().slice(0, 19).replace('T', ' '),
    client_context: {
      ...modelKeyParams(),
      enable_summary: !/^(0|false|no|off)$/i.test(
        String(process.env.INCORTA_A2A_ENABLE_SUMMARY || '').trim()
      ),
      verbosity: process.env.INCORTA_A2A_VERBOSITY || 'detailed',
    },
  };
}

/**
 * Compose the JSON-RPC payload for one outbound message.
 *
 * @param {object} options
 * @param {string} options.text - the user's message
 * @param {string} options.messageId - unique id for this message
 * @param {string} [options.contextId] - conversation this message belongs to.
 *   Omitted on the first message; Incorta assigns one in its reply.
 * @param {number} options.rpcId - JSON-RPC request id
 * @param {boolean} [options.blocking=true] - ask for a synchronous reply. When
 *   false no `configuration` is sent and Incorta answers with a task to poll.
 * @returns {object} the request body
 */
function buildMessagePayload({ text, messageId, contextId, rpcId, blocking = true }) {
  const params = {
    message: {
      messageId,
      role: 'user',
      kind: 'message',
      parts: [{ kind: 'text', text }],
      metadata: {
        conversation_context: buildConversationContext(),
      },
    },
  };

  if (blocking) {
    // Ask for a synchronous reply
    params.configuration = { blocking: true };
  }

  if (contextId) {
    params.contextId = contextId;
  }

  return {
    jsonrpc: '2.0',
    method: 'message/send',
    params,
    id: rpcId,
  };
}

/**
 * Headers for the A2A call. Only the API contract plus the Bearer token; see
 * the file header for what is intentionally omitted.
 */
function buildHeaders(accessToken) {
  const headers = {
    accept: 'application/json',
    'content-type': 'application/json',
    authorization: `Bearer ${accessToken}`,
  };

  // Three states, and the distinction matters:
  //   unset          -> send the defaults
  //   set, non-empty -> send exactly what was configured
  //   set, empty     -> send no x-a2a-extensions header at all, for an install
  //                     whose agent has no extensions and would choke on URLs it
  //                     does not recognize
  const configured = process.env.INCORTA_A2A_EXTENSIONS;
  const list = configured === undefined
    ? DEFAULT_EXTENSIONS
    : configured.split(',').map((e) => e.trim()).filter(Boolean);

  if (list.length) {
    headers['x-a2a-extensions'] = list.join(', ');
  }

  return headers;
}

/**
 * Full URL of the smart-agent endpoint for the configured tenant.
 *
 * The agent name is configurable because it is a per-install identifier; the
 * default matches the Incorta Copilot UI's own default.
 */
function agentUrl(agentName) {
  const agent = (agentName || process.env.INCORTA_A2A_AGENT || 'smart-agent').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(agent)) {
    throw new Error(
      `Invalid Incorta A2A agent "${agent}". Use letters, digits, dot, underscore or hyphen only.`
    );
  }
  return incortaApiUrl(`/copilot/a2a/agent/${agent}`);
}

module.exports = {
  DEFAULT_EXTENSIONS,
  buildConversationContext,
  buildMessagePayload,
  buildHeaders,
  agentUrl,
};