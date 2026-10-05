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
 * Parse INCORTA_A2A_DATASETS into the dataset shape the agent expects.
 *
 * Accepted forms, comma separated:
 *   HR              -> { type: 'business_view', data: { schema_name: 'HR' } }
 *   HR:Dept         -> { type: 'business_view', data: { schema_name: 'HR', table_name: 'Dept' } }
 *
 * The table half is optional so the same variable covers a schema-wide context
 * and a single-table one. An unset or empty value yields no datasets at all,
 * which is a valid request: it asks the agent to answer without dataset
 * grounding rather than failing.
 */
function resolveDatasets() {
  const raw = process.env.INCORTA_A2A_DATASETS || '';
  const datasets = [];

  for (const entry of raw.split(',')) {
    const trimmed = entry.trim();
    if (!trimmed) continue;

    const sep = trimmed.search(/[:/]/);
    const schema = sep === -1 ? trimmed : trimmed.slice(0, sep);
    const table = sep === -1 ? '' : trimmed.slice(sep + 1).trim();

    if (!schema) continue;

    const data = { schema_name: schema };
    if (table) data.table_name = table;

    datasets.push({ type: 'business_view', data });
  }

  return datasets;
}

/**
 * Build the conversation_context metadata block sent with every message.
 *
 * `current_date` is stamped per request rather than cached, because the agent
 * uses it to resolve relative dates like "last quarter". Sending a stale one
 * would make the agent answer relative to the wrong day.
 */
function buildConversationContext() {
  const context = {
    client: process.env.INCORTA_A2A_CLIENT || 'general',
    current_date: new Date().toISOString().slice(0, 19).replace('T', ' '),
    client_context: {
      datasets: resolveDatasets(),
      enable_summary: !/^(0|false|no|off)$/i.test(
        String(process.env.INCORTA_A2A_ENABLE_SUMMARY || '').trim()
      ),
      verbosity: process.env.INCORTA_A2A_VERBOSITY || 'detailed',
    },
  };

  return context;
}

/**
 * Compose the JSON-RPC payload for one outbound message.
 *
 * @param {object} options
 * @param {string} options.text - the user's message
 * @param {string} options.messageId - unique id for this message
 * @param {string} options.contextId - conversation this message belongs to
 * @param {number} options.rpcId - JSON-RPC request id, incremented per call
 * @returns {object} the request body
 */
function buildMessagePayload({ text, messageId, contextId, rpcId }) {
  return {
    // A blocking call keeps this a simple request/response exchange. Incorta's
    // UI streams, but the browser-side fetch in this app does not, so a
    // blocking:true request is the honest match for what it can consume.
    blocking: true,
    jsonrpc: '2.0',
    method: 'message/send',
    params: {
      message: {
        messageId,
        role: 'user',
        kind: 'message',
        parts: [{ kind: 'text', text }],
        metadata: {
          conversation_context: buildConversationContext(),
        },
      },
      contextId,
    },
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
  resolveDatasets,
  buildConversationContext,
  buildMessagePayload,
  buildHeaders,
  agentUrl,
};