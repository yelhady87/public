const axios = require('axios');

const {
  buildMessagePayload,
  buildHeaders,
  agentUrl,
} = require('./incorta-a2a');

/**
 * Incorta Copilot A2A client: the network calls only.
 *
 * Request validation, session handling and turning results into HTTP
 * responses stay with the callers (routes/).
 *
 * Neither call throws on a 4xx/5xx - Incorta reports permission and
 * configuration problems as error statuses with a readable body, and the
 * caller wants that body. Transport failures (timeout, connection refused) do
 * throw.
 *
 * Request headers, including the bearer token, are deliberately never logged;
 * only the URL and the JSON bodies are.
 */

/**
 * POST one JSON-RPC payload to the agent endpoint.
 *
 * @param {object} payload - the JSON-RPC request body
 * @param {object} options
 * @param {string} options.accessToken - Incorta access token
 * @param {number} options.timeout - axios timeout in ms
 * @param {boolean} [options.log=true] - log the URL and both bodies
 */
async function post(payload, { accessToken, timeout, log = true }) {
  const url = agentUrl();

  if (log) {
    console.log(`→ Incorta API request: POST ${url}`);
    console.log(`→ Incorta A2A request body:\n${JSON.stringify(payload, null, 2)}`);
  }

  const started = Date.now();
  const response = await axios.post(url, payload, {
    headers: buildHeaders(accessToken),
    // Surfaces Incorta's own JSON error body instead of an axios throw
    validateStatus: () => true,
    timeout,
  });
  const durationMs = Date.now() - started;

  if (log) {
    console.log(
      `← Incorta A2A response body (${response.status}, ${durationMs}ms):\n${JSON.stringify(
        response.data,
        null,
        2
      )}`
    );
  }

  return {
    status: response.status,
    data: response.data,
    traceId: response.headers['trace-id'],
    durationMs,
    url,
    payload,
  };
}

/**
 * Send one message to the agent.
 *
 * A blocking call (the default) waits for the answer, which can take a while,
 * so it gets a long timeout. A non-blocking call returns a task straight away;
 * `taskId` and `contextId` are read from the reply (never derived), and are
 * undefined if the reply is not a task.
 *
 * @param {object} options
 * @param {string} options.accessToken - Incorta access token
 * @param {string} options.text - the user's message
 * @param {string} options.messageId - unique id for this message
 * @param {string} [options.contextId] - conversation id (absent on the first message)
 * @param {number} options.rpcId - JSON-RPC request id
 * @param {boolean} [options.blocking=true] - wait for the answer
 */
async function sendMessage({
  accessToken,
  text,
  messageId,
  contextId,
  rpcId,
  blocking = true,
}) {
  const payload = buildMessagePayload({ text, messageId, contextId, rpcId, blocking });
  const timeout = blocking
    ? Number(process.env.INCORTA_A2A_TIMEOUT_MS) || 120000
    : 30000;

  const response = await post(payload, { accessToken, timeout });
  const result = response.data && response.data.result;

  return {
    ...response,
    taskId: result && result.id,
    contextId: result && result.contextId,
  };
}

/**
 * Fetch the current state of a task (`tasks/get`). Not logged here: a poll
 * repeats every couple of seconds, so the caller logs only what changed.
 */
async function getTask({ accessToken, taskId }) {
  const payload = {
    jsonrpc: '2.0',
    method: 'tasks/get',
    params: { id: taskId },
    id: 1,
  };
  return post(payload, { accessToken, timeout: 30000, log: false });
}

module.exports = { sendMessage, getTask };
