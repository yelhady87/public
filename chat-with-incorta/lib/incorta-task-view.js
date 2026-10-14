/**
 * Turning an A2A task (the `result` of `tasks/get`) into what the browser
 * needs. Pure functions, no network.
 *
 * The browser only ever sees this trimmed view: never the bearer token, the raw
 * payload, step inputs/outputs or tracebacks.
 */

// States where polling cannot make further progress. `input-required` and
// `auth-required` wait for the user, so polling them would only run to timeout.
const FINAL_STATES = [
  'completed',
  'failed',
  'canceled',
  'rejected',
  'input-required',
  'auth-required',
];
const ERROR_STATES = ['failed', 'canceled', 'rejected'];

const MAX_STEPS = 50;
const MAX_TEXT = 2000;
const MAX_ANSWER = 50000;

const clip = (value, max = MAX_TEXT) => String(value == null ? '' : value).slice(0, max);

/** Text of the `text` parts of a parts array, joined; other part kinds are ignored. */
function partsText(parts) {
  if (!Array.isArray(parts)) return '';
  return parts
    .map((p) => (p && typeof p.text === 'string' ? p.text : ''))
    .filter(Boolean)
    .join('\n');
}

/**
 * The agent's answer. It lives in the artifacts: `status.message` of a finished
 * task is only a status note such as "Response ready.", so it is never used.
 * A blocking reply is a message instead of a task, so message parts are the
 * fallback.
 */
function extractAnswer(task) {
  if (!task || typeof task !== 'object') return '';

  if (Array.isArray(task.artifacts)) {
    const text = task.artifacts
      .map((a) => (a ? partsText(a.parts) || (typeof a.text === 'string' ? a.text : '') : ''))
      .filter(Boolean)
      .join('\n');
    if (text.trim()) return text;
  }

  return partsText(task.parts) || partsText(task.message && task.message.parts);
}

/** The agent's reasoning steps, from the `reasoning_chain` history entries. */
function extractSteps(task) {
  const history = Array.isArray(task.history) ? task.history : [];

  return history
    .filter((m) => m && m.metadata && m.metadata.step_type === 'reasoning_chain')
    .slice(0, MAX_STEPS)
    .map((m) => {
      const data = (m.parts && m.parts[0] && m.parts[0].data) || {};
      const metrics = data.metrics || {};
      return {
        title: clip(data.title || m.metadata.description),
        description: clip(m.metadata.description),
        status: clip(data.status || m.metadata.status),
        subtitle: clip(data.subtitle),
        durationMs: Number.isFinite(metrics.execution_time_ms)
          ? metrics.execution_time_ms
          : null,
      };
    });
}

/** Message of the last step that failed, found in the unfiltered history. */
function lastStepError(task) {
  const history = Array.isArray(task.history) ? task.history : [];
  for (let i = history.length - 1; i >= 0; i -= 1) {
    const data = history[i] && history[i].parts && history[i].parts[0] && history[i].parts[0].data;
    if (data && data.error && data.error.message) return data.error.message;
  }
  return '';
}

/**
 * @param {object} task - `result` of a `tasks/get` reply
 * @param {string} [traceId] - Incorta's trace-id for the poll
 * @returns {{taskId: string, state: string, done: boolean, steps: object[],
 *   answer: string, error: ({message: string, traceId: (string|null)}|null)}}
 */
function toView(task, traceId) {
  task = task || {};
  const state = (task && task.status && task.status.state) || 'unknown';
  const statusText = partsText(task.status && task.status.message && task.status.message.parts);

  let error = null;
  if (ERROR_STATES.includes(state)) {
    error = {
      message: clip(statusText || lastStepError(task) || `The task ${state}.`),
      traceId: traceId || null,
    };
  } else if (state === 'input-required' || state === 'auth-required') {
    error = {
      message: clip(statusText || `The agent needs more from you (${state}).`),
      traceId: traceId || null,
    };
  }

  let answer = clip(extractAnswer(task), MAX_ANSWER);
  if (state === 'completed' && !answer.trim()) answer = 'No answer returned.';

  return {
    taskId: task.id,
    state,
    done: FINAL_STATES.includes(state),
    steps: extractSteps(task),
    answer: state === 'completed' ? answer : '',
    error,
  };
}

module.exports = { extractAnswer, toView, FINAL_STATES };
