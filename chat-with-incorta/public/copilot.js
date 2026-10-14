/**
 * Copilot page. The conversation lives here: the page holds the contextId and
 * the current task id, and a reload or "New chat" starts a fresh conversation.
 *
 * All text goes in through textContent, never as HTML.
 */

/**
 * Poll until the task is done, with these rules:
 *   - the next poll starts only after the previous one answered (no overlap)
 *   - a network error or 5xx is retried up to `maxTransient` times in a row
 *   - a 401, or any other 4xx, stops at once (the error is thrown)
 *   - it gives up after `timeoutMs` of wall-clock time
 *   - `isCancelled()` stops it quietly (Retry, New chat)
 *
 * @returns {Promise<{view?: object, timedOut?: boolean, cancelled?: boolean}>}
 */
async function pollTask({
  fetchView,
  onView,
  intervalMs,
  timeoutMs,
  isCancelled = () => false,
  maxTransient = 3,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now = Date.now,
}) {
  const started = now();
  let transient = 0;

  for (;;) {
    if (isCancelled()) return { cancelled: true };
    if (now() - started > timeoutMs) return { timedOut: true };

    try {
      const view = await fetchView();
      transient = 0;
      if (isCancelled()) return { cancelled: true };
      onView(view);
      if (view.done) return { view };
    } catch (err) {
      if (isCancelled()) return { cancelled: true };
      const fatal = err && err.status && err.status < 500;
      transient += 1;
      if (fatal || transient > maxTransient) throw err;
    }

    await sleep(intervalMs);
  }
}

/** GET/POST JSON; failures carry the HTTP status and Incorta's error body. */
async function requestJson(url, options) {
  const res = await fetch(url, options);
  let body = null;
  try {
    body = await res.json();
  } catch (e) {
    /* not JSON */
  }
  if (!res.ok) {
    const err = new Error((body && body.error) || `HTTP ${res.status}`);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return body;
}

function startPage() {
  const transcript = document.getElementById('transcript');
  const form = document.getElementById('form');
  const input = document.getElementById('input');
  const sendBtn = document.getElementById('send');
  const newChatBtn = document.getElementById('newChat');

  const intervalMs = Number(document.body.dataset.pollMs) || 2000;
  const timeoutMs = Number(document.body.dataset.timeoutMs) || 300000;

  let contextId = null; // conversation id assigned by Incorta on the first reply
  let runId = 0; // bumped by Retry / New chat so an old run's results are dropped
  let running = false;
  let controller = null;

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function setRunning(value) {
    running = value;
    input.disabled = value;
    sendBtn.disabled = value;
    transcript.setAttribute('aria-busy', String(value));
    if (!value) input.focus();
  }

  function newTurn(text) {
    const turn = el('div', 'turn');
    turn.appendChild(el('div', 'user', text));
    const agent = el('div', 'agent');
    turn.appendChild(agent);
    transcript.appendChild(turn);
    turn.scrollIntoView({ block: 'end' });
    return agent;
  }

  /** Agent side of one turn: "Thoughts" (steps) and a card for the answer or error. */
  function renderAgent(agent, { view, seconds, running: isRunning, error, text }) {
    agent.replaceChildren();

    const thoughts = el('details', 'thoughts' + (isRunning ? ' running' : ''));
    thoughts.open = isRunning;
    const summary = el('summary');
    summary.appendChild(el('span', 'dot'));
    summary.appendChild(
      el('span', null, isRunning ? 'Thinking…' : seconds != null ? `Thought for ${seconds}s` : 'Thoughts')
    );
    thoughts.appendChild(summary);

    const steps = (view && view.steps) || [];
    if (steps.length) {
      const list = el('ol', 'steps');
      for (const step of steps) {
        const item = el('li', /error/i.test(step.status) ? 'st-error' : '');
        item.appendChild(el('strong', null, step.title || step.description));
        const detail = [step.status, step.subtitle, step.durationMs != null ? `${step.durationMs} ms` : '']
          .filter(Boolean)
          .join(' · ');
        if (detail) {
          item.appendChild(document.createTextNode(' '));
          item.appendChild(el('small', null, detail));
        }
        list.appendChild(item);
      }
      thoughts.appendChild(list);
    }
    if (isRunning || steps.length) agent.appendChild(thoughts);

    if (error) {
      const card = el('div', 'card error');
      card.setAttribute('role', 'alert');
      card.appendChild(el('div', null, error.message));

      const actions = el('div', 'actions');
      const detailsBtn = el('button', null, 'View Error Details');
      detailsBtn.type = 'button';
      const pre = el('pre', 'details', error.details);
      pre.hidden = true;
      detailsBtn.addEventListener('click', () => {
        pre.hidden = !pre.hidden;
      });
      actions.appendChild(detailsBtn);

      if (error.retry) {
        const retryBtn = el('button', null, 'Retry');
        retryBtn.type = 'button';
        retryBtn.addEventListener('click', () => run(text, agent));
        actions.appendChild(retryBtn);
      }
      card.appendChild(actions);
      card.appendChild(pre);
      agent.appendChild(card);
    } else if (view && view.done && view.state === 'completed') {
      agent.appendChild(el('div', 'card', view.answer));
    }
  }

  function describeError(err) {
    if (err.status === 401) {
      return { message: 'Your session has ended. Please log in again.', details: 'HTTP 401', retry: false };
    }
    const body = err.body || {};
    const details = [
      `Status: ${err.status || 'network error'}`,
      body.traceId ? `Trace-id: ${body.traceId}` : '',
      body.details ? JSON.stringify(body.details, null, 2) : '',
    ]
      .filter(Boolean)
      .join('\n');
    return { message: err.message, details, retry: true };
  }

  /** Send `text` and poll it to the end, rendering into `agent`. */
  async function run(text, agent) {
    runId += 1;
    const myRun = runId;
    if (controller) controller.abort();
    controller = new AbortController();
    const signal = controller.signal;
    const cancelled = () => myRun !== runId;

    setRunning(true);
    const started = Date.now();
    renderAgent(agent, { running: true });

    try {
      const sent = await requestJson('/api/incorta/copilot/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, contextId }),
        signal,
      });
      if (cancelled()) return;
      contextId = sent.contextId;

      const outcome = await pollTask({
        fetchView: () => requestJson(`/api/incorta/copilot/tasks/${encodeURIComponent(sent.taskId)}`, { signal }),
        onView: (view) => renderAgent(agent, { view, running: !view.done }),
        intervalMs,
        timeoutMs,
        isCancelled: cancelled,
      });
      if (outcome.cancelled) return;

      const seconds = Math.round((Date.now() - started) / 1000);
      if (outcome.timedOut) {
        renderAgent(agent, {
          seconds,
          text,
          error: {
            message: `No answer after ${Math.round(timeoutMs / 1000)} seconds. The task may still be running in Incorta.`,
            details: `Task: ${sent.taskId}`,
            retry: true,
          },
        });
      } else {
        const view = outcome.view;
        renderAgent(agent, {
          view,
          seconds,
          text,
          error: view.error && {
            message: view.error.message,
            details: `State: ${view.state}\nTrace-id: ${view.error.traceId || 'n/a'}\nTask: ${view.taskId}`,
            retry: view.state !== 'input-required' && view.state !== 'auth-required',
          },
        });
      }
    } catch (err) {
      if (cancelled() || err.name === 'AbortError') return;
      renderAgent(agent, { text, error: describeError(err) });
    } finally {
      if (!cancelled()) setRunning(false);
    }
  }

  function submit() {
    const text = input.value.trim();
    if (!text || running) return;
    input.value = '';
    run(text, newTurn(text));
  }

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    submit();
  });
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      submit();
    }
  });
  newChatBtn.addEventListener('click', () => {
    runId += 1; // drop whatever is in flight
    if (controller) controller.abort();
    contextId = null;
    transcript.replaceChildren();
    setRunning(false);
  });
  window.addEventListener('pagehide', () => {
    if (controller) controller.abort();
  });

  input.focus();
}

if (typeof document !== 'undefined') {
  startPage();
}
if (typeof module !== 'undefined') {
  module.exports = { pollTask };
}
