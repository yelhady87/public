const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { sendMessage, getTask } = require('../lib/incorta-a2a-client');
const { toView } = require('../lib/incorta-task-view');
const { requireAuth, getIncortaToken } = require('../lib/incorta-session');

// Task and conversation ids end up inside a JSON-RPC body, so keep them to a
// plain id alphabet. The browser holds both ids; whether a user may read a task
// is decided by Incorta, which issued the token for that user.
const ID_PATTERN = /^[\w-]{1,128}$/;

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

/**
 * Polled Copilot chat API, mounted at /api/incorta/copilot.
 *
 * The server keeps no conversation state: the page holds the contextId and the
 * task id and sends them back with each call.
 *
 * @param {object} incorta - the IncortaOIDCClient instance
 */
function createCopilotRouter(incorta) {
  const router = express.Router();

  // Last state logged per task, so a poll is logged only when something
  // changed. Bounded: a task that never finishes must not grow this forever.
  const lastLogged = new Map();

  /**
   * Call Incorta with the user's token. If Incorta rejects the token (it may
   * have expired mid-task), fetch a fresh one and retry once.
   */
  async function withToken(req, call) {
    let response = await call(await getIncortaToken(req, incorta));
    if (response.status === 401) {
      response = await call(await getIncortaToken(req, incorta, { force: true }));
    }
    return response;
  }

  /**
   * Answer for an Incorta reply that cannot be used, or null if it is fine.
   * Incorta reports problems as error statuses with a readable body, and also
   * as JSON-RPC `error` objects under HTTP 200.
   */
  function upstreamProblem(response) {
    if (response.status >= 400) {
      return {
        status: response.status,
        body: {
          error: `Incorta Copilot returned ${response.status}`,
          traceId: response.traceId || null,
          details: response.data,
        },
      };
    }
    if (response.data && response.data.error) {
      return {
        status: 502,
        body: {
          error: response.data.error.message || 'Incorta returned a JSON-RPC error',
          traceId: response.traceId || null,
          details: response.data.error,
        },
      };
    }
    return null;
  }

  /**
   * POST /messages - start a task for one user message
   * body: { text, contextId? }  ->  { taskId, contextId }
   */
  router.post('/messages', requireAuth, async (req, res) => {
    try {
      if (!req.is('application/json')) {
        return res.status(415).json({ error: 'Content-Type must be application/json' });
      }

      const text = typeof req.body?.text === 'string' ? req.body.text.trim() : '';
      if (!text) {
        return res.status(400).json({ error: 'Message text is required' });
      }

      const maxLength = Number(process.env.INCORTA_A2A_MAX_MESSAGE_LENGTH) || 8000;
      if (text.length > maxLength) {
        return res.status(400).json({
          error: `Message is too long (${text.length} characters, limit ${maxLength})`,
        });
      }

      const { contextId } = req.body;
      if (contextId != null && !(typeof contextId === 'string' && ID_PATTERN.test(contextId))) {
        return res.status(400).json({ error: 'Invalid contextId' });
      }

      const response = await withToken(req, (accessToken) =>
        sendMessage({
          accessToken,
          text,
          messageId: crypto.randomUUID(),
          contextId: contextId || undefined,
          rpcId: 1,
          blocking: false,
        })
      );

      const problem = upstreamProblem(response);
      if (problem) {
        console.error(`✗ Incorta Copilot send failed (${problem.status}), trace-id: ${response.traceId || '(none)'}`);
        return res.status(problem.status).json(problem.body);
      }

      if (!response.taskId || !response.contextId) {
        console.error('✗ Incorta Copilot reply had no task id / context id');
        return res.status(502).json({
          error: 'Incorta did not return a task to poll',
          traceId: response.traceId || null,
          details: response.data,
        });
      }

      console.log(
        `✓ Incorta Copilot task ${response.taskId} started for ${req.session.user.email}` +
          (response.traceId ? ` (trace-id: ${response.traceId})` : '')
      );
      res.json({ taskId: response.taskId, contextId: response.contextId });
    } catch (err) {
      console.error('✗ Incorta Copilot send failed:', err.message);
      res.status(502).json({ error: err.message });
    }
  });

  /**
   * GET /tasks/:id - one poll: the task's current state, trimmed for the browser
   */
  router.get('/tasks/:id', requireAuth, async (req, res) => {
    try {
      const taskId = req.params.id;
      if (!ID_PATTERN.test(taskId)) {
        return res.status(400).json({ error: 'Invalid task id' });
      }

      const response = await withToken(req, (accessToken) =>
        getTask({ accessToken, taskId })
      );

      const problem = upstreamProblem(response);
      if (problem) {
        console.error(`✗ Incorta Copilot poll failed (${problem.status}), trace-id: ${response.traceId || '(none)'}`);
        return res.status(problem.status).json(problem.body);
      }

      const task = response.data && response.data.result;
      if (!task || typeof task !== 'object') {
        return res.status(502).json({
          error: 'Incorta returned no task',
          traceId: response.traceId || null,
        });
      }

      const view = toView(task, response.traceId);

      // Log a state change, and the whole body once the task is done
      if (lastLogged.get(taskId) !== view.state) {
        if (lastLogged.size >= 200) lastLogged.clear();
        lastLogged.set(taskId, view.state);
        console.log(`• Incorta Copilot task ${taskId}: ${view.state} (${view.steps.length} steps)`);
      }
      if (view.done) {
        lastLogged.delete(taskId);
        console.log(
          `← Incorta Copilot task ${taskId} final body:\n${JSON.stringify(response.data, null, 2)}`
        );
      }

      res.json(view);
    } catch (err) {
      console.error('✗ Incorta Copilot poll failed:', err.message);
      res.status(502).json({ error: err.message });
    }
  });

  return router;
}

/**
 * GET /copilot - the page. A logged-out visitor is sent to the home page, which
 * has the login buttons. The poll settings are numbers written into data-
 * attributes of the HTML, not into the script.
 */
function copilotPage(req, res) {
  if (!req.session.user) {
    return res.redirect('/');
  }

  const html = fs
    .readFileSync(path.join(PUBLIC_DIR, 'copilot.html'), 'utf8')
    .replace('__POLL_MS__', String(Number(process.env.INCORTA_COPILOT_POLL_MS) || 2000))
    .replace('__TIMEOUT_MS__', String(Number(process.env.INCORTA_COPILOT_TIMEOUT_MS) || 300000));

  res.type('html').send(html);
}

/** GET /copilot.js - the page's script. It holds no secrets, so it needs no login. */
function copilotScript(req, res) {
  res.type('js').sendFile(path.join(PUBLIC_DIR, 'copilot.js'));
}

module.exports = { createCopilotRouter, copilotPage, copilotScript };
