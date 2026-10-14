/**
 * A2A task shapes, condensed from real Incorta Copilot responses
 * (`result` of a `tasks/get` reply).
 */
const TASK_ID = '76d9ca8d-4a82-4d54-be54-df19167613cb_0';
const CONTEXT_ID = '76d9ca8d-4a82-4d54-be54-df19167613cb';

const userMessage = {
  contextId: CONTEXT_ID,
  kind: 'message',
  messageId: 'eadddd7b-4592-47b9-af9a-a288f6e89ead',
  parts: [{ kind: 'text', text: 'what are the schemas I have access to?' }],
  role: 'user',
  taskId: TASK_ID,
};

const intentStep = {
  contextId: CONTEXT_ID,
  kind: 'message',
  messageId: `${TASK_ID}_user_intent`,
  metadata: {
    step_type: 'reasoning_chain',
    sub_task_id: 'user_intent',
    description: 'Understanding the question',
    status: 'ERROR',
  },
  parts: [
    {
      kind: 'data',
      data: {
        type: 'TOOL',
        id: 'user_intent',
        title: 'Understanding the question',
        status: 'ERROR',
        subtitle: 'Clarifying the ask',
        output: ['Could not clarify the question - continuing with your original message.'],
        metrics: { execution_time_ms: 104 },
      },
    },
  ],
  role: 'agent',
  taskId: TASK_ID,
};

const schemasStep = {
  contextId: CONTEXT_ID,
  kind: 'message',
  messageId: `${TASK_ID}_toolu_1`,
  metadata: {
    step_type: 'reasoning_chain',
    sub_task_id: 'list_available_schemas',
    description: 'Listing your schemas',
    status: 'ERROR',
  },
  parts: [
    {
      kind: 'data',
      data: {
        type: 'TOOL',
        id: 'toolu_1',
        title: 'Discovering available data sources',
        status: 'ERROR',
        subtitle: 'Checking which data areas are available to you.',
        input: ['Checking which data areas are available to you.'],
        output: ['Schema discovery failed'],
        metrics: { execution_time_ms: 55 },
        error: {
          type: 'DataNotFoundException',
          message: 'No relevant tables were found for your question.',
          traceback: 'Traceback (most recent call last):\n  File "/build/source/secret.py"',
        },
      },
    },
  ],
  role: 'agent',
  taskId: TASK_ID,
};

const ANSWER_TEXT =
  "I couldn't find any schemas you have access to.\n\nThis usually means one of these:\n- **Your access hasn't been set up yet.**";

/** Task still running: submitted -> working with one step so far */
const working = {
  id: TASK_ID,
  contextId: CONTEXT_ID,
  kind: 'task',
  artifacts: [],
  history: [userMessage, intentStep],
  status: { state: 'working' },
};

/** Finished task. status.message is only "Response ready."; the answer is in the artifacts. */
const completed = {
  id: TASK_ID,
  contextId: CONTEXT_ID,
  kind: 'task',
  artifacts: [
    {
      artifactId: 'f6bd70c1-4fad-48d2-a042-b206e7cacac6',
      parts: [{ kind: 'text', metadata: { part_type: 'markdown' }, text: ANSWER_TEXT }],
    },
  ],
  history: [userMessage, intentStep, schemasStep],
  status: {
    state: 'completed',
    message: {
      kind: 'message',
      role: 'agent',
      parts: [{ kind: 'text', text: 'Response ready.' }],
    },
  },
};

/** A failed task carrying its error text in status.message (shape assumed, not yet observed) */
const failed = {
  id: TASK_ID,
  contextId: CONTEXT_ID,
  kind: 'task',
  artifacts: [],
  history: [userMessage, schemasStep],
  status: {
    state: 'failed',
    message: {
      kind: 'message',
      role: 'agent',
      parts: [{ kind: 'text', text: 'litellm.BadRequestError: Operation not allowed' }],
    },
  },
};

module.exports = { TASK_ID, CONTEXT_ID, ANSWER_TEXT, working, completed, failed };
