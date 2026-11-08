import test from 'node:test';
import assert from 'node:assert/strict';
import { createRedactor, redactMessages } from '../redactor.js';

test('admitted history stays byte-identical when new messages append', () => {
  const redact = createRedactor();
  const raw = [
    { id: 'first', role: 'user', content: [{ type: 'text', text: 'sk-' + 'x'.repeat(32) }] },
  ];
  const history = redactMessages(raw, redact);
  const prefix = JSON.stringify(history);
  const suffix = redactMessages(
    [
      {
        id: 'second',
        role: 'user',
        content: [{ type: 'text', text: 'Continue with ordinary text.' }],
      },
    ],
    redact,
  );
  const request = { messages: [...history, ...suffix] };
  assert.equal(history[0].content[0].text, '*');
  assert.equal(JSON.stringify(request.messages.slice(0, history.length)), prefix);
  assert.equal(JSON.stringify(history), prefix);
  assert.equal(JSON.stringify(redactMessages(raw, redact)), prefix);
});

test('dictionary changes affect only new admissions, not existing history', () => {
  const history = [
    { id: 'old', role: 'user', content: [{ type: 'text', text: 'previously-ordinary-term' }] },
  ];
  const before = JSON.stringify(history);
  const updated = createRedactor(['previously-ordinary-term']);
  assert.equal(redactMessages(history, updated)[0].content[0].text, '*');
  assert.equal(JSON.stringify(history), before);
});
