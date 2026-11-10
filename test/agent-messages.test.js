import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { apply } from '../index.js';
import { createDictionaryLoader } from '../dictionary.js';
import {
  AGENT_MESSAGE_SOURCES,
  createRedactor,
  redactMessages,
  shouldRedact,
} from '../redactor.js';

const secret = 'sk-' + 'a1B2'.repeat(8);
const redact = createRedactor();
const text = (value) => ({ type: 'text', text: value });
// Source shapes copied from DSH 0.2.2-rc.1 (dsh-subagent, dsh-experimental-agent-team, dsh-agent-loop).
const relay = () => ({
  id: 'relay',
  role: 'user',
  source: { kind: 'agent-message', form: 'relay', senderSessionId: 'session-child' },
  content: [text('Agent session-child sent a message: '), text(`password: ${'fake-value'}`)],
});
const settled = () => ({
  id: 'settled',
  role: 'user',
  source: {
    kind: 'subagent-settled',
    form: 'notice',
    summary: 'Background subagent finished.',
    senderSessionId: 'session-child',
  },
  content: [text('Its closing message:'), text(`function f(token) { return "${secret}" }`)],
});
const runtime = () => ({
  id: 'runtime',
  role: 'user',
  source: { kind: 'runtime-context' },
  content: [text(`Current runtime context: ${secret}`)],
});
const human = () => ({
  id: 'human',
  role: 'user',
  source: { kind: 'user' },
  content: [text(`my key ${secret}`)],
});

function harness(config) {
  const events = new Map();
  const commands = [];
  apply(
    {
      on: (name, fn) => events.set(name, fn),
      inject: (_deps, fn) =>
        fn({
          effect: (f) => f(),
          commands: {
            register: (definition) => {
              commands.push(definition);
              return () => {};
            },
          },
        }),
    },
    {
      dictionaryPath: fileURLToPath(new URL('./fixtures/empty-terms.json', import.meta.url)),
      ...config,
    },
  );
  return {
    admit: (messages) =>
      events.get('agent/pre-step')({}, async () => ({ kind: 'enter', extra: 1, messages })),
    status: () => commands[0].handler({ rawInput: 'status' }).text,
  };
}

test('agent relays and subagent notices pass through as the same objects by default', async () => {
  assert.deepEqual(AGENT_MESSAGE_SOURCES, ['agent-message', 'subagent-settled']);
  const messages = [relay(), settled(), runtime(), human()];
  const { admit, status } = harness();
  const decision = await admit(messages);
  assert.equal(decision.messages[0], messages[0]);
  assert.equal(decision.messages[1], messages[1]);
  assert.equal(decision.messages[2], messages[2]);
  assert.notEqual(decision.messages[3], messages[3]);
  assert.equal(decision.messages[3].content[0].text, 'my key *');
  assert.equal(decision.messages[3].source, messages[3].source);
  assert.equal(decision.extra, 1);
  assert.ok(status().includes('redactAgentMessages=false'));
});

test('redactAgentMessages=true masks agent messages but never runtime context', async () => {
  const messages = [relay(), settled(), runtime()];
  const { admit, status } = harness({ redactAgentMessages: true });
  const decision = await admit(messages);
  assert.equal(decision.messages[0].content[1].text, 'password: *');
  assert.equal(decision.messages[0].content[0], messages[0].content[0], 'unchanged block reused');
  assert.equal(decision.messages[1].content[1].text, 'function f(token) { return "*" }');
  assert.equal(decision.messages[2], messages[2]);
  assert.ok(status().includes('redactAgentMessages=true'));
});

test('a decision with nothing to mask is returned as the same object', async () => {
  const { admit } = harness();
  const messages = [{ role: 'user', source: { kind: 'user' }, content: [text('hello')] }];
  const next = { kind: 'enter', messages };
  const events = new Map();
  apply({ on: (name, fn) => events.set(name, fn), inject: () => {} });
  assert.equal(await events.get('agent/pre-step')({}, async () => next), next);
  assert.equal((await admit(messages)).messages, messages);
});

test('redactMessages reuses unchanged arrays, messages and blocks', () => {
  const clean = Object.freeze({ role: 'user', content: Object.freeze([text('ordinary')]) });
  const image = Object.freeze({ type: 'image', attachment: {} });
  const dirty = { role: 'user', content: [text('plain'), text(secret), image] };
  const all = [clean];
  assert.equal(redactMessages(all, redact), all);
  const result = redactMessages([clean, dirty], redact);
  assert.equal(result[0], clean);
  assert.equal(result[1].content[0], dirty.content[0]);
  assert.equal(result[1].content[2], image);
  assert.equal(result[1].content[1].text, '*');
  assert.equal(dirty.content[1].text, secret, 'input is never mutated');
});

test('shouldRedact covers user, unknown, agent and runtime sources', () => {
  assert.equal(shouldRedact({ source: { kind: 'user' } }), true);
  assert.equal(shouldRedact({}), true);
  assert.equal(shouldRedact({ source: { kind: 'schedule' } }), true);
  assert.equal(shouldRedact({ source: { kind: 'agent-message' } }), false);
  assert.equal(shouldRedact({ source: { kind: 'subagent-settled' } }), false);
  assert.equal(
    shouldRedact({ source: { kind: 'agent-message' } }, { redactAgentMessages: true }),
    true,
  );
  assert.equal(
    shouldRedact({ source: { kind: 'runtime-context' } }, { redactAgentMessages: true }),
    false,
  );
});

test('admission is deterministic and byte-identical across repeated runs', async () => {
  const build = () => [human(), { ...human(), id: 'h2', content: [text('password = "fake"')] }];
  const a = await harness().admit(build());
  const b = await harness().admit(build());
  assert.equal(JSON.stringify(a.messages), JSON.stringify(b.messages));
  assert.equal(JSON.stringify(redactMessages(a.messages, redact)), JSON.stringify(a.messages));
});

test('redactAgentMessages must be boolean', () => {
  assert.throws(() => apply({ on() {}, inject() {} }, { redactAgentMessages: 'yes' }));
});

test('dictionary regex is rebuilt only when the file identity changes', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-privacy-cache-'));
  t.after(() => {
    assert.equal(dirname(resolve(dir)), resolve(tmpdir()));
    assert.ok(basename(dir).startsWith('dsh-privacy-cache-'));
    rmSync(dir, { recursive: true });
  });
  const path = join(dir, 'terms.json');
  writeFileSync(path, JSON.stringify({ terms: ['synthetic-alpha'] }));
  const load = createDictionaryLoader(path);
  const first = load().redact;
  assert.equal(load().redact, first, 'unchanged file reuses the compiled redactor');
  assert.equal(load().redact, first);
  assert.equal(first('synthetic-alpha').text, '*');
  // Same size, different content and timestamp: must be re-read.
  writeFileSync(path, JSON.stringify({ terms: ['synthetic-omega'] }));
  utimesSync(path, new Date(2001, 0, 1), new Date(2001, 0, 1));
  const second = load().redact;
  assert.notEqual(second, first);
  assert.equal(second('synthetic-omega').text, '*');
  assert.equal(second('synthetic-alpha').changed, false);
  assert.equal(load().redact, second);
  // A failure keeps the last good redactor and warns; repair recompiles.
  writeFileSync(path, 'invalid');
  const failed = load();
  assert.ok(failed.warning);
  assert.equal(failed.configured, true);
  assert.equal(failed.redact, second);
  assert.ok(load().warning, 'failures are not cached as success');
  writeFileSync(path, JSON.stringify({ terms: ['synthetic-omega'] }));
  const repaired = load();
  assert.equal(repaired.warning, '');
  assert.notEqual(repaired.redact, second);
});
