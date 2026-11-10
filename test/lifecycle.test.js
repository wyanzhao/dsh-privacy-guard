import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { apply } from '../index.js';

// Ownership-aware unit host, not a substitute for a live Cordis integration test.
function host() {
  const listeners = new Map(),
    commands = new Map(),
    subscriptions = new Set();
  let available = false;
  const refresh = (subscription) => {
    subscription.clear();
    if (!available) return;
    const effects = [];
    subscription.clear = () => {
      for (const dispose of effects.reverse()) dispose();
      subscription.clear = () => {};
    };
    subscription.callback({
      effect(effect) {
        effects.push(effect());
      },
      commands: {
        register(command) {
          assert.equal(commands.has(command.name), false, 'duplicate command registration');
          commands.set(command.name, command);
          return () => commands.delete(command.name);
        },
      },
    });
  };
  return {
    listeners,
    commands,
    setCommandsAvailable(value) {
      available = value;
      for (const subscription of subscriptions) refresh(subscription);
    },
    owner() {
      const cleanup = [];
      return {
        ctx: {
          on(name, callback) {
            assert.equal(listeners.has(name), false, 'duplicate event listener');
            listeners.set(name, callback);
            const dispose = () => listeners.delete(name);
            cleanup.push(dispose);
            return dispose;
          },
          inject(_dependencies, callback) {
            const subscription = { callback, clear: () => {} };
            subscriptions.add(subscription);
            refresh(subscription);
            cleanup.push(() => {
              subscription.clear();
              subscriptions.delete(subscription);
            });
          },
        },
        dispose() {
          for (const dispose of cleanup.splice(0).reverse()) dispose();
        },
      };
    },
  };
}
const config = {
  dictionaryPath: fileURLToPath(new URL('./fixtures/empty-terms.json', import.meta.url)),
};
test('activation, optional service changes, disable and re-enable own exact registrations', async () => {
  const runtime = host();
  let owner = runtime.owner();
  apply(owner.ctx, config);
  assert.equal(runtime.listeners.size, 1);
  assert.equal(runtime.commands.size, 0);
  runtime.setCommandsAvailable(true);
  assert.equal(runtime.commands.size, 1);
  runtime.setCommandsAvailable(false);
  assert.equal(runtime.commands.size, 0);
  runtime.setCommandsAvailable(true);
  assert.equal(runtime.commands.size, 1);
  const next = async () => ({
    kind: 'enter',
    startsRequestSeries: true,
    extra: 'preserved',
    messages: [{ role: 'user', content: [{ type: 'text', text: 'sk-' + 'a1B2'.repeat(8) }] }],
  });
  const result = await runtime.listeners.get('agent/pre-step')({}, next);
  assert.equal(result.kind, 'enter');
  assert.equal(result.startsRequestSeries, true);
  assert.equal(result.extra, 'preserved');
  assert.equal(result.messages[0].content[0].text, '*');
  owner.dispose();
  assert.equal(runtime.commands.size, 0);
  assert.equal(runtime.listeners.size, 0);
  owner = runtime.owner();
  apply(owner.ctx, config);
  assert.equal(runtime.commands.size, 1);
  assert.equal(runtime.listeners.size, 1);
  const reject = { kind: 'reject' };
  assert.equal(await runtime.listeners.get('agent/pre-step')({}, async () => reject), reject);
  owner.dispose();
  assert.equal(runtime.listeners.size, 0);
  assert.equal(runtime.commands.size, 0);
});
test('invalid config is rejected at activation without exposing dictionary content', () => {
  for (const config of [
    { unknown: true },
    { dictionaryPath: 'relative.json' },
    { dictionaryPath: 17 },
    { blockAttachments: 'true' },
  ]) {
    const owner = host().owner();
    assert.throws(() => apply(owner.ctx, config));
    owner.dispose();
  }
});
