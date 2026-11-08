import test from 'node:test';
import assert from 'node:assert/strict';
import { createRedactor } from '../redactor.js';

const redact = createRedactor();
test('numeric substrings expand to complete negative, decimal and exponent JSON atoms', () => {
  for (const n of ['-13800138000', '13800138000.5', '-13800138000.5']) {
    const source = `{"n":${n},"keep":true}`;
    const result = redact(source);
    assert.deepEqual(JSON.parse(result.text), { n: '*', keep: true });
    assert.equal(redact(result.text).changed, false);
  }
});
test('scientific numbers are not guessed to be phones; explicit secrets still mask', () => {
  assert.equal(redact('{"n":13800138000e-5}').changed, false);
  assert.deepEqual(JSON.parse(redact('{"password":13800138000e-5}').text), { password: '*' });
  assert.deepEqual(JSON.parse(createRedactor(['13800138000'])('{"n":13800138000e-5}').text), {
    n: '*',
  });
});
test('custom terms preserve JSON scalar syntax and do not leave partial escapes', () => {
  for (const terms of [['2468'], ['468'], ['true'], ['u123'], ['"'], [':'], ['\\']]) {
    const r = createRedactor(terms);
    const source = '{"n":2468,"yes":true,"value":"prefix\\u1234 and \\"quote\\""}';
    const output = r(source).text;
    assert.doesNotThrow(() => JSON.parse(output));
    assert.equal(r(output).text, output);
  }
  assert.deepEqual(JSON.parse(createRedactor(['2468'])('{"n":2468}').text), { n: '*' });
});
test('escaped values retain surrounding prose and JSON structure', () => {
  const source = JSON.stringify({ text: 'before alice@example.invalid after', keep: 'unchanged' });
  assert.deepEqual(JSON.parse(redact(source).text), { text: 'before * after', keep: 'unchanged' });
});
test('explicit JSON fences preserve scalar syntax while surrounding prose remains intact', () => {
  const source = 'Before\n```json\n{"n":-13800138000.5}\n```\nAfter';
  assert.equal(redact(source).text, 'Before\n```json\n{"n":"*"}\n```\nAfter');
  const noLanguage = '```\n[13800138000]\n```';
  assert.equal(redact(noLanguage).text, '```\n["*"]\n```');
});
test('invalid JSON is treated as ordinary text rather than rejected', () => {
  assert.doesNotThrow(() => redact('{broken: "unterminated'));
  assert.equal(redact('ordinary text without secrets').changed, false);
});
test('synthetic JSON corpus stays parseable and stable with literal and built-in matches', () => {
  let seed = 12345;
  const next = () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed;
  };
  const values = [
    'plain',
    'alice@example.invalid',
    'escape"tail',
    '\\ slash',
    'line\nvalue',
    '🙂',
    '2468',
    'sk-' + 'a'.repeat(32),
  ];
  const r = createRedactor(['2468', 'escape', 'slash']);
  for (let i = 0; i < 1000; i++) {
    const value = {
      password: values[next() % values.length],
      array: [next(), values[next() % values.length], true, null],
      keep: 'unchanged',
    };
    const source = JSON.stringify(value, null, i % 2 ? 2 : undefined);
    const result = r(source).text;
    const parsed = JSON.parse(result);
    assert.equal(parsed.keep, 'unchanged');
    assert.equal(r(result).text, result);
  }
});
