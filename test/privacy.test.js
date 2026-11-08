import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRedactor, validateDictionary, redactMessages } from '../redactor.js';
import { apply, version } from '../index.js';
const r = createRedactor();
const samples = [
  'sk-' + 'a'.repeat(32),
  'ghp_' + 'a'.repeat(30),
  'AKIA' + 'A'.repeat(16),
  'Bearer ' + 'a'.repeat(20),
  'eyJabcdef.abcdef.abcdef',
  'api_key="local-test-only"',
  '{"password":"local-test-only"}',
  'access_token = local-test-only',
  'person' + '@example.invalid',
  '138' + '00138000',
  '+1 (415) 555-0100',
  '11010519900101001X',
  '姓名：虚构测试人',
  'full name: Synthetic Person',
  '地址：虚构测试路一号',
  'home address: 123 Fictional Street',
  '-----BEGIN ' + 'PRIVATE KEY-----\nsynthetic\n-----END ' + 'PRIVATE KEY-----',
  '-----BEGIN ' + 'PRIVATE KEY-----\nsynthetic',
];
for (let i = 0; i < samples.length; i++) {
  test(`rule fixture ${i + 1} uses short masking and is idempotent`, () => {
    const first = r(samples[i]);
    assert.equal(first.changed, true);
    assert.ok(first.text.includes('*'));
    assert.equal(first.text.includes('[REDACTED:'), false);
    assert.equal(r(first.text).changed, false);
  });
}
test('natural-language credentials are masked in preview and admission', async () => {
  const cases = [
    ['我的密码是24681357', '我的密码是*'],
    ['我的密钥是fictional-key-value', '我的密钥是*'],
    ['密码为 24681357。请继续', '密码为 *。请继续'],
    ['我的密码是：24681357，密钥是fictional-key-value', '我的密码是：*，密钥是*'],
    ['密码是“fictional value”，继续', '密码是“*”，继续'],
    ['My password is fictional-value', 'My password is *'],
    ['API key is fictional-value', 'API key is *'],
  ];
  const { events, commands } = harness();
  for (const [input, expected] of cases) {
    const masked = r(input);
    assert.equal(masked.text, expected);
    assert.equal(r(masked.text).changed, false);
    assert.ok(commands[0].handler({ rawInput: 'preview ' + input }).text.includes(expected));
    const decision = await events.get('agent/pre-step')({}, async () => ({
      kind: 'enter',
      messages: [{ role: 'user', content: [{ type: 'text', text: input }] }],
    }));
    assert.equal(decision.kind, 'enter');
    assert.equal(decision.messages[0].content[0].text, expected);
  }
  assert.equal(r('password issue needs investigation').changed, false);
});
test('a whole secret is replaced by exactly one character, regardless of length', () => {
  assert.equal(r(samples[0]).text, '*');
  assert.equal(r('sk-' + 'z'.repeat(200)).text, '*');
  assert.deepEqual(JSON.parse(r(samples[6]).text), { password: '*' });
  assert.equal(r('姓名：虚构测试人').text, '姓名：*');
});
test('ordinary prose, schema and existing masks stay unchanged', () => {
  for (const text of [
    '写一个排序函数',
    'Use port 8080, version 2026.11.',
    '*',
    '[REDACTED:EMAIL]',
    '{"apiKey":{"type":"string"}}',
    'api_key=*',
    '姓名：*',
  ])
    assert.equal(r(text).changed, false);
});
test('custom terms are literal, longest-first and protect legacy markers', () => {
  const redact = createRedactor(
    validateDictionary({ terms: ['a.b', 'NAME', '虚构人', '虚构人甲'] }),
  );
  assert.equal(redact('a.b axb 虚构人甲').text, '* axb *');
  assert.equal(redact('[REDACTED:NAME]').changed, false);
  assert.equal(redact(redact('NAME').text).changed, false);
});
test('dictionary validation rejects malformed input', () => {
  for (const value of [null, {}, { terms: [''] }, { terms: [17] }, { terms: ['[REDACTED:NAME]'] }])
    assert.throws(() => validateDictionary(value));
});
test('message identity and metadata are preserved without mutating input', () => {
  const original = Object.freeze({
    id: 'm1',
    role: 'user',
    source: Object.freeze({ kind: 'user' }),
    content: Object.freeze([Object.freeze({ type: 'text', text: samples[0] })]),
  });
  const [clean] = redactMessages([original], r);
  assert.equal(clean.id, original.id);
  assert.equal(clean.source, original.source);
  assert.equal(original.content[0].text, samples[0]);
  assert.equal(clean.content[0].text, '*');
});
test('attachments and unknown content pass unchanged without denial', () => {
  for (const type of ['image', 'file', 'future-content']) {
    const block = Object.freeze({ type, attachment: Object.freeze({}) });
    const [result] = redactMessages([{ role: 'user', content: [block] }], r);
    assert.equal(result.content[0], block);
  }
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
  return { events, commands };
}
test('status reports the exact manifest version without model calls', () => {
  const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(version, manifest.version);
  const { commands } = harness();
  assert.ok(commands[0].handler({ rawInput: 'status' }).text.includes(version));
  for (const locale of ['en', 'zh']) {
    const { meta } = JSON.parse(
      readFileSync(new URL(`../locale/${locale}.json`, import.meta.url), 'utf8'),
    );
    assert.ok(meta.title && meta.description);
  }
});
test('plugin continues admission, preserves downstream rejection, and has no stream guard', async () => {
  const { events, commands } = harness({ blockAttachments: true }); // Legacy option is intentionally ignored.
  const enter = {
    kind: 'enter',
    startsRequestSeries: true,
    messages: [
      {
        role: 'user',
        content: [
          { type: 'text', text: samples[0] },
          { type: 'image', attachment: {} },
        ],
      },
    ],
  };
  const admitted = await events.get('agent/pre-step')({}, async () => enter);
  assert.equal(admitted.kind, 'enter');
  assert.equal(admitted.startsRequestSeries, true);
  assert.equal(admitted.messages[0].content[0].text, '*');
  assert.equal(admitted.messages[0].content[1], enter.messages[0].content[1]);
  const reject = { kind: 'reject' };
  assert.equal(await events.get('agent/pre-step')({}, async () => reject), reject);
  assert.equal(events.has('llm/stream'), false);
  assert.deepEqual([...events.keys()], ['agent/pre-step']);
  assert.equal(commands[0].recordInput, false);
  assert.equal(commands[0].handler({ rawInput: 'status' }).kind, 'success');
  const preview = commands[0].handler({ rawInput: 'preview ' + samples[0] });
  assert.equal(preview.kind, 'success');
  assert.equal(preview.text.includes(samples[0]), false);
});
test('dictionary hot reload and malformed or missing dictionary never deny admission', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-privacy-test-'));
  const file = join(dir, 'terms.json');
  try {
    writeFileSync(file, JSON.stringify({ terms: [] }));
    const { events, commands } = harness({ dictionaryPath: file });
    const enter = {
      kind: 'enter',
      messages: [{ content: [{ type: 'text', text: 'unique-dictionary-fixture' }] }],
    };
    const admit = () => events.get('agent/pre-step')({}, async () => enter);
    assert.equal((await admit()).messages[0].content[0].text, 'unique-dictionary-fixture');
    writeFileSync(file, JSON.stringify({ terms: ['unique-dictionary-fixture'] }));
    assert.equal((await admit()).messages[0].content[0].text, '*');
    writeFileSync(file, 'invalid JSON');
    assert.equal((await admit()).messages[0].content[0].text, '*');
    assert.ok(commands[0].handler({ rawInput: 'status' }).text.includes('词库读取失败'));
    const missing = harness({ dictionaryPath: join(dir, 'missing.json') });
    const result = await missing.events.get('agent/pre-step')({}, async () => ({
      kind: 'enter',
      messages: [{ content: [{ type: 'text', text: samples[0] }] }],
    }));
    assert.equal(result.kind, 'enter');
    assert.equal(result.messages[0].content[0].text, '*');
  } finally {
    assert.equal(dirname(resolve(dir)), resolve(tmpdir()));
    assert.ok(basename(dir).startsWith('dsh-privacy-test-'));
    rmSync(dir, { recursive: true });
  }
});
