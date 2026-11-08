import test from 'node:test';
import assert from 'node:assert/strict';
import { createRedactor } from '../redactor.js';
const redact = createRedactor();
// All values in this file are synthetic. Tests require exact output, not just a hit.
function expectMask(label, input, expected, terms) {
  test(label, () => {
    const r = terms ? createRedactor(terms) : redact;
    const result = r(input);
    assert.equal(result.text, expected);
    assert.equal(r(result.text).text, expected, 'masking must be idempotent');
    assert.equal(r(result.text).changed, false);
    assert.deepEqual(r(result.text).counts, {});
  });
}
const keys = [
  'sk-' + 'a'.repeat(32),
  'sk-proj-' + 'a'.repeat(40) + '-',
  'sk-ant-' + 'a'.repeat(40) + '_',
  ...['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_', 'hf_', 'npm_'].map(
    (p) => p + 'a'.repeat(30),
  ),
  ...['AKIA', 'ASIA'].map((p) => p + 'A'.repeat(16)),
  'AIza' + 'a'.repeat(35),
  'glpat-' + 'a'.repeat(20) + '-',
  ...['xoxb-', 'xoxp-', 'xoxa-', 'xoxr-', 'xoxs-'].map((p) => p + '1'.repeat(16) + '-'),
  ...['sk_live_', 'sk_test_', 'rk_live_', 'rk_test_'].map((p) => p + 'a'.repeat(24)),
];
keys.forEach((key, i) =>
  expectMask(
    `key family ${i + 1} masks complete value and preserves punctuation`,
    `before (${key}), after`,
    'before (*), after',
  ),
);
for (const label of [
  'api_key',
  'API_KEY',
  'api-key',
  'api key',
  'access_token',
  'refresh_token',
  'auth_token',
  'client_secret',
  'secret_key',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
  'OPENAI_API_KEY',
  'DATABASE_PASSWORD',
  'MY_SERVICE_ACCESS_TOKEN',
  'api_token',
  'secret',
  'password',
  'passwd',
  'pwd',
  'token',
  '密码',
  '密钥',
  '口令',
  '令牌',
]) {
  expectMask(
    `explicit credential label ${label}`,
    `${label}=fictional-value; keep`,
    `${label}=*; keep`,
  );
}
for (const [input, expected] of [
  ['我的密码是fictional-value。继续', '我的密码是*。继续'],
  ['密钥为：fictional-value，继续', '密钥为：*，继续'],
  ['my password is fictional-value', 'my password is *'],
  ['password="fictional value with spaces"; keep', 'password="*"; keep'],
  ["password='fictional value'; keep", "password='*'; keep"],
  ['密码是“fictional value”。继续', '密码是“*”。继续'],
  ['密钥为‘fictional value’。继续', '密钥为‘*’。继续'],
  ['password=`fictional value`; keep', 'password=`*`; keep'],
  ['password="first\nsecond"; keep', 'password="*"; keep'],
  ['password="unfinished secret\nnext line', 'password="*\nnext line'],
  ['password="fake 地址: inner"; keep', 'password="*"; keep'],
  ['api_key=one, password=two', 'api_key=*, password=*'],
  ['Authorization: Bearer fictional-value==', 'Authorization: Bearer *'],
  ['Authorization: Bearer abc', 'Authorization: Bearer *'],
  ['Authorization: Basic dTpw', 'Authorization: Basic *'],
  ['{"Authorization":"Basic dXNlcjpwYXNz"}', '{"Authorization":"Basic *"}'],
  ['https://fake-user:fake-pass@example.invalid/path?q=1', 'https://*@example.invalid/path?q=1'],
  ['postgresql://fake-user:fake-pass@localhost/db', 'postgresql://*@localhost/db'],
  [
    'https://example.invalid/?api_key=fake-key&mode=fast#part',
    'https://example.invalid/?api_key=*&mode=fast#part',
  ],
  ['https://example.invalid/?password=fake-pass#part', 'https://example.invalid/?password=*#part'],
  ['password=fake#fragment', 'password=*'],
  ['eyJabcdef.fakepayload.fakesignature_', '*'],
])
  expectMask(`credential syntax ${JSON.stringify(input.slice(0, 28))}`, input, expected);

test('escaped JSON values and surrounding object structure survive exactly', () => {
  for (const secret of [
    'fake"quoted-tail',
    'fake\\backslash',
    'fake\nnewline',
    'fake,comma',
    'fake password=inner',
    'null',
  ]) {
    const input = JSON.stringify({ password: secret, note: 'unchanged', enabled: true });
    const output = redact(input).text;
    assert.deepEqual(JSON.parse(output), { password: '*', note: 'unchanged', enabled: true });
    assert.equal(output, JSON.stringify({ password: '*', note: 'unchanged', enabled: true }));
  }
  assert.deepEqual(JSON.parse(redact('{"password":\n "fake-value", "note":"unchanged"}').text), {
    password: '*',
    note: 'unchanged',
  });
});
for (const label of [
  'PRIVATE KEY',
  'RSA PRIVATE KEY',
  'EC PRIVATE KEY',
  'OPENSSH PRIVATE KEY',
  'DSA PRIVATE KEY',
  'ENCRYPTED PRIVATE KEY',
]) {
  const pem = `-----BEGIN ${label}-----\r\nsynthetic-body\r\n-----END ${label}-----`;
  expectMask(`PEM ${label}`, `before\n${pem}\nafter`, 'before\n*\nafter');
}
expectMask(
  'mismatched PEM footer cannot expose a suffix',
  '-----BEGIN RSA PRIVATE KEY-----\nsynthetic\n-----END EC PRIVATE KEY-----\nremaining',
  '*',
);
expectMask(
  'truncated PEM consumes the incomplete remainder',
  'before\n-----BEGIN PRIVATE KEY-----\nsynthetic',
  'before\n*',
);
expectMask(
  'two PEM blocks remain two masks',
  '-----BEGIN PRIVATE KEY-----a-----END PRIVATE KEY-----\n-----BEGIN EC PRIVATE KEY-----b-----END EC PRIVATE KEY-----',
  '*\n*',
);

for (const [input, expected] of [
  ['send to alice+tag@example.invalid, thanks', 'send to *, thanks'],
  ['send to +tag@example.invalid.', 'send to *.'],
  ["'alice@example.invalid'", "'*'"],
  ['"alice@example.invalid"', '"*"'],
  ["o'brien@example.invalid", '*'],
  ['EMAIL=alice@example.invalid', 'EMAIL=*'],
  [
    'https://example.invalid/?email=alice@example.invalid&n=1',
    'https://example.invalid/?email=*&n=1',
  ],
  ['13800138000', '*'],
  ['138 0013 8000', '*'],
  ['138-0013-8000', '*'],
  ['+86 138 0013 8000', '*'],
  ['0086-13800138000', '*'],
  ['+14155550100', '*'],
  ['+1 (415) 555-0100', '*'],
  ['(415) 555-0100', '*'],
  ['415.555.0100', '*'],
  ['手机：+44 20 7946 0958，继续', '手机：*，继续'],
  ['{"phone":"+44 20 7946 0958"}', '{"phone":"*"}'],
  ['{"姓名":"虚构测试人","地址":"虚构测试路"}', '{"姓名":"*","地址":"*"}'],
  ['full name: Fictional Person, keep', 'full name: *, keep'],
  ['地址：虚构测试路一号，电话：13800138000', '地址：*，电话：*'],
])
  expectMask(`personal text ${JSON.stringify(input.slice(0, 26))}`, input, expected);

for (const input of [
  'sort this array',
  '版本 2026.11.08, port 8080',
  '192.168.1.1',
  '12345678',
  '4155550100',
  'A13800138000B',
  '913800138000',
  '138001380000',
  'mypassword=ordinary',
  'password_reset=ordinary',
  'max_tokens=4096',
  'token_count=128',
  'password issue needs investigation',
  'Basic knowledge of sorting',
  'password=',
  'password=""',
  'password=null',
  'password=false',
  'password=true',
  '{"password":{"type":"string"}}',
  '{"apiKey":{"type":"string"}}',
  '{"password":[]}',
  'mail@@example.invalid',
  '.alice@example.invalid',
  'alice..tag@example.invalid',
  'alice@example..invalid',
  'sk-short',
  'prefixsk-' + 'a'.repeat(32),
  'AKIA' + 'A'.repeat(15),
  '-----BEGIN PUBLIC KEY-----synthetic-----END PUBLIC KEY-----',
  '-----BEGIN CERTIFICATE-----synthetic-----END CERTIFICATE-----',
  '11010519900231001X',
  '*',
  'password="*"',
  '密码是“*”',
  '[REDACTED:EMAIL]',
])
  expectMask(`negative ${JSON.stringify(input.slice(0, 35))}`, input, input);

expectMask(
  'custom term inside an email cannot hide the rest of the email',
  'alice@example.invalid',
  '*',
  ['alice'],
);
expectMask(
  'custom term inside PEM does not break private-key recognition',
  '-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----',
  '*',
  ['PRIVATE'],
);
expectMask('overlapping literal terms are unioned without residual suffix', 'abcd', '*', [
  'abc',
  'bcd',
]);
expectMask('literal metacharacters are never regexes', 'a.b aXb [abc] (a+)+$', '* aXb * *', [
  'a.b',
  '[abc]',
  '(a+)+$',
]);
expectMask(
  'legacy marker plus real suffix is not exempt',
  'password=[REDACTED:NAME]suffix',
  'password=*',
);
expectMask(
  'a credential containing an email is counted once',
  'password="alice@example.invalid"',
  'password="*"',
);
test('URL query context has no fixed lookbehind limit', () => {
  for (const delimiter of [',', ';']) {
    const prefix = 'https://example.invalid/' + 'a'.repeat(10000) + '?token=';
    const input = prefix + 'fake' + delimiter + 'synthetic-tail&mode=fast#part';
    const output = redact(input).text;
    assert.equal(output, prefix + '*&mode=fast#part');
    assert.equal(redact(output).text, output);
  }
  const quoted = "'https://example.invalid/?token=fake,tail'";
  assert.equal(redact(quoted).text, "'https://example.invalid/?token=*'");
  const multiple = 'https://a.invalid/?token=one;tail https://b.invalid/?token=two,tail';
  assert.equal(redact(multiple).text, 'https://a.invalid/?token=* https://b.invalid/?token=*');
});
test('overlapping detections count one replacement, not internal fragments', () => {
  const result = createRedactor(['alice'])('password="alice@example.invalid"');
  assert.equal(
    Object.values(result.counts).reduce((a, b) => a + b, 0),
    1,
  );
});
expectMask(
  'URL comma and semicolon remain inside the sensitive value',
  'https://example.invalid/?password=fake,tail;rest&mode=fast#part',
  'https://example.invalid/?password=*&mode=fast#part',
);
expectMask(
  'ampersand inside unquoted non-URL credential is not leaked',
  'password=fake&tail; keep',
  'password=*; keep',
);
expectMask(
  'dictionary prefix cannot hide a newly exposed known key',
  'prefixsk-' + 'a'.repeat(32),
  '**',
  ['prefix'],
);
test('mask character is reserved rather than permitting unstable dictionary chains', () => {
  assert.throws(() => createRedactor(['alpha', '*beta']));
});
test('numeric JSON credentials become valid string masks', () => {
  for (const value of [12345678, -12345678, 1.25, 1e30]) {
    const result = redact(JSON.stringify({ password: value, enabled: true }));
    assert.deepEqual(JSON.parse(result.text), { password: '*', enabled: true });
    assert.equal(redact(result.text).changed, false);
  }
  assert.deepEqual(JSON.parse(redact('{"phone":13800138000}').text), { phone: '*' });
  assert.deepEqual(JSON.parse(redact('{"phone":\n 13800138000}').text), { phone: '*' });
  assert.deepEqual(JSON.parse(redact('{"n":13800138000}').text), { n: '*' });
  assert.deepEqual(JSON.parse(redact('[13800138000, 13800138000]').text), ['*', '*']);
});
test('long URL-like input without userinfo terminates unchanged', () => {
  const input = 'https://' + ':'.repeat(64000);
  assert.equal(redact(input).text, input);
  const noScheme = 'a-'.repeat(64000);
  assert.equal(redact(noScheme).text, noScheme);
});
test('adversarial long prose and repeated labels terminate without changing ordinary text', () => {
  const ordinary = 'a'.repeat(100000) + ' ordinary prose';
  assert.equal(redact(ordinary).text, ordinary);
  const repeated = '地址: ordinary '.repeat(3000);
  assert.ok(redact(repeated).text.startsWith('地址: *'));
});
