import test from 'node:test';
import assert from 'node:assert/strict';
import { createRedactor } from '../redactor.js';

// All values are synthetic. Every case asserts the exact output, idempotence and determinism.
const redact = createRedactor();
function exact(label, input, expected) {
  test(label, () => {
    const first = redact(input);
    assert.equal(first.text, expected);
    assert.equal(first.changed, input !== expected);
    assert.deepEqual(redact(input), first, 'same input must give a byte-identical result');
    assert.equal(createRedactor()(input).text, expected, 'fresh redactor gives the same result');
    assert.equal(redact(first.text).text, expected, 'masking must be idempotent');
    assert.equal(redact(first.text).changed, false);
  });
}
const unchanged = (label, input) => exact(label, input, input);

// 1.3.0 review probe table: each row was corrupted before 1.4.0.
for (const input of [
  'function login(token: string, password: string) {}',
  'def auth(password: str, api_key: Optional[str]):',
  'def auth(password: str, api_key: Optional[str] = None):',
  'const pwd = process.cwd()',
  '      token: ${{ secrets.NPM_TOKEN }}',
  '服务器地址：http://127.0.0.1:3000/api',
  'max token: 4096',
  'max token: 4096, secret: <your-secret-here>',
  'pip install sk-learn-contrib-something',
  '110105199003071234',
  'order id 110105199003071234 shipped',
  'pwd: /Users/example/project',
  '仓库地址: https://github.com/example/dsh-privacy-guard',
  '{"token": 4096, "model": "x"}',
  'password = os.environ["DB_PASSWORD"]',
  'export GITHUB_TOKEN=$GH_TOKEN',
])
  unchanged(`review probe stays unchanged: ${JSON.stringify(input.slice(0, 40))}`, input);

// Probe rows that are real secrets or real contact data stay masked.
exact(
  'review probe: URL query token remains masked',
  'see https://example.com/cb?token=abc123&x=1',
  'see https://example.com/cb?token=*&x=1',
);
exact('review probe: dashed US phone remains masked', 'call 415-555-0123 now', 'call * now');
exact(
  'review probe: spaced US phone remains masked',
  'timeout 120 300 9999 and 212 555 0100',
  'timeout 120 300 9999 and *',
);

// Brackets and code punctuation are never swallowed by an unquoted value.
for (const [input, expected] of [
  ['login(password=hunter2-fake)', 'login(password=*)'],
  ['f(password: fake-value) {}', 'f(password: *) {}'],
  ['[password=fake-value]', '[password=*]'],
  ['{password: fake-value}', '{password: *}'],
  ['{ token: fake-value, x: 1 }', '{ token: *, x: 1 }'],
  ['password=fake-value; next()', 'password=*; next()'],
  ['(api_key=fake-value)', '(api_key=*)'],
  ['（密码：fake-value）', '（密码：*）'],
  ['password=fa(ke)-value) tail', 'password=*) tail'],
  [
    '[link](https://example.invalid/cb?token=fake-value)',
    '[link](https://example.invalid/cb?token=*)',
  ],
  ['my password is fake-value.', 'my password is *.'],
  ['password: fake-value. Next sentence', 'password: *. Next sentence'],
])
  exact(`syntax outside the value survives: ${JSON.stringify(input)}`, input, expected);

// Type names and annotations.
for (const type of [
  'string',
  'str',
  'int',
  'number',
  'boolean',
  'bool',
  'any',
  'unknown',
  'bytes',
  'String',
  'None',
  'null',
  'undefined',
  'SecretStr',
])
  unchanged(`type annotation ${type}`, `  password: ${type},`);
for (const input of [
  'api_key: Optional[str]',
  'token: Option<String>',
  'secret: Dict[str, str] = {}',
  'interface Login { token: string; password: string }',
  'type Creds = { password: string | null }',
  'fn new(token: &str, password: String) -> Self',
  'api_key: Optional[str] = None',
])
  unchanged(`typed signature ${JSON.stringify(input)}`, input);
exact(
  'annotation followed by a literal default still masks the literal',
  'def f(password: str = "fake-value"):',
  'def f(password: str = "*"):',
);
exact(
  'generic annotation followed by an unquoted literal masks it',
  'token: Optional[str] = fake-value',
  'token: Optional[str] = *',
);
unchanged('comparison after annotation is not an assignment', 'password: str == other');

// Variable, environment and expression references.
for (const input of [
  'password=$DB_PASSWORD',
  'password=${DB_PASSWORD}',
  'token: ${{ secrets.TOKEN }}',
  'password = process.env.DB_PASSWORD',
  'password = os.getenv("DB_PASSWORD")',
  "password = env('DB_PASSWORD')",
  'token = self.token',
  'token: this.token,',
  'password: req.body.password',
  'password = getPassword()',
  'secret = vault.read(path)',
  'password = config["db"]',
  'token = tokens[0]',
  'const pwd = process.cwd();',
  'api_key=xxx',
  'api_key=XXXXXXXX',
  'password=***',
  'password=...',
  'password=changeme',
  'API_KEY=your-api-key-here',
  'OPENAI_API_KEY=YOUR_API_KEY',
  'password=<placeholder>',
])
  unchanged(`reference or placeholder ${JSON.stringify(input)}`, input);

// Quoted values: masked as before, except a whole reference or obvious placeholder.
for (const input of [
  'password = "${DB_PASSWORD}"',
  'password = "$DB_PASSWORD"',
  "token: '{{ secrets.TOKEN }}'",
  'api_key = "<your-key>"',
  '{"api_key": "your-api-key"}',
  'password="***"',
  'password="..."',
  'password="%DB_PASSWORD%"',
])
  unchanged(`quoted reference or placeholder ${JSON.stringify(input)}`, input);
for (const [input, expected] of [
  ['password = "fake-value"', 'password = "*"'],
  ['"token": "fake-value"', '"token": "*"'],
  ['password = "${user}:fake-literal"', 'password = "*"'],
  ['password = "string"', 'password = "*"'],
  ['{"token": "4096"}', '{"token": "*"}'],
])
  exact(`quoted literal stays masked ${JSON.stringify(input)}`, input, expected);

// Label-specific exclusions.
for (const input of [
  'pwd: ~/project',
  'pwd=./build',
  'pwd: ../src',
  'pwd: C:\\Users\\example',
  'pwd = os.getcwd()',
])
  unchanged(`pwd path or call ${JSON.stringify(input)}`, input);
exact('pwd with a non-path value is still a password', 'pwd=fake-value', 'pwd=*');
exact('slash path under password is still masked', 'password: /fake-value', 'password: *');
for (const input of [
  '地址：http://127.0.0.1:8080/api',
  'IP 地址：192.168.1.10',
  '地址：localhost:3000',
  '地址：example.internal:443',
  'MAC 地址：aa:bb:cc:dd:ee:ff',
  '内存地址：0x7ffd5e8c',
  '文件地址：/var/log/app.log',
  '地址：~/Downloads',
  '地址：github.com/example/repo',
  '地址："https://example.invalid/a"',
])
  unchanged(`address label with non-street value ${JSON.stringify(input)}`, input);
exact('address label email is masked as an email', '地址：alice@example.invalid', '地址：*');
exact('street address remains masked', '收货地址：虚构市虚构路1号', '收货地址：*');
for (const input of ['token: 4096', 'token=128', '令牌：200', '{"token": 4096}'])
  unchanged(`integer under bare token ${JSON.stringify(input)}`, input);
for (const [input, expected] of [
  ['password: 12345678', 'password: *'],
  ['密码：123456', '密码：*'],
  ['{"password": 12345678}', '{"password": "*"}'],
  ['api_token=4096', 'api_token=*'],
  ['token: 1234567890123', 'token: *'],
  ['token: 12ab34', 'token: *'],
])
  exact(`numeric secret stays masked ${JSON.stringify(input)}`, input, expected);

// Bearer prose versus bearer credentials.
unchanged('Bearer token prose', 'Send a Bearer token in the Authorization header.');
unchanged('Bearer placeholder', 'Authorization: Bearer YOUR_TOKEN');
exact('Bearer credential masked', 'Authorization: Bearer fake.value-1', 'Authorization: Bearer *');

// sk- keys: real shapes only.
for (const input of [
  'pip install sk-learn-contrib-something',
  'sk-' + 'a'.repeat(32),
  'sk-' + '1'.repeat(32),
  'sk-short1',
  'sk-a1B2c3',
  'sk-foo-bar-baz-qux-quux-corge-1',
])
  unchanged(`not an sk- key ${JSON.stringify(input)}`, input);
for (const key of [
  'sk-' + 'a1B2'.repeat(12),
  'sk-' + '0123456789abcdef'.repeat(2),
  'sk-proj-' + 'Ab1_-'.repeat(8),
  'sk-ant-api03-' + 'x'.repeat(40),
  'sk-svcacct-' + 'y'.repeat(30),
  'sk-or-v1-' + 'f0'.repeat(32),
])
  exact(`real sk- shape ${key.slice(0, 12)}`, `key: ${key}`, 'key: *');

// Chinese resident ID: date and ISO 7064 MOD 11-2 check character.
for (const id of ['110105199003071239', '11010519900101007X', '11010519900101007x'])
  exact(`valid resident ID ${id}`, `ID ${id} end`, 'ID * end');
for (const id of ['110105199003071234', '110105199003071230', '110105199002301239'])
  unchanged(`invalid resident ID ${id}`, `ID ${id} end`);

// Real-secret detections are retained.
for (const [input, expected] of [
  ['export FOO_API_KEY=fake-value-123', 'export FOO_API_KEY=*'],
  ['API_KEY=fake-value-123', 'API_KEY=*'],
  ['DATABASE_PASSWORD=fake-value', 'DATABASE_PASSWORD=*'],
  ['Authorization: Bearer abc', 'Authorization: Bearer *'],
  ['eyJabcdef.fakepayload.fakesignature', '*'],
  ['postgres://user:fake-pass@localhost/db', 'postgres://*@localhost/db'],
  ['https://example.invalid/?api_key=fake&x=1', 'https://example.invalid/?api_key=*&x=1'],
  ['mail alice@example.invalid now', 'mail * now'],
  ['手机 13800138000', '手机 *'],
  ['password="fake value"', 'password="*"'],
  ['-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----', '*'],
  ['ghp_' + 'a'.repeat(30), '*'],
])
  exact(`real secret retained ${JSON.stringify(input.slice(0, 30))}`, input, expected);

test('dictionary terms still mask code-like values', () => {
  const custom = createRedactor(['internal.codename']);
  assert.equal(custom('const x = internal.codename()').text, 'const x = *()');
});
unchanged('mutable Rust reference type', 'fn f(password: &mut String)');
unchanged('Rust slice reference type', 'fn f(token: &[u8])');
exact('literal with a balanced call-like part is still masked', 'password=fa(ke)x', 'password=*');
