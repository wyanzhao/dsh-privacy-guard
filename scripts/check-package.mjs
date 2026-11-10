import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
// Invoke npm's JavaScript entry directly: no platform-dependent .cmd shell or quoting.
const npmCli = process.env.npm_execpath;
assert.ok(npmCli, 'Run this check through npm run check:package.');
const pack = spawnSync(
  process.execPath,
  [npmCli, 'pack', '--dry-run', '--json', '--ignore-scripts'],
  { cwd: root, encoding: 'utf8' },
);
assert.equal(pack.status, 0, 'npm package inspection failed.');
const [result] = JSON.parse(pack.stdout);
const paths = result.files.map((file) => file.path);
const required = [
  'index.js',
  'redactor.js',
  'json-spans.js',
  'dictionary.js',
  'package.json',
  'cordis.patch.yml',
  'private-terms.example.json',
  'locale/en.json',
  'locale/zh.json',
  'icon.svg',
  'README.md',
  'SECURITY.md',
  'CHANGELOG.md',
  'CONTRIBUTING.md',
  'LICENSE',
  'test/fixtures/empty-terms.json',
  'eslint.config.js',
  '.prettierrc.json',
  '.prettierignore',
  'scripts/check-package.mjs',
];
for (const path of required) assert.ok(paths.includes(path), `Missing package resource: ${path}`);
for (const path of paths) {
  assert.ok(
    required.includes(path) || /^test\/[^/]+\.test\.js$/u.test(path),
    `Unexpected package resource: ${path}`,
  );
  assert.ok(!isAbsolute(path) && !path.split('/').includes('..'), 'Unsafe package path.');
  const source = join(root, path);
  assert.ok(statSync(source).isFile(), 'Package resource must be a regular file.');
  const fromRoot = relative(realpathSync(root), realpathSync(source));
  assert.ok(
    fromRoot !== '..' &&
      !fromRoot.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) &&
      !isAbsolute(fromRoot),
    'Package resource escapes package root.',
  );
}
assert.ok(!paths.includes('private-terms.json'), 'Private dictionary must never be packaged.');
assert.deepEqual(JSON.parse(readFileSync(join(root, 'private-terms.example.json'), 'utf8')), {
  terms: [],
});
const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
assert.equal(manifest.private, true);
assert.equal(manifest.license, 'UNLICENSED');
assert.equal(manifest.exports['.'], './index.js');
assert.equal(manifest.exports['./icon'], './icon.svg');
assert.ok(statSync(join(root, 'icon.svg')).size <= 256 * 1024);

const clean = mkdtempSync(join(tmpdir(), 'dsh-privacy-package-'));
try {
  // Copy ONLY the actual distributable file list, never the user's live dictionary.
  for (const path of paths) {
    const target = join(clean, path);
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(join(root, path), target);
  }
  assert.equal(existsSync(join(clean, 'private-terms.json')), false);
  const { apply, version } = await import(pathToFileURL(join(clean, 'index.js')).href);
  assert.equal(version, manifest.version);
  const events = new Map(),
    commands = [];
  apply({
    on(name, callback) {
      events.set(name, callback);
    },
    inject(_dependencies, callback) {
      callback({
        effect: (effect) => effect(),
        commands: {
          register(definition) {
            commands.push(definition);
            return () => {};
          },
        },
      });
    },
  });
  const status = commands[0].handler({ rawInput: 'status' });
  assert.equal(status.kind, 'success');
  assert.ok(status.text.includes(version));
  assert.equal(status.text.includes('读取失败'), false);
  const secret = 'sk-' + 'a1B2'.repeat(8);
  const admitted = await events.get('agent/pre-step')({}, async () => ({
    kind: 'enter',
    messages: [{ role: 'user', content: [{ type: 'text', text: secret }] }],
  }));
  assert.equal(admitted.kind, 'enter');
  assert.equal(admitted.messages[0].content[0].text, '*');
  assert.equal(events.has('llm/stream'), false);
  console.log(
    `Package allowlist and clean-distribution activation passed (${paths.length} files; no private dictionary).`,
  );
} finally {
  assert.equal(dirname(clean), tmpdir());
  assert.ok(clean.startsWith(join(tmpdir(), 'dsh-privacy-package-')));
  rmSync(clean, { recursive: true });
}
