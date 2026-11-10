import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { createDictionaryLoader, MAX_DICTIONARY_BYTES } from '../dictionary.js';

function temporary(t) {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-dictionary-test-'));
  t.after(() => {
    assert.equal(dirname(resolve(dir)), resolve(tmpdir()));
    assert.ok(basename(dir).startsWith('dsh-dictionary-test-'));
    rmSync(dir, { recursive: true });
  });
  return dir;
}
test('missing optional default uses built-ins without a warning', (t) => {
  const load = createDictionaryLoader(join(temporary(t), 'missing.json'), { optional: true });
  const state = load();
  assert.equal(state.warning, '');
  assert.equal(state.configured, false);
  assert.equal(state.redact('sk-' + 'a1B2'.repeat(8)).text, '*');
});
test('explicit missing path warns without leaking path or refusing builtin masking', (t) => {
  const path = join(temporary(t), 'missing.json');
  const state = createDictionaryLoader(path)();
  assert.ok(state.warning);
  assert.equal(state.warning.includes(path), false);
  assert.equal(state.redact('sk-' + 'a1B2'.repeat(8)).text, '*');
});
test('last good dictionary survives invalid file, deletion and recovers after repair', (t) => {
  const path = join(temporary(t), 'terms.json');
  writeFileSync(path, JSON.stringify({ terms: ['synthetic-private-name'] }));
  const load = createDictionaryLoader(path, { optional: true });
  assert.equal(load().redact('synthetic-private-name').text, '*');
  for (const value of ['invalid JSON', '{"terms":[17]}', '{"terms":["*bad"]}']) {
    writeFileSync(path, value);
    const state = load();
    assert.ok(state.warning);
    assert.equal(state.warning.includes(value), false);
    assert.equal(state.redact('synthetic-private-name').text, '*');
  }
  unlinkSync(path);
  assert.ok(load().warning);
  assert.equal(load().redact('synthetic-private-name').text, '*');
  writeFileSync(path, '{"terms":[]}');
  assert.equal(load().warning, '');
  assert.equal(load().redact('synthetic-private-name').changed, false);
});
test('oversize and nonregular files fail safely', (t) => {
  const dir = temporary(t),
    path = join(dir, 'terms.json');
  writeFileSync(path, ' '.repeat(MAX_DICTIONARY_BYTES + 1));
  assert.ok(createDictionaryLoader(path)().warning);
  mkdirSync(join(dir, 'directory'));
  assert.ok(createDictionaryLoader(join(dir, 'directory'))().warning);
});
test(
  'FIFO cannot block the host dictionary reader',
  { skip: process.platform === 'win32', timeout: 5000 },
  (t) => {
    const path = join(temporary(t), 'pipe');
    const result = spawnSync('mkfifo', [path], { timeout: 2000 });
    assert.equal(result.status, 0);
    const code = `import assert from 'node:assert/strict'; import {createDictionaryLoader} from ${JSON.stringify(new URL('../dictionary.js', import.meta.url).href)}; assert.ok(createDictionaryLoader(process.argv[1])().warning);`;
    const checked = spawnSync(process.execPath, ['--input-type=module', '-e', code, path], {
      timeout: 2000,
      encoding: 'utf8',
    });
    assert.equal(checked.status, 0, 'FIFO check must finish in its isolated child process.');
  },
);
test('maximum supported term count loads without executing regular expressions', (t) => {
  const path = join(temporary(t), 'terms.json');
  const terms = Array.from({ length: 1000 }, (_, i) => `synthetic.term.${i}`);
  writeFileSync(path, JSON.stringify({ terms }));
  const state = createDictionaryLoader(path)();
  assert.equal(state.warning, '');
  assert.equal(state.redact(terms[999]).text, '*');
  assert.equal(state.redact('syntheticXtermX999').changed, false);
});
