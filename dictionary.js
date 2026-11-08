import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { createRedactor, validateDictionary } from './redactor.js';

export const MAX_DICTIONARY_BYTES = 1024 * 1024;
const warning = '词库读取失败：沿用本次运行最后可用词库；若尚无可用词库则仅使用内置规则。';

// Open nonblocking where available, reject non-regular files, and bound ACTUAL
// reads rather than relying only on a path stat that may change before opening.
function readDictionary(path) {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > MAX_DICTIONARY_BYTES)
      throw new Error('Invalid dictionary file.');
    const buffer = Buffer.alloc(Math.min(MAX_DICTIONARY_BYTES + 1, stat.size + 1));
    let used = 0;
    while (used < buffer.length) {
      const count = readSync(fd, buffer, used, buffer.length - used, null);
      if (!count) break;
      used += count;
    }
    if (used > MAX_DICTIONARY_BYTES || used > stat.size)
      throw new Error('Dictionary changed while reading.');
    return validateDictionary(JSON.parse(buffer.subarray(0, used).toString('utf8')));
  } finally {
    closeSync(fd);
  }
}

export function createDictionaryLoader(path, { optional = false } = {}) {
  let redact = createRedactor();
  let hasValidDictionary = false;
  return function load() {
    try {
      const next = createRedactor(readDictionary(path));
      redact = next;
      hasValidDictionary = true;
      return { redact, warning: '', configured: true };
    } catch (error) {
      if (optional && !hasValidDictionary && error?.code === 'ENOENT') {
        return { redact, warning: '', configured: false };
      }
      // Never return parser errors, raw terms, sensitive paths, or stack traces.
      return { redact, warning, configured: hasValidDictionary };
    }
  };
}
