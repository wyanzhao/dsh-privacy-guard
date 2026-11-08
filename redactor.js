import { preserveJsonScalars } from './json-spans.js';

// Deterministic, local-only span detection. Match the ORIGINAL text, then replace once.
// No network, raw-value logging, reversible map, random IDs, or request denial.
const legacyMask = /^\[REDACTED:[A-Z_]+\]$/;
const isMask = (value) => value === '*' || legacyMask.test(value);
const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
function overlapsRanges(ranges, start, end) {
  let low = 0,
    high = ranges.length;
  while (low < high) {
    const mid = (low + high) >>> 1;
    if (ranges[mid][1] <= start) low = mid + 1;
    else high = mid;
  }
  return low < ranges.length && ranges[low][0] < end;
}

function uriQueries(text) {
  const ranges = [];
  for (const match of text.matchAll(/\b[a-z][a-z0-9+.-]{0,31}:\/\/[^\s<>"`]+/gi)) {
    const token = match[0];
    const query = token.indexOf('?'),
      fragment = token.indexOf('#');
    if (query < 0 || (fragment >= 0 && fragment < query)) continue;
    let end = fragment >= 0 ? fragment : token.length;
    if (text[match.index - 1] === "'" && token[end - 1] === "'") end--;
    ranges.push([match.index + query + 1, match.index + end]);
  }
  return ranges;
}

function queryLimitAt(ranges, position) {
  let low = 0,
    high = ranges.length;
  while (low < high) {
    const mid = (low + high) >>> 1;
    if (ranges[mid][1] <= position) low = mid + 1;
    else high = mid;
  }
  return low < ranges.length && ranges[low][0] <= position ? ranges[low][1] : undefined;
}

const credentialLabels =
  '(?:(?:[A-Za-z][A-Za-z0-9]*_)+(?:API_KEY|API_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|AUTH_TOKEN|PASSWORD|PASSWD|CLIENT_SECRET|SECRET_KEY|SECRET_ACCESS_KEY|ACCESS_KEY_ID|SESSION_TOKEN)|api[_ -]?(?:key|token)|access[_ -]?token|refresh[_ -]?token|auth[_ -]?token|client[_ -]?secret|secret[_ -]?(?:key|access[_ -]?key)|password|passwd|pwd|token|secret|密码|密钥|口令|令牌)';
const fieldLabels = {
  CREDENTIAL: credentialLabels,
  NAME: '(?:姓名|联系人|收件人|真实姓名|full[ _-]?name)',
  ADDRESS:
    '(?:家庭住址|家庭地址|收货地址|详细地址|住址|地址|home[ _-]?address|shipping[ _-]?address)',
  PHONE:
    '(?:手机号|手机号码|联系电话|电话号码|电话|手机|phone(?:[ _-]?number)?|mobile(?:[ _-]?number)?)',
};
const fieldRules = Object.entries(fieldLabels).map(([type, label]) => ({
  type,
  pattern: new RegExp(
    '(?<![A-Za-z0-9_])' +
      label +
      '(?![A-Za-z0-9_])["\'’”]?[ \\t]*(?:[:=：]|(?:是|为)[ \\t]*[:：=]?|\\bis\\b)[ \\t]*',
    'gi',
  ),
}));
const quotedEnd = { '"': '"', "'": "'", '“': '”', '‘': '’', '`': '`' };

// Return only the value's character range, preserving quotes, escapes outside it and syntax.
function fieldValue(text, start, type, queryLimit) {
  if (text[start] === '\n' || text[start] === '\r') {
    const next = /^\s*/u.exec(text.slice(start))[0].length + start;
    if (!quotedEnd[text[next]] && !/[\d+-]/u.test(text[next] ?? '')) return undefined;
    start = next; // Quoted or numeric value on the next line (pretty-printed JSON).
  }
  const close = quotedEnd[text[start]];
  if (close) {
    let end = start + 1;
    while (end < text.length) {
      if (text[end] === '\\') {
        end += 2;
        continue;
      }
      if (text[end] === close) return { start: start + 1, end, quoted: true };
      end++;
    }
    // Incomplete quoted input: redact to line end, without inventing quotes.
    const newline = text.indexOf('\n', start + 1);
    return { start: start + 1, end: newline < 0 ? text.length : newline, quoted: true };
  }
  const oldMask = /^\[REDACTED:[A-Z_]+\]/u.exec(text.slice(start));
  if (oldMask) {
    let end = start + oldMask[0].length;
    while (end < text.length && !/[\s,;，；。！？<>[\]{}"'“”‘’`&]/u.test(text[end])) end++;
    return { start, end };
  }
  if (!text[start] || /[\s[\]{}<>]/u.test(text[start])) return undefined;
  if (type === 'PHONE') {
    const match = /^[+\d(][\d ()+.-]*\d/.exec(text.slice(start));
    if (!match) return undefined;
    const digits = match[0].replace(/\D/g, '');
    if (digits.length < 7 || digits.length > 15) return undefined;
    return { start, end: start + match[0].length };
  }
  let end = start;
  const urlQuery = queryLimit !== undefined;
  const stop = urlQuery
    ? /[\s<>"`]/u
    : type === 'NAME'
      ? /[\r\n,;，；。！？<>[\]{}"'“”‘’`]/u
      : type === 'ADDRESS'
        ? /[\r\n;；。！？<>[\]{}"'“”‘’`]/u
        : /[\s,;，；。！？<>[\]{}"'“”‘’`]/u;
  while (end < (queryLimit ?? text.length) && !stop.test(text[end])) {
    if (urlQuery && (text[end] === '#' || text[end] === '&')) break;
    // Preserve a following labeled field instead of swallowing the rest of the sentence.
    if (
      (type === 'NAME' || type === 'ADDRESS') &&
      /[,，]/u.test(text[end]) &&
      /^\s*(?:姓名|手机|电话|地址|密码|密钥)\s*[:：=是为]/u.test(text.slice(end + 1))
    )
      break;
    end++;
  }
  while (end > start && /[ \t]/u.test(text[end - 1])) end--;
  return { start, end };
}

const standalone = [
  [
    'PRIVATE_KEY',
    /-----BEGIN ((?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY)-----[\s\S]*?(?:-----END \1-----|$)/g,
  ],
  [
    'API_KEY',
    /(?<![A-Za-z0-9_-])(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{20,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})(?![A-Za-z0-9_-])/g,
  ],
  ['JWT', /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![A-Za-z0-9_-])/g],
  [
    'EMAIL',
    /(?<![A-Za-z0-9.!#$%&'*+^_`{|}~-])[A-Za-z0-9.!#$%&'*+^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+(?![A-Za-z0-9_-]|\.[A-Za-z0-9.-])/g,
    (value) => {
      const [local, domain] = value.split('@');
      return (
        local.length <= 64 &&
        !local.startsWith('.') &&
        !local.endsWith('.') &&
        !local.includes('..') &&
        domain.length <= 253 &&
        domain.split('.').every((label) => label.length <= 63)
      );
    },
  ],
  ['PHONE', /(?<![A-Za-z0-9_])(?:(?:\+?86|0086)[ -]?)?1[3-9]\d(?:[ -]?\d{4}){2}(?![A-Za-z0-9_])/g],
  [
    'PHONE',
    /(?<![A-Za-z0-9_])(?:(?:\+1|1)[ .-]?(?:\([2-9]\d{2}\)|[2-9]\d{2})[ .-]?[2-9]\d{2}[ .-]?\d{4}|\([2-9]\d{2}\)[ .-]?[2-9]\d{2}[ .-]?\d{4}|[2-9]\d{2}[ .-][2-9]\d{2}[ .-]\d{4})(?![A-Za-z0-9_])/g,
  ],
  [
    'ID',
    /(?<![A-Za-z0-9_])[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![A-Za-z0-9_])/g,
    (value) => {
      const year = +value.slice(6, 10),
        month = +value.slice(10, 12),
        day = +value.slice(12, 14);
      const date = new Date(Date.UTC(year, month - 1, day));
      return (
        date.getUTCFullYear() === year &&
        date.getUTCMonth() === month - 1 &&
        date.getUTCDate() === day
      );
    },
  ],
];

export function validateDictionary(value) {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    !Array.isArray(value.terms) ||
    value.terms.length > 1000
  )
    throw new Error('Privacy guard: expected {terms: string[]} with at most 1000 entries.');
  if (
    value.terms.some(
      (term) =>
        typeof term !== 'string' ||
        !term.trim() ||
        term.length > 4096 ||
        term.includes('*') ||
        term.includes('[REDACTED:'),
    )
  )
    throw new Error('Privacy guard: invalid literal dictionary entry.');
  return [...new Set(value.terms)].sort((a, b) => b.length - a.length);
}

export function createRedactor(terms = []) {
  const literals = validateDictionary({ terms });
  const custom = literals.length
    ? new RegExp('(?=(' + literals.map(escapeRegex).join('|') + '))', 'gu')
    : undefined;
  const finishBuiltins = literals.length ? createRedactor() : undefined;
  return function redact(text) {
    if (typeof text !== 'string') throw new Error('Privacy guard: unsupported text value.');
    const spans = [];
    const protectedSpans = [...text.matchAll(/\[REDACTED:[A-Z_]+\]/g)].map((m) => [
      m.index,
      m.index + m[0].length,
    ]);
    const add = (start, end, type, replacement = '*') => {
      if (end <= start || isMask(text.slice(start, end))) return;
      if (type === 'CUSTOM' && overlapsRanges(protectedSpans, start, end)) return;
      spans.push({ start, end, type, replacement });
    };
    const queries = uriQueries(text);
    const fields = fieldRules.flatMap(({ type, pattern }) =>
      [...text.matchAll(pattern)].map((match) => ({ type, match })),
    );
    fields.sort((a, b) => a.match.index - b.match.index);
    let fieldEnd = -1;
    for (const { type, match } of fields) {
      if (match.index < fieldEnd) continue; // Do not interpret labels inside a secret value.
      const start = match.index + match[0].length;
      const value = fieldValue(
        text,
        start,
        type,
        type === 'CREDENTIAL' ? queryLimitAt(queries, start) : undefined,
      );
      if (!value) continue;
      const raw = text.slice(value.start, value.end);
      if (
        type === 'PHONE' &&
        (!/^[+\d() .-]+$/u.test(raw) ||
          raw.replace(/\D/g, '').length < 7 ||
          raw.replace(/\D/g, '').length > 15)
      )
        continue;
      if (!value.quoted && /^(?:null|undefined|true|false)$/i.test(raw)) continue;
      add(value.start, value.end, type);
      fieldEnd = value.end;
    }
    // Authorization schemes: preserve the scheme and redact only its credential.
    for (const match of text.matchAll(/\b(Bearer[ \t]+)([A-Za-z0-9._~+/-]+={0,2})/gi))
      add(match.index + match[1].length, match.index + match[0].length, 'BEARER');
    for (const match of text.matchAll(
      /\b(Authorization["']?[ \t]*[:=：][ \t]*["']?Basic[ \t]+)([A-Za-z0-9+/]{4,}={0,2})/gi,
    ))
      add(match.index + match[1].length, match.index + match[0].length, 'AUTH');
    // URL userinfo: do not destroy the scheme, host, path or query structure.
    const urlUserinfo = [];
    for (const match of text.matchAll(/\b([a-z][a-z0-9+.-]{0,31}:\/\/)([^\s/@?#]+)(?=@)/gi)) {
      const start = match.index + match[1].length,
        end = match.index + match[0].length;
      urlUserinfo.push([start, end]);
      add(start, end, 'CREDENTIAL');
    }
    for (const [type, pattern, accepts] of standalone) {
      for (const match of text.matchAll(pattern)) {
        if (accepts && !accepts(match[0])) continue;
        if (type === 'EMAIL' && overlapsRanges(urlUserinfo, match.index, match.index + 1)) continue;
        const quotedEmail =
          type === 'EMAIL' &&
          match[0].startsWith("'") &&
          text[match.index + match[0].length] === "'";
        const start = match.index + (quotedEmail ? 1 : 0),
          end = match.index + match[0].length;
        add(start, end, type);
      }
    }
    if (custom)
      for (const match of text.matchAll(custom))
        add(match.index, match.index + match[1].length, 'CUSTOM');
    // Largest enclosing value wins; overlapping detectors never leak suffixes or double-count.
    const structured = preserveJsonScalars(text, spans);
    structured.sort((a, b) => a.start - b.start || b.end - a.end);
    const merged = [];
    for (const span of structured) {
      const last = merged.at(-1);
      if (last && span.start < last.end) last.end = Math.max(last.end, span.end);
      else merged.push({ ...span });
    }
    const counts = {};
    const parts = [];
    let cursor = 0;
    for (const { start, end, type, replacement } of merged) {
      parts.push(text.slice(cursor, start), replacement);
      counts[type] = (counts[type] ?? 0) + 1;
      cursor = end;
    }
    parts.push(text.slice(cursor));
    let output = parts.join('');
    // A removed custom prefix can expose a known key's lexical boundary. Recheck
    // built-ins only; never run a dictionary over the newly inserted mask character.
    if (finishBuiltins && output !== text) {
      const final = finishBuiltins(output);
      output = final.text;
      for (const [type, count] of Object.entries(final.counts))
        counts[type] = (counts[type] ?? 0) + count;
    }
    return { text: output, counts, changed: output !== text };
  };
}

export function redactMessages(messages, redact) {
  return messages.map((message) => ({
    ...message,
    content: message.content.map((block) => {
      if (block.type === 'text') return { ...block, text: redact(block.text).text };
      // Attachments and unknown content pass unchanged, not inspected or rejected.
      return block;
    }),
  }));
}
