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
    '(?<![A-Za-z0-9_])(' +
      label +
      ')(?![A-Za-z0-9_])["\'’”]?[ \\t]*(?:[:=：]|(?:是|为)[ \\t]*[:：=]?|\\bis\\b)[ \\t]*',
    'gi',
  ),
}));
const quotedEnd = { '"': '"', "'": "'", '“': '”', '‘': '’', '`': '`' };

// ---- Code-context exclusions: deterministic, whole-value tests only. ----
// Type names and annotations are not secrets (`password: string`, `api_key: Optional[str]`).
const typeNames = new Set(
  (
    'string str int integer number float double decimal boolean bool any unknown object void never ' +
    'bytes bytearray char long short bigint symbol uint int8 int16 int32 int64 uint8 uint16 uint32 ' +
    'uint64 usize isize u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 String Number Boolean Object Symbol ' +
    'BigInt Bytes Optional Option Maybe Nullable List Dict Map Set Array Vec Text Any SecretStr ' +
    'SecretBytes SecretString Secret Password Token None null nil undefined NULL Null Nil'
  ).split(' '),
);
// Member access on well-known code/config objects (`process.env.X`, `os.environ`, `self.token`).
const codeRoots = new Set(
  (
    'process os env ENV self this cls config cfg conf settings ctx context options opts args argv ' +
    'params props req request res secrets vars inputs credentials creds import window globalThis ' +
    'global System Environment Deno Bun'
  ).split(' '),
);
const identifierPath = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$/u;
// A whole call: `f()`, `vault.read(path)`, `a().b`, or `os.getenv(` cut short by a quoted argument.
const callExpression =
  /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\((?:[^()]*\)(?:\.[A-Za-z_$][\w$]*(?:\([^()]*\))?)*)?$/u;
// Whole-value placeholders; `<...>` can only occur in quoted values (unquoted `<` ends a value).
const placeholder =
  /^(?:<[^<>]*>|your[-_ ][\w .-]*|x{3,}|\*{2,}|\.{3,}|…+|change[-_ ]?me|replace[-_ ]?me|placeholder|redacted)$/iu;
// A single template/environment reference, not a literal mixed with one (`"${user}:literal"` stays masked).
const reference =
  /^(?:\$\{\{[^{}]*\}\}|\$\{[^{}]*\}|\$[A-Za-z_]\w*|\{\{[^{}]*\}\}|%[A-Za-z_]\w*%)$/u;
const pathLike = /^(?:~(?:[/\\]|$)|\.{1,2}[/\\]|\/|[A-Za-z]:[/\\]|\\\\)/u;
// Address labels followed by a URL, IP, host:port, MAC, hex pointer, file path or email are not street addresses.
const nonStreetAddress = new RegExp(
  '^(?:' +
    [
      '[a-z][a-z0-9+.-]{0,31}://',
      '(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\d.])',
      '\\[?[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,}\\]?',
      '0x[0-9a-f]+',
      'localhost(?![a-z0-9-])',
      '[a-z0-9-]+(?:\\.[a-z0-9-]+)*:\\d{1,5}(?!\\d)',
      '[a-z0-9-]+(?:\\.[a-z0-9-]+)+/',
      '[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.(?:com|net|org|io|dev|cn|ai|app|co|edu|gov|local|internal|invalid)(?![a-z0-9-])',
      '~?/',
      '\\.{1,2}[/\\\\]',
      '[a-z]:\\\\',
      '\\\\\\\\',
      '[^\\s@]+@[^\\s@]+\\.[a-z]{2,}',
    ].join('|') +
    ')',
  'iu',
);
const bareTokenLabels = new Set(['token', '令牌']);

function isCodeValue(raw, next) {
  if (raw.startsWith('$')) return true; // $X, ${X}, ${{ X }}, $(command)
  if (typeNames.has(raw) || /^(?:null|undefined|true|false)$/iu.test(raw)) return true;
  // Rust references: `&str`, `&mut String`, `&[u8]`, `&'static str`.
  if (/^&(?:mut)?$/u.test(raw) || (raw[0] === '&' && typeNames.has(raw.slice(1)))) return true;
  if (callExpression.test(raw)) return true; // getenv(...), process.cwd()
  if (identifierPath.test(raw)) {
    if (next === '[' || next === '<' || next === '(') return true; // Optional[str], env['X']
    if (raw.includes('.') && codeRoots.has(raw.slice(0, raw.indexOf('.')))) return true;
  }
  return placeholder.test(raw);
}
// Type annotations are excluded only when they look like annotations, so `a: str = "v"` can still be checked.
function isTypeAnnotation(raw, next) {
  return typeNames.has(raw) || (identifierPath.test(raw) && (next === '[' || next === '<'));
}

// Skip one balanced generic/index group on the same line, e.g. `Optional[str]` or `Option<String>`.
function skipGroup(text, position) {
  const open = text[position];
  const close = open === '[' ? ']' : open === '<' ? '>' : undefined;
  if (!close) return position;
  let depth = 0;
  for (let i = position; i < text.length && text[i] !== '\n'; i++) {
    if (text[i] === open) depth++;
    else if (text[i] === close && --depth === 0) return i + 1;
  }
  return position;
}

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
  let depth = 0;
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
    // An unbalanced closing parenthesis belongs to the surrounding code or prose, never to the value.
    if (text[end] === '(' || text[end] === '（') depth++;
    else if (text[end] === ')' || text[end] === '）') {
      if (depth === 0) break;
      depth--;
    }
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
  // Sentence punctuation that ends the line or is followed by whitespace stays outside the value.
  if (
    !urlQuery &&
    end - start > 1 &&
    /[.!?:]/u.test(text[end - 1]) &&
    !/[.!?:]/u.test(text[end - 2]) &&
    (end === text.length || /\s/u.test(text[end]))
  )
    end--;
  return { start, end };
}

const assignment = /[ \t]*=(?![=>])[ \t]*/uy;
const bearerProse =
  /^(?:tokens?|auth|authentication|authorization|header|headers|scheme|schemes|credentials?|string|value|type)$/iu;

// Decide the masked range for one labeled field, or undefined when the value is clearly not secret.
function fieldSpan(text, start, type, label, queries, followAssignment) {
  const queryLimit = type === 'CREDENTIAL' ? queryLimitAt(queries, start) : undefined;
  const value = fieldValue(text, start, type, queryLimit);
  if (!value) return undefined;
  const raw = text.slice(value.start, value.end);
  if (type === 'PHONE') {
    const digits = raw.replace(/\D/g, '').length;
    return /^[+\d() .-]+$/u.test(raw) && digits >= 7 && digits <= 15 ? value : undefined;
  }
  if (queryLimit !== undefined) return value; // URL query credentials keep the conservative rule.
  if (type === 'ADDRESS' && nonStreetAddress.test(raw)) return undefined;
  if (value.quoted) return reference.test(raw) || placeholder.test(raw) ? undefined : value;
  const next = text[value.end];
  if (isCodeValue(raw, next)) {
    // `password: str = "literal"`: the annotation is code, but the assigned literal is still checked.
    if (followAssignment && isTypeAnnotation(raw, next)) {
      assignment.lastIndex = skipGroup(text, value.end);
      const assigned = assignment.exec(text);
      if (assigned)
        return fieldSpan(text, assigned.index + assigned[0].length, type, label, queries, false);
    }
    return undefined;
  }
  if (type === 'CREDENTIAL') {
    const name = label.toLowerCase();
    if (name === 'pwd' && pathLike.test(raw)) return undefined; // working directory, not a password
    if (bareTokenLabels.has(name) && /^\d{1,9}$/u.test(raw)) return undefined; // token counts
  }
  return value;
}

const residentWeights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
// GB 11643 / ISO 7064 MOD 11-2 check character.
function residentChecksum(value) {
  let sum = 0;
  for (let i = 0; i < 17; i++) sum += Number(value[i]) * residentWeights[i];
  return '10X98765432'[sum % 11] === value[17].toUpperCase();
}

const standalone = [
  [
    'PRIVATE_KEY',
    /-----BEGIN ((?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY)-----[\s\S]*?(?:-----END \1-----|$)/g,
  ],
  [
    'API_KEY',
    /(?<![A-Za-z0-9_-])(?:sk-(?:(?:proj|ant|svcacct|admin|or-v1)-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{20,})|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{20,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})(?![A-Za-z0-9_-])/g,
    // Unprefixed `sk-` keys (OpenAI legacy, DeepSeek, DashScope, Moonshot) are one alphanumeric run
    // mixing letters and digits; hyphenated words such as `sk-learn-contrib-x` are package names.
    (value) =>
      !/^sk-[A-Za-z0-9]+$/u.test(value) || (/\d/u.test(value) && /[A-Za-z]/u.test(value.slice(3))),
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
        date.getUTCDate() === day &&
        residentChecksum(value)
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
      const value = fieldSpan(text, match.index + match[0].length, type, match[1], queries, true);
      if (!value) continue;
      add(value.start, value.end, type);
      fieldEnd = value.end;
    }
    // Authorization schemes: preserve the scheme and redact only its credential.
    for (const match of text.matchAll(/\b(Bearer[ \t]+)([A-Za-z0-9._~+/-]+={0,2})/gi)) {
      if (bearerProse.test(match[2]) || placeholder.test(match[2])) continue; // "a Bearer token"
      add(match.index + match[1].length, match.index + match[0].length, 'BEARER');
    }
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

// DSH message sources produced by agents from already-admitted input: send_message/team relays
// (`agent-message`) and background-subagent completion notices (`subagent-settled`).
export const AGENT_MESSAGE_SOURCES = Object.freeze(['agent-message', 'subagent-settled']);
const agentSources = new Set(AGENT_MESSAGE_SOURCES);

// Whether admission masks this message. The loop re-renders `runtime-context` from local runtime
// facts on every step, so masking it would be discarded and is never attempted.
export function shouldRedact(message, { redactAgentMessages = false } = {}) {
  const kind = message?.source?.kind;
  if (kind === 'runtime-context') return false;
  return redactAgentMessages || !agentSources.has(kind);
}

// Unchanged messages, blocks and arrays are returned as the same objects.
export function redactMessages(messages, redact, options) {
  let changed = false;
  const result = messages.map((message) => {
    if (!shouldRedact(message, options)) return message;
    let blockChanged = false;
    const content = message.content.map((block) => {
      // Attachments and unknown content pass unchanged, not inspected or rejected.
      if (block.type !== 'text') return block;
      const masked = redact(block.text);
      if (!masked.changed) return block;
      blockChanged = true;
      return { ...block, text: masked.text };
    });
    if (!blockChanged) return message;
    changed = true;
    return { ...message, content };
  });
  return changed ? result : messages;
}
