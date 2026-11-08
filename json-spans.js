// Preserve JSON syntax when a detector finds a substring of a scalar or escape.
// This is a lexer over already validated JSON, not a permissive JSON parser.
function atomsOf(source, offset) {
  try {
    JSON.parse(source);
  } catch {
    return undefined;
  }
  const atoms = [];
  for (let i = 0; i < source.length;) {
    if (source[i] === '"') {
      const start = ++i;
      const escapes = [];
      while (source[i] !== '"') {
        if (source[i] === '\\') {
          const end = i + (source[i + 1] === 'u' ? 6 : 2);
          escapes.push([offset + i, offset + end]);
          i = end;
        } else i++;
      }
      atoms.push({ start: offset + start, end: offset + i, string: true, escapes });
      i++;
    } else if (/[\d-]/u.test(source[i])) {
      const start = i;
      while (i < source.length && /[\d.eE+-]/u.test(source[i])) i++;
      atoms.push({ start: offset + start, end: offset + i, string: false });
    } else if (/[tfn]/u.test(source[i])) {
      const start = i;
      i += source[i] === 'f' ? 5 : 4;
      atoms.push({ start: offset + start, end: offset + i, string: false });
    } else i++;
  }
  return atoms;
}

function regionsOf(text) {
  const whole = ['[', '{', '"'].includes(text.trimStart()[0]) ? atomsOf(text, 0) : undefined;
  if (whole) return [{ start: 0, end: text.length, atoms: whole }];
  const regions = [];
  for (const match of text.matchAll(/```(?:json)?[ \t]*\r?\n([\s\S]*?)```/gi)) {
    const offset = match.index + match[0].indexOf('\n') + 1;
    const atoms = atomsOf(match[1], offset);
    if (atoms) regions.push({ start: offset, end: offset + match[1].length, atoms });
  }
  return regions;
}

function project(span, region) {
  const projected = [];
  let low = 0,
    high = region.atoms.length;
  while (low < high) {
    const mid = (low + high) >>> 1;
    if (region.atoms[mid].end <= span.start) low = mid + 1;
    else high = mid;
  }
  for (let i = low; i < region.atoms.length && region.atoms[i].start < span.end; i++) {
    const atom = region.atoms[i];
    if (!atom.string)
      projected.push({ ...span, start: atom.start, end: atom.end, replacement: '"*"' });
    else {
      let start = Math.max(atom.start, span.start),
        end = Math.min(atom.end, span.end);
      for (const [a, b] of atom.escapes) {
        if (start < b && end > a) {
          start = Math.min(start, a);
          end = Math.max(end, b);
        }
      }
      if (end > start) projected.push({ ...span, start, end, replacement: '*' });
    }
  }
  return projected;
}

export function preserveJsonScalars(text, spans) {
  if (!spans.length) return spans;
  const regions = regionsOf(text);
  if (!regions.length) return spans;
  return spans.flatMap((span) => {
    const result = [];
    let cursor = span.start;
    for (const region of regions) {
      if (region.end <= cursor) continue;
      if (region.start >= span.end) break;
      if (cursor < region.start) result.push({ ...span, start: cursor, end: region.start });
      result.push(
        ...project(
          { ...span, start: Math.max(cursor, region.start), end: Math.min(span.end, region.end) },
          region,
        ),
      );
      cursor = Math.min(span.end, region.end);
      if (cursor === span.end) break;
    }
    if (cursor < span.end) result.push({ ...span, start: cursor });
    return result;
  });
}
