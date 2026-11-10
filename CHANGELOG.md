# Changelog

## 1.4.0 — Code-aware masking and agent-message passthrough

- Unquoted field values no longer swallow unbalanced `)`/`）`, and `]`, `}`, `;`, `,` end credential values; trailing sentence punctuation stays outside the value. Text outside the value range is never changed.
- Code-context exclusions for labeled fields: type names and annotations (`password: string`, `api_key: Optional[str]`, `&str`), environment/template references (`$X`, `${X}`, `${{ X }}`), calls and member access on code objects (`process.cwd()`, `os.getenv(...)`, `os.environ[...]`, `self.token`), and whole-value placeholders (`your-...`, `xxx`, `***`, `...`, `changeme`, `<...>`). An annotation followed by `= literal` still masks the literal.
- Label-specific exclusions: paths and calls after `pwd`; URLs, IPs, host:port, MAC, hex pointers, file paths and domains after address labels; integers up to nine digits after a bare `token`/`令牌`. Numeric passwords stay masked.
- Quoted values stay masked except a whole reference or obvious placeholder (`"${TOKEN}"`, `"<your-key>"`).
- `sk-` keys require a real shape: a known prefix (`proj`, `ant`, `svcacct`, `admin`, `or-v1`) or one ≥20-character alphanumeric run mixing letters and digits. `sk-learn-contrib-x` and letter-only fixtures are no longer keys.
- Resident IDs require a valid ISO 7064 MOD 11-2 check character in addition to the date.
- `Bearer token`-style prose and Bearer placeholders are no longer masked.
- New `redactAgentMessages` option (default `false`): `agent-message` relays and `subagent-settled` notices pass through unchanged. `runtime-context` always passes through (the loop re-renders it every step).
- Unchanged decisions, message arrays, messages and blocks are returned as the same objects; the dictionary is opened only when a text block is inspected, and its compiled regex is reused while the file identity (dev, inode, size, mtime, ctime) is unchanged.
- `/privacy status` states exactly what is and is not masked, including the agent-message switch.

## 1.3.0 — Release hardening

- Exclude the personal dictionary from version control and package artifacts; ship an empty example and allow a clean install to use built-in rules without a dictionary.
- Bound dictionary reads, reject nonregular files, preserve sanitized last-good fallback, and support host-native absolute paths on Windows as well as Unix.
- Preserve complete JSON numeric atoms, scalar quotes and escape boundaries for built-in and literal matches in complete JSON values and explicit JSON fences.
- Mask complete URL query credential values containing comma/semicolon characters.
- Make host tests hermetic; add dictionary, JSON corpus, lifecycle and clean-package tests, coverage gates, lint/format checks and cross-platform CI.
- Keep single-asterisk masking, no request blocking, no network detection and no retroactive history rewriting.

## 1.2.0 — Local rules baseline

- Original-text span detection, merged overlaps and fixed asterisk masks.
- Broader key, credential, URL, PEM, email and phone formats with positive/negative tests.

## 1.1.x — Initial local iterations

- Replace detection hits instead of blocking requests.
- Add explicit natural-language credential expressions and local preview/status commands.
