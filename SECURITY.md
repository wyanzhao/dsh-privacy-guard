# Security policy

This is a best-effort local text masking plugin, not a security boundary or a complete DLP system. No audit or test result is a guarantee that all secrets will be detected.

## Reporting a vulnerability

Report privately to the repository owner through an existing trusted channel. If GitHub private vulnerability reporting is available for this repository, use it. Do not include real passwords, tokens, personal dictionaries, session logs or screenshots containing private information in an issue, pull request, CI log or public report. Provide a minimal synthetic reproduction instead.

## Important boundaries

- Only newly admitted user text blocks are transformed. Existing history, tool output, system context, attachments and external processes are not redacted.
- Original input can remain in local DSH/browser/session storage. Preview output may retain undetected secrets in local command records.
- Detection uses deterministic formats and explicit field labels. Encoded, obfuscated, unsupported or context-dependent secrets may be missed. False positives are possible.
- Detection does not block requests. An unreadable dictionary falls back to the last good dictionary, or built-in rules when none was loaded. Check `/privacy status` for warnings.
- Personal dictionaries must remain outside version control and distribution artifacts. The optional local dictionary is ignored; only an empty example is shipped.
- Runtime code has no network calls or third-party runtime dependencies. Development dependencies are pinned in the lockfile. CI installs with scripts disabled and uses commit-pinned actions with read-only repository permissions.

## Release checks

Before release run `npm ci --ignore-scripts` and `npm run check`, inspect the staged/packed file lists, and verify that the destination GitHub repository is private. Never change a private repository to public as part of this procedure. Do not treat a green unit suite as proof of provider cache hits or full live DSH integration.
