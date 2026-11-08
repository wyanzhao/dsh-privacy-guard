# Development

Use Node.js 22.13.0 or newer (CI covers the minimum, 24 and 26 on Linux, Windows and macOS).

```sh
npm ci --ignore-scripts
npm run check
```

Runtime has no third-party dependencies. ESLint and Prettier are development-only and exactly pinned. A `minimatch` override pins 11.0.1 to address GHSA-g3hv-75wg-m249 in the supported ESLint toolchain; remove the override when upstream dependency ranges include a fixed version. Lint behavior is checked across the CI OS/Node matrix. Use `npm run format` before committing.

## Changes to masking behavior

1. Add exact-output positive and negative cases using synthetic values only.
2. Test repeated transformation, JSON parseability, original-object immutability and unchanged surrounding prose.
3. Keep detection local; do not log matched values, add network calls, introduce request denial, or rewrite stored history.
4. Preserve DSH waterfall behavior and context-owned cleanup. Confirm API contracts against the supported DSH runtime before changing extension points.
5. Run coverage, lint, formatting and package checks. The clean-package smoke test activates only a synthetic host and does not access the developer's personal dictionary.

Never commit `private-terms.json`, `.env` files, credentials, session logs, private screenshots or generated archives. Use an external user-owned dictionary path where practical.

CI is a release gate, not a claim of exhaustive privacy detection or full DSH end-to-end testing. Live model-provider cache behavior remains outside the unit suite.

## Releasing

Choose a version, update the manifest, runtime version and changelog together. Inspect `git diff --cached` and `npm run check:package`. Verify the remote is the intended private repository before pushing. Do not publish to npm (`private: true` is intentional) or grant an open-source license without the repository owner's explicit decision.
