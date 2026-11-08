# Changelog

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
