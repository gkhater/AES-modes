# SOP: AES Modes Project

- Documentation: update `decisions.md` when making architectural/feature choices; keep this SOP current if practices change.
- Structure: keep crypto logic isolated in `src/crypto` with pure functions and zero UI dependencies; UI components in `src/ui`; shared helpers in `src/utils`; avoid tight coupling for future backend/API.
- AES specifics: implement key schedule, block encrypt/decrypt, and mode wrappers by hand; use zero IVs by default; CTR starts from user-specified counter; last block padded with zeroes plus pad-length count; avoid hardcoded constants in code paths that should be configurable.
- State: prefer ephemeral in-memory state for secrets; only persist non-sensitive prefs (e.g., theme) and make persistence opt-in; no server storage unless requirements change.
- Theming/UX: use CSS variables for tokens (colors, spacing, radii, motion); default to dark theme but keep tokens flexible; keep animations purposeful and minimal.
- Testing: add Vitest unit tests with known vectors; cross-verify against Web Crypto for validation only; include mode-specific edge cases (short blocks, non-block-aligned inputs, counter increments).
- Quality: lint/format (ESLint/Prettier) with CI-friendly scripts; aim for readability, small modules, and descriptive naming; add concise comments only where logic is non-obvious.
