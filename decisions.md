# Decisions Log

- Initial scope: implement AES (handwritten) with ECB, CBC, CFB, OFB, CTR (user sets initial counter), IVs default to zeros, zero-padding with pad-length count on last block.
- Stack choice: TypeScript + Vite + React for a browser-first app (no server API), modular core library for AES/modes, UI layer separated from crypto logic.
- Styling/theming: use CSS variables for tokens; support dark mode default with easy extension to other themes (no hardcoded colors).
- Encoding UX: accept plaintext and hex input; outputs available as hex and base64; consistent UTF-8 handling for text paths.
- State strategy: client-only (in-memory) with optional opt-in persistence (localStorage) for user prefs (theme) but not for secret material by default.
- Testing plan: unit tests via Vitest with NIST test vectors for AES/modes; cross-check implementation against Web Crypto only for verification.
- Project layout (planned): `src/crypto` (AES core + modes), `src/utils` (encoding, padding), `src/ui` (components, animations), `src/state` (stores), `tests` (vectors/helpers).
- Tooling: ESLint (flat config), Vitest (jsdom) + Testing Library, TypeScript project refs split for app/node; script `npm run test` runs once (non-watch).
- AES core: supports 128/192/256-bit keys; block-size 16 bytes; default IV/counter factories yield zeroed blocks from central config.
- Padding: zero-count padding utility pads to full blocks, marking pad length in the final byte; unpad validates zero fill.
