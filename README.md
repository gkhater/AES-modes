# AES Modes Playground

Scaffolded with Vite + React + TypeScript for implementing AES in ECB, CBC, CFB, OFB, and CTR modes with handwritten crypto logic.

## Scripts
- `npm install` – install dependencies
- `npm run dev` – start the dev server
- `npm run build` – type-check and build for production
- `npm run lint` – lint with ESLint (flat config)
- `npm run test` – run Vitest (jsdom + Testing Library)

## Structure
- `src/crypto` – AES core and modes
- `src/utils` – shared helpers (encoding, padding, etc.)
- `src/state` – state management utilities
- `src/ui` – UI components
- `tests` – Vitest suites and setup

See `decisions.md` for context and `SOP/sop.md` for working practices.
