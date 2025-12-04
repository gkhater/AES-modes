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

## Usage
- `npm run dev` and open the shown URL (e.g., http://localhost:5173) to use the AES playground UI.
- Choose operation (encrypt/decrypt), mode, and input encoding (UTF-8/Hex/Base64).
- Provide key in hex (16/24/32 bytes). IV/counter fields are optional; default to zero blocks for reproducibility.
- Padding toggle applies only to ECB/CBC; stream modes (CFB/OFB/CTR) ignore padding and allow arbitrary lengths.
- Outputs are shown as Hex/Base64/UTF-8.
