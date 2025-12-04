# Task Plan

1) ✅ Scaffold project structure with Vite + React + TypeScript; set up base directories (`src/crypto`, `src/utils`, `src/ui`, `src/state`, `tests`), add lint/format/test tooling.
2) ✅ Implement AES core (key schedule, block encrypt/decrypt) and shared padding/encoding utilities with configuration hooks (IV/counter defaults defined centrally, not scattered).
3) ✅ Implement mode adapters (ECB, CBC, CFB, OFB, CTR with user-defined initial counter) leveraging core; ensure zero IV defaults and padding per spec; add validation.
4) ✅ Build verification tests with NIST vectors and cross-checks against Web Crypto via Vitest.
5) ⏳ Create frontend UX: theme tokens (dark default, extendable), inputs for plaintext/hex, outputs hex/base64, mode/IV/counter controls, animations for block flow.
6) ⏳ Integrate state management (ephemeral for secrets; opt-in persistence for non-sensitive prefs), error handling, and accessibility polish.
7) ⏳ Add documentation (README updates, usage notes) and final QA pass (lint/format/tests).
