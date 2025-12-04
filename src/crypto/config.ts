export const BLOCK_SIZE_BYTES = 16;

export const defaultIvFactory = (): Uint8Array => new Uint8Array(BLOCK_SIZE_BYTES);

export const defaultCounterFactory = (): Uint8Array => new Uint8Array(BLOCK_SIZE_BYTES);
