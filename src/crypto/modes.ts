import { padZeroCount, unpadZeroCount } from '../utils/padding';
import { BLOCK_SIZE_BYTES, defaultCounterFactory, defaultIvFactory } from './config';
import { AesKeySchedule, createAesKey, decryptBlock, encryptBlock } from './aes';

type ByteArray = Uint8Array;

interface ModeOptions {
  iv?: ByteArray;
  counter?: ByteArray;
  pad?: boolean;
  schedule?: AesKeySchedule;
}

const ensureBlockSized = (label: string, value: ByteArray) => {
  if (value.length !== BLOCK_SIZE_BYTES) {
    throw new Error(`${label} must be ${BLOCK_SIZE_BYTES} bytes`);
  }
};

const xorBlocks = (a: ByteArray, b: ByteArray): ByteArray => {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i += 1) {
    out[i] = a[i] ^ b[i];
  }
  return out;
};

const getSchedule = (key: ByteArray, provided?: AesKeySchedule) => provided ?? createAesKey(key);

const maybePad = (data: ByteArray, pad: boolean | undefined): ByteArray => {
  if (pad === false) {
    if (data.length % BLOCK_SIZE_BYTES !== 0) throw new Error('Input length must align to block size when padding is disabled');
    return data;
  }
  return padZeroCount(data, BLOCK_SIZE_BYTES);
};

const maybeUnpad = (data: ByteArray, pad: boolean | undefined): ByteArray => {
  if (pad === false) return data;
  return unpadZeroCount(data, BLOCK_SIZE_BYTES);
};

export const encryptEcb = (key: ByteArray, plaintext: ByteArray, options: ModeOptions = {}): ByteArray => {
  const schedule = getSchedule(key, options.schedule);
  const input = maybePad(plaintext, options.pad);
  const out = new Uint8Array(input.length);
  for (let offset = 0; offset < input.length; offset += BLOCK_SIZE_BYTES) {
    const block = input.subarray(offset, offset + BLOCK_SIZE_BYTES);
    const cipher = encryptBlock(block, schedule);
    out.set(cipher, offset);
  }
  return out;
};

export const decryptEcb = (key: ByteArray, ciphertext: ByteArray, options: ModeOptions = {}): ByteArray => {
  const schedule = getSchedule(key, options.schedule);
  if (ciphertext.length % BLOCK_SIZE_BYTES !== 0) throw new Error('Ciphertext length must align to block size');
  const out = new Uint8Array(ciphertext.length);
  for (let offset = 0; offset < ciphertext.length; offset += BLOCK_SIZE_BYTES) {
    const block = ciphertext.subarray(offset, offset + BLOCK_SIZE_BYTES);
    const plain = decryptBlock(block, schedule);
    out.set(plain, offset);
  }
  return maybeUnpad(out, options.pad);
};

export const encryptCbc = (key: ByteArray, plaintext: ByteArray, options: ModeOptions = {}): ByteArray => {
  const schedule = getSchedule(key, options.schedule);
  const iv = options.iv ?? defaultIvFactory();
  ensureBlockSized('IV', iv);
  const input = maybePad(plaintext, options.pad);
  const out = new Uint8Array(input.length);
  let prev = iv;
  for (let offset = 0; offset < input.length; offset += BLOCK_SIZE_BYTES) {
    const block = input.subarray(offset, offset + BLOCK_SIZE_BYTES);
    const mixed = xorBlocks(block, prev);
    const cipher = encryptBlock(mixed, schedule);
    out.set(cipher, offset);
    prev = cipher;
  }
  return out;
};

export const decryptCbc = (key: ByteArray, ciphertext: ByteArray, options: ModeOptions = {}): ByteArray => {
  const schedule = getSchedule(key, options.schedule);
  const iv = options.iv ?? defaultIvFactory();
  ensureBlockSized('IV', iv);
  if (ciphertext.length % BLOCK_SIZE_BYTES !== 0) throw new Error('Ciphertext length must align to block size');
  const out = new Uint8Array(ciphertext.length);
  let prev = iv;
  for (let offset = 0; offset < ciphertext.length; offset += BLOCK_SIZE_BYTES) {
    const block = ciphertext.subarray(offset, offset + BLOCK_SIZE_BYTES);
    const plain = xorBlocks(decryptBlock(block, schedule), prev);
    out.set(plain, offset);
    prev = block;
  }
  return maybeUnpad(out, options.pad);
};

export const encryptCfb = (key: ByteArray, plaintext: ByteArray, options: ModeOptions = {}): ByteArray => {
  const schedule = getSchedule(key, options.schedule);
  const iv = options.iv ?? defaultIvFactory();
  ensureBlockSized('IV', iv);
  const out = new Uint8Array(plaintext.length);
  let prev = iv;
  for (let offset = 0; offset < plaintext.length; offset += BLOCK_SIZE_BYTES) {
    const block = plaintext.subarray(offset, offset + BLOCK_SIZE_BYTES);
    const keystream = encryptBlock(prev, schedule);
    const cipher = xorBlocks(block, keystream);
    out.set(cipher, offset);
    prev = cipher.length === BLOCK_SIZE_BYTES ? cipher : prev;
  }
  return out;
};

export const decryptCfb = (key: ByteArray, ciphertext: ByteArray, options: ModeOptions = {}): ByteArray => {
  const schedule = getSchedule(key, options.schedule);
  const iv = options.iv ?? defaultIvFactory();
  ensureBlockSized('IV', iv);
  const out = new Uint8Array(ciphertext.length);
  let prev = iv;
  for (let offset = 0; offset < ciphertext.length; offset += BLOCK_SIZE_BYTES) {
    const block = ciphertext.subarray(offset, offset + BLOCK_SIZE_BYTES);
    const keystream = encryptBlock(prev, schedule);
    const plain = xorBlocks(block, keystream);
    out.set(plain, offset);
    prev = block;
  }
  return out;
};

export const encryptOfb = (key: ByteArray, plaintext: ByteArray, options: ModeOptions = {}): ByteArray => {
  const schedule = getSchedule(key, options.schedule);
  const iv = options.iv ?? defaultIvFactory();
  ensureBlockSized('IV', iv);
  const out = new Uint8Array(plaintext.length);
  let prev = iv;
  for (let offset = 0; offset < plaintext.length; offset += BLOCK_SIZE_BYTES) {
    const keystream = encryptBlock(prev, schedule);
    const block = plaintext.subarray(offset, offset + BLOCK_SIZE_BYTES);
    const cipher = xorBlocks(block, keystream);
    out.set(cipher, offset);
    prev = keystream;
  }
  return out;
};

export const decryptOfb = (key: ByteArray, ciphertext: ByteArray, options: ModeOptions = {}): ByteArray => {
  const schedule = getSchedule(key, options.schedule);
  const iv = options.iv ?? defaultIvFactory();
  ensureBlockSized('IV', iv);
  const out = new Uint8Array(ciphertext.length);
  let prev = iv;
  for (let offset = 0; offset < ciphertext.length; offset += BLOCK_SIZE_BYTES) {
    const keystream = encryptBlock(prev, schedule);
    const block = ciphertext.subarray(offset, offset + BLOCK_SIZE_BYTES);
    const plain = xorBlocks(block, keystream);
    out.set(plain, offset);
    prev = keystream;
  }
  return out;
};

const incrementCounter = (counter: ByteArray): ByteArray => {
  const next = new Uint8Array(counter);
  for (let i = counter.length - 1; i >= 0; i -= 1) {
    next[i] = (next[i] + 1) & 0xff;
    if (next[i] !== 0) break;
  }
  return next;
};

export const encryptCtr = (key: ByteArray, plaintext: ByteArray, options: ModeOptions = {}): ByteArray => {
  const schedule = getSchedule(key, options.schedule);
  const initialCounter = options.counter ?? defaultCounterFactory();
  ensureBlockSized('Counter', initialCounter);
  const out = new Uint8Array(plaintext.length);
  let counter = initialCounter;
  for (let offset = 0; offset < plaintext.length; offset += BLOCK_SIZE_BYTES) {
    const keystream = encryptBlock(counter, schedule);
    const block = plaintext.subarray(offset, offset + BLOCK_SIZE_BYTES);
    const cipher = xorBlocks(block, keystream);
    out.set(cipher, offset);
    counter = incrementCounter(counter);
  }
  return out;
};

export const decryptCtr = (key: ByteArray, ciphertext: ByteArray, options: ModeOptions = {}): ByteArray => {
  const schedule = getSchedule(key, options.schedule);
  const initialCounter = options.counter ?? defaultCounterFactory();
  ensureBlockSized('Counter', initialCounter);
  const out = new Uint8Array(ciphertext.length);
  let counter = initialCounter;
  for (let offset = 0; offset < ciphertext.length; offset += BLOCK_SIZE_BYTES) {
    const keystream = encryptBlock(counter, schedule);
    const block = ciphertext.subarray(offset, offset + BLOCK_SIZE_BYTES);
    const plain = xorBlocks(block, keystream);
    out.set(plain, offset);
    counter = incrementCounter(counter);
  }
  return out;
};
