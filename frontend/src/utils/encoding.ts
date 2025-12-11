const resolveBtoa = (): ((data: string) => string) => {
  if (typeof globalThis.btoa === 'function') return globalThis.btoa;
  if (typeof Buffer !== 'undefined') {
    return (data: string) => Buffer.from(data, 'binary').toString('base64');
  }
  throw new Error('No base64 encoder available');
};

const resolveAtob = (): ((data: string) => string) => {
  if (typeof globalThis.atob === 'function') return globalThis.atob;
  if (typeof Buffer !== 'undefined') {
    return (data: string) => Buffer.from(data, 'base64').toString('binary');
  }
  throw new Error('No base64 decoder available');
};

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export const stringToUtf8Bytes = (input: string): Uint8Array => textEncoder.encode(input);

export const utf8BytesToString = (bytes: Uint8Array): string => textDecoder.decode(bytes);

export const hexToBytes = (hex: string): Uint8Array => {
  const normalized = hex.replace(/\s+/g, '').toLowerCase();
  if (normalized.length % 2 !== 0) throw new Error('Hex string length must be even');

  const output = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    const parsedByte = Number.parseInt(normalized.slice(i, i + 2), 16);
    if (Number.isNaN(parsedByte)) throw new Error('Invalid hex character');
    output[i / 2] = parsedByte;
  }

  return output;
};

export const bytesToHex = (bytes: Uint8Array): string => {
  const hexParts: string[] = [];
  for (let i = 0; i < bytes.length; i += 1) {
    hexParts.push(bytes[i].toString(16).padStart(2, '0'));
  }
  return hexParts.join('');
};

export const bytesToBase64 = (bytes: Uint8Array): string => {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return resolveBtoa()(binary);
};

export const base64ToBytes = (b64: string): Uint8Array => {
  const binary = resolveAtob()(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};
