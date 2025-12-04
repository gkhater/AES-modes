import { createAesKey, decryptBlock, encryptBlock } from '../src/crypto';
import { bytesToHex, hexToBytes } from '../src/utils';

const vector = (keyHex: string, plaintextHex: string, ciphertextHex: string) => ({
  key: hexToBytes(keyHex),
  plaintext: hexToBytes(plaintextHex),
  ciphertext: hexToBytes(ciphertextHex),
});

const vectors = [
  vector('000102030405060708090a0b0c0d0e0f', '00112233445566778899aabbccddeeff', '69c4e0d86a7b0430d8cdb78070b4c55a'),
  vector('000102030405060708090a0b0c0d0e0f1011121314151617', '00112233445566778899aabbccddeeff', 'dda97ca4864cdfe06eaf70a0ec0d7191'),
  vector(
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    '00112233445566778899aabbccddeeff',
    '8ea2b7ca516745bfea fc49904b496089'.replace(/\s+/g, ''),
  ),
];

describe('AES core block cipher', () => {
  it('encrypts known NIST examples', () => {
    for (const { key, plaintext, ciphertext } of vectors) {
      expect([16, 24, 32]).toContain(key.length);
      const schedule = createAesKey(key);
      const output = encryptBlock(plaintext, schedule);
      expect(bytesToHex(output)).toBe(bytesToHex(ciphertext));
    }
  });

  it('decrypts back to plaintext', () => {
    for (const { key, plaintext, ciphertext } of vectors) {
      expect([16, 24, 32]).toContain(key.length);
      const schedule = createAesKey(key);
      const output = decryptBlock(ciphertext, schedule);
      expect(bytesToHex(output)).toBe(bytesToHex(plaintext));
    }
  });

  it('throws on invalid key size', () => {
    const badKey = new Uint8Array([1, 2, 3]);
    expect(() => createAesKey(badKey)).toThrow(/AES key must be 128, 192, or 256 bits/);
  });
});
