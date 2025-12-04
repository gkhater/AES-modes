import { webcrypto } from 'crypto';
import { decryptCtr, encryptCtr } from '../src/crypto';
import { bytesToHex, hexToBytes } from '../src/utils';

const cryptoApi = webcrypto ?? globalThis.crypto;

const keyHex = '2b7e151628aed2a6abf7158809cf4f3c';
const ctrHex = 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff';

const plaintextHex =
  '6bc1bee22e409f96e93d7e117393172a' +
  'ae2d8a571e03ac9c9eb76fac45af8e51' +
  '30c81c46a35ce411e5fbc1191a0a52ef' +
  'f69f2445df4f9b17ad2b417be66c3710';

const subtleOrSkip = () => {
  if (!cryptoApi?.subtle) {
    return null;
  }
  return cryptoApi.subtle;
};

describe('Cross-verify with Web Crypto', () => {
  const subtle = subtleOrSkip();
  if (!subtle) {
    it.skip('skipped - Web Crypto not available', () => {});
    return;
  }

  const key = hexToBytes(keyHex);
  const counter = hexToBytes(ctrHex);
  const plaintext = hexToBytes(plaintextHex);

  const importCtrKey = async () =>
    subtle.importKey('raw', key, { name: 'AES-CTR', length: 128 }, false, ['encrypt', 'decrypt']);

  it('matches AES-CTR encrypt output', async () => {
    const wcKey = await importCtrKey();
    const wcCipher = new Uint8Array(
      await subtle.encrypt({ name: 'AES-CTR', counter, length: 128 }, wcKey, plaintext),
    );
    const ours = encryptCtr(key, plaintext, { counter, pad: false });
    expect(bytesToHex(ours)).toBe(bytesToHex(wcCipher));
  });

  it('round-trips AES-CTR decrypt', async () => {
    const wcKey = await importCtrKey();
    const wcCipher = new Uint8Array(
      await subtle.encrypt({ name: 'AES-CTR', counter, length: 128 }, wcKey, plaintext),
    );
    const oursPlain = decryptCtr(key, wcCipher, { counter, pad: false });
    expect(bytesToHex(oursPlain)).toBe(bytesToHex(plaintext));
  });
});
