import {
  decryptCbc,
  decryptCfb,
  decryptCtr,
  decryptEcb,
  decryptOfb,
  encryptCbc,
  encryptCfb,
  encryptCtr,
  encryptEcb,
  encryptOfb,
} from '../src/crypto';
import { hexToBytes, bytesToHex } from '../src/utils';

const key128 = hexToBytes('2b7e151628aed2a6abf7158809cf4f3c');
const iv = hexToBytes('000102030405060708090a0b0c0d0e0f');
const ctrInit = hexToBytes('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');

const plaintextBlocks = [
  '6bc1bee22e409f96e93d7e117393172a',
  'ae2d8a571e03ac9c9eb76fac45af8e51',
  '30c81c46a35ce411e5fbc1191a0a52ef',
  'f69f2445df4f9b17ad2b417be66c3710',
];

const asBytes = (hexBlocks: string[]) => hexToBytes(hexBlocks.join(''));

describe('AES modes against NIST SP 800-38A vectors', () => {
  const plain = asBytes(plaintextBlocks);

  it('ECB encrypt/decrypt', () => {
    const expected = asBytes([
      '3ad77bb40d7a3660a89ecaf32466ef97',
      'f5d3d58503b9699de785895a96fdbaaf',
      '43b1cd7f598ece23881b00e3ed030688',
      '7b0c785e27e8ad3f8223207104725dd4',
    ]);
    const cipher = encryptEcb(key128, plain, { pad: false });
    expect(bytesToHex(cipher)).toBe(bytesToHex(expected));
    const decrypted = decryptEcb(key128, cipher, { pad: false });
    expect(bytesToHex(decrypted)).toBe(bytesToHex(plain));
  });

  it('CBC encrypt/decrypt', () => {
    const expected = asBytes([
      '7649abac8119b246cee98e9b12e9197d',
      '5086cb9b507219ee95db113a917678b2',
      '73bed6b8e3c1743b7116e69e22229516',
      '3ff1caa1681fac09120eca307586e1a7',
    ]);
    const cipher = encryptCbc(key128, plain, { iv, pad: false });
    expect(bytesToHex(cipher)).toBe(bytesToHex(expected));
    const decrypted = decryptCbc(key128, cipher, { iv, pad: false });
    expect(bytesToHex(decrypted)).toBe(bytesToHex(plain));
  });

  it('CFB encrypt/decrypt', () => {
    const expected = asBytes([
      '3b3fd92eb72dad20333449f8e83cfb4a',
      'c8a64537a0b3a93fcde3cdad9f1ce58b',
      '26751f67a3cbb140b1808cf187a4f4df',
      'c04b05357c5d1c0eeac4c66f9ff7f2e6',
    ]);
    const cipher = encryptCfb(key128, plain, { iv, pad: false });
    expect(bytesToHex(cipher)).toBe(bytesToHex(expected));
    const decrypted = decryptCfb(key128, cipher, { iv, pad: false });
    expect(bytesToHex(decrypted)).toBe(bytesToHex(plain));
  });

  it('OFB encrypt/decrypt', () => {
    const expected = asBytes([
      '3b3fd92eb72dad20333449f8e83cfb4a',
      '7789508d16918f03f53c52dac54ed825',
      '9740051e9c5fecf64344f7a82260edcc',
      '304c6528f659c77866a510d9c1d6ae5e',
    ]);
    const cipher = encryptOfb(key128, plain, { iv, pad: false });
    expect(bytesToHex(cipher)).toBe(bytesToHex(expected));
    const decrypted = decryptOfb(key128, cipher, { iv, pad: false });
    expect(bytesToHex(decrypted)).toBe(bytesToHex(plain));
  });

  it('CTR encrypt/decrypt', () => {
    const expected = asBytes([
      '874d6191b620e3261bef6864990db6ce',
      '9806f66b7970fdff8617187bb9fffdff',
      '5ae4df3edbd5d35e5b4f09020db03eab',
      '1e031dda2fbe03d1792170a0f3009cee',
    ]);
    const cipher = encryptCtr(key128, plain, { counter: ctrInit, pad: false });
    expect(bytesToHex(cipher)).toBe(bytesToHex(expected));
    const decrypted = decryptCtr(key128, cipher, { counter: ctrInit, pad: false });
    expect(bytesToHex(decrypted)).toBe(bytesToHex(plain));
  });
});
