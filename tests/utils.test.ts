import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes, stringToUtf8Bytes, utf8BytesToString } from '../src/utils';
import { padZeroCount, unpadZeroCount } from '../src/utils/padding';

describe('encoding utilities', () => {
  it('hex round-trip', () => {
    const original = '001122aabbcc';
    const bytes = hexToBytes(original);
    expect(bytesToHex(bytes)).toBe(original);
  });

  it('utf8 round-trip', () => {
    const text = 'AES modes OK';
    const bytes = stringToUtf8Bytes(text);
    expect(utf8BytesToString(bytes)).toBe(text);
  });

  it('base64 round-trip', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5, 250]);
    const b64 = bytesToBase64(data);
    expect(base64ToBytes(b64)).toEqual(data);
  });
});

describe('zero-count padding', () => {
  const blockSize = 16;

  it('pads and unpads data shorter than a block', () => {
    const data = stringToUtf8Bytes('hello');
    const padded = padZeroCount(data, blockSize);
    expect(padded.length % blockSize).toBe(0);
    const unpadded = unpadZeroCount(padded, blockSize);
    expect(bytesToHex(unpadded)).toBe(bytesToHex(data));
  });

  it('pads full block with extra block carrying pad length', () => {
    const data = new Uint8Array(blockSize);
    const padded = padZeroCount(data, blockSize);
    expect(padded.length).toBe(blockSize * 2);
    expect(padded[padded.length - 1]).toBe(blockSize);
  });

  it('rejects bad padding markers', () => {
    const invalid = new Uint8Array(blockSize);
    expect(() => unpadZeroCount(invalid, blockSize)).toThrow(/Invalid padding length/);
  });
});
