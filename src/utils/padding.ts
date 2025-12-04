export const padZeroCount = (input: Uint8Array, blockSize: number): Uint8Array => {
  if (blockSize <= 0) throw new Error('Block size must be positive');
  const remainder = input.length % blockSize;
  const padLength = remainder === 0 ? blockSize : blockSize - remainder;
  const output = new Uint8Array(input.length + padLength);
  output.set(input);
  output[output.length - 1] = padLength;
  return output;
};

export const unpadZeroCount = (input: Uint8Array, blockSize: number): Uint8Array => {
  if (input.length === 0 || input.length % blockSize !== 0) {
    throw new Error('Padded input length must be a positive multiple of block size');
  }
  const padLength = input[input.length - 1];
  if (padLength === 0 || padLength > blockSize) {
    throw new Error('Invalid padding length marker');
  }
  // All pad bytes except the marker are expected to be zero
  for (let i = input.length - padLength; i < input.length - 1; i += 1) {
    if (input[i] !== 0) {
      throw new Error('Invalid zero-count padding content');
    }
  }
  return input.slice(0, input.length - padLength);
};
