export interface InfoSection {
  title: string;
  body: string[];
}

export const infoSections: InfoSection[] = [
  {
    title: 'Usage',
    body: [
      'Pick operation and mode, set key (16/24/32-byte hex).',
      'IV (CBC/CFB/OFB) or Counter (CTR) defaults to zeros; use the random buttons for fresh values and reuse them for decryption.',
      'Select input encoding that matches what you paste. Decrypt auto-detects hex/base64 when encoding is left on UTF-8.',
      'ECB/CBC auto-apply padding if needed; stream modes ignore padding.',
    ],
  },
  {
    title: 'Padding',
    body: [
      'Zero-count padding is used for ECB/CBC when needed (last byte stores pad length, preceding pad bytes are zero).',
      'Disable padding only if your data is already a multiple of 16 bytes.',
      'Stream modes (CFB/OFB/CTR) do not use padding and accept any length.',
    ],
  },
  {
    title: 'Reproducibility vs. Safety',
    body: [
      'Zeros IV/counter are kept for reproducibility/test vectors.',
      'Use random IV/counter in practice and keep/copy them to decrypt.',
    ],
  },
  {
    title: 'Known Vectors',
    body: [
      'NIST SP 800-38A vectors are built-in for ECB/CBC/CFB/OFB/CTR.',
      'Web Crypto cross-check is used for CTR. CBC cross-check uses NIST because Web Crypto pads differently by default.',
    ],
  },
];
