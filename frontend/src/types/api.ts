import type { Encoding } from './crypto-ui';

export interface StepField {
  label: string;
  value: string;
}

export interface Step {
  title: string;
  fields: StepField[];
}

export interface CipherRequest {
  operation: 'encrypt' | 'decrypt';
  mode: 'ECB' | 'CBC' | 'CFB' | 'OFB' | 'CTR';
  inputEncoding: Encoding;
  padding: boolean;
  text: string;
  keyHex: string;
  ivHex: string;
  counterHex: string;
}

export interface CipherResponse {
  output: {
    hex: string;
    base64: string;
    utf8: string;
  };
  encodingUsed: Encoding;
  autoPadded: boolean;
  ivUsed?: string;
  counterUsed?: string;
  steps: Step[];
}
