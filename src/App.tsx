import { useMemo, useState } from 'react';
import {
  decryptCbc,
  decryptCfb,
  decryptCtr,
  decryptEcb,
  decryptOfb,
  defaultCounterFactory,
  defaultIvFactory,
  encryptCbc,
  encryptCfb,
  encryptCtr,
  encryptEcb,
  encryptOfb,
} from './crypto';
import { bytesToBase64, bytesToHex, hexToBytes, stringToUtf8Bytes, utf8BytesToString, base64ToBytes } from './utils';
import type { AesMode, Encoding, Operation } from './types/crypto-ui';
import './App.css';

interface FormState {
  operation: Operation;
  mode: AesMode;
  inputEncoding: Encoding;
  padding: boolean;
  text: string;
  keyHex: string;
  ivHex: string;
  counterHex: string;
}

interface OutputState {
  hex: string;
  base64: string;
  utf8: string;
}

const modeLabels: Record<AesMode, string> = {
  ECB: 'ECB',
  CBC: 'CBC',
  CFB: 'CFB',
  OFB: 'OFB',
  CTR: 'CTR',
};

const encodingLabels: Record<Encoding, string> = {
  utf8: 'Text (UTF-8)',
  hex: 'Hex',
  base64: 'Base64',
};

const BLOCK_BYTES = 16;

const defaultForm: FormState = {
  operation: 'encrypt',
  mode: 'CBC',
  inputEncoding: 'utf8',
  padding: true,
  text: '',
  keyHex: '000102030405060708090a0b0c0d0e0f',
  ivHex: '',
  counterHex: '',
};

const parseInput = (value: string, encoding: Encoding): Uint8Array => {
  if (encoding === 'utf8') return stringToUtf8Bytes(value);
  if (encoding === 'hex') return hexToBytes(value);
  return base64ToBytes(value);
};

const formatOutputs = (bytes: Uint8Array): OutputState => ({
  hex: bytesToHex(bytes),
  base64: bytesToBase64(bytes),
  utf8: utf8BytesToString(bytes),
});

const parseKey = (hex: string): Uint8Array => {
  const key = hexToBytes(hex);
  if (![16, 24, 32].includes(key.length)) {
    throw new Error('Key must be 128, 192, or 256 bits (16/24/32 bytes hex)');
  }
  return key;
};

const parseBlockOrDefault = (label: string, hex: string): Uint8Array | undefined => {
  if (!hex.trim()) {
    return undefined;
  }
  const bytes = hexToBytes(hex);
  if (bytes.length !== BLOCK_BYTES) {
    throw new Error(`${label} must be ${BLOCK_BYTES} bytes`);
  }
  return bytes;
};

const runCipher = (form: FormState): OutputState => {
  const key = parseKey(form.keyHex);
  const iv = parseBlockOrDefault('IV', form.ivHex) ?? defaultIvFactory();
  const counter = parseBlockOrDefault('Counter', form.counterHex) ?? defaultCounterFactory();
  const payload = parseInput(form.text, form.inputEncoding);
  const pad = form.padding;

  const encrypt = (mode: AesMode, data: Uint8Array): Uint8Array => {
    switch (mode) {
      case 'ECB':
        return encryptEcb(key, data, { pad });
      case 'CBC':
        return encryptCbc(key, data, { iv, pad });
      case 'CFB':
        return encryptCfb(key, data, { iv, pad });
      case 'OFB':
        return encryptOfb(key, data, { iv, pad });
      case 'CTR':
        return encryptCtr(key, data, { counter, pad });
      default:
        return data;
    }
  };

  const decrypt = (mode: AesMode, data: Uint8Array): Uint8Array => {
    switch (mode) {
      case 'ECB':
        return decryptEcb(key, data, { pad });
      case 'CBC':
        return decryptCbc(key, data, { iv, pad });
      case 'CFB':
        return decryptCfb(key, data, { iv, pad });
      case 'OFB':
        return decryptOfb(key, data, { iv, pad });
      case 'CTR':
        return decryptCtr(key, data, { counter, pad });
      default:
        return data;
    }
  };

  const result = form.operation === 'encrypt' ? encrypt(form.mode, payload) : decrypt(form.mode, payload);
  return formatOutputs(result);
};

function App() {
  const [form, setForm] = useState<FormState>(defaultForm);
  const [output, setOutput] = useState<OutputState | null>(null);
  const [error, setError] = useState<string | null>(null);

  const isStreamMode = form.mode === 'CFB' || form.mode === 'OFB' || form.mode === 'CTR';
  const showIv = form.mode !== 'ECB' && form.mode !== 'CTR';
  const showCounter = form.mode === 'CTR';

  const placeholders = useMemo(
    () => ({
      iv: 'Defaults to 16-byte zeros if left empty',
      counter: 'Defaults to 16-byte zeros if left empty',
      text:
        form.operation === 'encrypt'
          ? form.inputEncoding === 'utf8'
            ? 'Enter plaintext...'
            : 'Enter plaintext in selected encoding...'
          : 'Enter ciphertext in selected encoding...',
    }),
    [form.inputEncoding, form.operation],
  );

  const onSubmit = () => {
    setError(null);
    try {
      const result = runCipher(form);
      setOutput(result);
    } catch (err) {
      setOutput(null);
      setError(err instanceof Error ? err.message : 'Unexpected error');
    }
  };

  const onModeChange = (mode: AesMode) => {
    setForm((prev) => ({
      ...prev,
      mode,
      padding: mode === 'CFB' || mode === 'OFB' || mode === 'CTR' ? false : prev.padding,
    }));
  };

  const updateField = <K extends keyof FormState>(key: K, value: FormState[K]) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark">AES</span>
          <div className="brand-text">
            <div className="brand-title">Modes Playground</div>
            <div className="brand-subtitle">ECB · CBC · CFB · OFB · CTR</div>
          </div>
        </div>
        <p className="tagline">
          Handwritten AES core with configurable modes, padding, IVs, and counters. Inputs stay in-memory; defaults use zero IV/counter
          for reproducibility.
        </p>
      </header>

      <main className="grid">
        <section className="card">
          <div className="controls">
            <div className="control-row">
              <label className="label">Operation</label>
              <div className="pill-group">
                {(['encrypt', 'decrypt'] as Operation[]).map((op) => (
                  <button
                    key={op}
                    type="button"
                    className={form.operation === op ? 'pill active' : 'pill'}
                    onClick={() => updateField('operation', op)}
                  >
                    {op === 'encrypt' ? 'Encrypt' : 'Decrypt'}
                  </button>
                ))}
              </div>
            </div>

            <div className="control-row">
              <label className="label">Mode</label>
              <select value={form.mode} onChange={(e) => onModeChange(e.target.value as AesMode)}>
                {(Object.keys(modeLabels) as AesMode[]).map((mode) => (
                  <option key={mode} value={mode}>
                    {modeLabels[mode]}
                  </option>
                ))}
              </select>
            </div>

            <div className="control-row">
              <label className="label">Input encoding</label>
              <select value={form.inputEncoding} onChange={(e) => updateField('inputEncoding', e.target.value as Encoding)}>
                {(Object.keys(encodingLabels) as Encoding[]).map((enc) => (
                  <option key={enc} value={enc}>
                    {encodingLabels[enc]}
                  </option>
                ))}
              </select>
            </div>

            <div className="control-row">
              <label className="label" htmlFor="key">
                Key (hex, 16/24/32 bytes)
              </label>
              <input
                id="key"
                value={form.keyHex}
                onChange={(e) => updateField('keyHex', e.target.value)}
                spellCheck={false}
                placeholder="000102... (hex)"
              />
            </div>

            {showIv && (
              <div className="control-row">
                <label className="label" htmlFor="iv">
                  IV (hex, 16 bytes)
                </label>
                <input
                  id="iv"
                  value={form.ivHex}
                  onChange={(e) => updateField('ivHex', e.target.value)}
                  spellCheck={false}
                  placeholder={placeholders.iv}
                />
              </div>
            )}

            {showCounter && (
              <div className="control-row">
                <label className="label" htmlFor="counter">
                  Counter (hex, 16 bytes)
                </label>
                <input
                  id="counter"
                  value={form.counterHex}
                  onChange={(e) => updateField('counterHex', e.target.value)}
                  spellCheck={false}
                  placeholder={placeholders.counter}
                />
              </div>
            )}

            <div className="control-row inline">
              <label className="label">Padding</label>
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={form.padding}
                  disabled={isStreamMode}
                  onChange={(e) => updateField('padding', e.target.checked)}
                />
                <span>{isStreamMode ? 'Padding not used for CFB/OFB/CTR' : 'Zero-count padding'}</span>
              </label>
              {!isStreamMode && <span className="hint">Disable only if data is already block-aligned</span>}
            </div>
          </div>
        </section>

        <section className="card stretch">
          <div className="control-row">
            <label className="label" htmlFor="text">
              {form.operation === 'encrypt' ? 'Plaintext' : 'Ciphertext'}
            </label>
            <textarea
              id="text"
              value={form.text}
              onChange={(e) => updateField('text', e.target.value)}
              placeholder={placeholders.text}
              spellCheck={false}
              rows={6}
            />
          </div>
          <div className="actions">
            <button type="button" className="primary" onClick={onSubmit}>
              Run {form.operation === 'encrypt' ? 'Encryption' : 'Decryption'}
            </button>
            <div className="hint">All operations occur locally in your browser</div>
          </div>
          {error && <div className="alert error">{error}</div>}
          {output && (
            <div className="outputs">
              <div className="output-row">
                <div className="output-label">Hex</div>
                <code className="output-value">{output.hex}</code>
              </div>
              <div className="output-row">
                <div className="output-label">Base64</div>
                <code className="output-value">{output.base64}</code>
              </div>
              <div className="output-row">
                <div className="output-label">UTF-8</div>
                <code className="output-value">{output.utf8}</code>
              </div>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
