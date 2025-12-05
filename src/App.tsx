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
import { infoSections } from './content/info';
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

interface RunResult {
  output: OutputState;
  encodingUsed: Encoding;
  autoPadded: boolean;
  ivUsed?: string;
  counterUsed?: string;
}
const hexPattern = /^[0-9a-fA-F\s]+$/;
const base64Pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

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

const runCipher = (form: FormState): RunResult => {
  const key = parseKey(form.keyHex);
  const iv = form.mode !== 'ECB' && form.mode !== 'CTR' ? parseBlockOrDefault('IV', form.ivHex) ?? defaultIvFactory() : undefined;
  const counter = form.mode === 'CTR' ? parseBlockOrDefault('Counter', form.counterHex) ?? defaultCounterFactory() : undefined;
  const payloadEncoding =
    form.operation === 'decrypt' && form.inputEncoding === 'utf8'
      ? detectEncoding(form.text) ?? form.inputEncoding
      : form.inputEncoding;
  const payload = parseInput(form.text, payloadEncoding);
  const pad = form.padding;
  const blockMode = form.mode === 'ECB' || form.mode === 'CBC';
  const autoPad = blockMode && form.operation === 'encrypt' && pad === false && payload.length % BLOCK_BYTES !== 0;
  const effectivePad = blockMode ? pad || autoPad : false;

  const encrypt = (mode: AesMode, data: Uint8Array): Uint8Array => {
    switch (mode) {
      case 'ECB':
        return encryptEcb(key, data, { pad: effectivePad });
      case 'CBC':
        return encryptCbc(key, data, { iv, pad: effectivePad });
      case 'CFB':
        return encryptCfb(key, data, { iv, pad: false });
      case 'OFB':
        return encryptOfb(key, data, { iv, pad: false });
      case 'CTR':
        return encryptCtr(key, data, { counter, pad: false });
      default:
        return data;
    }
  };

  const decrypt = (mode: AesMode, data: Uint8Array): Uint8Array => {
    switch (mode) {
      case 'ECB':
        return decryptEcb(key, data, { pad: effectivePad });
      case 'CBC':
        return decryptCbc(key, data, { iv, pad: effectivePad });
      case 'CFB':
        return decryptCfb(key, data, { iv, pad: false });
      case 'OFB':
        return decryptOfb(key, data, { iv, pad: false });
      case 'CTR':
        return decryptCtr(key, data, { counter, pad: false });
      default:
        return data;
    }
  };

  const result = form.operation === 'encrypt' ? encrypt(form.mode, payload) : decrypt(form.mode, payload);
  return {
    output: formatOutputs(result),
    encodingUsed: payloadEncoding,
    autoPadded: autoPad,
    ivUsed: iv ? bytesToHex(iv) : undefined,
    counterUsed: counter ? bytesToHex(counter) : undefined,
  };
};

const detectEncoding = (value: string): Encoding | null => {
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (hexPattern.test(trimmed) && trimmed.replace(/\s+/g, '').length % 2 === 0) return 'hex';
  if (base64Pattern.test(trimmed) && trimmed.length % 4 === 0) return 'base64';
  return null;
};

const randomBlock = (): Uint8Array => {
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    const arr = new Uint8Array(BLOCK_BYTES);
    crypto.getRandomValues(arr);
    return arr;
  }
  // Weak fallback for environments without crypto (not expected in browser/Node)
  const arr = new Uint8Array(BLOCK_BYTES);
  for (let i = 0; i < BLOCK_BYTES; i += 1) {
    arr[i] = Math.floor(Math.random() * 256);
  }
  return arr;
};

function App() {
  const [form, setForm] = useState<FormState>(defaultForm);
  const [output, setOutput] = useState<OutputState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [usedIv, setUsedIv] = useState<string | null>(null);
  const [usedCounter, setUsedCounter] = useState<string | null>(null);
  const [detectedEncoding, setDetectedEncoding] = useState<Encoding | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

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

  const validateFields = (): boolean => {
    const errs: Record<string, string> = {};
    try {
      parseKey(form.keyHex);
    } catch (e) {
      errs.key = e instanceof Error ? e.message : 'Invalid key';
    }
    if (showIv && form.ivHex.trim()) {
      try {
        parseBlockOrDefault('IV', form.ivHex);
      } catch (e) {
        errs.iv = e instanceof Error ? e.message : 'Invalid IV';
      }
    }
    if (showCounter && form.counterHex.trim()) {
      try {
        parseBlockOrDefault('Counter', form.counterHex);
      } catch (e) {
        errs.counter = e instanceof Error ? e.message : 'Invalid counter';
      }
    }
    setFieldErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const onSubmit = () => {
    setError(null);
    setNotice(null);
    setUsedIv(null);
    setUsedCounter(null);
    if (!validateFields()) {
      setError('Please fix the highlighted fields.');
      return;
    }
    try {
      const result = runCipher(form);
      setOutput(result.output);
      setDetectedEncoding(result.encodingUsed !== form.inputEncoding ? result.encodingUsed : null);
      if (result.autoPadded) {
        setNotice('Padding was auto-applied to align data to 16 bytes for this mode.');
      }
      if (result.ivUsed) setUsedIv(result.ivUsed);
      if (result.counterUsed) setUsedCounter(result.counterUsed);
    } catch (err: unknown) {
      const message = err instanceof Error ? String(err.message) : 'Unexpected error';
      setOutput(null);
      setError(message);
    }
  };

  const onModeChange = (mode: AesMode) => {
    setForm((prev) => ({
      ...prev,
      mode,
      padding: mode === 'CFB' || mode === 'OFB' || mode === 'CTR' ? false : prev.padding,
    }));
  };

  const onAutoFillRandom = (target: 'ivHex' | 'counterHex') => {
    const bytes = randomBlock();
    updateField(target, bytesToHex(bytes));
  };

  const updateField = <K extends keyof FormState>(key: K, value: FormState[K]) => {
    setForm((prev) => ({ ...prev, [key]: value }));
    setFieldErrors((prev) => {
      const copy = { ...prev };
      delete copy[key as string];
      return copy;
    });
  };

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark">AES</span>
          <div className="brand-text">
            <div className="brand-title">Modes Playground</div>
            <div className="brand-subtitle">ECB / CBC / CFB / OFB / CTR</div>
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
                className={fieldErrors.key ? 'error' : ''}
                value={form.keyHex}
                onChange={(e) => updateField('keyHex', e.target.value)}
                spellCheck={false}
                placeholder="000102... (hex)"
              />
              {fieldErrors.key && <div className="field-error">{fieldErrors.key}</div>}
            </div>

            {showIv && (
              <div className="control-row">
                <label className="label" htmlFor="iv">
                  IV (hex, 16 bytes)
                </label>
                <input
                  id="iv"
                  className={fieldErrors.iv ? 'error' : ''}
                  value={form.ivHex}
                  onChange={(e) => updateField('ivHex', e.target.value)}
                  spellCheck={false}
                  placeholder={placeholders.iv}
                />
                {fieldErrors.iv && <div className="field-error">{fieldErrors.iv}</div>}
                <div className="inline-actions">
                  <button
                    type="button"
                    className="small"
                    onClick={() => onAutoFillRandom('ivHex')}
                    title="Generate a random IV and fill the field"
                  >
                    Random IV
                  </button>
                  <button
                    type="button"
                    className="small ghost"
                    onClick={() => {
                      updateField('ivHex', '');
                    }}
                  >
                    Use zeros
                  </button>
                  {usedIv && <span className="hint">Used IV: {usedIv}</span>}
                </div>
              </div>
            )}

            {showCounter && (
              <div className="control-row">
                <label className="label" htmlFor="counter">
                  Counter (hex, 16 bytes)
                </label>
                <input
                  id="counter"
                  className={fieldErrors.counter ? 'error' : ''}
                  value={form.counterHex}
                  onChange={(e) => updateField('counterHex', e.target.value)}
                  spellCheck={false}
                  placeholder={placeholders.counter}
                />
                {fieldErrors.counter && <div className="field-error">{fieldErrors.counter}</div>}
                <div className="inline-actions">
                  <button
                    type="button"
                    className="small"
                    onClick={() => onAutoFillRandom('counterHex')}
                    title="Generate a random counter and fill the field"
                  >
                    Random counter
                  </button>
                  <button
                    type="button"
                    className="small ghost"
                    onClick={() => {
                      updateField('counterHex', '');
                    }}
                  >
                    Use zeros
                  </button>
                  {usedCounter && <span className="hint">Used counter: {usedCounter}</span>}
                </div>
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
          {notice && <div className="alert info">{notice}</div>}
          {detectedEncoding && <div className="alert info">Detected input as {detectedEncoding.toUpperCase()} for decryption.</div>}
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

      <section className="card info-card">
        <h2>How this works</h2>
        <div className="info-grid">
          {infoSections.map((section) => (
            <div key={section.title} className="info-block">
              <h3>{section.title}</h3>
              <ul>
                {section.body.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

export default App;
