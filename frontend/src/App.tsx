import { useState } from 'react';
import { callCipher } from './api';
import { bytesToHex, hexToBytes } from './utils';
import type { AesMode, Encoding, Operation } from './types/crypto-ui';
import type { CipherResponse } from './types/api';
import { infoSections } from './content/info';
import './App.css';

type FormState = {
  operation: Operation;
  mode: AesMode;
  inputEncoding: Encoding;
  text: string;
  keyHex: string;
  ivHex: string;
  counterHex: string;
};

const modes: AesMode[] = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR'];
const encodings: Encoding[] = ['utf8', 'hex', 'base64'];
const BLOCK_BYTES = 16;

const initialForm: FormState = {
  operation: 'encrypt',
  mode: 'CBC',
  inputEncoding: 'utf8',
  text: '',
  keyHex: '000102030405060708090a0b0c0d0e0f',
  ivHex: '',
  counterHex: '',
};

const badKey = (hex: string) => {
  const key = hexToBytes(hex);
  return ![16, 24, 32].includes(key.length);
};

const badBlock = (hex: string) => {
  if (!hex.trim()) return false;
  return hexToBytes(hex).length !== BLOCK_BYTES;
};

function App() {
  const [form, setForm] = useState<FormState>(initialForm);
  const [result, setResult] = useState<CipherResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const needsIv = form.mode !== 'ECB' && form.mode !== 'CTR';
  const needsCounter = form.mode === 'CTR';

  const placeholders = {
    iv: 'Defaults to 16-byte zeros if empty',
    counter: 'Defaults to 16-byte zeros if empty',
    text:
      form.operation === 'encrypt'
        ? form.inputEncoding === 'utf8'
          ? 'Enter plaintext...'
          : 'Enter plaintext in selected encoding...'
        : 'Enter ciphertext in selected encoding...',
  };

  const setField = (key: keyof FormState, value: string | boolean) => {
    setForm((prev) => ({ ...prev, [key]: value }));
    setFieldErrors((prev) => {
      const copy = { ...prev };
      delete copy[key as string];
      return copy;
    });
  };

  const checkInputs = () => {
    const errs: Record<string, string> = {};
    if (badKey(form.keyHex)) errs.key = 'Key must be 16/24/32 bytes hex';
    if (needsIv && badBlock(form.ivHex)) errs.iv = 'IV must be 16 bytes hex';
    if (needsCounter && badBlock(form.counterHex)) errs.counter = 'Counter must be 16 bytes hex';
    setFieldErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const run = async () => {
    setError(null);
    setNotice(null);
    setResult(null);
    if (!checkInputs()) {
      setError('Please fix the highlighted fields.');
      return;
    }
    setLoading(true);
    try {
      const response = await callCipher({ ...form, padding: true });
      setResult(response);
      if (response.autoPadded) {
        setNotice('Padding was auto-applied for this mode.');
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Unexpected error';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const fillRandom = (key: 'ivHex' | 'counterHex') => {
    const bytes = new Uint8Array(BLOCK_BYTES);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(bytes);
    } else {
      for (let i = 0; i < BLOCK_BYTES; i += 1) bytes[i] = Math.floor(Math.random() * 256);
    }
    setField(key, bytesToHex(bytes));
  };

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark">AES</span>
          <div className="brand-text">
            <div className="brand-title">Modes Playground</div>
            <div className="brand-subtitle">Python backend · ECB / CBC / CFB / OFB / CTR</div>
          </div>
        </div>
        <p className="tagline">Simple React UI calling a Flask API. Enter key/data, pick a mode, see output and steps.</p>
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
                    onClick={() => setField('operation', op)}
                  >
                    {op === 'encrypt' ? 'Encrypt' : 'Decrypt'}
                  </button>
                ))}
              </div>
            </div>

            <div className="control-row">
              <label className="label">Mode</label>
              <select value={form.mode} onChange={(e) => setField('mode', e.target.value)}>
                {modes.map((mode) => (
                  <option key={mode} value={mode}>
                    {mode}
                  </option>
                ))}
              </select>
            </div>

            <div className="control-row">
              <label className="label">Input encoding</label>
              <select value={form.inputEncoding} onChange={(e) => setField('inputEncoding', e.target.value)}>
                {encodings.map((enc) => (
                  <option key={enc} value={enc}>
                    {enc}
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
                onChange={(e) => setField('keyHex', e.target.value)}
                spellCheck={false}
                placeholder="000102... (hex)"
              />
              {fieldErrors.key && <div className="field-error">{fieldErrors.key}</div>}
            </div>

            {needsIv && (
              <div className="control-row">
                <label className="label" htmlFor="iv">
                  IV (hex, 16 bytes)
                </label>
                <input
                  id="iv"
                  className={fieldErrors.iv ? 'error' : ''}
                  value={form.ivHex}
                  onChange={(e) => setField('ivHex', e.target.value)}
                  spellCheck={false}
                  placeholder={placeholders.iv}
                />
                {fieldErrors.iv && <div className="field-error">{fieldErrors.iv}</div>}
                <div className="inline-actions">
                  <button type="button" className="small" onClick={() => fillRandom('ivHex')}>
                    Random IV
                  </button>
                  <button type="button" className="small ghost" onClick={() => setField('ivHex', '')}>
                    Use zeros
                  </button>
                </div>
              </div>
            )}

            {needsCounter && (
              <div className="control-row">
                <label className="label" htmlFor="counter">
                  Counter (hex, 16 bytes)
                </label>
                <input
                  id="counter"
                  className={fieldErrors.counter ? 'error' : ''}
                  value={form.counterHex}
                  onChange={(e) => setField('counterHex', e.target.value)}
                  spellCheck={false}
                  placeholder={placeholders.counter}
                />
                {fieldErrors.counter && <div className="field-error">{fieldErrors.counter}</div>}
                <div className="inline-actions">
                  <button type="button" className="small" onClick={() => fillRandom('counterHex')}>
                    Random counter
                  </button>
                  <button type="button" className="small ghost" onClick={() => setField('counterHex', '')}>
                    Use zeros
                  </button>
                </div>
              </div>
            )}
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
              onChange={(e) => setField('text', e.target.value)}
              placeholder={placeholders.text}
              spellCheck={false}
              rows={6}
            />
          </div>
          <div className="actions">
            <button type="button" className="primary" onClick={run} disabled={loading}>
              {loading ? 'Working...' : `Run ${form.operation === 'encrypt' ? 'Encryption' : 'Decryption'}`}
            </button>
            <div className="hint">Work happens on the Python server</div>
          </div>
          {error && <div className="alert error">{error}</div>}
          {notice && <div className="alert info">{notice}</div>}
          {result && (
            <div className="outputs">
              <div className="output-row">
                <div className="output-label">Hex</div>
                <code className="output-value">{result.output.hex}</code>
              </div>
              <div className="output-row">
                <div className="output-label">Base64</div>
                <code className="output-value">{result.output.base64}</code>
              </div>
              <div className="output-row">
                <div className="output-label">UTF-8</div>
                <code className="output-value">{result.output.utf8}</code>
              </div>
              {result.ivUsed && <div className="hint">Used IV: {result.ivUsed}</div>}
              {result.counterUsed && <div className="hint">Used counter: {result.counterUsed}</div>}
            </div>
          )}
        </section>
      </main>

      {result && result.steps.length > 0 && (
        <section className="card">
          <h2>Step-by-step ({form.mode})</h2>
          <div className="steps">
            {result.steps.map((step) => (
              <div key={step.title} className="step-block">
                <div className="step-title">{step.title}</div>
                <div className="step-fields">
                  {step.fields.map((field) => (
                    <div key={field.label} className="step-field">
                      <div className="output-label">{field.label}</div>
                      <code className="output-value">{field.value}</code>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

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
