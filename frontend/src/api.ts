import type { CipherRequest, CipherResponse } from './types/api';

const API_BASE = '/api';

export const callCipher = async (payload: CipherRequest): Promise<CipherResponse> => {
  const res = await fetch(`${API_BASE}/cipher`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed with status ${res.status}`);
  }

  return (await res.json()) as CipherResponse;
};
