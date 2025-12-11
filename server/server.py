from __future__ import annotations

import base64
import json
import re
from flask import Flask, jsonify, request

app = Flask(__name__)

BLOCK_SIZE = 16

# hex encode bytes
def bytes_to_hex(data):
    return data.hex()


# parse hex string
#Chat GPT helped with error handling and regex syntax
def hex_to_bytes(data):
    cleaned = re.sub(r"\s+", "", data).lower()
    if len(cleaned) % 2 != 0:
        raise ValueError("Hex string length must be even")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:  # pragma: no cover - ValueError message is enough
        raise ValueError("Invalid hex string") from exc


# base64 encode bytes
def bytes_to_base64(data):
    return base64.b64encode(data).decode("utf-8")


# parse base64 string
#Chat GPT helped with error Handling here
def base64_to_bytes(data):
    try:
        return base64.b64decode(data, validate=True)
    except Exception as exc: 
        raise ValueError("Invalid base64 string") from exc


# utf8 encode string
def string_to_utf8(data):
    return data.encode("utf-8")


# utf8 decode bytes
def utf8_to_string(data):
    return data.decode("utf-8", errors="replace")


# zero-count pad
def pad_zero_count(data, block_size):
    remainder = len(data) % block_size
    pad_len = block_size if remainder == 0 else block_size - remainder
    return data + bytes([0] * (pad_len - 1) + [pad_len])


# strip zero-count pad
def unpad_zero_count(data, block_size):
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Padded input length must be a positive multiple of block size")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("Invalid padding length marker")
    if any(b != 0 for b in data[-pad_len:-1]):
        raise ValueError("Invalid zero-count padding content")
    return data[:-pad_len]


# AES tables
#TODO: check correct, AI generated 
SBOX = [
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
]

INV_SBOX = [
    0x52,
    0x09,
    0x6A,
    0xD5,
    0x30,
    0x36,
    0xA5,
    0x38,
    0xBF,
    0x40,
    0xA3,
    0x9E,
    0x81,
    0xF3,
    0xD7,
    0xFB,
    0x7C,
    0xE3,
    0x39,
    0x82,
    0x9B,
    0x2F,
    0xFF,
    0x87,
    0x34,
    0x8E,
    0x43,
    0x44,
    0xC4,
    0xDE,
    0xE9,
    0xCB,
    0x54,
    0x7B,
    0x94,
    0x32,
    0xA6,
    0xC2,
    0x23,
    0x3D,
    0xEE,
    0x4C,
    0x95,
    0x0B,
    0x42,
    0xFA,
    0xC3,
    0x4E,
    0x08,
    0x2E,
    0xA1,
    0x66,
    0x28,
    0xD9,
    0x24,
    0xB2,
    0x76,
    0x5B,
    0xA2,
    0x49,
    0x6D,
    0x8B,
    0xD1,
    0x25,
    0x72,
    0xF8,
    0xF6,
    0x64,
    0x86,
    0x68,
    0x98,
    0x16,
    0xD4,
    0xA4,
    0x5C,
    0xCC,
    0x5D,
    0x65,
    0xB6,
    0x92,
    0x6C,
    0x70,
    0x48,
    0x50,
    0xFD,
    0xED,
    0xB9,
    0xDA,
    0x5E,
    0x15,
    0x46,
    0x57,
    0xA7,
    0x8D,
    0x9D,
    0x84,
    0x90,
    0xD8,
    0xAB,
    0x00,
    0x8C,
    0xBC,
    0xD3,
    0x0A,
    0xF7,
    0xE4,
    0x58,
    0x05,
    0xB8,
    0xB3,
    0x45,
    0x06,
    0xD0,
    0x2C,
    0x1E,
    0x8F,
    0xCA,
    0x3F,
    0x0F,
    0x02,
    0xC1,
    0xAF,
    0xBD,
    0x03,
    0x01,
    0x13,
    0x8A,
    0x6B,
    0x3A,
    0x91,
    0x11,
    0x41,
    0x4F,
    0x67,
    0xDC,
    0xEA,
    0x97,
    0xF2,
    0xCF,
    0xCE,
    0xF0,
    0xB4,
    0xE6,
    0x73,
    0x96,
    0xAC,
    0x74,
    0x22,
    0xE7,
    0xAD,
    0x35,
    0x85,
    0xE2,
    0xF9,
    0x37,
    0xE8,
    0x1C,
    0x75,
    0xDF,
    0x6E,
    0x47,
    0xF1,
    0x1A,
    0x71,
    0x1D,
    0x29,
    0xC5,
    0x89,
    0x6F,
    0xB7,
    0x62,
    0x0E,
    0xAA,
    0x18,
    0xBE,
    0x1B,
    0xFC,
    0x56,
    0x3E,
    0x4B,
    0xC6,
    0xD2,
    0x79,
    0x20,
    0x9A,
    0xDB,
    0xC0,
    0xFE,
    0x78,
    0xCD,
    0x5A,
    0xF4,
    0x1F,
    0xDD,
    0xA8,
    0x33,
    0x88,
    0x07,
    0xC7,
    0x31,
    0xB1,
    0x12,
    0x10,
    0x59,
    0x27,
    0x80,
    0xEC,
    0x5F,
    0x60,
    0x51,
    0x7F,
    0xA9,
    0x19,
    0xB5,
    0x4A,
    0x0D,
    0x2D,
    0xE5,
    0x7A,
    0x9F,
    0x93,
    0xC9,
    0x9C,
    0xEF,
    0xA0,
    0xE0,
    0x3B,
    0x4D,
    0xAE,
    0x2A,
    0xF5,
    0xB0,
    0xC8,
    0xEB,
    0xBB,
    0x3C,
    0x83,
    0x53,
    0x99,
    0x61,
    0x17,
    0x2B,
    0x04,
    0x7E,
    0xBA,
    0x77,
    0xD6,
    0x26,
    0xE1,
    0x69,
    0x14,
    0x63,
    0x55,
    0x21,
    0x0C,
    0x7D,
]

RCON = [
    0x00000000,
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1B000000,
    0x36000000,
]


# rotate 32-bit word
def rot_word(w):
    return ((w << 8) | (w >> 24)) & 0xFFFFFFFF


# substitute word bytes
def sub_word(w):
    return (
        (SBOX[(w >> 24) & 0xFF] << 24)
        | (SBOX[(w >> 16) & 0xFF] << 16)
        | (SBOX[(w >> 8) & 0xFF] << 8)
        | SBOX[w & 0xFF]
    ) & 0xFFFFFFFF


# multiply in GF(2^8)
def gf_mul(a, b):
    res = 0
    aa = a
    bb = b
    for _ in range(8):
        if bb & 1:
            res ^= aa
        hi_bit = aa & 0x80
        aa = (aa << 1) & 0xFF
        if hi_bit:
            aa ^= 0x1B
        bb >>= 1
    return res


# 4 bytes to u32
def bytes_to_word(block, offset):
    return (
        (block[offset] << 24)
        | (block[offset + 1] << 16)
        | (block[offset + 2] << 8)
        | block[offset + 3]
    )


# u32 to 4 bytes
def word_to_bytes(word):
    return bytes([(word >> 24) & 0xFF, (word >> 16) & 0xFF, (word >> 8) & 0xFF, word & 0xFF])


# derive round keys
def expand_key(key):
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 128, 192, or 256 bits")
    nk = len(key) // 4
    nr = nk + 6
    nb = 4
    total_words = nb * (nr + 1)
    w = [0] * total_words
    for i in range(nk):
        w[i] = bytes_to_word(key, i * 4)
    for i in range(nk, total_words):
        temp = w[i - 1]
        if i % nk == 0:
            temp = sub_word(rot_word(temp)) ^ RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        w[i] = (w[i - nk] ^ temp) & 0xFFFFFFFF
    round_keys_bytes = b"".join(word_to_bytes(word) for word in w)
    return nk, nr, round_keys_bytes


# xor round key
def add_round_key(state, round_keys, round_idx):
    offset = round_idx * BLOCK_SIZE
    for i in range(BLOCK_SIZE):
        state[i] ^= round_keys[offset + i]


# s-box 
def sub_bytes(state):
    for i in range(BLOCK_SIZE):
        state[i] = SBOX[state[i]]


# inverse s-box
def inv_sub_bytes(state):
    for i in range(BLOCK_SIZE):
        state[i] = INV_SBOX[state[i]]


# row shifts
def shift_rows(state):
    t = state[1]
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], t

    t1, t2 = state[2], state[6]
    state[2], state[6], state[10], state[14] = state[10], state[14], t1, t2

    t = state[15]
    state[15], state[11], state[7], state[3] = state[11], state[7], state[3], t


# inverse row shifts
def inv_shift_rows(state):
    t = state[13]
    state[13], state[9], state[5], state[1] = state[9], state[5], state[1], t

    t1, t2 = state[2], state[6]
    state[2], state[6], state[10], state[14] = state[10], state[14], t1, t2

    t = state[3]
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], t


# mix columns
def mix_columns(state):
    for c in range(4):
        idx = c * 4
        b0, b1, b2, b3 = state[idx : idx + 4]
        state[idx] = gf_mul(b0, 2) ^ gf_mul(b1, 3) ^ b2 ^ b3
        state[idx + 1] = b0 ^ gf_mul(b1, 2) ^ gf_mul(b2, 3) ^ b3
        state[idx + 2] = b0 ^ b1 ^ gf_mul(b2, 2) ^ gf_mul(b3, 3)
        state[idx + 3] = gf_mul(b0, 3) ^ b1 ^ b2 ^ gf_mul(b3, 2)


# inverse mix columns
def inv_mix_columns(state):
    for c in range(4):
        idx = c * 4
        b0, b1, b2, b3 = state[idx : idx + 4]
        state[idx] = gf_mul(b0, 0x0E) ^ gf_mul(b1, 0x0B) ^ gf_mul(b2, 0x0D) ^ gf_mul(b3, 0x09)
        state[idx + 1] = gf_mul(b0, 0x09) ^ gf_mul(b1, 0x0E) ^ gf_mul(b2, 0x0B) ^ gf_mul(b3, 0x0D)
        state[idx + 2] = gf_mul(b0, 0x0D) ^ gf_mul(b1, 0x09) ^ gf_mul(b2, 0x0E) ^ gf_mul(b3, 0x0B)
        state[idx + 3] = gf_mul(b0, 0x0B) ^ gf_mul(b1, 0x0D) ^ gf_mul(b2, 0x09) ^ gf_mul(b3, 0x0E)


# AES encrypt one block
def encrypt_block(block, round_keys, nr):
    if len(block) != BLOCK_SIZE:
        raise ValueError("AES block must be 16 bytes")
    state = bytearray(block)
    add_round_key(state, round_keys, 0)
    for rnd in range(1, nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys, rnd)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys, nr)
    return bytes(state)


# AES decrypt one block
def decrypt_block(block, round_keys, nr):
    if len(block) != BLOCK_SIZE:
        raise ValueError("AES block must be 16 bytes")
    state = bytearray(block)
    add_round_key(state, round_keys, nr)
    for rnd in range(nr - 1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys, rnd)
        inv_mix_columns(state)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys, 0)
    return bytes(state)


# xor two byte strings
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# check block size
def ensure_block(label, value):
    if len(value) != BLOCK_SIZE:
        raise ValueError(f"{label} must be {BLOCK_SIZE} bytes")


# chunk into 16-byte blocks
def split_blocks(data):
    return [data[i : i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


# ECB encrypt
def encrypt_ecb(key, plaintext, pad, round_keys, nr):
    data = pad_zero_count(plaintext, BLOCK_SIZE) if pad else plaintext
    if not pad and len(data) % BLOCK_SIZE != 0:
        raise ValueError("Input length must align to block size when padding is disabled")
    output = bytearray()
    steps: List[Dict] = []
    for idx, block in enumerate(split_blocks(data)):
        cipher = encrypt_block(block, round_keys, nr)
        output.extend(cipher)
        steps.append(
          {"title": f"Block {idx + 1}", "fields": [{"label": "Input", "value": bytes_to_hex(block)}, {"label": "Cipher", "value": bytes_to_hex(cipher)}]}
        )
    return bytes(output), steps


# ECB decrypt
def decrypt_ecb(key, ciphertext, pad, round_keys, nr):
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must align to block size")
    output = bytearray()
    steps = []
    for idx, block in enumerate(split_blocks(ciphertext)):
        plain = decrypt_block(block, round_keys, nr)
        output.extend(plain)
        steps.append(
          {"title": f"Block {idx + 1}", "fields": [{"label": "Cipher", "value": bytes_to_hex(block)}, {"label": "Plain", "value": bytes_to_hex(plain)}]}
        )
    if pad:
        try:
            output = bytearray(unpad_zero_count(bytes(output), BLOCK_SIZE))
        except ValueError:
            pass
    return bytes(output), steps


# CBC encrypt
def encrypt_cbc(key, plaintext, iv, pad, round_keys, nr):
    ensure_block("IV", iv)
    data = pad_zero_count(plaintext, BLOCK_SIZE) if pad else plaintext
    if not pad and len(data) % BLOCK_SIZE != 0:
        raise ValueError("Input length must align to block size when padding is disabled")
    output = bytearray()
    prev = iv
    steps = []
    for idx, block in enumerate(split_blocks(data)):
        mixed = xor_bytes(block, prev)
        cipher = encrypt_block(mixed, round_keys, nr)
        output.extend(cipher)
        steps.append(
          {"title": f"Block {idx + 1}", "fields": [
            {"label": "Plain", "value": bytes_to_hex(block)},
            {"label": "Prev/IV", "value": bytes_to_hex(prev)},
            {"label": "XOR", "value": bytes_to_hex(mixed)},
            {"label": "Cipher", "value": bytes_to_hex(cipher)},
          ]}
        )
        prev = cipher
    return bytes(output), steps


# CBC decrypt
def decrypt_cbc(key, ciphertext, iv, pad, round_keys, nr):
    ensure_block("IV", iv)
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must align to block size")
    output = bytearray()
    prev = iv
    steps = []
    for idx, block in enumerate(split_blocks(ciphertext)):
        decrypted = decrypt_block(block, round_keys, nr)
        plain = xor_bytes(decrypted, prev)
        output.extend(plain)
        steps.append(
          {"title": f"Block {idx + 1}", "fields": [
            {"label": "Cipher", "value": bytes_to_hex(block)},
            {"label": "Prev/IV", "value": bytes_to_hex(prev)},
            {"label": "Block Dec", "value": bytes_to_hex(decrypted)},
            {"label": "Plain", "value": bytes_to_hex(plain)},
          ]}
        )
        prev = block
    if pad:
        try:
            output = bytearray(unpad_zero_count(bytes(output), BLOCK_SIZE))
        except ValueError:
            pass
    return bytes(output), steps


# CFB encrypt
def encrypt_cfb(key, plaintext, iv, round_keys, nr):
    ensure_block("IV", iv)
    output = bytearray()
    feedback = iv
    steps = []
    for idx, offset in enumerate(range(0, len(plaintext), BLOCK_SIZE)):
        block = plaintext[offset : offset + BLOCK_SIZE]
        keystream = encrypt_block(feedback, round_keys, nr)
        cipher = xor_bytes(block, keystream[: len(block)])
        output.extend(cipher)
        steps.append(
          {"title": f"Chunk {idx + 1}", "fields": [
            {"label": "Plain", "value": bytes_to_hex(block)},
            {"label": "Keystream", "value": bytes_to_hex(keystream)},
            {"label": "Cipher", "value": bytes_to_hex(cipher)},
          ]}
        )
        if len(cipher) == BLOCK_SIZE:
            feedback = cipher
    return bytes(output), steps


# CFB decrypt
def decrypt_cfb(key, ciphertext, iv, round_keys, nr):
    ensure_block("IV", iv)
    output = bytearray()
    feedback = iv
    steps = []
    for idx, offset in enumerate(range(0, len(ciphertext), BLOCK_SIZE)):
        block = ciphertext[offset : offset + BLOCK_SIZE]
        keystream = encrypt_block(feedback, round_keys, nr)
        plain = xor_bytes(block, keystream[: len(block)])
        output.extend(plain)
        steps.append(
          {"title": f"Chunk {idx + 1}", "fields": [
            {"label": "Cipher", "value": bytes_to_hex(block)},
            {"label": "Keystream", "value": bytes_to_hex(keystream)},
            {"label": "Plain", "value": bytes_to_hex(plain)},
          ]}
        )
        feedback = block
    return bytes(output), steps


# OFB encrypt
def encrypt_ofb(key, plaintext, iv, round_keys, nr):
    ensure_block("IV", iv)
    output = bytearray()
    feedback = iv
    steps = []
    for idx, offset in enumerate(range(0, len(plaintext), BLOCK_SIZE)):
        keystream = encrypt_block(feedback, round_keys, nr)
        block = plaintext[offset : offset + BLOCK_SIZE]
        cipher = xor_bytes(block, keystream[: len(block)])
        output.extend(cipher)
        steps.append(
          {"title": f"Chunk {idx + 1}", "fields": [
            {"label": "Plain", "value": bytes_to_hex(block)},
            {"label": "Keystream", "value": bytes_to_hex(keystream)},
            {"label": "Cipher", "value": bytes_to_hex(cipher)},
          ]}
        )
        feedback = keystream
    return bytes(output), steps


# OFB decrypt (same as encrypt), I had already written the code with decrypt sorry 
def decrypt_ofb(key, ciphertext, iv, round_keys, nr):
    return encrypt_ofb(key, ciphertext, iv, round_keys, nr)


# increment counter bytes
def increment_counter(counter):
    counter_list = list(counter)
    for i in range(len(counter_list) - 1, -1, -1):
        counter_list[i] = (counter_list[i] + 1) & 0xFF
        if counter_list[i] != 0:
            break
    return bytes(counter_list)


# CTR encrypt
def encrypt_ctr(key, plaintext, counter, round_keys, nr):
    ensure_block("Counter", counter)
    output = bytearray()
    current = counter
    steps = []
    for idx, offset in enumerate(range(0, len(plaintext), BLOCK_SIZE)):
        keystream = encrypt_block(current, round_keys, nr)
        block = plaintext[offset : offset + BLOCK_SIZE]
        cipher = xor_bytes(block, keystream[: len(block)])
        output.extend(cipher)
        steps.append(
          {"title": f"Chunk {idx + 1}", "fields": [
            {"label": "Counter", "value": bytes_to_hex(current)},
            {"label": "Keystream", "value": bytes_to_hex(keystream)},
            {"label": "Output", "value": bytes_to_hex(cipher)},
          ]}
        )
        current = increment_counter(current)
    return bytes(output), steps


# CTR decrypt (same as encrypt)
def decrypt_ctr(key, ciphertext, counter, round_keys, nr):
    return encrypt_ctr(key, ciphertext, counter, round_keys, nr)


# guess encoding for decrypt
def detect_encoding(text):
    cleaned = text.strip()
    if not cleaned:
        return None
    if re.fullmatch(r"[0-9a-fA-F\s]+", cleaned) and len(re.sub(r"\s+", "", cleaned)) % 2 == 0:
        return "hex"
    if re.fullmatch(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", cleaned) and len(cleaned) % 4 == 0:
        return "base64"
    return None


# decode input foreach encoding
def decode_input(text, encoding):
    if encoding == "utf8":
        return string_to_utf8(text)
    if encoding == "hex":
        return hex_to_bytes(text)
    if encoding == "base64":
        return base64_to_bytes(text)
    raise ValueError("Unknown encoding")


# prepare outputs
def format_outputs(data):
    # trim trailing nulls for nicer utf8 display
    clean = data.rstrip(b"\x00")
    return {
        "hex": bytes_to_hex(data),
        "base64": bytes_to_base64(data),
        "utf8": utf8_to_string(clean),
    }


# IV is zero by default 
def default_iv():
    return bytes([0] * BLOCK_SIZE)


# counter default at zero 
def default_counter():
    return bytes([0] * BLOCK_SIZE)


# main cipher
def run_cipher(payload):
    operation = payload.get("operation")
    mode = payload.get("mode")
    input_encoding = payload.get("inputEncoding", "utf8")
    padding_flag = bool(payload.get("padding", False))
    text = payload.get("text", "")
    key_hex = payload.get("keyHex", "")
    iv_hex = payload.get("ivHex", "")
    counter_hex = payload.get("counterHex", "")

    key = hex_to_bytes(key_hex)
    if len(key) not in (16, 24, 32):
        raise ValueError("Key must be 128, 192, or 256 bits (16/24/32 bytes hex)")

    iv = hex_to_bytes(iv_hex) if iv_hex.strip() else default_iv()
    counter = hex_to_bytes(counter_hex) if counter_hex.strip() else default_counter()

    if mode not in ("ECB", "CBC"):
        padding_flag = False

    # auto-detect encoding :)
    chosen_encoding = input_encoding
    if operation == "decrypt" and input_encoding == "utf8":
        detected = detect_encoding(text)
        if detected:
            chosen_encoding = detected

    data_bytes = decode_input(text, chosen_encoding)

    if mode in ("ECB", "CBC") and len(data_bytes) % BLOCK_SIZE != 0 and operation == "decrypt":
        # block modes need aligned length
        raise ValueError("Ciphertext length must be a multiple of 16 bytes for this mode.")

    nk, nr, round_keys = expand_key(key)

    auto_padded = False
    if operation == "encrypt":
        pad_now = padding_flag
        if mode in ("ECB", "CBC"):
            if len(data_bytes) % BLOCK_SIZE != 0:
                auto_padded = True
            pad_now = True  # always pad block modes on encrypt

        if mode == "ECB":
            output, steps = encrypt_ecb(key, data_bytes, pad_now, round_keys, nr)
            iv_used = None
            counter_used = None
        elif mode == "CBC":
            output, steps = encrypt_cbc(key, data_bytes, iv, pad_now, round_keys, nr)
            iv_used = bytes_to_hex(iv)
            counter_used = None
        elif mode == "CFB":
            output, steps = encrypt_cfb(key, data_bytes, iv, round_keys, nr)
            iv_used = bytes_to_hex(iv)
            counter_used = None
        elif mode == "OFB":
            output, steps = encrypt_ofb(key, data_bytes, iv, round_keys, nr)
            iv_used = bytes_to_hex(iv)
            counter_used = None
        elif mode == "CTR":
            output, steps = encrypt_ctr(key, data_bytes, counter, round_keys, nr)
            iv_used = None
            counter_used = bytes_to_hex(counter)
        else:
            raise ValueError("Unknown mode")
    else:
        pad_now = padding_flag
        if mode == "ECB":
            output, steps = decrypt_ecb(key, data_bytes, pad_now, round_keys, nr)
            iv_used = None
            counter_used = None
        elif mode == "CBC":
            output, steps = decrypt_cbc(key, data_bytes, iv, pad_now, round_keys, nr)
            iv_used = bytes_to_hex(iv)
            counter_used = None
        elif mode == "CFB":
            output, steps = decrypt_cfb(key, data_bytes, iv, round_keys, nr)
            iv_used = bytes_to_hex(iv)
            counter_used = None
        elif mode == "OFB":
            output, steps = decrypt_ofb(key, data_bytes, iv, round_keys, nr)
            iv_used = bytes_to_hex(iv)
            counter_used = None
        elif mode == "CTR":
            output, steps = decrypt_ctr(key, data_bytes, counter, round_keys, nr)
            iv_used = None
            counter_used = bytes_to_hex(counter)
        else:
            raise ValueError("Unknown mode")

    return {
        "output": format_outputs(output),
        "encodingUsed": chosen_encoding,
        "autoPadded": auto_padded,
        "ivUsed": iv_used,
        "counterUsed": counter_used,
        "steps": steps,
    }

#Note: Chat-GPT helped with this section of the code
#I just needed backend and frontend to communicate clearly

@app.after_request
def add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    return resp


@app.route("/api/cipher", methods=["POST"])
def api_cipher():
    # handle cipher requests
    try:
        payload = request.get_json(force=True)
    except Exception:
        return "Invalid JSON", 400
    try:
        result = run_cipher(payload)
        return jsonify(result)
    except Exception as exc:
        return str(exc), 400


@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
