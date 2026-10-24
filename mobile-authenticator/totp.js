// TOTP (RFC 6238) desde cero. Solo se usa una librería para el primitivo HMAC-SHA1.
import sha1 from 'js-sha1';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// 1. Base32 -> bytes
export function base32Decode(input) {
  const clean = input.replace(/[\s=]/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error('Carácter Base32 inválido: ' + ch);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

// 3. Contador como entero de 8 bytes big-endian
function counterToBytes(counter) {
  const buf = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    buf[i] = c % 256;
    c = Math.floor(c / 256);
  }
  return buf;
}

export function hotp(keyBytes, counter, digits = 6) {
  const hash = sha1.hmac.array(Array.from(keyBytes), Array.from(counterToBytes(counter))); // 4. 20 bytes
  const offset = hash[19] & 0x0f;                                                          // 5. truncamiento dinámico
  const bin =
    ((hash[offset] & 0x7f) << 24) |
    (hash[offset + 1] << 16) |
    (hash[offset + 2] << 8) |
    hash[offset + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

// 2. C = floor(UnixTime / 30)
export function totp(secretBase32, unixSeconds = Math.floor(Date.now() / 1000)) {
  return hotp(base32Decode(secretBase32), Math.floor(unixSeconds / 30));
}

export function secondsRemaining(unixSeconds = Math.floor(Date.now() / 1000)) {
  return 30 - (unixSeconds % 30);
}

// otpauth://totp/Label?secret=XXXX&issuer=...
export function parseOtpauth(uri) {
  const m = uri.match(/^otpauth:\/\/totp\/([^?]*)\?(.*)$/i);
  if (!m) return null;
  const params = new URLSearchParams(m[2]);
  const secret = params.get('secret');
  if (!secret) return null;
  return { label: decodeURIComponent(m[1]), secret };
}
