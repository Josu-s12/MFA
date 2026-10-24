// Ejecutar: node totp.test.mjs  (vectores RFC 6238, SHA1, 8 dígitos)
import { base32Decode, hotp, totp } from './totp.js';

const key = base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
const cases = [[59, '94287082'], [1111111109, '07081804'], [1234567890, '89005924'], [2000000000, '69279037']];
let ok = true;
for (const [t, exp] of cases) {
  const got = hotp(key, Math.floor(t / 30), 8);
  console.log(t, got, got === exp ? 'OK' : 'FAIL (esperado ' + exp + ')');
  ok = ok && got === exp;
}
console.log('6 dígitos @59:', totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59));
process.exit(ok ? 0 : 1);
