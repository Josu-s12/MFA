"""TOTP (RFC 6238) implementado desde cero: HMAC-SHA1 + truncamiento dinámico."""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

PERIOD = 30
DIGITS = 6


def generate_secret(n_bytes: int = 20) -> str:
    return base64.b32encode(secrets.token_bytes(n_bytes)).decode().rstrip("=")


def b32decode(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    msg = struct.pack(">Q", counter)                  # entero de 8 bytes big-endian
    h = hmac.new(key, msg, hashlib.sha1).digest()     # 20 bytes
    offset = h[19] & 0x0F                             # truncamiento dinámico
    value = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


def counter_at(unix_time: float | None = None) -> int:
    return int((time.time() if unix_time is None else unix_time) // PERIOD)


def totp(secret: str, unix_time: float | None = None) -> str:
    return hotp(b32decode(secret), counter_at(unix_time))


def verify_with_window(secret: str, code: str, unix_time: float | None = None):
    """Evalúa las ventanas C-1, C y C+1. Devuelve el offset (-1, 0, 1) o None."""
    key = b32decode(secret)
    c = counter_at(unix_time)
    for offset in (0, -1, 1):
        if hmac.compare_digest(hotp(key, c + offset), code):
            return offset
    return None


def provisioning_uri(secret: str, username: str, issuer: str = "MFA-Taller") -> str:
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
