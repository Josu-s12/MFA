"""JWT (pre_auth vs access) y caché anti-replay en memoria."""
import os
import threading
import time

import jwt

SECRET = os.environ.get("JWT_SECRET", "dev-only-secret-change-me-0123456789abcdef")
PRE_AUTH_TTL = 300
ACCESS_TTL = 3600
REPLAY_TTL = 90


def make_token(user_id: int, scope: str, ttl: int, **extra) -> str:
    now = int(time.time())
    return jwt.encode({"sub": str(user_id), "scope": scope, "iat": now, "exp": now + ttl, **extra},
                      SECRET, algorithm="HS256")


def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET, algorithms=["HS256"])


class ReplayCache:
    """(user_id, code) -> instante de uso. Retiene 90 s."""

    def __init__(self, ttl: int = REPLAY_TTL):
        self.ttl = ttl
        self._d: dict[tuple[int, str], float] = {}
        self._lock = threading.Lock()

    def _purge(self):
        now = time.time()
        for k in [k for k, t in self._d.items() if now - t > self.ttl]:
            del self._d[k]

    def seen(self, user_id: int, code: str) -> bool:
        with self._lock:
            self._purge()
            return (user_id, code) in self._d

    def mark(self, user_id: int, code: str):
        with self._lock:
            self._d[(user_id, code)] = time.time()

    def clear(self):
        with self._lock:
            self._d.clear()


replay_cache = ReplayCache()
