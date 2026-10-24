"""Persistencia: Supabase (REST/PostgREST) si hay SUPABASE_URL, si no SQLite local."""
import hashlib
import hmac
import os
import sqlite3
from pathlib import Path

import httpx

try:  # carga backend-prefect/.env si existe
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass

# Estados del Process Manager de aprovisionamiento 2FA
PENDING_VERIFICATION = "PENDING_VERIFICATION"
ACTIVE = "ACTIVE"

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")
USE_SUPABASE = bool(SUPABASE_URL and SUPABASE_KEY)
DB_PATH = Path(os.environ.get("MFA_DB", Path(__file__).resolve().parent.parent / "mfa.db"))


class UserExists(Exception):
    pass


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + "$" + dk.hex()


def check_password(password: str, stored: str) -> bool:
    salt_hex, dk_hex = stored.split("$")
    dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
    return hmac.compare_digest(dk.hex(), dk_hex)


def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


# ---------------------------------------------------------------- Supabase
def _rest(method: str, table: str, params=None, json=None, prefer: str | None = None):
    headers = {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}
    if prefer:
        headers["Prefer"] = prefer
    r = httpx.request(method, f"{SUPABASE_URL}/rest/v1/{table}", params=params, json=json,
                      headers=headers, timeout=15)
    if r.status_code == 409:
        raise UserExists()
    r.raise_for_status()
    return r.json() if r.content else None


# ------------------------------------------------------------------ SQLite
def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    if USE_SUPABASE:
        return
    with _conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS mfa_config(user_id INTEGER PRIMARY KEY REFERENCES users(id),
                secret TEXT NOT NULL, state TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS backup_codes(id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id), code_hash TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0);
            """
        )


# ------------------------------------------------------------- API común
def create_user(username: str, password: str):
    ph = hash_password(password)
    if USE_SUPABASE:
        _rest("POST", "users", json={"username": username, "password_hash": ph})
        return
    try:
        with _conn() as c:
            c.execute("INSERT INTO users(username, password_hash) VALUES(?,?)", (username, ph))
    except sqlite3.IntegrityError:
        raise UserExists()


def get_user_by_name(username: str):
    if USE_SUPABASE:
        rows = _rest("GET", "users", params={"username": f"eq.{username}", "select": "id,username,password_hash"})
        return rows[0] if rows else None
    with _conn() as c:
        row = c.execute("SELECT id, username, password_hash FROM users WHERE username=?", (username,)).fetchone()
    return dict(row) if row else None


def get_username(user_id: int) -> str:
    if USE_SUPABASE:
        return _rest("GET", "users", params={"id": f"eq.{user_id}", "select": "username"})[0]["username"]
    with _conn() as c:
        return c.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()["username"]


def get_mfa(user_id: int):
    if USE_SUPABASE:
        rows = _rest("GET", "mfa_config", params={"user_id": f"eq.{user_id}", "select": "secret,state"})
        return rows[0] if rows else None
    with _conn() as c:
        row = c.execute("SELECT secret, state FROM mfa_config WHERE user_id=?", (user_id,)).fetchone()
    return dict(row) if row else None


def upsert_mfa(user_id: int, secret: str, state: str):
    if USE_SUPABASE:
        _rest("POST", "mfa_config", params={"on_conflict": "user_id"},
              json={"user_id": user_id, "secret": secret, "state": state},
              prefer="resolution=merge-duplicates")
        return
    with _conn() as c:
        c.execute("INSERT OR REPLACE INTO mfa_config(user_id, secret, state) VALUES(?,?,?)", (user_id, secret, state))


def set_mfa_state(user_id: int, state: str):
    if USE_SUPABASE:
        _rest("PATCH", "mfa_config", params={"user_id": f"eq.{user_id}"}, json={"state": state})
        return
    with _conn() as c:
        c.execute("UPDATE mfa_config SET state=? WHERE user_id=?", (state, user_id))


def replace_backup_codes(user_id: int, codes: list[str]):
    if USE_SUPABASE:
        _rest("DELETE", "backup_codes", params={"user_id": f"eq.{user_id}"})
        _rest("POST", "backup_codes", json=[{"user_id": user_id, "code_hash": hash_code(c)} for c in codes])
        return
    with _conn() as c:
        c.execute("DELETE FROM backup_codes WHERE user_id=?", (user_id,))
        c.executemany("INSERT INTO backup_codes(user_id, code_hash) VALUES(?,?)",
                      [(user_id, hash_code(x)) for x in codes])


def consume_backup_code(user_id: int, code: str) -> bool:
    h = hash_code(code)
    if USE_SUPABASE:  # UPDATE ... WHERE used=false RETURNING: atómico, un solo uso
        rows = _rest("PATCH", "backup_codes",
                     params={"user_id": f"eq.{user_id}", "code_hash": f"eq.{h}", "used": "eq.false"},
                     json={"used": True}, prefer="return=representation")
        return bool(rows)
    with _conn() as c:
        cur = c.execute("UPDATE backup_codes SET used=1 WHERE user_id=? AND code_hash=? AND used=0", (user_id, h))
        return cur.rowcount > 0
