import os
import sys
import tempfile
from pathlib import Path

os.environ["SUPABASE_URL"] = ""  # los tests usan SQLite, nunca Supabase
from cryptography.fernet import Fernet
os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["MFA_DB"] = str(Path(tempfile.mkdtemp()) / "test.db")
os.environ["PREFECT_API_URL"] = ""  # tests con servidor efímero, sin depender del Prefect del usuario
os.environ.setdefault("PREFECT_SERVER_ALLOW_EPHEMERAL_MODE", "true")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import time

from fastapi.testclient import TestClient

from app import security, totp
from app.main import app

# Vectores de prueba RFC 6238 (SHA1, secreto ASCII "12345678901234567890", 8 dígitos)
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def test_rfc6238_vectors():
    key = totp.b32decode(RFC_SECRET)
    for t, expected in [(59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"),
                        (2000000000, "69279037")]:
        assert totp.hotp(key, t // 30, 8) == expected


def test_full_flow():
    security.replay_cache.clear()
    with TestClient(app) as c:
        assert c.post("/auth/register", json={"username": "ana", "password": "pw"}).status_code == 200
        pre = c.post("/auth/login", json={"username": "ana", "password": "pw"}).json()["pre_auth_token"]
        h = {"Authorization": f"Bearer {pre}"}
        # pre_auth no sirve para la bóveda
        assert c.get("/api/boveda-secreta", headers=h).status_code == 403
        s = c.post("/auth/2fa/setup", headers=h).json()
        assert s["state"] == "PENDING_VERIFICATION"
        # PENDING no permite verify-2fa
        assert c.post("/auth/verify-2fa", headers=h, json={"code": "000000"}).status_code == 409
        code = totp.totp(s["secret"])
        r = c.post("/auth/2fa/activate", headers=h, json={"code": code})
        assert r.status_code == 200 and len(r.json()["backup_codes"]) == 8
        backup = r.json()["backup_codes"][0]
        # Replay: mismo código otra vez
        assert c.post("/auth/verify-2fa", headers=h, json={"code": code}).status_code == 409
        # Código de ventana adyacente (C-1) válido
        prev = totp.totp(s["secret"], time.time() - 30)
        r = c.post("/auth/verify-2fa", headers=h, json={"code": prev})
        assert r.status_code == 200
        access = r.json()["access_token"]
        ok = c.get("/api/boveda-secreta", headers={"Authorization": f"Bearer {access}"})
        assert ok.status_code == 200
        # Código de respaldo: un solo uso
        assert c.post("/auth/verify-2fa", headers=h, json={"code": backup, "method": "backup"}).status_code == 200
        assert c.post("/auth/verify-2fa", headers=h, json={"code": backup, "method": "backup"}).status_code == 409
