import base64
import io
import secrets
from pathlib import Path

import jwt
import qrcode
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from . import db, flows, security, totp

app = FastAPI(title="MFA Taller - Step-Up Auth + Prefect")
bearer = HTTPBearer()
STATIC = Path(__file__).resolve().parent.parent / "static"


@app.on_event("startup")
def _startup():
    db.init_db()


class Credentials(BaseModel):
    username: str
    password: str


class CodeBody(BaseModel):
    code: str
    method: str = "totp"  # "totp" | "backup"


def claims_for(scope: str):
    def dep(cred: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
        try:
            claims = security.decode_token(cred.credentials)
        except jwt.PyJWTError:
            raise HTTPException(401, "Token inválido o expirado")
        if claims.get("scope") != scope:
            raise HTTPException(403, f"Este endpoint requiere un token con scope '{scope}'")
        if scope == "access" and claims.get("mfa_verified") is not True:
            raise HTTPException(403, "mfa_verified requerido")
        return claims
    return dep


def mfa_state(user_id: int):
    row = db.get_mfa(user_id)
    return row["state"] if row else None


def run_flow(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except flows.ReplayAttackDetected as e:
        raise HTTPException(409, f"ReplayAttackDetected: {e}")
    except (flows.InvalidPreAuth, flows.InvalidCredentials) as e:
        raise HTTPException(401, str(e))
    except flows.SecondFactorFailed as e:
        raise HTTPException(401, str(e))


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.post("/auth/register")
def register(body: Credentials):
    try:
        db.create_user(body.username, body.password)
    except db.UserExists:
        raise HTTPException(409, "Usuario ya existe")
    return {"ok": True}


@app.post("/auth/login")
def login(body: Credentials):
    pre = run_flow(flows.login_flow, body.username, body.password)
    user_id = int(security.decode_token(pre)["sub"])
    return {"pre_auth_token": pre, "mfa_state": mfa_state(user_id)}


@app.post("/auth/2fa/setup")
def setup_2fa(claims: dict = Depends(claims_for("pre_auth"))):
    """Process Manager: crea la config en PENDING_VERIFICATION."""
    user_id = int(claims["sub"])
    if mfa_state(user_id) == db.ACTIVE:
        raise HTTPException(409, "2FA ya está ACTIVE")
    username = db.get_username(user_id)
    secret = totp.generate_secret()
    db.upsert_mfa(user_id, secret, db.PENDING_VERIFICATION)
    uri = totp.provisioning_uri(secret, username)
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format="PNG")
    return {"state": db.PENDING_VERIFICATION, "secret": secret, "otpauth_uri": uri,
            "qr_png_base64": base64.b64encode(buf.getvalue()).decode()}


@app.post("/auth/2fa/activate")
def activate_2fa(body: CodeBody, cred: HTTPAuthorizationCredentials = Depends(bearer),
                 claims: dict = Depends(claims_for("pre_auth"))):
    """Primer código válido: PENDING_VERIFICATION -> ACTIVE y entrega códigos de respaldo."""
    user_id = int(claims["sub"])
    if mfa_state(user_id) != db.PENDING_VERIFICATION:
        raise HTTPException(409, "No hay 2FA en estado PENDING_VERIFICATION")
    access = run_flow(flows.verify_2fa_flow, cred.credentials, body.code, "totp", True)
    codes = [secrets.token_hex(4) for _ in range(8)]
    db.replace_backup_codes(user_id, codes)
    return {"access_token": access, "backup_codes": codes, "state": db.ACTIVE}


@app.post("/auth/verify-2fa")
def verify_2fa(body: CodeBody, cred: HTTPAuthorizationCredentials = Depends(bearer),
               claims: dict = Depends(claims_for("pre_auth"))):
    if mfa_state(int(claims["sub"])) != db.ACTIVE:
        raise HTTPException(409, "2FA no está ACTIVE; use /auth/2fa/setup y /auth/2fa/activate")
    access = run_flow(flows.verify_2fa_flow, cred.credentials, body.code, body.method, False)
    return {"access_token": access, "mfa_verified": True}


@app.get("/api/boveda-secreta")
def boveda(claims: dict = Depends(claims_for("access"))):
    return {"mensaje": "Bienvenido a la bóveda secreta", "user_id": claims["sub"], "mfa_verified": True}
